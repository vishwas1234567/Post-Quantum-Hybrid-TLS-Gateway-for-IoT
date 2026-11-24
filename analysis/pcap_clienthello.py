#!/usr/bin/env python3
"""Summarise TLS 1.3 handshakes in a capture: is the key exchange quantum-safe?

Reads .pcap (tcpdump) and .pcapng (Wireshark's default), reassembles the TCP
streams and prints, per connection, what you would otherwise click through in
Wireshark: offered groups, key_share sizes, the group the server selected, the
ClientHello size and how many TCP segments it needed.

    python analysis/pcap_clienthello.py capture/hybrid.pcapng [--json]
"""
import argparse
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tls_parse import PQ_GROUPS, summarize_flow  # noqa: E402


# ---------------------------------------------------------------- readers
def read_pcap(data):
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        end = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        end = ">"
    else:
        raise ValueError("not a pcap file")
    linktype = struct.unpack(end + "I", data[20:24])[0]
    i = 24
    while i + 16 <= len(data):
        _, _, caplen, _ = struct.unpack(end + "IIII", data[i:i + 16])
        yield linktype, data[i + 16:i + 16 + caplen]
        i += 16 + caplen


def read_pcapng(data):
    end = "<" if data[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
    links, i = [], 0
    while i + 12 <= len(data):
        btype, blen = struct.unpack(end + "II", data[i:i + 8])
        if blen < 12:
            break
        body = data[i + 8:i + blen - 4]
        if btype == 1:                                   # Interface Description
            links.append(struct.unpack(end + "H", body[:2])[0])
        elif btype == 6:                                 # Enhanced Packet
            ifid, _, _, caplen, _ = struct.unpack(end + "IIIII", body[:20])
            yield (links[ifid] if ifid < len(links) else 1), body[20:20 + caplen]
        i += blen


def read_packets(path):
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        return read_pcapng(data)
    return read_pcap(data)


# ---------------------------------------------------------------- decoding
def strip_link(linktype, pkt):
    """Return (ethertype-ish ip version, ip bytes) or None."""
    if linktype == 1:                                    # Ethernet
        et, off = struct.unpack("!H", pkt[12:14])[0], 14
        while et in (0x8100, 0x88A8):
            et, off = struct.unpack("!H", pkt[off + 2:off + 4])[0], off + 4
        return pkt[off:] if et in (0x0800, 0x86DD) else None
    if linktype == 0:                                    # BSD loopback
        return pkt[4:]
    if linktype == 113:                                  # Linux cooked v1
        return pkt[16:]
    if linktype == 276:                                  # Linux cooked v2
        return pkt[20:]
    if linktype in (101, 228, 229):                      # raw IP
        return pkt
    return None


def decode_tcp(ip):
    ver = ip[0] >> 4
    if ver == 4:
        ihl = (ip[0] & 0x0F) * 4
        if ip[9] != 6:
            return None
        src, dst = ip[12:16], ip[16:20]
        tcp = ip[ihl:struct.unpack("!H", ip[2:4])[0]]
    elif ver == 6:
        if ip[6] != 6:
            return None
        src, dst, tcp = ip[8:24], ip[24:40], ip[40:]
    else:
        return None
    sport, dport, seq = struct.unpack("!HHI", tcp[:8])
    off = (tcp[12] >> 4) * 4
    return (src, sport), (dst, dport), seq, tcp[off:]


def fmt_addr(a):
    ip, port = a
    s = ".".join(map(str, ip)) if len(ip) == 4 else ip.hex(":", 2)
    return "%s:%d" % (s, port)


def reassemble(segs):
    """segs: [(seq, payload)] -> (bytes, n_segments_used)."""
    out, nxt, used = bytearray(), None, 0
    for seq, pl in sorted(segs, key=lambda s: s[0]):
        if not pl:
            continue
        if nxt is None:
            nxt = seq
        if seq > nxt:                    # gap -> stop, stream truncated
            break
        if seq + len(pl) <= nxt:         # pure retransmission
            continue
        out += pl[nxt - seq:]
        nxt = seq + len(pl)
        used += 1
    return bytes(out), used


# ---------------------------------------------------------------- analysis
def analyse(path):
    streams = {}
    for linktype, pkt in read_packets(path):
        ip = strip_link(linktype, pkt)
        if not ip:
            continue
        try:
            d = decode_tcp(ip)
        except (struct.error, IndexError):
            continue
        if d and d[3]:
            src, dst, seq, payload = d
            streams.setdefault((src, dst), []).append((seq, payload))

    results, done = [], set()
    for (src, dst), segs in streams.items():
        data, _ = reassemble(segs)
        # a client stream starts with a TLS handshake record carrying ClientHello
        if not (len(data) > 9 and data[0] == 0x16 and data[5] == 1):
            continue
        if (src, dst) in done:
            continue
        done.add((src, dst))
        reply, _ = reassemble(streams.get((dst, src), []))
        flow = summarize_flow(data, reply)
        ch = flow["client_hello"]
        if not ch:
            continue
        # how many TCP segments did the ClientHello flight need?
        need, acc, n = ch["msg_len"] + 5, 0, 0
        for _, pl in sorted(segs, key=lambda s: s[0]):
            if not pl:
                continue
            acc += len(pl)
            n += 1
            if acc >= need:
                break
        sh = flow["server_hello"]
        results.append({
            "client": fmt_addr(src), "server": fmt_addr(dst),
            "sni": ch["sni"],
            "offered_groups": [n_ for _, n_ in ch["supported_groups"]],
            "key_shares": ["%s (%d B)" % (n_, l) for _, n_, l in ch["key_shares"]],
            "client_hello_bytes": ch["msg_len"],
            "client_hello_tcp_segments": n,
            "server_selected_group": sh["selected_group"][1] if sh and sh["selected_group"] else None,
            "hello_retry_request": bool(sh and sh["hello_retry_request"]),
            "quantum_safe_kex": bool(sh and sh["selected_group"]
                                     and sh["selected_group"][0] in PQ_GROUPS),
            "client_stream_bytes": len(data), "server_stream_bytes": len(reply),
        })
    return results


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("capture")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    res = analyse(args.capture)
    if args.json:
        print(json.dumps(res, indent=2))
        return
    if not res:
        print("no TLS ClientHello found (is the capture on the right port/interface?)")
        return
    for r in res:
        print("%s -> %s   SNI=%s" % (r["client"], r["server"], r["sni"]))
        print("  offered groups     : %s" % ", ".join(r["offered_groups"]))
        print("  key_share sent     : %s" % ", ".join(r["key_shares"]))
        print("  server selected    : %s%s" % (r["server_selected_group"],
              "  (HelloRetryRequest!)" if r["hello_retry_request"] else ""))
        print("  ClientHello        : %d B in %d TCP segment(s)" % (
            r["client_hello_bytes"], r["client_hello_tcp_segments"]))
        print("  QUANTUM-SAFE KEX   : %s" % ("YES" if r["quantum_safe_kex"] else "no"))


if __name__ == "__main__":
    main()
