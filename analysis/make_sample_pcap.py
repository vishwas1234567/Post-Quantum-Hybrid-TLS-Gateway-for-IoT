#!/usr/bin/env python3
"""Write a demo .pcap from a LIVE handshake's real TLS bytes.

The TLS records are real (captured via MemoryBIO from a real handshake with the
gateway). The Ethernet/IP/TCP headers around them are fabricated, because this
is NOT a tcpdump capture. Use it as a fallback demo file you can open in
Wireshark (filter: tls.handshake.type == 1) when you cannot capture live.

    python analysis/make_sample_pcap.py --profile hybrid --port 8884 --out results/sample_hybrid.pcap
"""
import argparse
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "edge"))
from tls_profiles import PROFILES, ensure_profile  # noqa: E402

MSS = 1460


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def frame(src, dst, sport, dport, seq, ack, flags, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack("!H", csum(pseudo + tcp + payload)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(payload), 0, 0x4000,
                     64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    eth = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00"
    return eth + ip + tcp + payload


def build_pcap(c2s, s2c, port):
    cip, sip, cport = bytes([10, 0, 0, 2]), bytes([10, 0, 0, 1]), 50123
    first_len = 5 + struct.unpack("!H", c2s[3:5])[0]       # the ClientHello record
    flights = [("c", c2s[:first_len]), ("s", s2c), ("c", c2s[first_len:])]
    pkts, t = [], 1.0
    cseq, sseq = 1000, 5000
    pkts.append((t, frame(cip, sip, cport, port, cseq - 1, 0, 0x02)))          # SYN
    pkts.append((t + 0.0002, frame(sip, cip, port, cport, sseq - 1, cseq, 0x12)))  # SYN/ACK
    pkts.append((t + 0.0004, frame(cip, sip, cport, port, cseq, sseq, 0x10)))      # ACK
    t += 0.001
    for who, data in flights:
        for i in range(0, len(data), MSS):
            chunk = data[i:i + MSS]
            if who == "c":
                pkts.append((t, frame(cip, sip, cport, port, cseq, sseq, 0x18, chunk)))
                cseq += len(chunk)
            else:
                pkts.append((t, frame(sip, cip, port, cport, sseq, cseq, 0x18, chunk)))
                sseq += len(chunk)
            t += 0.0001
        t += 0.0008
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts, pk in pkts:
        out += struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(pk), len(pk)) + pk
    return out


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--profile", choices=sorted(PROFILES), required=True)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--ca", default="certs/ca.crt")
    p.add_argument("--out", required=True)
    args = p.parse_args(argv)
    ensure_profile(args.profile)
    from handshake_probe import probe
    r = probe(args.host, args.port, args.ca, keep_raw=True)
    c2s, s2c = r["raw"]
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "wb") as fh:
        fh.write(build_pcap(c2s, s2c, args.port))
    print("wrote %s (%s, group %s)" % (args.out, args.profile,
                                        r["server_hello"]["selected_group"][1]))


if __name__ == "__main__":
    main()
