"""Minimal TLS 1.3 handshake parser (records, ClientHello, ServerHello).

Used by handshake_probe.py (live bytes) and pcap_clienthello.py (Wireshark
captures) so both report exactly the same fields Wireshark shows:
supported_groups, key_share group + size, and the selected group.
"""
import struct

GROUP_NAMES = {
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x001D: "x25519",
    0x0200: "MLKEM512",
    0x0201: "MLKEM768",
    0x0202: "MLKEM1024",
    0x11EB: "SecP256r1MLKEM768",
    0x11EC: "X25519MLKEM768",
    0x11ED: "SecP384r1MLKEM1024",
    0x6399: "X25519Kyber768Draft00",
}
PQ_GROUPS = {0x0200, 0x0201, 0x0202, 0x11EB, 0x11EC, 0x11ED, 0x6399}

HELLO_RETRY_RANDOM = bytes.fromhex(
    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")


def group_name(gid):
    return GROUP_NAMES.get(gid, "0x%04x" % gid)


def split_records(stream):
    """Split a TCP byte stream into TLS records -> [(type, version, payload)]."""
    out, i = [], 0
    while i + 5 <= len(stream):
        ctype, ver, ln = struct.unpack("!BHH", stream[i:i + 5])
        if ctype not in (20, 21, 22, 23) or ln > 18432:
            break          # not TLS (or truncated garbage): stop
        if i + 5 + ln > len(stream):
            out.append((ctype, ver, stream[i + 5:]))   # truncated tail
            break
        out.append((ctype, ver, stream[i + 5:i + 5 + ln]))
        i += 5 + ln
    return out


def handshake_messages(records):
    """Reassemble handshake messages (they may span several records)."""
    buf = b"".join(p for t, _, p in records if t == 22)
    msgs, i = [], 0
    while i + 4 <= len(buf):
        mtype = buf[i]
        ln = int.from_bytes(buf[i + 1:i + 4], "big")
        msgs.append((mtype, buf[i + 4:i + 4 + ln]))
        i += 4 + ln
    return msgs


def _extensions(data):
    exts, i = {}, 0
    while i + 4 <= len(data):
        et, el = struct.unpack("!HH", data[i:i + 4])
        exts[et] = data[i + 4:i + 4 + el]
        i += 4 + el
    return exts


def parse_client_hello(body):
    i = 2 + 32                                   # legacy_version + random
    sid = body[i]; i += 1 + sid                  # session id
    cs_len = struct.unpack("!H", body[i:i + 2])[0]; i += 2
    suites = [struct.unpack("!H", body[j:j + 2])[0] for j in range(i, i + cs_len, 2)]
    i += cs_len
    i += 1 + body[i]                             # compression methods
    ext_len = struct.unpack("!H", body[i:i + 2])[0]; i += 2
    exts = _extensions(body[i:i + ext_len])

    groups = []
    if 10 in exts:
        n = struct.unpack("!H", exts[10][:2])[0]
        groups = [struct.unpack("!H", exts[10][2 + k:4 + k])[0] for k in range(0, n, 2)]
    shares = []
    if 51 in exts:
        data = exts[51]
        total = struct.unpack("!H", data[:2])[0]
        j = 2
        while j < 2 + total:
            g, kl = struct.unpack("!HH", data[j:j + 4])
            shares.append((g, kl))
            j += 4 + kl
    sni = None
    if 0 in exts and len(exts[0]) > 5:
        sni = exts[0][5:5 + struct.unpack("!H", exts[0][3:5])[0]].decode(errors="replace")
    sigalgs = []
    if 13 in exts:
        n = struct.unpack("!H", exts[13][:2])[0]
        sigalgs = [struct.unpack("!H", exts[13][2 + k:4 + k])[0] for k in range(0, n, 2)]
    return {
        "msg_len": len(body) + 4,
        "cipher_suites": len(suites),
        "sni": sni,
        "supported_groups": [(g, group_name(g)) for g in groups],
        "key_shares": [(g, group_name(g), kl) for g, kl in shares],
        "sig_algs": ["0x%04x" % s for s in sigalgs],
        "offers_pq": any(g in PQ_GROUPS for g in groups),
        "key_share_pq": any(g in PQ_GROUPS for g, _ in shares),
    }


def parse_server_hello(body):
    random = body[2:34]
    i = 34
    sid = body[i]; i += 1 + sid
    suite = struct.unpack("!H", body[i:i + 2])[0]; i += 3     # suite + compression
    ext_len = struct.unpack("!H", body[i:i + 2])[0]; i += 2
    exts = _extensions(body[i:i + ext_len])
    sel, sel_len = None, 0
    if 51 in exts:
        e = exts[51]
        if len(e) == 2:                       # HelloRetryRequest: group only
            sel = struct.unpack("!H", e)[0]
        else:
            sel, sel_len = struct.unpack("!HH", e[:4])
    return {
        "msg_len": len(body) + 4,
        "cipher_suite": "0x%04x" % suite,
        "hello_retry_request": random == HELLO_RETRY_RANDOM,
        "selected_group": None if sel is None else (sel, group_name(sel)),
        "key_share_len": sel_len,
    }


def summarize_flow(c2s, s2c):
    """Parse both directions of one TCP connection's byte streams."""
    c_rec, s_rec = split_records(c2s), split_records(s2c)
    out = {"client_hello": None, "server_hello": None}
    for mtype, body in handshake_messages(c_rec):
        if mtype == 1 and out["client_hello"] is None:
            out["client_hello"] = parse_client_hello(body)
    for mtype, body in handshake_messages(s_rec):
        if mtype == 2 and out["server_hello"] is None:
            out["server_hello"] = parse_server_hello(body)
    return out
