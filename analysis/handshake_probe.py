#!/usr/bin/env python3
"""Do ONE TLS 1.3 handshake against the gateway and report what really went on the wire.

No root, tcpdump or Wireshark needed: the handshake runs over ssl.MemoryBIO, so
every byte sent/received is captured here and parsed with tls_parse.py. It
shows exactly what Wireshark would: the groups the client offered, the
key_share it sent, the group the server picked, and the handshake sizes.

    python analysis/handshake_probe.py --profile hybrid --port 8884 --ca certs/ca.crt
"""
import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "edge"))
from tls_parse import summarize_flow  # noqa: E402
from tls_profiles import PROFILES, ensure_profile  # noqa: E402


def probe(host, port, ca, sni="localhost", timeout=10, keep_raw=False):
    """Run one handshake. Call only after ensure_profile() has been applied.

    keep_raw=True adds flow["raw"] = (client_bytes, server_bytes)."""
    import socket
    import ssl

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(ca)
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_hostname=sni)

    sock = socket.create_connection((host, port), timeout=timeout)
    c2s, s2c = bytearray(), bytearray()
    round_trips = 0
    t0 = time.perf_counter()
    try:
        while True:
            try:
                obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                pass
            pending = out.read()
            if pending:
                sock.sendall(pending)
                c2s += pending
            chunk = sock.recv(65536)
            if not chunk:
                raise ConnectionError("server closed during handshake")
            round_trips += 1
            s2c += chunk
            inc.write(chunk)
        tail = out.read()                 # client Finished
        if tail:
            sock.sendall(tail)
            c2s += tail
        elapsed_ms = (time.perf_counter() - t0) * 1e3
    finally:
        sock.close()

    flow = summarize_flow(bytes(c2s), bytes(s2c))
    flow.update({
        "handshake_ms": round(elapsed_ms, 3),
        "round_trips": round_trips,
        "c2s_bytes": len(c2s),
        "s2c_bytes": len(s2c),
        "total_bytes": len(c2s) + len(s2c),
        "tls_version": obj.version(),
        "cipher": obj.cipher()[0],
        "openssl": ssl.OPENSSL_VERSION,
    })
    if keep_raw:
        flow["raw"] = (bytes(c2s), bytes(s2c))
    return flow


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--profile", choices=sorted(PROFILES), default="hybrid")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8884)
    p.add_argument("--sni", default="localhost")
    p.add_argument("--ca", default=os.environ.get("CA_FILE", "certs/ca.crt"))
    args = p.parse_args(argv)
    ensure_profile(args.profile)
    res = probe(args.host, args.port, args.ca, args.sni)
    res["profile"] = args.profile
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
