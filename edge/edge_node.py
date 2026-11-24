#!/usr/bin/env python3
"""Simulated IoT edge node: sends telemetry to the gateway over TLS 1.3.

    # MQTT over TLS through the hybrid gateway (docker compose defaults)
    python edge/edge_node.py --profile hybrid --port 8884 --count 20

    # HTTPS telemetry through the classical gateway
    python edge/edge_node.py --profile classical --proto https --port 8443

Prints ONE JSON line with timings, so a benchmark harness can parse it.
`--profile` selects the key-exchange groups this client offers (see
tls_profiles.py); it re-executes the process once so OpenSSL picks it up.
"""
import argparse
import json
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tls_profiles import PROFILES, ensure_profile  # noqa: E402


def build_parser():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--profile", choices=sorted(PROFILES), default="hybrid")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8884)
    p.add_argument("--proto", choices=["mqtt", "https"], default="mqtt")
    p.add_argument("--sni", default="localhost", help="server name to verify")
    p.add_argument("--ca", default=os.environ.get("CA_FILE", "certs/ca.crt"))
    p.add_argument("--node-id", default="edge-%04d" % random.randint(0, 9999))
    p.add_argument("--count", type=int, default=10, help="messages to send")
    p.add_argument("--interval", type=float, default=0.0, help="seconds between messages")
    p.add_argument("--qos", type=int, choices=[0, 1], default=1)
    return p


def telemetry(node_id, seq):
    return {
        "node": node_id,
        "seq": seq,
        "ts": round(time.time(), 3),
        "temp_c": round(random.uniform(18, 32), 2),
        "humidity": round(random.uniform(30, 70), 1),
        "battery_mv": random.randint(3300, 4150),
    }


def run(args):
    import socket
    import ssl

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(args.ca)

    t0 = time.perf_counter()
    raw = socket.create_connection((args.host, args.port), timeout=10)
    t_tcp = time.perf_counter()
    tls = ctx.wrap_socket(raw, server_hostname=args.sni)   # TLS handshake here
    t_tls = time.perf_counter()

    result = {
        "node": args.node_id, "profile": args.profile, "proto": args.proto,
        "port": args.port, "openssl": ssl.OPENSSL_VERSION,
        "tls_version": tls.version(), "cipher": tls.cipher()[0],
        "tcp_ms": round((t_tcp - t0) * 1e3, 3),
        "handshake_ms": round((t_tls - t_tcp) * 1e3, 3),
        "sent": 0, "bytes_app": 0,
    }

    t_send = time.perf_counter()
    if args.proto == "mqtt":
        from mqtt_min import MQTTClient
        client = MQTTClient(tls, args.node_id)
        client.connect()
        for i in range(args.count):
            body = json.dumps(telemetry(args.node_id, i))
            client.publish("sensors/%s/telemetry" % args.node_id, body, qos=args.qos)
            result["sent"] += 1
            result["bytes_app"] += len(body)
            if args.interval:
                time.sleep(args.interval)
        client.close()
    else:
        tls_conn = tls  # keep-alive: reuse the already-handshaken socket
        for i in range(args.count):
            body = json.dumps(telemetry(args.node_id, i)).encode()
            req = ("POST /telemetry HTTP/1.1\r\nHost: %s\r\n"
                   "Content-Type: application/json\r\nContent-Length: %d\r\n\r\n"
                   % (args.sni, len(body))).encode() + body
            tls_conn.sendall(req)
            resp = b""
            while b"\r\n\r\n" not in resp:
                resp += tls_conn.recv(4096)
            head, _, rest = resp.partition(b"\r\n\r\n")
            clen = 0
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    clen = int(line.split(b":")[1])
            while len(rest) < clen:
                rest += tls_conn.recv(4096)
            if not head.startswith(b"HTTP/1.1 200"):
                raise SystemExit("backend returned: %r" % head.split(b"\r\n")[0])
            result["sent"] += 1
            result["bytes_app"] += len(body)
            if args.interval:
                time.sleep(args.interval)
        tls_conn.close()
    result["send_ms"] = round((time.perf_counter() - t_send) * 1e3, 3)
    print(json.dumps(result), flush=True)


def main(argv=None):
    args = build_parser().parse_args(argv)
    ensure_profile(args.profile)   # may re-exec once; must precede `import ssl`
    run(args)


if __name__ == "__main__":
    main()
