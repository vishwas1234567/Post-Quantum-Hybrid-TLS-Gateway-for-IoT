#!/usr/bin/env python3
"""Benchmark N TLS 1.3 handshakes for ONE profile against one gateway port.

Prints one JSON object per handshake (JSONL) followed by a final summary line
({"summary": {...}}). Client-side cost is what matters for constrained IoT, so
besides latency and bytes we report client CPU time per handshake and the
client's peak RSS.

    python bench/handshake_bench.py --profile hybrid --port 8884 -n 200
"""
import argparse
import json
import os
import resource
import statistics
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "edge"))
sys.path.insert(0, os.path.join(HERE, "..", "analysis"))
from tls_profiles import PROFILES, ensure_profile  # noqa: E402


def pct(sorted_vals, q):
    if not sorted_vals:
        return 0.0
    k = min(len(sorted_vals) - 1, max(0, int(round(q * (len(sorted_vals) - 1)))))
    return sorted_vals[k]


def run(args):
    from handshake_probe import probe

    for _ in range(args.warmup):
        probe(args.host, args.port, args.ca, args.sni)

    rows = []
    cpu0 = time.process_time()
    wall0 = time.perf_counter()
    for i in range(args.n):
        r = probe(args.host, args.port, args.ca, args.sni)
        ch, sh = r["client_hello"], r["server_hello"]
        rows.append({
            "i": i, "profile": args.profile,
            "handshake_ms": r["handshake_ms"],
            "c2s_bytes": r["c2s_bytes"], "s2c_bytes": r["s2c_bytes"],
            "total_bytes": r["total_bytes"],
            "client_hello_bytes": ch["msg_len"],
            "group": sh["selected_group"][1],
            "key_share_bytes": sh["key_share_len"],
            "round_trips": r["round_trips"],
        })
        print(json.dumps(rows[-1]), flush=True)
        if args.pause:
            time.sleep(args.pause)
    cpu = time.process_time() - cpu0
    wall = time.perf_counter() - wall0

    lat = sorted(r["handshake_ms"] for r in rows)
    summary = {
        "profile": args.profile, "n": args.n, "group": rows[-1]["group"],
        "openssl": r["openssl"],
        "lat_mean_ms": round(statistics.fmean(lat), 3),
        "lat_median_ms": round(pct(lat, 0.5), 3),
        "lat_p95_ms": round(pct(lat, 0.95), 3),
        "lat_p99_ms": round(pct(lat, 0.99), 3),
        "lat_stdev_ms": round(statistics.pstdev(lat), 3),
        "client_cpu_ms_per_hs": round(cpu / args.n * 1e3, 3),
        "client_maxrss_kb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "client_hello_bytes": rows[-1]["client_hello_bytes"],
        "c2s_bytes": rows[-1]["c2s_bytes"], "s2c_bytes": rows[-1]["s2c_bytes"],
        "total_bytes": rows[-1]["total_bytes"],
        "handshakes_per_s": round(args.n / wall, 1),
    }
    print(json.dumps({"summary": summary}), flush=True)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--profile", choices=sorted(PROFILES), required=True)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--sni", default="localhost")
    p.add_argument("--ca", default=os.environ.get("CA_FILE", "certs/ca.crt"))
    p.add_argument("-n", type=int, default=100, help="measured handshakes")
    p.add_argument("--warmup", type=int, default=5)
    p.add_argument("--pause", type=float, default=0.0,
                   help="idle seconds between handshakes (keeps CPU quotas fair)")
    args = p.parse_args(argv)
    ensure_profile(args.profile)
    run(args)


if __name__ == "__main__":
    main()
