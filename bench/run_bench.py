#!/usr/bin/env python3
"""Run the handshake benchmark for classical / hybrid / pqc and write results/.

Local mode (gateways already running on 127.0.0.1, e.g. started by `make local`):
    python bench/run_bench.py --mode local -n 200 \
        --port classical=8883 --port hybrid=8884 --port pqc=8885 \
        --target classical=pid:123 --target hybrid=pid:124 --target pqc=pid:125

Docker mode (docker compose up -d first; the client runs in the CPU/RAM-limited
`edge` container to emulate a constrained node):
    python bench/run_bench.py --mode docker -n 200

Outputs:
    results/handshakes.csv   every single handshake
    results/summary.csv      one row per profile (the numbers used in the report)
    results/summary.json     same, with metadata
"""
import argparse
import csv
import json
import os
import platform
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
from proc_stats import read_proc  # noqa: E402

PROFILES = ["classical", "hybrid", "pqc"]


def kv(items):
    return dict(i.split("=", 1) for i in items or [])


def client_cmd(args, profile, ports):
    common = ["--profile", profile, "-n", str(args.n),
              "--warmup", str(args.warmup), "--pause", str(args.pause)]
    if args.mode == "local":
        return [sys.executable, os.path.join(HERE, "handshake_bench.py"),
                "--port", ports[profile], "--ca", os.path.join(ROOT, "certs/ca.crt")] + common
    name = "gateway-%s" % profile
    return (["docker", "compose", "run", "--rm", "-T", "edge", "python",
             "/app/bench/handshake_bench.py", "--host", name, "--port", "8883",
             "--sni", name, "--ca", "/certs/ca.crt"] + common)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--mode", choices=["local", "docker"], default="docker")
    p.add_argument("-n", type=int, default=200)
    p.add_argument("--warmup", type=int, default=5)
    p.add_argument("--pause", type=float, default=0.0)
    p.add_argument("--port", action="append", help="profile=port (local mode)")
    p.add_argument("--target", action="append",
                   help="profile=pid:N | docker:NAME to sample gateway CPU/RAM")
    p.add_argument("--out", default=os.path.join(ROOT, "results"))
    args = p.parse_args(argv)

    ports = {**{"classical": "8883", "hybrid": "8884", "pqc": "8885"}, **kv(args.port)}
    targets = kv(args.target)
    if args.mode == "docker":
        targets = {pr: "docker:gateway-%s" % pr for pr in PROFILES}
    os.makedirs(args.out, exist_ok=True)

    all_rows, summaries = [], []
    for profile in PROFILES:
        before = read_proc(targets[profile]) if profile in targets else None
        print("== %s: running %d handshakes ..." % (profile, args.n), file=sys.stderr)
        proc = subprocess.run(client_cmd(args, profile, ports), cwd=ROOT,
                              capture_output=True, text=True)
        if proc.returncode != 0:
            print(proc.stderr[-800:], file=sys.stderr)
            print("   %s FAILED (exit %d); continuing" % (profile, proc.returncode),
                  file=sys.stderr)
            continue
        after = read_proc(targets[profile]) if profile in targets else None
        summary = None
        for line in proc.stdout.splitlines():
            if not line.startswith("{"):
                continue
            obj = json.loads(line)
            if "summary" in obj:
                summary = obj["summary"]
            else:
                all_rows.append(obj)
        if summary is None:
            print("   no summary for %s" % profile, file=sys.stderr)
            continue
        if before and after:
            total = args.n + args.warmup
            summary["gw_cpu_ms_per_hs"] = round(
                (after["cpu_s"] - before["cpu_s"]) / total * 1e3, 3)
            summary["gw_rss_kb"] = after["rss_kb"]
            summary["gw_peak_rss_kb"] = after["hwm_kb"]
        summaries.append(summary)
        print("   median %.2f ms | p95 %.2f ms | %d B on the wire | group %s" % (
            summary["lat_median_ms"], summary["lat_p95_ms"],
            summary["total_bytes"], summary["group"]), file=sys.stderr)

    if not summaries:
        sys.exit("no profile produced results; are the gateways running?")

    with open(os.path.join(args.out, "handshakes.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(all_rows[0]))
        w.writeheader()
        w.writerows(all_rows)
    cols = []
    for s in summaries:
        cols += [k for k in s if k not in cols]
    with open(os.path.join(args.out, "summary.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(summaries)
    meta = {"mode": args.mode, "n": args.n, "date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "host": platform.platform(), "python": platform.python_version(),
            "edge_cpus": os.environ.get("EDGE_CPUS", "0.25 (compose default)")
            if args.mode == "docker" else "unconstrained (local)"}
    with open(os.path.join(args.out, "summary.json"), "w") as fh:
        json.dump({"meta": meta, "summary": summaries}, fh, indent=2)
    print("wrote %s/{handshakes.csv,summary.csv,summary.json}" % args.out,
          file=sys.stderr)


if __name__ == "__main__":
    main()
