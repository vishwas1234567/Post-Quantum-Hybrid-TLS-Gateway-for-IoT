#!/usr/bin/env python3
"""Lightweight TLS 1.3 terminating proxy for IoT traffic (MQTT, HTTP, anything TCP).

The gateway terminates TLS from edge nodes and forwards plaintext to an
upstream service on the trusted side (Mosquitto, an HTTP backend, ...).

Which key-exchange groups are offered is NOT hard-coded here. It is decided by
the OpenSSL configuration the process starts with (see openssl-*.cnf and
entrypoint.sh), so the very same code runs as:

    classical  : X25519 / secp256r1
    hybrid     : X25519MLKEM768 (preferred) with X25519 fallback
    pqc        : pure MLKEM768 (no classical fallback)

This needs an OpenSSL >= 3.5 (native ML-KEM) behind Python's ssl module, or an
OpenSSL 3.x with oqs-provider loaded.  With an older OpenSSL the gateway still
works in classical mode, which is handy for development.

Usage:
    pqc_gateway.py --cert certs/server.crt --key certs/server.key \
        --map 8883=mosquitto:1883 --map 8443=backend:8000
"""
import argparse
import asyncio
import json
import logging
import os
import signal
import ssl
import sys
import time

log = logging.getLogger("pqc-gw")
BUF = 16384


class Stats:
    def __init__(self):
        self.accepted = 0
        self.active = 0
        self.bytes_up = 0      # edge -> upstream
        self.bytes_down = 0    # upstream -> edge
        self.upstream_errors = 0
        self.tls_errors = 0
        self.started = time.time()

    def snapshot(self):
        return {
            "ts": round(time.time(), 3),
            "uptime_s": round(time.time() - self.started, 1),
            "accepted": self.accepted,
            "active": self.active,
            "bytes_up": self.bytes_up,
            "bytes_down": self.bytes_down,
            "upstream_errors": self.upstream_errors,
            "tls_errors": self.tls_errors,
            "rss_kb": rss_kb(),
            "cpu_s": round(time.process_time(), 3),
            "profile": os.environ.get("GATEWAY_PROFILE", "unknown"),
        }


def rss_kb():
    """Resident set size of this process in kB (Linux only, 0 elsewhere)."""
    try:
        with open("/proc/self/status") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return 0


def make_server_ctx(cert, key, client_ca=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert, key)
    if client_ca:
        ctx.load_verify_locations(client_ca)
        ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


async def pipe(reader, writer, stats, counter):
    try:
        while True:
            data = await reader.read(BUF)
            if not data:
                break
            setattr(stats, counter, getattr(stats, counter) + len(data))
            writer.write(data)
            await writer.drain()
    except (ConnectionError, ssl.SSLError, asyncio.IncompleteReadError):
        pass
    finally:
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass


async def handle(creader, cwriter, upstream, stats):
    peer = cwriter.get_extra_info("peername")
    sslobj = cwriter.get_extra_info("ssl_object")
    stats.accepted += 1
    stats.active += 1
    if sslobj is not None:
        cipher = sslobj.cipher()
        log.debug("accepted %s tls=%s cipher=%s", peer, sslobj.version(),
                  cipher[0] if cipher else "?")
    try:
        try:
            ureader, uwriter = await asyncio.open_connection(*upstream)
        except OSError as exc:
            stats.upstream_errors += 1
            log.warning("upstream %s:%s unreachable: %s", *upstream, exc)
            cwriter.close()
            return
        up = asyncio.create_task(pipe(creader, uwriter, stats, "bytes_up"))
        down = asyncio.create_task(pipe(ureader, cwriter, stats, "bytes_down"))
        _, pending = await asyncio.wait({up, down},
                                        return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for w in (uwriter, cwriter):
            try:
                w.close()
            except Exception:  # noqa: BLE001
                pass
    finally:
        stats.active -= 1


async def stats_loop(stats, interval, path):
    while True:
        await asyncio.sleep(interval)
        line = json.dumps(stats.snapshot())
        print(line, flush=True)
        if path:
            with open(path, "a") as fh:
                fh.write(line + "\n")


def parse_map(spec):
    """'8883=mosquitto:1883' -> (8883, ('mosquitto', 1883))"""
    listen, target = spec.split("=", 1)
    host, port = target.rsplit(":", 1)
    return int(listen), (host, int(port))


async def main_async(args):
    stats = Stats()
    ctx = make_server_ctx(args.cert, args.key, args.client_ca)
    loop = asyncio.get_running_loop()

    def exc_handler(_loop, context):
        exc = context.get("exception")
        if isinstance(exc, ssl.SSLError) or "SSL" in context.get("message", ""):
            stats.tls_errors += 1
            log.debug("TLS error: %s", exc or context.get("message"))
        else:
            log.error("loop error: %s", context.get("message"))
    loop.set_exception_handler(exc_handler)

    servers = []
    for spec in args.map:
        port, upstream = parse_map(spec)

        async def cb(r, w, upstream=upstream):
            await handle(r, w, upstream, stats)

        srv = await asyncio.start_server(
            cb, host=args.host, port=port, ssl=ctx,
            ssl_handshake_timeout=args.handshake_timeout)
        servers.append(srv)
        log.info("listening :%d (TLS1.3) -> %s:%d", port, *upstream)

    tasks = [asyncio.create_task(stats_loop(stats, args.stats_interval,
                                            args.stats_file))]
    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:  # pragma: no cover (Windows)
            pass
    await stop.wait()
    for t in tasks:
        t.cancel()
    for s in servers:
        s.close()
    print(json.dumps(stats.snapshot()), flush=True)


def build_parser():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--host", default=os.environ.get("GW_HOST", "0.0.0.0"))
    p.add_argument("--cert", default=os.environ.get("GW_CERT", "certs/server.crt"))
    p.add_argument("--key", default=os.environ.get("GW_KEY", "certs/server.key"))
    p.add_argument("--client-ca", default=os.environ.get("GW_CLIENT_CA"),
                   help="enable mutual TLS with this CA bundle")
    p.add_argument("--map", action="append", default=[],
                   help="LISTEN_PORT=UPSTREAM_HOST:PORT (repeatable)")
    p.add_argument("--handshake-timeout", type=float, default=10.0)
    p.add_argument("--stats-interval", type=float, default=5.0)
    p.add_argument("--stats-file", default=os.environ.get("GW_STATS_FILE"))
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not args.map:
        args.map = ["8883=mosquitto:1883", "8443=backend:8000"]
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s",
                        stream=sys.stderr)
    log.info("OpenSSL: %s | profile: %s", ssl.OPENSSL_VERSION,
             os.environ.get("GATEWAY_PROFILE", "unknown"))
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
