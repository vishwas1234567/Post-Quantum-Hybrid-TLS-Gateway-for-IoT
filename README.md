# PQC Hybrid TLS Gateway for IoT

A small TLS 1.3 terminating proxy that puts **post-quantum key exchange** (NIST ML-KEM,
hybrid with X25519) in front of an unmodified Mosquitto MQTT broker and an HTTP backend,
plus the tooling to **prove it on the wire** and **measure the cost**.

```
edge node --TLS1.3 (X25519MLKEM768)--> [ gateway ] --plain--> Mosquitto :1883
edge node --TLS1.3 (X25519MLKEM768)--> [ gateway ] --plain--> HTTP API  :8000
```

Three gateways run side by side so every comparison hits identical upstreams:

| Profile | OpenSSL groups | MQTT/TLS | HTTPS |
|---|---|---|---|
| classical | `X25519:secp256r1` | 8883 | 8443 |
| hybrid | `X25519MLKEM768:X25519` | 8884 | 8444 |
| pqc | `MLKEM768` (no fallback) | 8885 | 8445 |

## Requirements
- **OpenSSL >= 3.5** behind Python's `ssl` (native ML-KEM). Docker images use Debian 13, which has it.
  Check: `python3 -c "import ssl; print(ssl.OPENSSL_VERSION)"`
- Docker + Compose (for the container setup), Python 3.10+, `pip install -r requirements.txt`
- Optional: tcpdump / Wireshark (live captures), LaTeX (`latexmk`) for the report, `liboqs-python`

> This design uses OpenSSL 3.5's built-in ML-KEM rather than `oqs-provider`. If you must use an older
> OpenSSL, load `oqs-provider` in the `openssl-*.cnf` files (comment included) and use its group names.

## Quick start (Docker)
```
make up              # certs + mosquitto + backend + 3 gateways
make bench-docker    # edge container, 0.25 CPU / 64 MB by default
make figures
make report          # report/report.pdf
```
Slower node: `EDGE_CPUS=0.1 EDGE_MEM=32m make bench-docker`.

Try one edge node by hand:
```
python edge/edge_node.py --profile hybrid --port 8884 --count 10          # MQTT over hybrid TLS
python edge/edge_node.py --profile classical --proto https --port 8443    # HTTPS telemetry
mosquitto_sub -h 127.0.0.1 -p 1883 -t 'sensors/#'   # (inside the network) see delivered messages
```

## Without Docker
Run the gateway directly (backend/broker any host:port):
```
GATEWAY_PROFILE=hybrid OPENSSL_CONF=gateway/openssl-hybrid.cnf \
  python gateway/pqc_gateway.py --cert certs/server.crt --key certs/server.key --map 8884=127.0.0.1:1883
```
On a **Raspberry Pi** (64-bit Raspberry Pi OS Trixie has OpenSSL 3.5): copy `edge/`, `bench/`, `analysis/`,
`certs/ca.crt` and run `bench/handshake_bench.py --host <gateway-ip> --profile hybrid --port 8884 --sni localhost -n 200`.
Note the SNI must be in the server certificate (`gen_certs.sh` includes `localhost`, `gateway*`; add your host).

## Proving it in Wireshark
`sudo make capture PROFILE=hybrid PORT=8884` captures a handshake and runs the verifier.
Filters and what to screenshot are in `capture/WIRESHARK.md` (key_share group `0x11ec`, 1216-byte client share).
No root? `python analysis/handshake_probe.py --profile hybrid --port 8884` prints the same fields from live bytes.
`analysis/make_sample_pcap.py` writes a demo `.pcap` from real TLS bytes with **synthetic** IP/TCP headers: label it as such.

## Layout
```
gateway/   pqc_gateway.py (proxy), openssl-{classical,hybrid,pqc}.cnf, Dockerfile
edge/      edge_node.py (MQTT/HTTPS sensor), mqtt_min.py, tls_profiles.py
bench/     handshake_bench.py, run_bench.py, primitive_bench.py, proc_stats.py
analysis/  tls_parse.py, handshake_probe.py, pcap_clienthello.py, make_figures.py
capture/   capture.sh, WIRESHARK.md
report/    report.tex (+ figures/, tables/ generated)
results/   CSVs and sample pcaps from the runs shipped with this project
tests/     10 tests: real handshakes, MQTT via stub broker, codec, pcap parser
```
`make test` runs the suite.

## What the shipped results are (and are not)
`results/` and the report numbers come from **loopback, unconstrained CPU, Python 3.13 / OpenSSL 3.5.9** in a
cloud sandbox: they show byte overhead (robust) and CPU (small, noisy). They do **not** include network
latency, Docker CPU limits, Raspberry Pi hardware or energy. Re-run `make bench-docker` on your machine and
`make report` to regenerate everything with your numbers. The Docker Compose files were not run in the
sandbox (no Docker daemon there); they are untested here.

## Security notes
- Demo CA/keys in `certs/` are for the demo only. Regenerate; never reuse.
- Hybrid server authentication uses ECDSA here; ML-DSA certs are generated if your OpenSSL supports them
  (`certs/gen_certs.sh`) but the handshake benchmark with ML-DSA chains is future work.
- The broker is anonymous and only meant to be reachable inside the compose network.
- Use mutual TLS in production (`--client-ca`) and session resumption to cut handshake bytes on constrained links.
