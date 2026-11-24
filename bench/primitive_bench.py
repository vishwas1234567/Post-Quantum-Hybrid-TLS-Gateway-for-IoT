#!/usr/bin/env python3
"""Micro-benchmark of the raw primitives behind the handshake.

Backends
  cryptography : OpenSSL 3.5 native ML-KEM / ML-DSA (pip install cryptography>=48)
  liboqs       : Open Quantum Safe via liboqs-python (pip install liboqs-python;
                 needs the liboqs C library). Used automatically when importable.

Classical baselines (X25519, ECDSA P-256) are always measured with `cryptography`.
Writes results/primitives.csv and prints a table.

    python bench/primitive_bench.py --iters 300 --backend both
"""
import argparse
import csv
import os
import statistics
import time

# Expanded secret-key sizes from FIPS 203 / FIPS 204 / RFC 7748 (the
# `cryptography` API only hands out the 64-byte seed for ML-KEM/ML-DSA keys).
STD_SK_BYTES = {"ML-KEM-512": 1632, "ML-KEM-768": 2400, "ML-KEM-1024": 3168,
                "ML-DSA-44": 2560, "ML-DSA-65": 4032, "ML-DSA-87": 4896,
                "X25519": 32, "ECDSA-P256": 32}


def timeit(fn, iters):
    for _ in range(max(3, iters // 20)):        # warm-up
        fn()
    samples = []
    for _ in range(iters):
        t = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t) * 1e6)
    return statistics.fmean(samples), statistics.median(samples)


def row(backend, alg, kind, op, fn, iters, pk, ct_or_sig):
    mean, med = timeit(fn, iters)
    return {"backend": backend, "algorithm": alg, "type": kind, "op": op,
            "mean_us": round(mean, 1), "median_us": round(med, 1), "iters": iters,
            "pk_bytes": pk, "sk_bytes": STD_SK_BYTES.get(alg, ""),
            "ct_or_sig_bytes": ct_or_sig}


def bench_cryptography(iters):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, mldsa, mlkem, x25519

    rows, b = [], "cryptography"
    for alg, cls in (("ML-KEM-768", mlkem.MLKEM768PrivateKey),
                     ("ML-KEM-1024", mlkem.MLKEM1024PrivateKey)):
        sk = cls.generate()
        pk = sk.public_key()
        ss, ct = pk.encapsulate()
        pkb = len(pk.public_bytes_raw())
        rows += [row(b, alg, "KEM", "keygen", cls.generate, iters, pkb, len(ct)),
                 row(b, alg, "KEM", "encaps", pk.encapsulate, iters, pkb, len(ct)),
                 row(b, alg, "KEM", "decaps", lambda: sk.decapsulate(ct), iters, pkb, len(ct))]
    msg = b"telemetry:node-0001:seq=42" * 3
    for alg, cls in (("ML-DSA-44", mldsa.MLDSA44PrivateKey),
                     ("ML-DSA-65", mldsa.MLDSA65PrivateKey),
                     ("ML-DSA-87", mldsa.MLDSA87PrivateKey)):
        sk = cls.generate()
        pk = sk.public_key()
        sig = sk.sign(msg)
        pkb = len(pk.public_bytes_raw())
        rows += [row(b, alg, "SIG", "keygen", cls.generate, iters, pkb, len(sig)),
                 row(b, alg, "SIG", "sign", lambda: sk.sign(msg), iters, pkb, len(sig)),
                 row(b, alg, "SIG", "verify", lambda: pk.verify(sig, msg), iters, pkb, len(sig))]
    # classical baselines
    xa, xb = x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
    xpub = xb.public_key()
    rows += [row(b, "X25519", "KEM", "keygen", x25519.X25519PrivateKey.generate, iters, 32, 32),
             row(b, "X25519", "KEM", "exchange", lambda: xa.exchange(xpub), iters, 32, 32)]
    ek = ec.generate_private_key(ec.SECP256R1())
    esig = ek.sign(msg, ec.ECDSA(hashes.SHA256()))
    epub = ek.public_key()
    rows += [row(b, "ECDSA-P256", "SIG", "keygen",
                 lambda: ec.generate_private_key(ec.SECP256R1()), iters, 65, len(esig)),
             row(b, "ECDSA-P256", "SIG", "sign",
                 lambda: ek.sign(msg, ec.ECDSA(hashes.SHA256())), iters, 65, len(esig)),
             row(b, "ECDSA-P256", "SIG", "verify",
                 lambda: epub.verify(esig, msg, ec.ECDSA(hashes.SHA256())), iters, 65, len(esig))]
    return rows


def bench_liboqs(iters):
    import oqs  # liboqs-python

    rows, b = [], "liboqs"
    kems, sigs = oqs.get_enabled_kem_mechanisms(), oqs.get_enabled_sig_mechanisms()
    for alg in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"):
        if alg not in kems:
            continue
        with oqs.KeyEncapsulation(alg) as kem:
            pk = kem.generate_keypair()
            ct, _ = kem.encap_secret(pk)
            d = kem.details
            rows.append(row(b, alg, "KEM", "keygen", kem.generate_keypair, iters,
                            d["length_public_key"], d["length_ciphertext"]))
            rows.append(row(b, alg, "KEM", "encaps", lambda: kem.encap_secret(pk), iters,
                            d["length_public_key"], d["length_ciphertext"]))
            rows.append(row(b, alg, "KEM", "decaps", lambda: kem.decap_secret(ct), iters,
                            d["length_public_key"], d["length_ciphertext"]))
    msg = b"telemetry:node-0001:seq=42" * 3
    for alg in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "Falcon-512"):
        if alg not in sigs:
            continue
        with oqs.Signature(alg) as sig:
            pk = sig.generate_keypair()
            s = sig.sign(msg)
            d = sig.details
            rows.append(row(b, alg, "SIG", "keygen", sig.generate_keypair, iters,
                            d["length_public_key"], d["length_signature"]))
            rows.append(row(b, alg, "SIG", "sign", lambda: sig.sign(msg), iters,
                            d["length_public_key"], d["length_signature"]))
            rows.append(row(b, alg, "SIG", "verify", lambda: sig.verify(msg, s, pk), iters,
                            d["length_public_key"], d["length_signature"]))
    return rows


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--iters", type=int, default=300)
    p.add_argument("--backend", choices=["auto", "cryptography", "liboqs", "both"],
                   default="auto")
    p.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "..",
                                                 "results", "primitives.csv"))
    args = p.parse_args(argv)

    try:
        import oqs  # noqa: F401
        have_oqs = True
    except Exception:  # noqa: BLE001  (ImportError or missing liboqs .so)
        have_oqs = False
    want = {"auto": ["liboqs"] if have_oqs else [], "both": ["liboqs"],
            "liboqs": ["liboqs"], "cryptography": []}[args.backend]
    if "liboqs" in want and not have_oqs:
        raise SystemExit("liboqs-python is not installed (pip install liboqs-python)")

    rows = bench_cryptography(args.iters)
    if "liboqs" in want:
        rows += bench_liboqs(args.iters)
    elif args.backend == "auto":
        print("note: liboqs-python not found; used OpenSSL-native (cryptography) only")

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print("%-13s %-12s %-5s %-9s %10s %8s %8s" % (
        "backend", "algorithm", "type", "op", "mean_us", "pk_B", "ct/sig_B"))
    for r in rows:
        print("%-13s %-12s %-5s %-9s %10.1f %8s %8s" % (
            r["backend"], r["algorithm"], r["type"], r["op"], r["mean_us"],
            r["pk_bytes"], r["ct_or_sig_bytes"]))
    print("wrote", os.path.abspath(args.out))


if __name__ == "__main__":
    main()
