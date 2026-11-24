#!/bin/sh
# Generate a demo CA and a gateway server certificate.
#   ECDSA P-256 chain  -> always (works with any OpenSSL)
#   ML-DSA-65 chain    -> only if the local openssl can generate ML-DSA keys
#                         (OpenSSL >= 3.5 or oqs-provider). Experimental: whether
#                         a TLS handshake can *use* ML-DSA certs depends on the build.
# Usage: certs/gen_certs.sh [output_dir]
set -e
OUT="${1:-$(dirname "$0")}"
mkdir -p "$OUT"
cd "$OUT"

SAN="subjectAltName=DNS:gateway,DNS:gateway-classical,DNS:gateway-hybrid,DNS:gateway-pqc,DNS:localhost,IP:127.0.0.1"

# ---- classical (ECDSA P-256) ----
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 825 -subj "/CN=PQC-IoT Demo CA" -out ca.crt
openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -key server.key -subj "/CN=pqc-iot-gateway" -out server.csr
printf "%s\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n" "$SAN" > server.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -sha256 -days 365 -extfile server.ext -out server.crt
echo "[certs] ECDSA P-256 chain written to $PWD"

# ---- optional ML-DSA-65 ----
if openssl list -signature-algorithms 2>/dev/null | grep -qi "ML-DSA-65"; then
  openssl genpkey -algorithm ML-DSA-65 -out ca-mldsa.key
  openssl req -x509 -new -key ca-mldsa.key -days 825 -subj "/CN=PQC-IoT Demo ML-DSA CA" -out ca-mldsa.crt
  openssl genpkey -algorithm ML-DSA-65 -out server-mldsa.key
  openssl req -new -key server-mldsa.key -subj "/CN=pqc-iot-gateway" -out server-mldsa.csr
  openssl x509 -req -in server-mldsa.csr -CA ca-mldsa.crt -CAkey ca-mldsa.key -CAcreateserial \
    -days 365 -extfile server.ext -out server-mldsa.crt
  echo "[certs] ML-DSA-65 chain written (server-mldsa.*)"
else
  echo "[certs] ML-DSA-65 not available in this openssl; skipped (ECDSA chain is enough for the KEM demo)"
fi
rm -f server.csr server-mldsa.csr *.srl
chmod 644 *.crt *.key
