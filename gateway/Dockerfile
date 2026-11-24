# Debian 13 (trixie) ships OpenSSL 3.5 = native ML-KEM / X25519MLKEM768.
# Python's ssl module links against the system OpenSSL, so it inherits PQC.
FROM python:3.13-slim-trixie

RUN python -c "import ssl; print(ssl.OPENSSL_VERSION)" \
 && python - <<'EOF'
import ssl, sys
v = ssl.OPENSSL_VERSION_INFO
if v < (3, 5):
    sys.exit("OpenSSL %s has no native ML-KEM; need >= 3.5" % ssl.OPENSSL_VERSION)
EOF

WORKDIR /app
COPY pqc_gateway.py entrypoint.sh openssl-classical.cnf openssl-hybrid.cnf openssl-pqc.cnf /app/
RUN chmod +x /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]
