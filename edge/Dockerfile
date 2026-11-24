FROM python:3.13-slim-trixie
# OpenSSL 3.5 from Debian 13 => the client offers X25519MLKEM768 by default;
# the profile is forced per run through OPENSSL_CONF (see edge_node.py --profile).
WORKDIR /app
COPY . /app/edge
ENV PYTHONUNBUFFERED=1
CMD ["python", "/app/edge/edge_node.py", "--help"]
