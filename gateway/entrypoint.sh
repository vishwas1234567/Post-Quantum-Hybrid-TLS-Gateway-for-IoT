#!/bin/sh
# Select the OpenSSL group profile, then start the gateway.
# GATEWAY_PROFILE = classical | hybrid | pqc
set -e
PROFILE="${GATEWAY_PROFILE:-hybrid}"
CNF="/app/openssl-${PROFILE}.cnf"
if [ ! -f "$CNF" ]; then
  echo "unknown GATEWAY_PROFILE '$PROFILE' (use classical|hybrid|pqc)" >&2
  exit 2
fi
export OPENSSL_CONF="$CNF"
export GATEWAY_PROFILE="$PROFILE"
echo "gateway profile=$PROFILE OPENSSL_CONF=$OPENSSL_CONF" >&2
exec python /app/pqc_gateway.py "$@"
