#!/usr/bin/env bash
# gen-tls.sh — bootstrap TLS material for a FANGS dev/test deployment.
#
# Produces:
#   tls/ca.crt          — root CA (trust this to verify both server + clients)
#   tls/ca.key          — root CA private key (keep offline in prod)
#   tls/server.crt      — orchestrator server cert (SAN: 127.0.0.1, localhost, $SERVER_HOSTS)
#   tls/server.key      — orchestrator private key
#   tls/runner.crt      — runner client cert (CN: $RUNNER_ID)
#   tls/runner.key      — runner private key
#
# Usage:
#   docs/scripts/gen-tls.sh                  # uses defaults
#   SERVER_HOSTS="fangs.internal" RUNNER_ID="prod-runner-1" docs/scripts/gen-tls.sh
#
# Run the orchestrator with mTLS:
#   ./bin/fangs-orchestrator \
#     -tls-cert tls/server.crt -tls-key tls/server.key \
#     -tls-client-ca tls/ca.crt
#
# Run the runner against it:
#   sudo ./bin/fangs-runner \
#     -orchestrator https://127.0.0.1:8443 \
#     -tls-ca tls/ca.crt \
#     -tls-cert tls/runner.crt -tls-key tls/runner.key
set -euo pipefail

OUT=${OUT:-tls}
SERVER_HOSTS=${SERVER_HOSTS:-}
RUNNER_ID=${RUNNER_ID:-fangs-runner}
DAYS=${DAYS:-365}

mkdir -p "$OUT"
cd "$OUT"

if [[ -f ca.crt && -f server.crt && -f runner.crt ]]; then
    echo "✓ tls/ already populated. delete it to regenerate."
    exit 0
fi

# 1. CA
openssl genrsa -out ca.key 4096 2>/dev/null
openssl req -x509 -new -nodes -key ca.key -sha256 -days "$DAYS" \
    -subj "/CN=fangs-ca" -out ca.crt 2>/dev/null
echo "✓ CA: ca.crt"

# 2. Server cert (with SANs)
SAN="DNS:localhost,IP:127.0.0.1,IP:::1"
if [[ -n "$SERVER_HOSTS" ]]; then
    for h in $SERVER_HOSTS; do
        if [[ "$h" =~ ^[0-9.]+$ ]]; then
            SAN="$SAN,IP:$h"
        else
            SAN="$SAN,DNS:$h"
        fi
    done
fi
openssl genrsa -out server.key 4096 2>/dev/null
openssl req -new -key server.key -subj "/CN=fangs-orchestrator" -out server.csr 2>/dev/null
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days "$DAYS" -sha256 \
    -extfile <(printf "subjectAltName=%s\nextendedKeyUsage=serverAuth\n" "$SAN") 2>/dev/null
rm -f server.csr
echo "✓ server cert: server.crt (SAN: $SAN)"

# 3. Runner client cert
openssl genrsa -out runner.key 4096 2>/dev/null
openssl req -new -key runner.key -subj "/CN=$RUNNER_ID" -out runner.csr 2>/dev/null
openssl x509 -req -in runner.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out runner.crt -days "$DAYS" -sha256 \
    -extfile <(printf "extendedKeyUsage=clientAuth\n") 2>/dev/null
rm -f runner.csr
echo "✓ runner cert: runner.crt (CN: $RUNNER_ID)"

chmod 600 *.key
echo
echo "All material in $(pwd)"
ls -la
