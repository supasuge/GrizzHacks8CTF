#!/usr/bin/env bash
set -euo pipefail

mkdir -p /data/pki /var/www/html/.well-known/pki

# Default hostname used inside certs (AIA + SAN). Override with env HOSTNAME.
# Example: docker run -e HOSTNAME=challenge.yourdomain.com ...
export HOSTNAME="${HOSTNAME:-localhost}"

python3 /app/generate_pki.py \
  --out-dir /data/pki \
  --web-dir /var/www/html \
  --hostname "$HOSTNAME"

# Nginx expects cert/key paths; generator writes them and renders config.
cp /data/pki/nginx.conf /etc/nginx/nginx.conf

nginx -g "daemon off;"