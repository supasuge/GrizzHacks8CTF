#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="pki-ctf"
CONTAINER_NAME="pki-ctf"

HOSTNAME="${HOSTNAME:-localhost}"

docker build -t "$IMAGE_NAME" .

docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

docker run --name "$CONTAINER_NAME" \
  -e HOSTNAME="$HOSTNAME" \
  -p 80:80 \
  -p 443:443 \
  "$IMAGE_NAME"