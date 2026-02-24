#!/usr/bin/env bash
set -euo pipefail

IMAGE="nebula-vault:latest"
CONTAINER="nebula-vault"
PORT="6969"

echo "[*] Checking Docker installation..."

if ! command -v docker >/dev/null 2>&1; then
    echo "[-] Docker is not installed. Please install Docker first."
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "[-] Docker daemon is not running. Start Docker and try again."
    exit 1
fi

echo "[+] Docker is available."

# Ensure script runs from src directory
cd "$(dirname "$0")"

echo "[*] Building image: $IMAGE"
docker build -t "$IMAGE" .

# Stop existing container if running
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
    echo "[*] Removing existing container: $CONTAINER"
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
fi

echo "[*] Starting container on port $PORT..."
docker run -d \
    --name "$CONTAINER" \
    -p "${PORT}:${PORT}" \
    "$IMAGE" >/dev/null

echo "[+] Nebula Vault is running."
echo "    -> http://127.0.0.1:${PORT}"
echo
echo "[*] To stop:"
echo "    docker rm -f ${CONTAINER}"