#!/bin/bash

set -e

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║        AegisRelay - Setup Script            ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

echo "[*] Installing dependencies..."
npm install

echo ""
echo "[*] Generating Alice's keypair..."
npm run generate-keys

echo ""
echo "[*] Generating sample signed messages..."
npm run generate-samples

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                    Setup Complete!                        ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "To run with Docker:"
echo "  docker compose up --build -d"
echo ""
