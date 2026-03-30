#!/bin/bash
# LoL Private Server - Start Script
# Usage: ./start-server.sh [--raw]

export PATH="$HOME/.dotnet:$PATH"

echo "========================================="
echo "  LoL Private Server - Launcher"
echo "========================================="
echo ""

cd "$(dirname "$0")"

# Build
echo "[1/2] Building server..."
dotnet build server/LoLServer.sln -c Debug -v quiet 2>&1 | tail -3

if [ $? -ne 0 ]; then
    echo "[ERROR] Build failed!"
    exit 1
fi

echo "[2/2] Starting server..."
echo ""

# Run with raw capture mode by default for protocol analysis
dotnet run --project server/src/LoLServer.Console -- --raw \
    --client="/media/louisdelez/VM/LeagueOfLegendsV2/client/Game" \
    "$@"
