#!/bin/bash
# LoL Private Server - Client Launcher
# Launches League of Legends.exe pointed at local server
# Usage: ./start-client.sh [player_id]

PLAYER_ID=${1:-1}
SERVER_IP="127.0.0.1"
SERVER_PORT="5119"
BLOWFISH_KEY="17BLOhi6KZsTtldTsizvHg=="
GAME_DIR="/media/louisdelez/VM/LeagueOfLegendsV2/client/Game"
GAME_EXE="$GAME_DIR/League of Legends.exe"

echo "========================================="
echo "  LoL Private Server - Client Launcher"
echo "========================================="
echo ""
echo "Server: $SERVER_IP:$SERVER_PORT"
echo "Player ID: $PLAYER_ID"
echo "Blowfish Key: $BLOWFISH_KEY"
echo "Game EXE: $GAME_EXE"
echo ""

if [ ! -f "$GAME_EXE" ]; then
    echo "[ERROR] Game executable not found at: $GAME_EXE"
    exit 1
fi

# Check for Wine
if command -v wine &> /dev/null; then
    echo "[OK] Wine found: $(wine --version)"
    echo ""
    echo "Launching client via Wine..."
    cd "$GAME_DIR"
    wine "$GAME_EXE" "8394" "LoLLauncher.exe" "" "$SERVER_IP $SERVER_PORT $BLOWFISH_KEY $PLAYER_ID"
else
    echo "[WARN] Wine not found!"
    echo ""
    echo "To install Wine on Debian/Ubuntu:"
    echo "  sudo apt install wine"
    echo ""
    echo "Or run this command manually on a Windows machine:"
    echo "  cd \"$GAME_DIR\""
    echo "  \"League of Legends.exe\" \"8394\" \"LoLLauncher.exe\" \"\" \"$SERVER_IP $SERVER_PORT $BLOWFISH_KEY $PLAYER_ID\""
    echo ""
    echo "Or copy the client/Game folder to a Windows PC and run:"
    echo "  \"League of Legends.exe\" \"8394\" \"LoLLauncher.exe\" \"\" \"$SERVER_IP $SERVER_PORT $BLOWFISH_KEY $PLAYER_ID\""
fi
