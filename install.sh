#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCE="$SCRIPT_DIR/stav.c"
BINARY="/usr/local/bin/stav"

echo "================================"
echo "       STAV INSTALLER"
echo "================================"

if [ ! -f "$SOURCE" ]; then
    echo "ERROR: stav.c not found!"
    read -r -p "Press ENTER to close..."
    exit 1
fi

echo "[1/4] Installing dependencies..."
sudo apt-get update
sudo apt-get install -y gcc make libssl-dev libcurl4-openssl-dev

echo "[2/4] Compiling STAV..."
gcc "$SOURCE" -o "$SCRIPT_DIR/stav" -O2 -lcrypto -lssl -lcurl -ljansson

echo "[3/4] Installing binary..."
sudo install -m 755 "$SCRIPT_DIR/stav" "$BINARY"

echo "[4/4] Installation completed."
echo
echo "STAV is installed at: $BINARY"
echo "Run it using: stav"

echo
read -r -p "Press ENTER to close..."
