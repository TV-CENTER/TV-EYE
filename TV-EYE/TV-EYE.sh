#!/usr/bin/env bash
# TV-EYE launcher for Linux/macOS - by Mr_TV (github.com/TV-CENTER)
cd "$(dirname "$0")" || exit 1
if command -v python3 >/dev/null 2>&1; then
    python3 tveye.py "$@"
else
    echo "[!] python3 not found. Install it with: sudo apt install python3"
fi
