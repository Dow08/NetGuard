#!/bin/bash
cd "$(dirname "$0")"
PY=$(command -v python3 || command -v python)
echo "🔒 NetGuard — démarrage..."
[ "$EUID" -eq 0 ] && echo "📡 Mode root — capture DNS activée" || echo "📡 Mode normal — pour DNS: sudo $0"
$PY netguard_server.py
