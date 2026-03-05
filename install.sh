#!/bin/bash
# ═══════════════════════════════════════════════════
# NetGuard — Installation Linux
# ═══════════════════════════════════════════════════

set -e
CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════╗"
echo "║   🔒  NetGuard v2.1 — Installation           ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${NC}"

# Python
if command -v python3 &>/dev/null; then PY=python3
elif command -v python &>/dev/null; then PY=python
else echo "❌ Python 3.8+ requis"; exit 1; fi
echo -e "${GREEN}✓${NC} $($PY --version)"

# Dépendances
echo -e "\n${YELLOW}Installation des dépendances...${NC}"
$PY -m pip install -q requests flask flask-cors
echo -e "${GREEN}✓${NC} Dépendances installées"

# Scapy (optionnel)
$PY -m pip install -q scapy 2>/dev/null && echo -e "${GREEN}✓${NC} scapy installé (capture DNS)" || echo -e "${YELLOW}⚠${NC} scapy non installé (optionnel)"

# Dashboard
mkdir -p dashboard
echo -e "${GREEN}✓${NC} Prêt!"

echo -e "\n${CYAN}Pour lancer:${NC}"
echo "  $PY netguard_server.py"
echo ""
echo -e "${CYAN}Avec capture DNS:${NC}"
echo "  sudo $PY netguard_server.py"
echo ""
echo -e "Dashboard: ${CYAN}http://localhost:8765${NC}"
