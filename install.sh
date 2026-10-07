#!/bin/bash
# ReconHawk installer for Linux
set -e
echo "[*] Installing system dependencies..."
command -v python3 >/dev/null || { echo "[-] python3 required"; exit 1; }
command -v pip3 >/dev/null || { sudo apt-get install -y python3-pip 2>/dev/null || sudo yum install -y python3-pip; }

echo "[*] Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "[*] Installing Python dependencies..."
pip install -r requirements.txt

echo "[*] Making scripts executable..."
chmod +x recon.py app.py start_ui.sh

echo ""
echo "[+] Installation complete!"
echo ""
echo "  CLI:  source venv/bin/activate && python3 recon.py <domain>"
echo "  GUI:  ./start_ui.sh"
echo ""
