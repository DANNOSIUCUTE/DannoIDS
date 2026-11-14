#!/usr/bin/env bash
echo "================================================================"
echo "          WEB ATTACK DETECTION SYSTEM (ML & IDS)"
echo "================================================================"
echo ""
echo "  [1] Start Web Dashboard (http://localhost:5000)"
echo "  [2] Scan sample log (logsfile.txt - 20 requests)"
echo "  [3] Scan Nginx/Apache access log (access.log)"
echo "  [4] Install dependencies (pip install -r requirements.txt)"
echo "  [5] Exit"
echo ""
read -p "Select option [1-5]: " choice

case $choice in
    1)
        echo ""
        echo "[*] Starting Web Dashboard..."
        echo "[*] Open browser: http://localhost:5000"
        echo "[*] Press Ctrl+C to stop."
        echo ""
        python3 web_app.py
        ;;
    2)
        echo ""
        echo "[*] Scanning logsfile.txt..."
        python3 detector.py --log logsfile.txt
        ;;
    3)
        echo ""
        echo "[*] Scanning access.log..."
        python3 detector.py --log access.log
        ;;
    4)
        echo ""
        echo "[*] Installing requirements..."
        pip install -r requirements.txt
        ;;
    *)
        exit 0
        ;;
esac

