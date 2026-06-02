#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# deploy.sh — EC2 (Ubuntu 22.04, ap-south-1) deployment script
#
# Run once on a fresh EC2 instance:
#   chmod +x deploy.sh && sudo ./deploy.sh
#
# What this script does:
#   1. Installs system dependencies (Python 3.12, Nginx)
#   2. Clones the repo and creates a virtualenv
#   3. Installs Python dependencies (including greenlet)
#   4. Creates a systemd service so the app restarts on crash/reboot
#   5. Configures and enables Nginx as a reverse proxy
#   6. Opens EC2 security group ports (informational reminder)
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

# ── Config ─────────────────────────────────────────────────────────────────
APP_DIR="/home/ubuntu/honeypot"
APP_USER="ubuntu"
PYTHON="python3"
SERVICE_NAME="honeypot"

echo "🍯  HoneyNet EC2 Deployment"
echo "=============================="

# ── 1. System packages ──────────────────────────────────────────────────────
echo "[1/6] Installing system packages…"
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv nginx git curl

# ── 2. App directory ────────────────────────────────────────────────────────
echo "[2/6] Setting up app directory at ${APP_DIR}…"
# If already cloned (re-deploy), just pull. Otherwise, copy from current dir.
if [ -d "${APP_DIR}/.git" ]; then
    cd "${APP_DIR}" && git pull
else
    cp -r "$(dirname "$0")" "${APP_DIR}" 2>/dev/null || true
fi
chown -R "${APP_USER}:${APP_USER}" "${APP_DIR}"

# ── 3. Python virtualenv + dependencies ────────────────────────────────────
echo "[3/6] Creating virtualenv and installing dependencies…"
cd "${APP_DIR}"
sudo -u "${APP_USER}" ${PYTHON} -m venv venv
sudo -u "${APP_USER}" venv/bin/pip install -q --upgrade pip
sudo -u "${APP_USER}" venv/bin/pip install -q -r requirements.txt

# ── 4. Production .env ─────────────────────────────────────────────────────
echo "[4/6] Writing production .env…"
if [ ! -f "${APP_DIR}/.env" ]; then
cat > "${APP_DIR}/.env" <<EOF
APP_ENV=production
APP_HOST=127.0.0.1
APP_PORT=8000
DATABASE_URL=sqlite+aiosqlite:///./honeypot.db
GEOIP_API_URL=http://ip-api.com/json
EOF
    chown "${APP_USER}:${APP_USER}" "${APP_DIR}/.env"
    chmod 600 "${APP_DIR}/.env"
fi

# ── 5. Systemd service ──────────────────────────────────────────────────────
echo "[5/6] Installing systemd service…"
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=HoneyNet API Honeypot
After=network.target

[Service]
Type=exec
User=${APP_USER}
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1 --proxy-headers --forwarded-allow-ips="*"
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=honeypot
# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable  "${SERVICE_NAME}"
systemctl restart "${SERVICE_NAME}"
echo "   ✅  systemd service '${SERVICE_NAME}' started."

# ── 6. Nginx ────────────────────────────────────────────────────────────────
echo "[6/6] Configuring Nginx…"
cp "${APP_DIR}/nginx/honeypot.conf" /etc/nginx/sites-available/honeypot
ln -sf /etc/nginx/sites-available/honeypot /etc/nginx/sites-enabled/honeypot
rm -f /etc/nginx/sites-enabled/default   # Remove default site
nginx -t && systemctl reload nginx
echo "   ✅  Nginx configured and reloaded."

# ── Done ────────────────────────────────────────────────────────────────────
echo ""
echo "=============================="
echo "🍯  Deployment complete!"
echo ""
echo "📋  Checklist:"
echo "   ✓  App running:    sudo systemctl status honeypot"
echo "   ✓  Nginx running:  sudo systemctl status nginx"
echo "   ✓  Logs:           sudo journalctl -u honeypot -f"
echo ""
echo "🔐  EC2 Security Group — ensure inbound rules allow:"
echo "   • Port 22   (SSH)"
echo "   • Port 80   (HTTP)"
echo "   • Port 443  (HTTPS — after adding SSL cert)"
echo ""
echo "🌐  Dashboard: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo '<YOUR_EC2_IP>')"
echo ""
echo "📜  Next: Add SSL with Let's Encrypt:"
echo "   sudo apt install certbot python3-certbot-nginx"
echo "   sudo certbot --nginx -d YOUR_DOMAIN"
