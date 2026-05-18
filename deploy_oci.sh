#!/usr/bin/env bash
# =============================================================================
# SOC Dashboard — Deploy en Oracle Cloud Free Tier (Oracle Linux 9 ARM)
# Correr este script en el VM de OCI despues de copiar el proyecto
# =============================================================================
set -euo pipefail

echo "==> Actualizando sistema..."
sudo dnf update -y -q

echo "==> Instalando Docker..."
sudo dnf install -y docker
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker "$USER"

echo "==> Instalando Docker Compose plugin..."
sudo dnf install -y docker-compose-plugin

echo "==> Abriendo puerto 8000 en firewall..."
sudo firewall-cmd --permanent --add-port=8000/tcp
sudo firewall-cmd --reload

echo "==> Construyendo imagen Docker..."
sudo docker compose build

echo "==> Levantando servicio..."
sudo docker compose up -d

echo "==> Configurando arranque automatico con systemd..."
sudo tee /etc/systemd/system/soc-dashboard.service > /dev/null <<EOF
[Unit]
Description=SOC Dashboard
Requires=docker.service
After=docker.service

[Service]
WorkingDirectory=$(pwd)
ExecStart=/usr/bin/docker compose up
ExecStop=/usr/bin/docker compose down
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable soc-dashboard

echo ""
echo "============================================================"
echo "  SOC Dashboard desplegado exitosamente"
echo "  URL: http://$(curl -s ifconfig.me):8000"
echo "============================================================"
