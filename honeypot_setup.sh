#!/bin/bash
# AWS EC2 Initial Setup for Cowrie Honeypot
# Run as ubuntu user

set -e

echo "=== AWS Cowrie Honeypot Setup ==="
echo ""
echo "⚠️  CRITICAL: Before running this script, you MUST:"
echo "    1. Go to AWS Console → EC2 → Security Groups"
echo "    2. Add inbound rule: Port 2200, TCP, Source: Your IP"
echo "    3. Keep port 22 open until you verify port 2200 works"
echo ""
echo "This script will:"
echo "  1. Move real SSH to port 2200"
echo "  2. Install Docker and Docker Compose"
echo "  3. Install Tailscale for secure log shipping"
echo ""
read -p "Have you added port 2200 to Security Group? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Please add port 2200 to Security Group first, then run this script again."
    exit 1
fi

# Update system
echo "[+] Updating system..."
sudo apt-get update
sudo apt-get upgrade -y

# Move SSH to port 2200
echo "[+] Moving SSH to port 2200..."
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Change port to 2200 (replace default port 22)
if grep -q "^#Port 22" /etc/ssh/sshd_config; then
    sudo sed -i 's/^#Port 22/Port 2200/' /etc/ssh/sshd_config
elif grep -q "^Port 22" /etc/ssh/sshd_config; then
    sudo sed -i 's/^Port 22/Port 2200/' /etc/ssh/sshd_config
else
    # No Port directive, add it
    echo "Port 2200" | sudo tee -a /etc/ssh/sshd_config
fi

# Restart SSH service (your current session stays connected!)
sudo systemctl restart ssh.service

echo ""
echo "✅ SSH has been moved to port 2200"
echo "⚠️  Your current connection is still active and won't drop"
echo ""
echo "⚠️  IMPORTANT: Test in a NEW terminal BEFORE closing this one!"
echo ""
echo "Test command:"
echo "  ssh -p 2200 ubuntu@$(curl -s ifconfig.me)"
echo ""
echo "Once confirmed working, you can close this terminal."
echo ""
read -p "Press Enter to continue with Docker installation..." 

# Install Docker
echo "[+] Installing Docker..."
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker ubuntu
rm get-docker.sh

# Install Docker Compose v2 (plugin)
echo "[+] Installing Docker Compose v2..."
DOCKER_COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep 'tag_name' | cut -d\" -f4)
sudo mkdir -p /usr/local/lib/docker/cli-plugins
sudo curl -SL "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-linux-x86_64" -o /usr/local/lib/docker/cli-plugins/docker-compose
sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

# Verify installation
docker compose version
echo "✅ Docker Compose v2 installed"

# Install Tailscale
echo "[+] Installing Tailscale..."
curl -fsSL https://tailscale.com/install.sh | sh

echo ""
echo "[+] All dependencies installed!"
echo "    - Docker & Docker Compose: ✅"
echo "    - Tailscale: ✅"
echo "    - Filebeat: Will run in Docker (see docker-compose.yml)"
echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "  1. Logout and login again (for Docker group): ssh -p 2200 -i ~/.ssh/<your-honeypot-key.pem> ubuntu@<IP>"
echo "  2. Connect Tailscale: sudo tailscale up"
echo "  3. Clone honeypot repo and configure"
echo "  4. Deploy Cowrie with docker compose up -d"
echo ""
