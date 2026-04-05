#!/usr/bin/env bash
set -euo pipefail

# ── Lattice server setup for Ubuntu ─────────────────────────────
# Run as root: curl/scp this script to the server, then:
#   chmod +x setup-server.sh && sudo ./setup-server.sh

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo ./setup-server.sh"
  exit 1
fi

echo "==> Updating system"
apt-get update
apt-get upgrade -y
apt-get install -y curl git

# ── Docker ──────────────────────────────────────────────────────
echo "==> Installing Docker"
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  > /etc/apt/sources.list.d/docker.list

apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

systemctl enable --now docker

# ── Kernel tuning ───────────────────────────────────────────────
echo "==> Applying sysctl tuning"
cat > /etc/sysctl.d/99-lattice.conf << 'SYSCTL'
# Network performance
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5

# TCP buffers
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# Connection tracking
net.netfilter.nf_conntrack_max = 262144

# File descriptors
fs.file-max = 1048576
fs.nr_open = 1048576

# VM
vm.swappiness = 10
vm.overcommit_memory = 1
SYSCTL
sysctl --system

# ── File descriptor limits ──────────────────────────────────────
echo "==> Raising file descriptor limits"
cat > /etc/security/limits.d/99-lattice.conf << 'LIMITS'
*  soft  nofile  1048576
*  hard  nofile  1048576
LIMITS

# ── Docker daemon config ───────────────────────────────────────
echo "==> Configuring Docker daemon"
mkdir -p /etc/docker
cat > /etc/docker/daemon.json << 'DAEMON'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "20m",
    "max-file": "3"
  },
  "default-ulimits": {
    "nofile": { "Name": "nofile", "Soft": 1048576, "Hard": 1048576 }
  }
}
DAEMON
systemctl restart docker

echo ""
echo "==> Done. Deploy with:"
echo "    git clone <repo> /opt/lattice"
echo "    cd /opt/lattice && docker compose up -d --build"
