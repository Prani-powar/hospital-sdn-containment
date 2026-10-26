#!/usr/bin/env bash
# Install lab host packages only. Run in the dedicated Linux lab.
set -euo pipefail
if [[ "${1:-}" != "--install" ]]; then
  echo "Usage: bash infra/setup.sh --install"
  echo "Supports Ubuntu 22.04/24.04 and Mint 22.x; installs Docker, OVS and Mininet."
  exit 2
fi
source /etc/os-release
if ! { [[ "${ID:-}" == ubuntu && ( "${VERSION_ID:-}" == 22.04 || "${VERSION_ID:-}" == 24.04 ) ]] || [[ "${ID:-}" == linuxmint && "${VERSION_ID:-}" == 22.* && "${UBUNTU_CODENAME:-}" == noble ]]; }; then
  echo "Unsupported OS: expected Ubuntu 22.04/24.04 or Mint 22.x (noble). No packages changed." >&2
  exit 1
fi
if [[ $EUID -eq 0 ]]; then
  echo "Run as your normal user; sudo will be used for host packages." >&2
  exit 1
fi
sudo apt-get update
sudo apt-get install -y docker.io openvswitch-switch mininet \
  python3 python3-venv python3-pytest iproute2 iputils-ping
if [[ "${VERSION_ID:-}" == 22.04 && "${ID:-}" == ubuntu ]]; then
  sudo apt-get install -y docker-compose
else
  sudo apt-get install -y docker-compose-v2
fi
sudo systemctl enable --now docker openvswitch-switch
echo "Host packages ready. Docker commands below use sudo; no group changes made."
