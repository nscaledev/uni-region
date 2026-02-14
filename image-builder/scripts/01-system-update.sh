#!/bin/bash
set -euo pipefail

echo "==============================================="
echo "  System Update and Base Configuration"
echo "==============================================="

# Update package lists
sudo apt-get update

# Upgrade all packages
sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

# Install essential packages
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential \
    linux-headers-generic \
    dkms \
    curl \
    wget \
    git \
    vim \
    htop \
    net-tools \
    ca-certificates \
    gnupg \
    lsb-release \
    software-properties-common \
    apt-transport-https

echo "System update completed successfully"
