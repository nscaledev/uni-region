#!/bin/bash
set -euo pipefail

echo "==============================================="
echo "  Installing Kubernetes Tools"
echo "==============================================="

KUBERNETES_VERSION="${KUBERNETES_VERSION:-v1.30.0}"

# Install container runtime prerequisites
sudo apt-get install -y \
    containerd \
    runc

# Configure containerd
sudo mkdir -p /etc/containerd
sudo containerd config default | sudo tee /etc/containerd/config.toml > /dev/null

# Enable systemd cgroup driver
sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml

# Enable containerd service
sudo systemctl enable containerd
sudo systemctl start containerd

# Add Kubernetes repository
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.30/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.30/deb/ /" | sudo tee /etc/apt/sources.list.d/kubernetes.list

# Update and install kubelet, kubeadm, kubectl
sudo apt-get update
sudo apt-get install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl

# Disable swap (required for Kubernetes)
sudo swapoff -a
sudo sed -i '/ swap / s/^/#/' /etc/fstab

# Enable kernel modules
sudo modprobe overlay
sudo modprobe br_netfilter

# Configure sysctl
sudo bash -c 'cat > /etc/sysctl.d/99-kubernetes.conf <<EOF
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
EOF'

sudo sysctl --system

echo "Kubernetes tools installed: ${KUBERNETES_VERSION}"
