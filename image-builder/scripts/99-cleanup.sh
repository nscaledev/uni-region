#!/bin/bash
set -euo pipefail

echo "==============================================="
echo "  Cleaning Up Image"
echo "==============================================="

# Clean apt cache
sudo apt-get clean
sudo apt-get autoclean
sudo apt-get autoremove -y

# Clear logs
sudo rm -rf /var/log/*.log
sudo rm -rf /var/log/*/*.log
sudo find /var/log -type f -name "*.gz" -delete
sudo find /var/log -type f -name "*.1" -delete

# Clear bash history
cat /dev/null > ~/.bash_history
history -c

# Clear machine-id (will be regenerated on first boot)
sudo truncate -s 0 /etc/machine-id
if [ -f /var/lib/dbus/machine-id ]; then
    sudo truncate -s 0 /var/lib/dbus/machine-id
fi

# Clear SSH host keys (will be regenerated on first boot)
sudo rm -f /etc/ssh/ssh_host_*

# Clear cloud-init state
sudo cloud-init clean --logs --seed

# Clear temporary files
sudo rm -rf /tmp/*
sudo rm -rf /var/tmp/*

# Clear user cache
rm -rf ~/.cache/*

# Clear any SSH keys
sudo rm -rf /root/.ssh
rm -rf ~/.ssh

# Clear package lists (save space)
sudo rm -rf /var/lib/apt/lists/*

# Sync filesystem
sync

echo "Cleanup completed successfully"
