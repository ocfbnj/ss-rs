#!/bin/sh

# Set up the repository
apt-get update
apt-get --yes install ca-certificates curl gnupg

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine
apt-get update
apt-get --yes install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Install ss-rs
docker pull ghcr.io/ocfbnj/ss-rs:latest
docker run --name ss-rs -p 8080:8080 -d ghcr.io/ocfbnj/ss-rs ss-rs -s 0.0.0.0:8080 -k ss-rs-123456
