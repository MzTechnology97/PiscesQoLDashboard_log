#!/bin/bash
latest=$(curl -s https://quay.io/api/v1/repository/team-helium/miner?tab=tags | grep -Po 'miner-arm64_[0-9]+\.[0-9]+\.[0-9]+\.[^"]' | sort -n | tail -1)

echo $latest > /var/dashboard/statuses/latest_miner_version
docker ps --format "{{.Image}}" --filter "name=miner" | grep -Po "miner-arm64_.*" > /var/dashboard/statuses/current_miner_version
