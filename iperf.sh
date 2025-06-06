#!/bin/bash

set -euxo pipefail

docker compose kill && docker compose up --build --detach

docker exec --privileged -t wireguard_client sh -c 'mkdir -p /dev/net && mknod /dev/net/tun c 10 200 && chmod 600 /dev/net/tun'
docker exec --privileged -t wireguard_client wire-on-snow --secret-key "$(cat client_key)" --peer-public-key '7amH6ynyO4Wcpj1y7aIdjBoo54FjWBTrTHoVjlDGRy4=' --peer-address '192.168.200.2' --exit-after-pings 10 &
TO_KILL=$!
trap "kill $TO_KILL" SIGINT SIGABRT
sleep 3
docker exec --privileged -t wireguard_client sh -c 'ip addr add 192.168.100.3/24 dev tun7 && ip link set tun7 up'
sleep 3
docker exec --privileged -t wireguard_client sh -c "iperf3 --client 192.168.100.2"
