#!/bin/bash


set -euxo pipefail

check_icmp_pairs() {
    local pcap_file="$1"
    local expected_pairs="$2"
    
    if [[ ! -f "$pcap_file" ]]; then
        echo "File $pcap_file not found!"
        return 1
    fi

    local request_count=$(tcpdump -r "$pcap_file" icmp 2>/dev/null | grep -c "echo request")
    local reply_count=$(tcpdump -r "$pcap_file" icmp 2>/dev/null | grep -c "echo reply")

    if [[ "$request_count" -eq "$expected_pairs" && "$reply_count" -eq "$expected_pairs" ]]; then
        echo "Exactly $expected_pairs ICMP request-response pairs found."
        return 0
    else
        echo "Mismatch: Found $request_count requests and $reply_count replies."
        return 1
    fi
}

PINGS_TO_SEND=10

rm -f dumps/dump.pcap
docker compose kill && docker compose up --build --detach
docker exec --privileged -t --detach wireguard_server tcpdump -i any -w /dumps/dump.pcap

docker exec --privileged -t wireguard_client sh -c 'mkdir -p /dev/net && mknod /dev/net/tun c 10 200 && chmod 600 /dev/net/tun'
docker exec --privileged -t wireguard_client wire-on-snow --secret-key "$(cat client_key)" --peer-public-key '7amH6ynyO4Wcpj1y7aIdjBoo54FjWBTrTHoVjlDGRy4=' --peer-address '192.168.200.2' --exit-after-pings $PINGS_TO_SEND &
TO_KILL=$!
trap "kill $TO_KILL" SIGINT SIGABRT
sleep 3
docker exec --privileged -t wireguard_client sh -c 'ip addr add 192.168.100.3/24 dev tun7 && ip link set tun7 up'
sleep 3
docker exec --privileged -t wireguard_client sh -c "ping -i 0.1 192.168.100.2 -p aabbccdd -c $PINGS_TO_SEND; echo 'ping done'"
echo "Ping done"
echo "Wait 10s to make sure that there is no handshake due to missing keepalive from the rust side..."
set +x
for i in `seq 10 -1 1` ; do echo -ne "\r$i " ; sleep 1 ; done

docker exec --privileged -t wireguard_server killall -w tcpdump

tcpdump -nvr dumps/dump.pcap

check_icmp_pairs 'dumps/dump.pcap' $(($PINGS_TO_SEND+1))
