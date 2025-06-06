FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    wireguard \
    iproute2 \
    iptables \
    tcpdump \
    procps \
    psmisc \
    iperf3 \
    && rm -rf /var/lib/apt/lists/*


# Create WireGuard configuration
WORKDIR /etc/wireguard
COPY ./server_key ./privatekey
COPY ./client_pub_key ./client_pub_key
RUN echo "[Interface]" > wg0.conf && \
    echo "PrivateKey = $(cat privatekey)" >> wg0.conf && \
    echo "Address = 192.168.100.2/24" >> wg0.conf && \
    echo "ListenPort = 51820" >> wg0.conf && \
    echo "PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT" >> wg0.conf && \
    echo "PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT" >> wg0.conf && \
    echo "[Peer]" >> wg0.conf && \
    echo "PublicKey = $(cat client_pub_key)" >> wg0.conf && \
    echo "AllowedIPs = 192.168.100.3/32" >> wg0.conf

CMD ["sh", "-c", "wg-quick up wg0 && iperf3 --server"]
