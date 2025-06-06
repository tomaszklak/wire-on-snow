FROM rust:1.85.0-bookworm AS builder

WORKDIR /app

# Copy the project files
COPY . .

RUN cargo build

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    iproute2 \
    iputils-ping \
    dnsutils \
    wireguard \
    tcpdump \
    iperf3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/debug/wire-on-snow /usr/local/bin/wire-on-snow

# Set the default command
CMD ["sleep", "infinity"]
