# Wire-on-Snow: A WireGuard Protocol Implementation

## Overview

`wire-on-snow` is a **pure Rust implementation** of the WireGuard VPN protocol that demonstrates how to build a custom **PoC** WireGuard client from scratch for Linux. The project implements the core WireGuard cryptographic handshake and data transport mechanisms using the Noise Protocol Framework, specifically the [snow](https://crates.io/crates/snow) crate, which is a Rust implementation of the Noise Protocol.

WireGuard is built on the **Noise Protocol Framework**, using the **Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s** construction.

## Architecture and Code Flow

### Setup

After getting the all the config, the first step is to establish a connection to the WireGuard server.

```rust
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_line_number(true)
        .with_level(true)
        .init();

    // Parse cryptographic keys
    let local_private_key: [u8; 32] = BASE64_STANDARD.decode(args.secret_key)?.try_into().unwrap();
    let remote_public_key: [u8; 32] = BASE64_STANDARD
        .decode(args.peer_public_key)?
        .try_into()
        .unwrap();

    // Perform WireGuard handshake
    let (noise, wg_sock, initiator_session_id) = send_handshake_initiation(
        local_private_key,
        remote_public_key,
        &args.peer_address,
        args.port,
    )
    .await?;
```
### Noise construction

Thanks to Wireguard's usage of noise protocol, all of the cryptographic operations are handled by the `snow` crate. This makes it easy to implement the handshake protocol and ensures that the resulting packets are secure and authenticated.

```rust
const CONSTRUCTION: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
// ...
let mut noise = snow::Builder::new(CONSTRUCTION.parse()?)
    .local_private_key(&local_private_key)
    .remote_public_key(&remote_public_key)
    .prologue(IDENTIFIER)
    .psk(2, &[0u8; 32])
    .build_initiator()?;
```

### Handshake Initiation

First a [handshake initiation](https://www.wireguard.com/papers/wireguard.pdf#subsubsection.5.4.2) needs to be sent to the remote peer. This is done by calling the `make_handshake_initiation` function, which takes a mutable reference to a `snow::HandshakeState` object and the remote public key as input. The function returns a tuple containing the handshake initiation packet and the sender session ID.

```rust
fn make_handshake_initiation(
    noise: &mut snow::HandshakeState,
    remote_public_key: &[u8; 32],
) -> Result<([u8; 148], [u8; 4])> {
    let mut buf = [0u8; 148];
    buf[0] = 1;  // Message type: handshake initiation
    let sender: [u8; 4] = random::<u32>().to_be_bytes();
    buf[4..8].copy_from_slice(sender.as_slice());
    let tai64n = Tai64N::now();
    let len = noise.write_message(&tai64n.to_bytes(), &mut buf[8..116])?;
    ensure!(108 == len);
    let mac1 = mac1(remote_public_key, &buf[0..116]);
    buf[116..132].copy_from_slice(&mac1);
    // mac2 is all zeros for now
    Ok((buf, sender))
}
```

**What this does:**
- Creates a 148-byte WireGuard handshake initiation packet
- Sets message type to `1` (handshake initiation)
- Generates a random 4-byte sender session ID
- Uses the Noise protocol to encrypt a timestamp (TAI64N format)
- Calculates MAC1 for anti-DoS protection using BLAKE2s

### Handshake Response Processing

Next, we need to wait for the [handshake response](https://www.wireguard.com/papers/wireguard.pdf#subsubsection.5.4.3) from the remote peer and process it:

```rust
pub fn process_handshake_response(
    noise: &mut snow::HandshakeState,
    buf: &[u8],
    expected_receiver: &[u8; 4],
) -> Result<[u8; 4]> {
    let buf: [u8; 92] = buf.try_into()?;
    ensure!([2, 0, 0, 0] == &buf[0..4]);  // Message type: handshake response

    let sender: [u8; 4] = buf[4..8].try_into()?;
    let receiver: [u8; 4] = buf[8..12].try_into()?;
    ensure!(receiver == *expected_receiver);

    let mut tmp = [0u8; 65535];
    noise.read_message(&buf[12..(92 - 16 - 16)], &mut tmp)?;

    Ok(sender)
}
```

**What this does:**
- Processes a 92-byte handshake response (message type `2`)
- Validates session IDs match
- Uses Noise protocol to decrypt the response
- Returns the responder's session ID for future data packets

### TUN interface

Now that we have the responder's session ID, we can create a TUN interface to handle incoming and outgoing data packets. We will listen for packets that arrive at the TUN interface and forward them to the responder. Additionally, we will receive data from the responder and forward it to the TUN interface. But first we need to actually create the TUN interface:

```rust
pub fn create(name: &str) -> Result<AsyncFd<File>> {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")?;

    let fd = f.as_raw_fd();

    let mut ifreq = libc::ifreq {
        ifr_name: [0; IFNAMSIZ],
        ifr_ifru: __c_anonymous_ifr_ifru {
            ifru_flags: (IFF_TUN | IFF_NO_PI) as _,
        },
    };

    for (i, byte) in name.as_bytes().iter().enumerate() {
        ifreq.ifr_name[i] = *byte as i8;
    }

    unsafe {
        tun_set_iff(fd, &ifreq)?;
    }

    Ok(AsyncFd::new(f)?)
}
```

The `IFF_NO_PI` flag means [no packet information headers](https://www.kernel.org/doc/Documentation/networking/tuntap.txt). The resulting file descriptor will be wrapped in an `AsyncFd` for asynchronous I/O operations.

### Data Transport

Thanks to the encryption encapsulation in the Noise framework, transfering data is a simple matter:

```rust
pub fn transport_data(
    noise: &mut TransportState,
    payload: &[u8],
    responder_session_id: [u8; 4],
    counter: u64,
) -> Result<Vec<u8>> {
    // Header + encrypted payload + authentication tag
    let mut output = vec![0u8; 16 + payload.len() + 16];
    output[0] = 4;  // Message type: transport data
    output[4..8].copy_from_slice(&responder_session_id);
    output[8..16].copy_from_slice(counter.to_le_bytes().as_slice());
    let len = noise.write_message(payload, &mut output[16..])?;

    Ok(output)
}
```

**What this does:**
- Creates data transport packets (message type `4`)
- Includes the responder's session ID and a packet counter
- Uses ChaCha20Poly1305 AEAD to encrypt and authenticate the payload

## Program flow sequence

1. **Initialization**: Parse command-line arguments including private key, peer public key, and server address

2. **Handshake Phase**:
   - Generate handshake initiation using Noise IKpsk2
   - Send 148-byte handshake packet to WireGuard server
   - Receive and validate 92-byte handshake response
   - Derive transport keys using Noise protocol

3. **Initial Ping Test**:
   - Create ICMP ping packet (`192.168.100.3` → `192.168.100.2`)
   - Encrypt using derived transport keys
   - Send via UDP to WireGuard server
   - Wait for encrypted ping reply

4. **TUN Interface Operation**:
   - Create TUN interface `tun7`
   - Assign IP address `192.168.100.3/24`
   - Bridge between TUN interface and WireGuard UDP socket
   - Encrypt outgoing packets, decrypt incoming packets

5. **Bidirectional Data Flow**:
   - **Outbound**: TUN → Encrypt → UDP socket → WireGuard server
   - **Inbound**: WireGuard server → UDP socket → Decrypt → TUN

## Usage

### Prerequisites

- Docker and Docker Compose
- Rust toolchain (for building from source)

### Running the Test

```bash
# Run the complete test suite
./test.sh
```

This will:
1. Build both client and server Docker containers
2. Start a Linux WireGuard server
3. Run the `wire-on-snow` client
4. Perform ping tests through the encrypted tunnel
5. Validate packet capture results

### Performance Testing with iperf3

```bash
# Run iperf3 performance testing
./iperf.sh
```

The iperf3 test demonstrates real-world performance of the WireGuard tunnel by:
1. Establishing the WireGuard connection using `wire-on-snow`
2. Configuring the TUN interface with proper IP addressing
3. Running iperf3 client against the server through the encrypted tunnel
4. Measuring actual throughput and latency over the VPN connection


### Manual Usage

```bash
# Build the project
cargo build

# Run with custom parameters
./target/debug/wire-on-snow \
    --secret-key "<base64-private-key>" \
    --peer-public-key "<base64-public-key>" \
    --peer-address "192.168.200.2" \
    --port 51820 \
    --exit-after-pings 5
```

### Docker Environment

The test environment includes:

- **Server Container**: Real WireGuard server using `wg-quick`
  - IP: `192.168.200.2` (container network)
  - Tunnel IP: `192.168.100.2/24`
  - Port: `51820`

- **Client Container**: `wire-on-snow` implementation
  - IP: `192.168.200.3` (container network)
  - Tunnel IP: `192.168.100.3/24`

## CI

### 1. Functional Test (`test.sh`)
- Establishes WireGuard tunnel connecting this custom implementation and official WireGuard in-kernell one
- Performs ICMP ping tests through the encrypted tunnel
- Captures network traffic for analysis
- Validates exact packet counts and protocol compliance
- Uploads packet capture artifacts for debugging

### 2. Performance Test (`iperf.sh`)
- Establishes WireGuard tunnel connecting this custom implementation and official WireGuard in-kernell one
- Runs iperf3 performance testing through the tunnel
- Measures throughput and validates sustained data transfer
- Ensures the implementation can handle more than just pings, even if it's lacking many important parts of the WireGuard specification
