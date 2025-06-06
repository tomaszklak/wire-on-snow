use std::sync::Arc;

use anyhow::{ensure, Result};
use blake2::{digest::FixedOutput, Blake2s, Blake2sMac, Digest};
use log::info;
use rand::random;
use snow::{HandshakeState, TransportState};
use tai64::Tai64N;
use tokio::net::UdpSocket;

const CONSTRUCTION: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";

pub async fn send_handshake_initiation(
    local_private_key: [u8; 32],
    remote_public_key: [u8; 32],
    peer_address: &str,
    port: u16,
) -> Result<(HandshakeState, Arc<UdpSocket>, [u8; 4])> {
    let mut noise = snow::Builder::new(CONSTRUCTION.parse()?)
        .local_private_key(&local_private_key)
        .remote_public_key(&remote_public_key)
        .prologue(IDENTIFIER)
        .psk(2, &[0u8; 32]) // TODO: add optional parameter in Args for this
        .build_initiator()?;

    let (handshake_initiation_packet, initiator_session_id) =
        make_handshake_initiation(&mut noise, &remote_public_key)?;

    let wg_sock = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let remote_addr = format!("{}:{}", peer_address, port);
    wg_sock.connect(remote_addr).await?;
    let len = wg_sock.send(handshake_initiation_packet.as_slice()).await?;
    assert_eq!(148, len);
    Ok((noise, wg_sock, initiator_session_id))
}

pub async fn wait_for_handshake_response(
    mut noise: HandshakeState,
    wg_sock: &UdpSocket,
    initiator_session_id: &[u8; 4],
) -> Result<(TransportState, [u8; 4])> {
    let mut buf = [0u8; 92];
    let len = wg_sock.recv(&mut buf).await?;
    ensure!(len == 92);

    let responder_session_id = process_handshake_response(&mut noise, &buf, &initiator_session_id)?;

    Ok((noise.into_transport_mode()?, responder_session_id))
}

fn make_handshake_initiation(
    noise: &mut snow::HandshakeState,
    remote_public_key: &[u8; 32],
) -> Result<([u8; 148], [u8; 4])> {
    let mut buf = [0u8; 148];
    buf[0] = 1;
    let sender: [u8; 4] = random::<u32>().to_be_bytes();
    buf[4..8].copy_from_slice(sender.as_slice());
    let tai64n = Tai64N::now();
    let len = noise.write_message(&tai64n.to_bytes(), &mut buf[8..116])?;
    ensure!(108 == len);
    let mac1 = mac1(remote_public_key, &buf[0..116]);
    buf[116..132].copy_from_slice(&mac1);
    // mac2 is all zeros for now
    info!(" Handshake request: {buf:?}");
    Ok((buf, sender))
}

pub fn process_handshake_response(
    noise: &mut snow::HandshakeState,
    buf: &[u8],
    expected_receiver: &[u8; 4],
) -> Result<[u8; 4]> {
    let buf: [u8; 92] = buf.try_into()?;
    ensure!([2, 0, 0, 0] == &buf[0..4]);
    info!("Handshake response: {buf:?}");

    let sender: [u8; 4] = buf[4..8].try_into()?;
    let receiver: [u8; 4] = buf[8..12].try_into()?;
    ensure!(receiver == *expected_receiver);

    let mut tmp = [0u8; 65535];
    noise.read_message(&buf[12..(92 - 16 - 16)], &mut tmp)?;
    info!("Received handshake response is correct!");

    Ok(sender)
}

pub fn transport_data(
    noise: &mut TransportState,
    payload: &[u8],
    responder_session_id: [u8; 4],
    counter: u64,
) -> Result<Vec<u8>> {
    // Header + encrypted payload + authentication tag
    let mut output = vec![0u8; 16 + payload.len() + 16];
    output[0] = 4;
    output[4..8].copy_from_slice(&responder_session_id);
    output[8..16].copy_from_slice(counter.to_le_bytes().as_slice());
    let len = noise.write_message(payload, &mut output[16..])?;
    ensure!(
        len == payload.len() + 16,
        "Wrong len, expected {len}, got {}",
        payload.len()
    );

    Ok(output)
}

fn hash(input1: impl AsRef<[u8]>, input2: impl AsRef<[u8]>) -> [u8; 32] {
    let mut hasher = Blake2s::new();
    hasher.update(input1.as_ref());
    hasher.update(input2.as_ref());
    hasher.finalize().into()
}

fn mac(key: impl AsRef<[u8]>, input: impl AsRef<[u8]>) -> [u8; 16] {
    use blake2::digest::KeyInit;

    let mut mac = Blake2sMac::new_from_slice(key.as_ref()).unwrap();
    blake2::digest::Update::update(&mut mac, input.as_ref());
    mac.finalize_fixed().into()
}

fn mac1(remote_pubkey: &[u8], buf: &[u8]) -> [u8; 16] {
    let mac1_key = hash(LABEL_MAC1, remote_pubkey);
    mac(mac1_key.as_ref(), buf)
}
