mod icmp;
mod tun;
mod wireguard;

use std::{
    io::{Read, Write},
    sync::Arc,
};

use anyhow::Result;
use base64::prelude::*;
use log::{debug, info};

use pnet_packet::{
    icmp::{
        echo_reply::EchoReplyPacket,
        IcmpPacket,
        IcmpTypes::{self},
        MutableIcmpPacket,
    },
    ip::IpNextHeaderProtocols::{self, Icmp},
    ipv4::{Ipv4Packet, MutableIpv4Packet},
    Packet,
};

use tokio::{io::Interest, sync::Mutex};

const ICMP_PAYLOAD: &[u8] = b"test ping payload... 1.. 2.. 3!";

use clap::Parser;

use crate::{
    icmp::make_icmp4_with_body,
    wireguard::{send_handshake_initiation, transport_data, wait_for_handshake_response},
};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Your base64 encoded private key
    #[arg(long)]
    secret_key: String,

    /// Base64 encoded public key of your peer
    #[arg(long)]
    peer_public_key: String,

    /// Address of your peer (hostname or ip)
    #[arg(long)]
    peer_address: String,

    /// Port number on which your peer is listening
    #[arg(long, default_value_t = 51820)]
    port: u16,

    /// Number of ping packets to wait for, before exiting
    #[arg(long)]
    exit_after_pings: usize,
}

fn is_icmp(buf: &[u8]) -> bool {
    let mut buf = buf.to_vec();
    if let Some(packet) = MutableIpv4Packet::new(&mut buf) {
        return packet.get_next_level_protocol() == Icmp;
    }
    false
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_line_number(true)
        .with_level(true)
        .init();

    let local_private_key: [u8; 32] = BASE64_STANDARD.decode(args.secret_key)?.try_into().unwrap();
    let remote_public_key: [u8; 32] = BASE64_STANDARD
        .decode(args.peer_public_key)?
        .try_into()
        .unwrap();

    let (noise, wg_sock, initiator_session_id) = send_handshake_initiation(
        local_private_key,
        remote_public_key,
        &args.peer_address,
        args.port,
    )
    .await?;

    let (mut transport, responder_session_id) =
        wait_for_handshake_response(noise, &wg_sock, &initiator_session_id).await?;

    let icmp_body = make_icmp4_with_body("192.168.100.3", "192.168.100.2", ICMP_PAYLOAD);

    let mut counter = 0;

    let output = transport_data(&mut transport, &icmp_body, responder_session_id, counter)?;

    wg_sock.send(&output).await?;

    info!(
        "ping sent! (len={}, icmp_body={})",
        output.len(),
        icmp_body.len()
    );
    counter += 1;

    loop {
        let mut input = [0u8; 1024];
        let len = wg_sock.recv(&mut input).await?;
        info!("Received: {:?}", &input[..len]);

        if [4, 0, 0, 0] == input[0..4] {
            let mut tmp = [0u8; 65535];
            if let Ok(n) = transport.read_message(&input[16..len], &mut tmp) {
                let buf = &tmp[..n];

                let ip = Ipv4Packet::new(buf).unwrap();
                if ip.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
                    let icmp = IcmpPacket::new(ip.payload()).unwrap();

                    assert_eq!(icmp.get_icmp_type(), IcmpTypes::EchoReply);
                    // We don't expect anything other than reply to our ping:
                    let reply = EchoReplyPacket::new(ip.payload()).unwrap();
                    info!("got ping reply: {reply:?}");
                    assert!(reply.payload().starts_with(ICMP_PAYLOAD));

                    // Nedds to happen within 10s of the last received data packet from the other side:
                    let keepalive =
                        transport_data(&mut transport, &[], responder_session_id, counter)?;
                    counter += 1;
                    wg_sock.send(&keepalive).await?;
                    break;
                }
            }
        }
    }
    let wg_sock_tmp = wg_sock.clone();
    let transport = Arc::new(Mutex::new(transport));
    let packets: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(vec![]));
    let transport_tmp = transport.clone();
    let packets_tmp = packets.clone();
    tokio::spawn(async move {
        let packets = packets_tmp;
        let transport = transport_tmp;
        let wg_sock = wg_sock_tmp;
        loop {
            let mut input = [0u8; 1024];
            let len = wg_sock.recv(&mut input).await.unwrap();
            let input = &input[..len];
            debug!("Received payload:: {:?}", input);
            if [4, 0, 0, 0] == input[0..4] {
                let mut tmp = [0u8; 65535];
                match transport.lock().await.read_message(&input[16..], &mut tmp) {
                    Ok(n) => {
                        let buf = &tmp[..n];
                        packets.lock().await.push(buf.to_vec());
                    }
                    Err(e) => todo!("err: {e:?}"),
                }
            }
        }
    });

    let mut fd = tun::create("tun7")?;
    let mut pings = 0;
    'out: loop {
        let guard = fd.ready(Interest::READABLE | Interest::WRITABLE).await?;

        if guard.ready().is_readable() {
            let mut data = vec![0; 4 * 1024];
            let n = fd.get_ref().read(&mut data)?;
            let buf = &mut data[..n];
            debug!("ready next packet from tun (will send as {counter} wg packet): {buf:x?}");

            let wg_packet = transport_data(
                &mut *transport.lock().await,
                buf,
                responder_session_id,
                counter,
            )?;
            counter += 1;
            wg_sock.send(&wg_packet).await?;
        }
        if guard.ready().is_writable() {
            let mut packets = packets.lock().await;
            if !packets.is_empty() {
                let mut done = vec![];
                for (idx, packet) in packets.iter().enumerate() {
                    show_packet(packet);
                    match fd.get_mut().write_all(packet) {
                        Ok(_) => {
                            done.push(idx);
                            if is_icmp(packet) {
                                pings += 1;
                                if pings == args.exit_after_pings {
                                    break 'out;
                                }
                                break;
                            }
                        }
                        Err(e) => {
                            info!("Packet #{idx} failed to send to tun: {e:?}");
                            break;
                        }
                    }
                }
                done.reverse();
                for idx in done {
                    packets.remove(idx);
                }
            }
        }
    }

    Ok(())
}

fn show_packet(p: &[u8]) {
    let mut binding = p.to_vec();
    if let Some(ipv4) = MutableIpv4Packet::new(&mut binding) {
        debug!("packet: {ipv4:?}");
        if ipv4.get_next_level_protocol() == Icmp {
            let mut vec = ipv4.payload().to_vec();
            let icmp = MutableIcmpPacket::new(&mut vec).unwrap();
            info!("icmp: {icmp:?}");
        }
    }
}
