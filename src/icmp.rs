use std::net::Ipv4Addr;

use pnet_packet::{
    icmp::{checksum, echo_request::MutableEchoRequestPacket, IcmpCode, IcmpPacket, IcmpTypes},
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::MutableIpv4Packet,
    Packet,
};

pub fn make_icmp4_with_body(src: &str, dst: &str, body: &[u8]) -> Vec<u8> {
    const ICMP_HEADER: usize = 8;
    const IPV4_HEADER_MIN: usize = 20;
    let additional_body_len = body.len();
    let ip_len = IPV4_HEADER_MIN + ICMP_HEADER + 10 + additional_body_len;
    let mut raw = vec![0u8; ip_len];

    make_icmp_request_packet(&mut raw[IPV4_HEADER_MIN..], body);

    let mut ip = MutableIpv4Packet::new(&mut raw).expect("ICMP: Bad IP buffer");
    let src = src.parse().expect("ICMP: Bad src IP");
    let dst = dst.parse().expect("ICMP: Bad dst IP");
    set_ipv4(
        &mut ip,
        IpNextHeaderProtocols::Icmp,
        IPV4_HEADER_MIN,
        ip_len,
        src,
        dst,
    );

    raw
}

fn make_icmp_request_packet(buf: &mut [u8], body: &[u8]) {
    let mut echo_packet = MutableEchoRequestPacket::new(buf).unwrap();
    echo_packet.set_sequence_number(0x42);
    echo_packet.set_identifier(0x1337);
    echo_packet.set_icmp_type(IcmpTypes::EchoRequest);
    echo_packet.set_icmp_code(IcmpCode::new(0));
    echo_packet.set_payload(body);

    let echo_checksum = checksum(&IcmpPacket::new(echo_packet.packet()).unwrap());
    echo_packet.set_checksum(echo_checksum);
}

fn set_ipv4(
    ip: &mut MutableIpv4Packet,
    protocol: IpNextHeaderProtocol,
    header_length: usize,
    total_length: usize,
    source: Ipv4Addr,
    destination: Ipv4Addr,
) {
    ip.set_next_level_protocol(protocol);
    ip.set_version(4);
    ip.set_header_length((header_length / 4) as u8);
    ip.set_total_length(total_length.try_into().unwrap());
    ip.set_flags(2);
    ip.set_ttl(64);

    ip.set_source(source);
    ip.set_destination(destination);
    ip.set_checksum(pnet_packet::ipv4::checksum(&ip.to_immutable()));
}
