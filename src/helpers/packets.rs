use pnet::{
    datalink::NetworkInterface,
    packet::{
        Packet,
        arp::ArpPacket,
        ethernet::{EtherTypes, EthernetPacket},
        ipv4::Ipv4Packet,
        ipv6::Ipv6Packet,
    },
};
use std::net::IpAddr;

use crate::helpers::protocol::handle_transport_protocol;

pub fn handle_ethernet_frame(
    interface: &NetworkInterface,
    ethernet: &EthernetPacket,
) -> Result<(), String> {
    let interface_name = &interface.name[..];
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(interface_name, ethernet),
        EtherTypes::Ipv6 => handle_ipv6_packet(interface_name, ethernet),
        EtherTypes::Arp => handle_arp_packet(interface_name, ethernet),
        _ => Err(format!(
            "[{}]: Unknown packet: {} > {}; ethertype: {:?} length: {}",
            interface_name,
            ethernet.get_source(),
            ethernet.get_destination(),
            ethernet.get_ethertype(),
            ethernet.packet().len()
        )),
    }
}

fn handle_arp_packet(interface_name: &str, ethernet: &EthernetPacket) -> Result<(), String> {
    let header = ArpPacket::new(ethernet.payload());

    if let Some(header) = header {
        println!(
            "[{}]: ARP Packet: {}({}) > {}({}); Operation: {:?}",
            interface_name,
            ethernet.get_source(),
            header.get_sender_proto_addr(),
            ethernet.get_destination(),
            header.get_target_proto_addr(),
            header.get_operation()
        );
        Ok(())
    } else {
        Err(format!("[{}]: Malformed ARP Packet", interface_name))
    }
}

fn handle_ipv4_packet(interface_name: &str, ethernet: &EthernetPacket) -> Result<(), String> {
    let header = Ipv4Packet::new(ethernet.payload());

    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
        )
    } else {
        Err(format!("[{}]: Malformed IPv4 Packet", interface_name))
    }
}

fn handle_ipv6_packet(interface_name: &str, ethernet: &EthernetPacket) -> Result<(), String> {
    let header = Ipv6Packet::new(ethernet.payload());

    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V6(header.get_source()),
            IpAddr::V6(header.get_destination()),
            header.get_next_header(),
            header.payload(),
        )
    } else {
        Err(format!("[{}]: Malformed IPv6 Packet", interface_name))
    }
}
