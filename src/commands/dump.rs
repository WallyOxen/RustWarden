use pnet::{
    datalink::{self, interfaces},
    packet::{
        ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
        ipv4::Ipv4Packet,
    },
    util::MacAddr,
};

use crate::helpers::handle_ethernet_frame;

pub fn dump(network_interface: &str) -> Result<(), String> {
    let interface = interfaces()
        .into_iter()
        .filter(|i| &i.name == network_interface)
        .next()
        .ok_or(format!(
            "Unable to find interface for {}",
            network_interface
        ))?;

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Unable to create channel: {}", e),
    };

    loop {
        let mut buf: [u8; 4096] = [0u8; 4096];
        let mut fake_ethernet_frame = MutableEthernetPacket::new(&mut buf[..]).unwrap();

        match rx.next() {
            Ok(packet) => {
                let payload_offset;
                if interface.is_up() {
                    if interface.is_loopback() {
                        // The pnet code for BPF loopback adds a zero'd out Ethernet header
                        payload_offset = 14;
                    } else {
                        // Maybe is TUN interface
                        payload_offset = 0;
                    }

                    if packet.len() > payload_offset {
                        let version = Ipv4Packet::new(&packet[payload_offset..])
                            .unwrap()
                            .get_version();

                        if version == 4 {
                            fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_ethertype(EtherTypes::Ipv4);
                            fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                            match handle_ethernet_frame(
                                &interface,
                                &fake_ethernet_frame.to_immutable(),
                            ) {
                                Ok(_) => (),
                                Err(e) => println!("Error: {e}"),
                            }
                            continue;
                        } else if version == 6 {
                            fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_ethertype(EtherTypes::Ipv6);
                            fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                            match handle_ethernet_frame(
                                &interface,
                                &fake_ethernet_frame.to_immutable(),
                            ) {
                                Ok(_) => (),
                                Err(e) => println!("Error: {e}"),
                            }
                        }

                        match handle_ethernet_frame(
                            &interface,
                            &EthernetPacket::new(packet).unwrap(),
                        ) {
                            Ok(_) => (),
                            Err(e) => println!("Error: {e}"),
                        }
                    }
                }
            }
            Err(e) => panic!("Unable to receive packet: {}", e),
        }
    }
}
