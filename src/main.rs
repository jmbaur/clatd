use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::str::FromStr;

use serde::Deserialize;

use crate::tun::Tun;

pub(crate) mod tun;
pub(crate) mod bindings {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

// TODO(jared): find constant for this in linux source
const MAX_PACKET_SIZE: usize = (1 << 16) - 1;

#[derive(Deserialize)]
pub struct Config {
    ignore_ipv4_tos: bool,
}

impl Config {
    pub fn load_from_file(file: &str) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(file)?;
        Ok(toml::from_str(&contents)?)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ignore_ipv4_tos: false,
        }
    }
}

// TODO(jared): use actual NDP messages to discover plat prefix instead of using DNS results from
// "ipv4only.arpa"
fn discover_plat_prefix() -> anyhow::Result<Option<(Ipv6Addr, usize)>> {
    // port does not matter here
    for socket_addr in "ipv4only.arpa.:0".to_socket_addrs()? {
        let ip = if true {
            Ipv6Addr::from_str("64:ff9b::c000:aa").unwrap()
        } else {
            let ip = socket_addr.ip();

            match ip {
                IpAddr::V4(_) => continue,
                IpAddr::V6(ip) => ip,
            }
        };

        let octets = ip.octets();

        let Some(prefix_length) = octets.windows(4).enumerate().find_map(|(i, octet)| {
            // well-known addresses for "ipv4only.arpa."
            if octet == &[192, 0, 0, 170] || octet == &[192, 0, 0, 171] {
                Some(i * 8)
            } else {
                None
            }
        }) else {
            continue;
        };

        match prefix_length {
            32 | 40 | 48 | 56 | 64 | 96 => {}
            _ => {
                // TODO(jared): invalid prefix length
                continue;
            }
        }

        let pref64_octets = &mut [0u8; 16];
        octets.into_iter().enumerate().for_each(|(i, octet)| {
            if i * 8 < prefix_length {
                pref64_octets[i] = octet;
            } else {
                pref64_octets[i] = 0x0;
            }
        });

        let pref64_ip = Ipv6Addr::from(*pref64_octets);
        return Ok(Some((pref64_ip, prefix_length)));
    }

    Ok(None)
}

fn main() -> anyhow::Result<()> {
    // println!("{}", bindings::TUNSETIFF);

    let config = if false {
        Config::load_from_file("/tmp/clatd-config.toml")?
    } else {
        Config::default()
    };

    loop {
        if let Some((plat_prefix_addr, plat_prefix_length)) = discover_plat_prefix()? {
            let mut tun_dev = Tun::new("clat");
            tun_dev.open()?;

            loop {
                let mut buf = [0u8; MAX_PACKET_SIZE];
                let n_bytes = tun_dev.read(&mut buf)?;
                let packet_bytes = &buf[0..n_bytes];
                match etherparse::IpSlice::from_slice(packet_bytes) {
                    Ok(packet) => {
                        if let Some(v4_packet) = packet.ipv4() {
                            eprintln!("{:?}", v4_packet);

                            let header = v4_packet.header();
                            let v6_source_addr =
                                nat46(plat_prefix_addr, plat_prefix_length, header.source_addr());

                            let v6_dest_addr = nat46(
                                plat_prefix_addr,
                                plat_prefix_length,
                                header.destination_addr(),
                            );
                            let payload = packet.payload().payload;
                            let mut out = Vec::<u8>::with_capacity(
                                etherparse::Ipv6Header::LEN + payload.len(),
                            );
                            let v6_header = convert_ip_header(
                                &config,
                                &header,
                                &v6_source_addr,
                                &v6_dest_addr,
                            )?;
                            v6_header.write(&mut out)?;
                            out.write_all(payload)?;
                            tun_dev.write_all(&out)?;
                        }
                    }
                    Err(e) => {
                        eprintln!("invalid packet: {}", e);
                        continue;
                    }
                }
            }
        } else {
            std::thread::sleep(std::time::Duration::from_secs(60 * 10));
        }
    }
}

/// Convert an IPv4 header to an IPv6 header as specified in RFC 6145 Section 4.1.
fn convert_ip_header(
    config: &Config,
    v4_header: &etherparse::Ipv4HeaderSlice,
    v6_source_addr: &Ipv6Addr,
    v6_dest_addr: &Ipv6Addr,
) -> anyhow::Result<etherparse::Ipv6Header> {
    let v6_header = etherparse::Ipv6Header {
        source: v6_source_addr.octets(),
        destination: v6_dest_addr.octets(),
        flow_label: etherparse::Ipv6FlowLabel::ZERO,
        payload_length: v4_header.payload_len()? - v4_header.slice().len() as u16,
        hop_limit: v4_header.ttl(),
        traffic_class: if config.ignore_ipv4_tos {
            0
        } else {
            v4_header.dcp().value()
        },
        ..Default::default()
    };

    Ok(v6_header)
}

// TODO(jared): mask plat prefix address with plat prefix length
fn nat46(plat_prefix_addr: Ipv6Addr, _plat_prefix_length: usize, v4_addr: Ipv4Addr) -> Ipv6Addr {
    let v4_octets = v4_addr.octets();

    let v6_without_plat_prefix = Ipv6Addr::new(
        0,
        0,
        0,
        0,
        0,
        0,
        ((v4_octets[0] as u16) << 8) | v4_octets[1] as u16,
        ((v4_octets[2] as u16) << 8) | v4_octets[3] as u16,
    );

    plat_prefix_addr | v6_without_plat_prefix
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn nat46() {
        assert_eq!(
            super::nat46(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                96,
                Ipv4Addr::new(192, 0, 2, 1),
            ),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0xc000, 0x201)
        );
    }
}