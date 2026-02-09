use std::net::Ipv4Addr;

use untrustended::Readable;

use crate::types::{
    Dhcp, DhcpMessageType, DhcpOp, DhcpOption, EthernetHeader, Ipv4Header, UdpHeader,
};

pub mod types;

#[derive(Debug)]
#[allow(unused)]
pub struct SniffedPacket {
    pub eth: EthernetHeader,
    pub ip: Ipv4Header,
    pub udp: UdpHeader,
    pub dhcp: Dhcp,
}

impl SniffedPacket {
    pub fn dhcp_type(&self) -> Option<DhcpMessageType> {
        self.dhcp
            .options
            .iter()
            .filter_map(|o| match o {
                DhcpOption::MessageType(typ) if !matches!(typ, DhcpMessageType::Unknown(_)) => {
                    Some(*typ)
                }
                _ => None,
            })
            .next()
    }

    pub fn dhcp_hostname(&self) -> Option<&str> {
        self.dhcp
            .options
            .iter()
            .filter_map(|o| match o {
                DhcpOption::Hostname(name) => Some(name.as_ref()),
                _ => None,
            })
            .next()
    }

    pub fn dhcp_vendor_class_id(&self) -> Option<&str> {
        self.dhcp
            .options
            .iter()
            .filter_map(|o| match o {
                DhcpOption::VendorClassIdentifier(id) => Some(id.as_ref()),
                _ => None,
            })
            .next()
    }

    pub fn dhcp_client_ip(&self) -> Option<Ipv4Addr> {
        match self.dhcp.op {
            DhcpOp::BOOTREPLY => self.dhcp.yiaddr,
            DhcpOp::BOOTREQUEST => self.dhcp.ciaddr,
            DhcpOp::Unknown(_) => None,
        }
    }
}

pub fn parse(buf: &[u8]) -> Result<SniffedPacket, untrustended::Error> {
    let input = untrusted::Input::from(buf);

    input.read_all(untrustended::Error::ParseError, |input| {
        let eth_header = EthernetHeader::read(input)?;
        tracing::debug!(?eth_header);

        let ip_header = Ipv4Header::read(input)?;
        tracing::debug!(?ip_header);

        let ip_payload = input.read_bytes(usize::from(ip_header.len))?;

        let (udp_header, udp_payload) =
            ip_payload.read_all(untrustended::Error::ParseError, |input| {
                let udp_header = UdpHeader::read(input)?;
                tracing::debug!(?udp_header);

                let udp_payload = input.read_bytes(usize::from(udp_header.len))?;
                Ok((udp_header, udp_payload))
            })?;

        let dhcp = udp_payload.read_all(untrustended::Error::ParseError, |input| {
            let dhcp = Dhcp::read(input)?;
            tracing::debug!(?dhcp);
            Ok(dhcp)
        })?;

        Ok(SniffedPacket {
            eth: eth_header,
            ip: ip_header,
            udp: udp_header,
            dhcp,
        })
    })
}
