use std::fmt;
use std::net::Ipv4Addr;

use luomu_common::{Destination, MacAddr, Source};
use untrustended::{Readable, ReaderExt};

#[derive(Debug, Clone, Copy)]
#[allow(unused)]
pub struct EthernetHeader {
    pub dst: Destination<MacAddr>,
    pub src: Source<MacAddr>,
    pub typ: EtherType,
}

impl Readable for EthernetHeader {
    type Output = EthernetHeader;

    fn read(input: &mut untrusted::Reader<'_>) -> Result<Self::Output, untrustended::Error> {
        let dst =
            MacAddr::try_from(input.read_u48be()?).map_err(|_| untrustended::Error::ParseError)?;
        let src =
            MacAddr::try_from(input.read_u48be()?).map_err(|_| untrustended::Error::ParseError)?;
        let typ = EtherType::read(input)?;
        Ok(EthernetHeader {
            dst: Destination::new(dst),
            src: Source::new(src),
            typ,
        })
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u16)]
pub enum EtherType {
    Ipv4 = 0x0800,
}

impl Readable for EtherType {
    type Output = EtherType;

    fn read(input: &mut untrusted::Reader<'_>) -> Result<Self::Output, untrustended::Error> {
        match input.read_u16be()? {
            0x0800 => Ok(EtherType::Ipv4),
            _ => Err(untrustended::Error::ParseError),
        }
    }
}

impl fmt::Display for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EtherType::Ipv4 => f.write_str("IPv4"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[allow(unused)]
pub struct Ipv4Header {
    pub src: Source<Ipv4Addr>,
    pub dst: Destination<Ipv4Addr>,
    pub protocol: Protocol,
    pub len: u16,
}

impl Readable for Ipv4Header {
    type Output = Ipv4Header;

    fn read(input: &mut untrusted::Reader<'_>) -> Result<Self::Output, untrustended::Error> {
        let word = input.read_u16be()?;
        if (word >> 12) != 4 {
            return Err(untrustended::Error::ParseError);
        }
        if (word >> 8) & 0b1111 != 5 {
            return Err(untrustended::Error::ParseError);
        }

        let total_len = input.read_u16be()?.saturating_sub(20);
        let _identification = input.read_u16be()?;
        let _flags_offset = input.read_u16be()?;
        let _ttl = input.read_u8()?;
        let protocol = Protocol::read(input)?;
        let _header_checksum = input.read_u16be()?;
        let src = input.read_ipv4addr()?;
        let dst = input.read_ipv4addr()?;

        Ok(Ipv4Header {
            src: Source::new(src),
            dst: Destination::new(dst),
            protocol,
            len: total_len,
        })
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum Protocol {
    Udp = 17,
}

impl Readable for Protocol {
    type Output = Protocol;

    fn read(input: &mut untrusted::Reader<'_>) -> Result<Self::Output, untrustended::Error> {
        match input.read_u8()? {
            17 => Ok(Protocol::Udp),
            _ => Err(untrustended::Error::ParseError),
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Udp => f.write_str("UDP"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[allow(unused)]
pub struct UdpHeader {
    pub src: Source<u16>,
    pub dst: Destination<u16>,
    pub len: u16,
}

impl Readable for UdpHeader {
    type Output = UdpHeader;

    fn read(input: &mut untrusted::Reader<'_>) -> Result<Self::Output, untrustended::Error> {
        let src = input.read_u16be()?;
        let dst = input.read_u16be()?;
        let len = input.read_u16be()?.saturating_sub(8);
        let _checksum = input.read_u16be()?;

        Ok(UdpHeader {
            src: Source::new(src),
            dst: Destination::new(dst),
            len,
        })
    }
}

#[derive(Debug, Clone)]
#[allow(unused)]
pub struct Dhcp {
    pub op: DhcpOp,
    pub xid: u32,
    pub chaddr: MacAddr,
    pub options: Box<[DhcpOption]>,
}

impl Readable for Dhcp {
    type Output = Dhcp;

    fn read(input: &mut untrusted::Reader<'_>) -> Result<Self::Output, untrustended::Error> {
        let op = DhcpOp::read(input)?;
        let htype = input.read_u8()?;
        if htype != 1 {
            return Err(untrustended::Error::ParseError);
        }
        let hlen = input.read_u8()?;
        if hlen != 6 {
            return Err(untrustended::Error::ParseError);
        }
        let _hops = input.read_u8()?;
        let xid = input.read_u32be()?;
        let _secs = input.read_u16be()?;
        let _flags = input.read_u16be()?;
        let _caddr = input.read_ipv4addr()?;
        let _yaddr = input.read_ipv4addr()?;
        let _saddr = input.read_ipv4addr()?;
        let _gaddr = input.read_ipv4addr()?;
        let chaddr = {
            let u48 = input.read_u48be()?;
            MacAddr::try_from(u48).map_err(|_| untrustended::Error::ParseError)?
        };
        input.skip(10)?;
        let _sname = input.read_bytes(64)?;
        let _file = input.read_bytes(128)?;

        let magic = input.read_u32be()?;
        if magic != 0x63825363 {
            return Err(untrustended::Error::ParseError);
        }

        let mut options = Vec::new();
        loop {
            let option = DhcpOption::read(input)?;
            tracing::trace!("Parsed DHCP Option: {option:?}");
            if option == DhcpOption::End {
                break;
            }
            if option == DhcpOption::Pad {
                continue;
            }
            options.push(option);
        }

        Ok(Dhcp {
            op,
            xid,
            chaddr,
            options: options.into_boxed_slice(),
        })
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
#[allow(clippy::upper_case_acronyms)]
pub enum DhcpOp {
    BOOTREQUEST = 1,
    BOOTREPLY = 2,
}

impl Readable for DhcpOp {
    type Output = DhcpOp;

    fn read(input: &mut untrusted::Reader<'_>) -> Result<Self::Output, untrustended::Error> {
        match input.read_u8()? {
            1 => Ok(DhcpOp::BOOTREQUEST),
            2 => Ok(DhcpOp::BOOTREPLY),
            _ => Err(untrustended::Error::ParseError),
        }
    }
}

impl fmt::Display for DhcpOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DhcpOp::BOOTREPLY => f.write_str("BOOT Reply"),
            DhcpOp::BOOTREQUEST => f.write_str("BOOT Request"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpOption {
    Pad,
    End,
    Hostname(Box<str>),
    MessageType(DhcpMessageType),
    ParameterRequestList(Box<[u8]>),
    Unknown(u8, u8),
}

impl Readable for DhcpOption {
    type Output = DhcpOption;

    fn read(input: &mut untrusted::Reader<'_>) -> Result<Self::Output, untrustended::Error> {
        let code = input.read_u8()?;

        match code {
            0 => Ok(DhcpOption::Pad),
            255 => Ok(DhcpOption::End),

            // Hostname
            12 => {
                let len = input.read_u8()?;
                let name = input.read_utf8(usize::from(len))?;
                Ok(DhcpOption::Hostname(name.into()))
            }

            // DHCP Message Type
            53 => DhcpMessageType::read(input),

            // DHCP Parameter Request list
            55 => {
                let len = input.read_u8()?;
                let params = input
                    .read_bytes(usize::from(len))?
                    .as_slice_less_safe()
                    .into();
                Ok(DhcpOption::ParameterRequestList(params))
            }

            // Unknown option. We catch type and length
            typ => {
                let len = input.read_u8()?;
                Ok(DhcpOption::Unknown(typ, len))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(clippy::upper_case_acronyms)]
pub enum DhcpMessageType {
    DHCPDISCOVER = 1,
    DHCPOFFER = 2,
    DHCPREQUEST = 3,
    DHCPDECLINE = 4,
    DHCPACK = 5,
    DHCPNAK = 6,
    DHCPRELEASE = 7,
    DHCPINFORM = 8,
    Unknown(u8),
}

impl Readable for DhcpMessageType {
    type Output = DhcpOption;

    fn read(input: &mut untrusted::Reader<'_>) -> Result<Self::Output, untrustended::Error> {
        let len = input.read_u8()?;
        if len != 1 {
            return Err(untrustended::Error::ParseError);
        }
        let typ = match input.read_u8()? {
            1 => DhcpMessageType::DHCPDISCOVER,
            2 => DhcpMessageType::DHCPOFFER,
            3 => DhcpMessageType::DHCPREQUEST,
            4 => DhcpMessageType::DHCPDECLINE,
            5 => DhcpMessageType::DHCPACK,
            6 => DhcpMessageType::DHCPNAK,
            7 => DhcpMessageType::DHCPRELEASE,
            8 => DhcpMessageType::DHCPINFORM,
            n => DhcpMessageType::Unknown(n),
        };
        Ok(DhcpOption::MessageType(typ))
    }
}

impl fmt::Display for DhcpMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DhcpMessageType::DHCPDISCOVER => f.write_str("DHCP Discover"),
            DhcpMessageType::DHCPOFFER => f.write_str("DHCP Offer"),
            DhcpMessageType::DHCPREQUEST => f.write_str("DHCP Request"),
            DhcpMessageType::DHCPDECLINE => f.write_str("DHCP Descline"),
            DhcpMessageType::DHCPACK => f.write_str("DHCP ACK"),
            DhcpMessageType::DHCPNAK => f.write_str("DCHP NAK"),
            DhcpMessageType::DHCPRELEASE => f.write_str("DHCP Release"),
            DhcpMessageType::DHCPINFORM => f.write_str("DHCP Inform"),
            DhcpMessageType::Unknown(n) => write!(f, "DHCP Unknown({n})"),
        }
    }
}
