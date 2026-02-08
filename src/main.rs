use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::PathBuf;
use std::time::SystemTime;

use jiff::SignedDuration;
use luomu_libpcap::Packet;
use untrustended::Readable;

use crate::types::{Dhcp, DhcpMessageType, DhcpOption, EthernetHeader, Ipv4Header, UdpHeader};

mod types;

/// Vectorama's ledrama controller sniffer
#[derive(Debug, argh::FromArgs)]
struct Args {
    /// sniff network interface
    #[argh(option, short = 'i', long = "interface")]
    interface: Option<String>,

    /// read packets from pcap file
    #[argh(option, short = 'r', long = "file")]
    file: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args: Args = argh::from_env();
    tracing::debug!("{args:?}");

    let pcap = {
        if let Some(interface) = args.interface {
            let pcap = luomu_libpcap::Pcap::builder(&interface)?
                .set_immediate(true)?
                .set_promiscuous(true)?
                .set_snaplen(65535)?
                .activate()?;
            tracing::debug!("pcap active on interface {interface}");
            pcap
        } else if let Some(pcap_file) = args.file {
            let pcap = luomu_libpcap::Pcap::offline(&pcap_file)?;
            tracing::debug!("pcap active on file {}", pcap_file.display());
            pcap
        } else {
            eprintln!("ERROR: Give either interface (-i) or file (-r) to read from. See --help.");
            std::process::exit(1);
        }
    };

    const PCAP_FILTER: &str = "ip and udp and (port 67 or port 68)";
    pcap.set_filter(PCAP_FILTER)?;
    tracing::debug!("pcap filter: {PCAP_FILTER}");

    for packet in pcap.capture() {
        let _hash = {
            let mut hash = std::hash::DefaultHasher::new();
            packet.packet().hash(&mut hash);
            packet.timestamp().hash(&mut hash);
            let hash_int: u32 = hash.finish() as u32;
            tracing::debug_span!("packet", id = hash_int).entered()
        };

        let Ok(sniffed) = parse(packet.packet()) else {
            tracing::trace!("parse error");
            continue;
        };

        let timestamp = {
            let since_epoch =
                SignedDuration::system_until(SystemTime::UNIX_EPOCH, packet.timestamp())?;
            jiff::Timestamp::from_duration(since_epoch)?
        };

        let mut output = std::io::stdout().lock();

        write!(output, "[{}] ", timestamp.strftime("%T"))?;

        if let Some(typ) = sniffed.dhcp_type() {
            write!(output, "{typ} from ")?;
        } else {
            write!(output, "{} from ", sniffed.dhcp.op)?;
        }

        write!(output, "{} ", sniffed.dhcp.chaddr)?;

        if let Some(hostname) = sniffed.dhcp_hostname() {
            write!(output, "with hostname {hostname}")?;
        }

        writeln!(output)?;
    }

    Ok(())
}

#[derive(Debug)]
#[allow(unused)]
struct SniffedPacket {
    eth: EthernetHeader,
    ip: Ipv4Header,
    udp: UdpHeader,
    dhcp: Dhcp,
}

impl SniffedPacket {
    fn dhcp_type(&self) -> Option<DhcpMessageType> {
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

    fn dhcp_hostname(&self) -> Option<&str> {
        self.dhcp
            .options
            .iter()
            .filter_map(|o| match o {
                DhcpOption::Hostname(name) => Some(name.as_ref()),
                _ => None,
            })
            .next()
    }
}

fn parse(buf: &[u8]) -> Result<SniffedPacket, untrustended::Error> {
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

            // skip padding
            input.skip_to_end();

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
