use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::PathBuf;
use std::time::SystemTime;

use jiff::SignedDuration;
use ledrama_sniffer::types::{DhcpMessageType, DhcpOp};
use luomu_libpcap::Packet;

const PCAP_FILTER: &str = "ip and udp and (port 67 or port 68)";

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

    pcap.set_filter(PCAP_FILTER)?;
    tracing::debug!("pcap filter: {PCAP_FILTER}");

    for packet in pcap.capture() {
        let _hash = {
            let mut hash = std::hash::DefaultHasher::new();
            packet.packet().hash(&mut hash);
            packet.timestamp().hash(&mut hash);
            let hash_int = hash.finish();
            tracing::debug_span!("packet", id = hash_int).entered()
        };

        let sniffed = match ledrama_sniffer::parse(packet.packet()) {
            Ok(k) => k,
            Err(err) => {
                tracing::debug!("ERROR: parse error: {err:?}");
                continue;
            }
        };

        let timestamp = {
            let since_epoch =
                SignedDuration::system_until(SystemTime::UNIX_EPOCH, packet.timestamp())?;
            jiff::Timestamp::from_duration(since_epoch)?
        };

        let mut output = std::io::stdout().lock();

        write!(output, "[{}] ", timestamp.strftime("%T"))?;

        if let Some(typ) = sniffed.dhcp_type() {
            match typ {
                DhcpMessageType::DHCPDISCOVER
                | DhcpMessageType::DHCPINFORM
                | DhcpMessageType::DHCPRELEASE
                | DhcpMessageType::DHCPREQUEST => write!(output, "{typ} from ")?,
                DhcpMessageType::DHCPACK
                | DhcpMessageType::DHCPDECLINE
                | DhcpMessageType::DHCPNAK
                | DhcpMessageType::DHCPOFFER => write!(output, "{typ} for ")?,
                DhcpMessageType::Unknown(_) => unreachable!("we shouldn't be here"),
            }
        } else {
            match sniffed.dhcp.op {
                DhcpOp::BOOTREPLY => write!(output, "{} for ", sniffed.dhcp.op)?,
                DhcpOp::BOOTREQUEST => write!(output, "{} from ", sniffed.dhcp.op)?,
                DhcpOp::Unknown(_) => write!(output, "{} for/from ", sniffed.dhcp.op)?,
            }
        }

        write!(output, "{} ", sniffed.dhcp.chaddr)?;

        if let Some(ip) = sniffed.dhcp_client_ip() {
            write!(output, "client ip {ip} ")?;
        }

        if let Some(hostname) = sniffed.dhcp_hostname() {
            write!(output, "hostname {hostname} ")?;
        }

        if let Some(class_id) = sniffed.dhcp_vendor_class_id() {
            write!(output, "vendor class id {class_id}")?;
        }

        writeln!(output)?;
    }

    Ok(())
}
