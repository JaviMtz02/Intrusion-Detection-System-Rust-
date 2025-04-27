use std::net::{Ipv4Addr, Ipv6Addr};
use log::info;
use etherparse::PacketHeaders;
use serde_json::json;
use chrono::Utc;
use crate::detector::AttackType;


pub fn log_alert(headers: &PacketHeaders, attack_type: AttackType, details: Option<String>) {
    let src_ip = match &headers.ip {
        Some(etherparse::IpHeader::Version4(ip, _)) => Ipv4Addr::from(ip.source).to_string(),
        Some(etherparse::IpHeader::Version6(ip, _)) => Ipv6Addr::from(ip.source).to_string(),
        _ => String::from("Unknown"),
    };

    // To customize the log alerts depending on what the attack might be, a specified message is attached with the specific attack type
    let attack_details = match attack_type {
        AttackType::PortScan => details.unwrap_or_else(|| "Detected suspicious activity (multiple connections from the same IP address)".to_string()),
        AttackType::SynFlood => details.unwrap_or_else(|| "Multiple SYN requests without ACK, indicating a potential SYN flood attack".to_string()),
        AttackType::UdpFlood => details.unwrap_or_else(|| "High frequency of UDP packets from the same source IP, indicating a possible UDP flood".to_string()),
        AttackType::SuspiciousTcpFlags => details.unwrap_or_else(|| "Detected suspicious TCP flag combinations (e.g., SYN+FIN, or no flags at all)".to_string()),
        AttackType::TooManyConnectionAttempts => details.unwrap_or_else(|| "Too many connection attempts from the same IP in a short period".to_string()),
        AttackType::Unknown => "Unknown attack detected".to_string(),
    };

    // Build the log entry
    let log_entry = json!({
        "timestamp": Utc::now().to_rfc3339(),
        "src_ip": src_ip,
        "attack_type": format!("{:?}", attack_type),
        "details": attack_details
    });

    // Log the entry to console
    info!("{}", log_entry.to_string());
}
