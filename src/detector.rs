use etherparse::{PacketHeaders, IpHeader};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

// Using a lazy static to create the hashmaps at runtime!
lazy_static::lazy_static! {
    static ref CONNECTION_ATTEMPTS: Arc<Mutex<HashMap<Ipv4Addr, i32>>> = Arc::new(Mutex::new(HashMap::new()));
    static ref SYN_FLOOD_ATTEMPTS: Arc<Mutex<HashMap<Ipv4Addr, i32>>> = Arc::new(Mutex::new(HashMap::new()));
    static ref PORT_SCAN_ATTEMPTS: Arc<Mutex<HashMap<Ipv4Addr, HashSet<u16>>>> = Arc::new(Mutex::new(HashMap::new()));
    static ref UDP_VOLUME_TRACKER: Arc<Mutex<HashMap<Ipv4Addr, (i32, Instant)>>> = Arc::new(Mutex::new(HashMap::new()));
}

// Enum that will be used across files to specify the attack type, this is super useful for the logger.rs file
#[derive(Debug)]
pub enum AttackType {
    TooManyConnectionAttempts,
    SynFlood,
    PortScan,
    SuspiciousTcpFlags,
    UdpFlood,
    Unknown,
}

pub fn detect_intrusion(headers: &PacketHeaders) -> Result<(bool, Option<AttackType>, Option<String>), String> {
    if let Some(IpHeader::Version4(ip, _)) = &headers.ip {
        let src_ip = Ipv4Addr::from(ip.source);

        // TCP detection
        if let Some(etherparse::TransportHeader::Tcp(tcp)) = &headers.transport {
            // === 1. Basic connection attempt counting ===
            let mut attempts = CONNECTION_ATTEMPTS
                .lock()
                .map_err(|e| format!("Mutex error: {}", e))?;
            let count = attempts.entry(src_ip).or_insert(0);
            *count += 1;
            if *count > 100 {
                return Ok((true, Some(AttackType::TooManyConnectionAttempts), 
                    Some("Too many TCP connection attempts from the same IP.".to_string())));
            }

            // === 2. SYN Flood Detection ===
            if tcp.syn && !tcp.ack {
                let mut syn_attempts = SYN_FLOOD_ATTEMPTS
                    .lock()
                    .map_err(|e| format!("Mutex error: {}", e))?;
                let syn_count = syn_attempts.entry(src_ip).or_insert(0);
                *syn_count += 1;
                if *syn_count > 100 {
                    return Ok((true, Some(AttackType::SynFlood), 
                        Some("Potential SYN flood detected.".to_string())));
                }
            }

            // === 3. Port Scan Detection ===
            let mut scan_attempts = PORT_SCAN_ATTEMPTS
                .lock()
                .map_err(|e| format!("Mutex error: {}", e))?;
            let ports = scan_attempts.entry(src_ip).or_insert_with(HashSet::new);
            ports.insert(tcp.destination_port);
            if ports.len() > 20 {
                return Ok((true, Some(AttackType::PortScan), 
                    Some("Too many unique destination ports (port scan) from the same IP.".to_string())));
            }

            // === 4. Suspicious TCP Flag Combinations ===
            if tcp.syn && tcp.fin {
                return Ok((true, Some(AttackType::SuspiciousTcpFlags), 
                    Some("SYN+FIN flags detected, likely malicious.".to_string())));
            }
            if !tcp.syn && !tcp.ack && !tcp.fin && !tcp.rst && !tcp.psh && !tcp.urg {
                return Ok((true, Some(AttackType::SuspiciousTcpFlags), 
                    Some("Packet with no flags at all, likely suspicious.".to_string())));
            }
        }

        // UDP detection (basic rate-based)
        if let Some(etherparse::TransportHeader::Udp(_udp)) = &headers.transport {
            let mut udp_tracker = UDP_VOLUME_TRACKER
                .lock()
                .map_err(|e| format!("Mutex error: {}", e))?;
            let entry = udp_tracker.entry(src_ip).or_insert((0, Instant::now()));
            let elapsed = entry.1.elapsed();

            if elapsed > Duration::from_secs(5) {
                // Reset counter after 5 seconds
                *entry = (1, Instant::now());
            } else {
                entry.0 += 1;
                if entry.0 > 200 {
                    return Ok((true, Some(AttackType::UdpFlood), 
                        Some("Potential UDP flood detected.".to_string())));
                }
            }
        }
    }

    Ok((false, None, None)) // No intrusion detected
}
