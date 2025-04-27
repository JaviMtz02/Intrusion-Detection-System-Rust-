// sudo -E RUSTUP_HOME=$HOME/.rustup CARGO_HOME=$HOME/.cargo /home/azureuser/.cargo/bin/cargo run
//use etherparse::{PacketHeaders, TcpHeader, IpHeader};
use log::error;
//use std::net::IpAddr;
use std::process;
use pcap::Device;

mod packet_parser; // file for packet parser
mod detector; // file for intrusion detection
mod logger; // file that logs intrusions

// Project structure:
/*
    main.rs -> Entry point of IDS
    packet_parser.rs -> Handles packet parsing with etherparse library
    detector.rs -> Implements detection logic
    logger.rs -> Manages logging and alerts

    logs -> stores IDS logs
*/

fn get_default_interface() -> Option<String> {
    match Device::list() {
        Ok(devices) => {
            for device in devices {
                if !device.flags.is_loopback() {
                    return Some(device.name);
                }
            }
            None
        }
        Err(e) => {
            log::error!("Failed to list devices: {}", e);
            None
        }
    }
}

fn main() {
    env_logger::init(); // initializes logger for intrusion detecting logging

    println!("Starting packet capture");
    let interface =  match get_default_interface() {
        Some(name) => name,
        None => {
            error!("No network interface found!");
            process::exit(1);
        }
    };
    println!("Capturing packets on interface: {}", interface);

    // Using the packet parser file, the start_packet_capture function is used with the specified interface
    let mut capture = match packet_parser::start_packet_capture(&interface){
        // if no errors, then we can use that packet capture to detect intrusions
        Ok(capture) => capture,
        Err(e) => {
            error!("Failed to start packet capture: {}", e);
            process::exit(1);
        }
    };

    // Loop over the packets
    loop {
        match capture.next_packet() {
            Ok(packet) => {
                match packet_parser::parse_packet(packet.data) {
                    Ok(parsed) => {
                        match detector::detect_intrusion(&parsed) {
                            // This checks all possible outcomes that can happen
                            Ok((true, Some(attack_type), Some(details))) => {
                                logger::log_alert(&parsed, attack_type, Some(details));
                            }
                            Ok((true, Some(_attack_type), None)) => {

                            }
                            Ok((true, None, Some(details))) => {
                                logger::log_alert(&parsed, detector::AttackType::Unknown, Some(details));
                            }
                            Ok((true, None, None)) => {

                            }
                            Ok((false, _, _)) => {
                                // No intrusion detected, do nothing
                            }
                            Err(e) => error!("Detection error: {}", e),
                        }
                    }
                    Err(e) => error!("Parsing failed: {}", e),
                }
            }
            Err(e) => error!("Packet capture error: {}", e),
        }
    }
}
