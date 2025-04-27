use etherparse::PacketHeaders;
use pcap::{Device, Capture, Active};  // You can use this or pnet if you want packet capture

pub fn start_packet_capture(interface: &str) -> Result<Capture<Active>, String>{
    let devices = Device::list()
    .map_err(|e| format!("Failed to list devices: {}", e))?;

// Find matching interface
let device = devices.into_iter()
    .find(|d| d.name == interface)
    .ok_or_else(|| format!("Interface '{}' not found", interface))?;

// Create and activate capture
Capture::from_device(device)
    .map_err(|e| e.to_string())?
    .open()
    .map_err(|e| e.to_string())
}

pub fn parse_packet(packet: &[u8]) -> Result<PacketHeaders, String> {
    match PacketHeaders::from_ethernet_slice(packet){
        Ok(headers) => Ok(headers),
        Err(e) => Err(format!("Failed to parse packet: {}", e)),
    }
}