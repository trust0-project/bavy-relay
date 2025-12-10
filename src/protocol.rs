//! Protocol definitions for the P2P WebTransport relay network.
//!
//! Frames are prefixed with a message type byte:
//! - 0x00 = Control message (JSON-encoded)
//! - 0x01 = Ethernet data frame
//!
//! Control messages handle peer registration, IP assignment, and heartbeat.

use serde::{Deserialize, Serialize};

/// Message type prefix bytes
pub const MSG_TYPE_CONTROL: u8 = 0x00;
pub const MSG_TYPE_DATA: u8 = 0x01;
/// Chunked data frame for large packets that exceed QUIC datagram limits
pub const MSG_TYPE_CHUNKED: u8 = 0x02;

/// Maximum safe chunk payload size (leave room for QUIC overhead)
/// QUIC datagrams are typically limited to ~1200 bytes
pub const MAX_CHUNK_PAYLOAD: usize = 900;

/// Threshold for chunking - frames larger than this will be chunked
pub const CHUNK_THRESHOLD: usize = 950;

/// Network configuration constants
pub const GATEWAY_IP: [u8; 4] = [10, 0, 2, 2];
pub const GATEWAY_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
pub const NETWORK_MASK: [u8; 4] = [255, 255, 255, 0];
pub const DNS_SERVER: [u8; 4] = [8, 8, 8, 8];

/// IP pool range for peer assignment
pub const IP_POOL_START: u8 = 10; // 10.0.2.10
pub const IP_POOL_END: u8 = 254; // 10.0.2.254

/// Control messages exchanged between peers and the relay hub.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ControlMessage {
    /// Peer requests registration with its MAC address
    Register { mac: [u8; 6] },

    /// Hub assigns IP configuration to peer
    Assigned {
        ip: [u8; 4],
        gateway: [u8; 4],
        netmask: [u8; 4],
        dns: [u8; 4],
    },

    /// Heartbeat to keep connection alive
    Heartbeat,

    /// Heartbeat acknowledgment
    HeartbeatAck,

    /// Peer disconnecting gracefully
    Disconnect,

    /// Error message from hub
    Error { message: String },

    /// List of connected peers (optional, for discovery)
    PeerList { peers: Vec<PeerInfo> },
}

/// Information about a connected peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub ip: [u8; 4],
    pub mac: [u8; 6],
}

impl ControlMessage {
    /// Encode a control message as a framed datagram (type prefix + JSON)
    pub fn encode(&self) -> Vec<u8> {
        let json = serde_json::to_vec(self).expect("Failed to serialize control message");
        let mut frame = Vec::with_capacity(1 + json.len());
        frame.push(MSG_TYPE_CONTROL);
        frame.extend(json);
        frame
    }

    /// Decode a control message from a framed datagram
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        if data.is_empty() {
            return Err("Empty message".to_string());
        }
        if data[0] != MSG_TYPE_CONTROL {
            return Err(format!("Not a control message (type={})", data[0]));
        }
        serde_json::from_slice(&data[1..])
            .map_err(|e| format!("Failed to parse control message: {}", e))
    }
}

/// Encode an Ethernet frame as a data datagram
pub fn encode_data_frame(ethernet_frame: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(1 + ethernet_frame.len());
    frame.push(MSG_TYPE_DATA);
    frame.extend(ethernet_frame);
    frame
}

/// Helper to format MAC address for display
pub fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Helper to format IP address for display
pub fn format_ip(ip: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

/// Chunked frame header:
/// [MSG_TYPE_CHUNKED] [chunk_id: u16 BE] [chunk_index: u8] [total_chunks: u8] [payload...]
/// Total header size: 5 bytes

/// Encode a large Ethernet frame as multiple chunks
/// Returns a vector of chunk datagrams ready to send
pub fn encode_chunked_frame(ethernet_frame: &[u8], chunk_id: u16) -> Vec<Vec<u8>> {
    let total_chunks = (ethernet_frame.len() + MAX_CHUNK_PAYLOAD - 1) / MAX_CHUNK_PAYLOAD;
    let total_chunks = total_chunks.min(255) as u8; // Cap at 255 chunks
    
    let mut chunks = Vec::new();
    
    for (i, chunk_data) in ethernet_frame.chunks(MAX_CHUNK_PAYLOAD).enumerate() {
        let mut frame = Vec::with_capacity(5 + chunk_data.len());
        frame.push(MSG_TYPE_CHUNKED);
        frame.extend(&chunk_id.to_be_bytes());
        frame.push(i as u8);
        frame.push(total_chunks);
        frame.extend(chunk_data);
        chunks.push(frame);
    }
    
    chunks
}

/// Decoded chunk information
#[derive(Debug, Clone)]
pub struct ChunkInfo {
    pub chunk_id: u16,
    pub chunk_index: u8,
    pub total_chunks: u8,
    pub payload: Vec<u8>,
}

/// Decode a chunked frame header
/// Returns None if the data is too short or malformed
pub fn decode_chunk(data: &[u8]) -> Option<ChunkInfo> {
    if data.len() < 5 {
        return None;
    }
    if data[0] != MSG_TYPE_CHUNKED {
        return None;
    }
    
    let chunk_id = u16::from_be_bytes([data[1], data[2]]);
    let chunk_index = data[3];
    let total_chunks = data[4];
    let payload = data[5..].to_vec();
    
    Some(ChunkInfo {
        chunk_id,
        chunk_index,
        total_chunks,
        payload,
    })
}

/// Smart frame encoder: uses chunking only if needed
/// Returns datagrams ready to send (either single frame or multiple chunks)
pub fn encode_frame_smart(ethernet_frame: &[u8], chunk_id_counter: &mut u16) -> Vec<Vec<u8>> {
    if ethernet_frame.len() <= CHUNK_THRESHOLD {
        // Small frame - send directly
        vec![encode_data_frame(ethernet_frame)]
    } else {
        // Large frame - chunk it
        let id = *chunk_id_counter;
        *chunk_id_counter = chunk_id_counter.wrapping_add(1);
        encode_chunked_frame(ethernet_frame, id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_message_roundtrip() {
        let msg = ControlMessage::Register {
            mac: [0x52, 0x54, 0x00, 0xab, 0xcd, 0xef],
        };
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();

        match decoded {
            ControlMessage::Register { mac } => {
                assert_eq!(mac, [0x52, 0x54, 0x00, 0xab, 0xcd, 0xef]);
            }
            _ => panic!("Wrong message type"),
        }
    }
}
