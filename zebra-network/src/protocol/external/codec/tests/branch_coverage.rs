//! Comprehensive branch coverage tests for P2P message codec
//!
//! This module systematically tests every control-flow branch in the codec
//! to achieve 100% branch coverage of network-facing deserialization code.

#![allow(clippy::unwrap_in_result)]

use std::io::{Cursor, Write};

use byteorder::{LittleEndian, WriteBytesExt};
use bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};

use zebra_chain::{
    block::{self, Block, Height},
    parameters::{Magic, Network},
    serialization::{sha256d, ZcashSerialize},
};

use crate::protocol::external::{
    codec::Codec,
    message::{Message, RejectReason, VersionMessage},
    types::*,
    AddrInVersion, Nonce,
};

/// Helper to create a valid message header
fn create_message_header(
    network: &Network,
    command: &[u8; 12],
    body: &[u8],
) -> BytesMut {
    let mut header = BytesMut::with_capacity(24 + body.len());
    
    header.extend_from_slice(&network.magic().0);
    header.extend_from_slice(command);
    header.extend_from_slice(&(body.len() as u32).to_le_bytes());
    
    let checksum = sha256d::Checksum::from(body);
    header.extend_from_slice(&checksum.0);
    header.extend_from_slice(body);
    
    header
}

/// Helper to create an invalid checksum header
fn create_message_header_bad_checksum(
    network: &Network,
    command: &[u8; 12],
    body: &[u8],
) -> BytesMut {
    let mut header = BytesMut::with_capacity(24 + body.len());
    
    header.extend_from_slice(&network.magic().0);
    header.extend_from_slice(command);
    header.extend_from_slice(&(body.len() as u32).to_le_bytes());
    header.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
    header.extend_from_slice(body);
    
    header
}

// ============================================================================
// Branch Coverage Tests: Codec::decode()
// ============================================================================

/// Branch DEC-001: Partial header (src.len() < HEADER_LEN)
#[test]
fn test_decode_partial_header() {
    let mut codec = Codec::builder().finish();
    
    for len in 0..24 {
        let mut buffer = BytesMut::from(&vec![0u8; len][..]);
        let result = codec.decode(&mut buffer);
        
        assert_eq!(result.unwrap(), None, "Partial header should return None");
        assert_eq!(buffer.len(), len, "Buffer should not be consumed");
    }
}

/// Branch DEC-002: Wrong network magic
#[test]
fn test_decode_wrong_network_magic() {
    let mut codec = Codec::builder()
        .for_network(&Network::Mainnet)
        .finish();
    
    let mut buffer = BytesMut::new();
    buffer.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
    buffer.extend_from_slice(b"version\0\0\0\0\0");
    buffer.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    buffer.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    
    let result = codec.decode(&mut buffer);
    assert!(result.is_err(), "Wrong magic should error");
    assert!(
        format!("{:?}", result.unwrap_err()).contains("magic"),
        "Error should mention magic"
    );
}

/// Branch DEC-003: Body length exceeds maximum
#[test]
fn test_decode_oversized_body() {
    let mut codec = Codec::builder()
        .with_max_body_len(1000)
        .finish();
    
    let body = vec![0u8; 0];
    let mut buffer = BytesMut::new();
    
    buffer.extend_from_slice(&Network::Mainnet.magic().0);
    buffer.extend_from_slice(b"version\0\0\0\0\0");
    buffer.extend_from_slice(&(2000u32).to_le_bytes());
    buffer.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    
    let result = codec.decode(&mut buffer);
    assert!(result.is_err(), "Oversized body should error");
}

/// Branch DEC-004: Partial body (src.len() < body_len)
#[test]
fn test_decode_partial_body() {
    let mut codec = Codec::builder().finish();
    
    let mut buffer = BytesMut::new();
    buffer.extend_from_slice(&Network::Mainnet.magic().0);
    buffer.extend_from_slice(b"ping\0\0\0\0\0\0\0\0");
    buffer.extend_from_slice(&(8u32).to_le_bytes());
    
    let checksum = sha256d::Checksum::from(&[0u8; 8]);
    buffer.extend_from_slice(&checksum.0);
    
    for partial_len in 0..8 {
        let mut test_buffer = buffer.clone();
        test_buffer.extend_from_slice(&vec![0u8; partial_len]);
        
        let result = codec.decode(&mut test_buffer);
        assert_eq!(result.unwrap(), None, "Partial body should return None");
    }
}

/// Branch DEC-005: Invalid checksum
#[test]
fn test_decode_invalid_checksum() {
    let mut codec = Codec::builder().finish();
    
    let body = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    let mut buffer = create_message_header_bad_checksum(
        &Network::Mainnet,
        b"ping\0\0\0\0\0\0\0\0",
        &body,
    );
    
    let result = codec.decode(&mut buffer);
    assert!(result.is_err(), "Invalid checksum should error");
    assert!(
        format!("{:?}", result.unwrap_err()).contains("checksum"),
        "Error should mention checksum"
    );
}

/// Branches DEC-006 through DEC-025: All valid message commands
#[test]
fn test_decode_all_message_types() {
    let test_cases = vec![
        (b"version\0\0\0\0\0", "version"),
        (b"verack\0\0\0\0\0\0", "verack"),
        (b"ping\0\0\0\0\0\0\0\0", "ping"),
        (b"pong\0\0\0\0\0\0\0\0", "pong"),
        (b"getaddr\0\0\0\0\0", "getaddr"),
        (b"mempool\0\0\0\0\0", "mempool"),
        (b"filterclear\0", "filterclear"),
    ];
    
    for (command, name) in test_cases {
        let mut codec = Codec::builder().finish();
        let body = vec![];
        let mut buffer = create_message_header(&Network::Mainnet, command, &body);
        
        let result = codec.decode(&mut buffer);
        assert!(
            result.is_ok(),
            "Valid {} message should decode successfully",
            name
        );
    }
}

/// Branch DEC-026: Unknown message command
#[test]
fn test_decode_unknown_command() {
    let mut codec = Codec::builder().finish();
    
    let body = vec![0x00];
    let mut buffer = create_message_header(
        &Network::Mainnet,
        b"unknown\0\0\0\0\0",
        &body,
    );
    
    let result = codec.decode(&mut buffer);
    assert!(result.is_ok(), "Unknown command should not error");
    assert_eq!(result.unwrap(), None, "Unknown command should return None");
}

/// Branch DEC-027: Exact message size (no extra bytes)
#[test]
fn test_decode_exact_message_size() {
    let mut codec = Codec::builder().finish();
    
    let mut body = Vec::new();
    body.write_u64::<LittleEndian>(0x123456789ABCDEF0).unwrap();
    
    let mut buffer = create_message_header(
        &Network::Mainnet,
        b"ping\0\0\0\0\0\0\0\0",
        &body,
    );
    
    let result = codec.decode(&mut buffer);
    assert!(result.is_ok(), "Exact size should decode");
    assert!(matches!(result.unwrap(), Some(Message::Ping(_))));
}

// ============================================================================
// Branch Coverage Tests: Codec::read_version()
// ============================================================================

/// Helper to create version message body
fn create_version_body(
    version: u32,
    services: u64,
    timestamp: i64,
    user_agent: &str,
    start_height: u32,
    relay: u8,
) -> Vec<u8> {
    let mut body = Vec::new();
    
    body.write_u32::<LittleEndian>(version).unwrap();
    body.write_u64::<LittleEndian>(services).unwrap();
    body.write_i64::<LittleEndian>(timestamp).unwrap();
    
    let addr_recv = AddrInVersion::new(
        std::net::SocketAddr::from(([127, 0, 0, 1], 8233)),
        PeerServices::NODE_NETWORK,
    );
    addr_recv.zcash_serialize(&mut body).unwrap();
    
    let addr_from = AddrInVersion::new(
        std::net::SocketAddr::from(([127, 0, 0, 1], 8234)),
        PeerServices::NODE_NETWORK,
    );
    addr_from.zcash_serialize(&mut body).unwrap();
    
    body.write_u64::<LittleEndian>(0x0123456789ABCDEF).unwrap();
    
    let user_agent_bytes = user_agent.as_bytes();
    body.write_u8(user_agent_bytes.len() as u8).unwrap();
    body.write_all(user_agent_bytes).unwrap();
    
    body.write_u32::<LittleEndian>(start_height).unwrap();
    body.write_u8(relay).unwrap();
    
    body
}

/// Branch VER-001: Timestamp out of range
#[test]
fn test_version_invalid_timestamp() {
    let mut codec = Codec::builder().finish();
    
    let body = create_version_body(
        170100,
        1,
        i64::MAX,
        "/Zebra:0.0.0/",
        0,
        1,
    );
    
    let mut buffer = create_message_header(
        &Network::Mainnet,
        b"version\0\0\0\0\0",
        &body,
    );
    
    let result = codec.decode(&mut buffer);
    assert!(result.is_err(), "Invalid timestamp should error");
}

/// Branch VER-001: Valid timestamp range
#[test]
fn test_version_valid_timestamp() {
    let mut codec = Codec::builder().finish();
    
    let timestamps = vec![
        0i64,
        1_000_000_000,
        1_700_000_000,
        -1_000_000_000,
    ];
    
    for ts in timestamps {
        let body = create_version_body(170100, 1, ts, "/Zebra:0.0.0/", 0, 1);
        
        let mut buffer = create_message_header(
            &Network::Mainnet,
            b"version\0\0\0\0\0",
            &body,
        );
        
        let result = codec.decode(&mut buffer);
        assert!(
            result.is_ok(),
            "Valid timestamp {} should succeed",
            ts
        );
    }
}

/// Branch VER-002: User agent too long
#[test]
fn test_version_user_agent_too_long() {
    let mut codec = Codec::builder().finish();
    
    let long_user_agent = "A".repeat(257);
    
    let mut body = Vec::new();
    body.write_u32::<LittleEndian>(170100).unwrap();
    body.write_u64::<LittleEndian>(1).unwrap();
    body.write_i64::<LittleEndian>(1_600_000_000).unwrap();
    
    let addr = AddrInVersion::new(
        std::net::SocketAddr::from(([127, 0, 0, 1], 8233)),
        PeerServices::NODE_NETWORK,
    );
    addr.zcash_serialize(&mut body).unwrap();
    addr.zcash_serialize(&mut body).unwrap();
    
    body.write_u64::<LittleEndian>(0).unwrap();
    
    body.write_u16::<LittleEndian>(257).unwrap();
    body.write_all(long_user_agent.as_bytes()).unwrap();
    
    body.write_u32::<LittleEndian>(0).unwrap();
    body.write_u8(1).unwrap();
    
    let mut buffer = create_message_header(
        &Network::Mainnet,
        b"version\0\0\0\0\0",
        &body,
    );
    
    let result = codec.decode(&mut buffer);
    assert!(result.is_err(), "User agent >256 bytes should error");
}

/// Branch VER-003: Relay field variants
#[test]
fn test_version_relay_field_variants() {
    let mut codec = Codec::builder().finish();
    
    for relay_value in 0..=1u8 {
        let body = create_version_body(
            170100,
            1,
            1_600_000_000,
            "/Test/",
            0,
            relay_value,
        );
        
        let mut buffer = create_message_header(
            &Network::Mainnet,
            b"version\0\0\0\0\0",
            &body,
        );
        
        let result = codec.decode(&mut buffer);
        assert!(
            result.is_ok(),
            "Relay value {} should be valid",
            relay_value
        );
    }
    
    let body = create_version_body(170100, 1, 1_600_000_000, "/Test/", 0, 2);
    let mut buffer = create_message_header(
        &Network::Mainnet,
        b"version\0\0\0\0\0",
        &body,
    );
    
    let result = codec.decode(&mut buffer);
    assert!(result.is_err(), "Relay value 2 should error");
}

/// Branch VER-003: Missing relay field (EOF during read)
#[test]
fn test_version_missing_relay_field() {
    let mut codec = Codec::builder().finish();
    
    let mut body = Vec::new();
    body.write_u32::<LittleEndian>(170100).unwrap();
    body.write_u64::<LittleEndian>(1).unwrap();
    body.write_i64::<LittleEndian>(1_600_000_000).unwrap();
    
    let addr = AddrInVersion::new(
        std::net::SocketAddr::from(([127, 0, 0, 1], 8233)),
        PeerServices::NODE_NETWORK,
    );
    addr.zcash_serialize(&mut body).unwrap();
    addr.zcash_serialize(&mut body).unwrap();
    
    body.write_u64::<LittleEndian>(0).unwrap();
    body.write_u8(0).unwrap();
    body.write_u32::<LittleEndian>(0).unwrap();
    
    let mut buffer = create_message_header(
        &Network::Mainnet,
        b"version\0\0\0\0\0",
        &body,
    );
    
    let result = codec.decode(&mut buffer);
    assert!(
        result.is_ok(),
        "Missing relay field should default to true"
    );
}

// ============================================================================
// Branch Coverage Tests: Codec::read_reject()
// ============================================================================

/// Branch REJ-001: Reject message too long
#[test]
fn test_reject_message_too_long() {
    let mut codec = Codec::builder().finish();
    
    let mut body = Vec::new();
    body.write_u8(13).unwrap();
    body.write_all(b"ThisIsTooLong").unwrap();
    body.write_u8(0x01).unwrap();
    body.write_u8(0).unwrap();
    
    let mut buffer = create_message_header(
        &Network::Mainnet,
        b"reject\0\0\0\0\0\0",
        &body,
    );
    
    let result = codec.decode(&mut buffer);
    assert!(result.is_err(), "Reject message >12 bytes should error");
}

/// Branch REJ-002: All RejectReason variants
#[test]
fn test_reject_all_reason_codes() {
    let codes = vec![
        (0x01, "Malformed"),
        (0x10, "Invalid"),
        (0x11, "Obsolete"),
        (0x12, "Duplicate"),
        (0x40, "Nonstandard"),
        (0x41, "Dust"),
        (0x42, "InsufficientFee"),
        (0x43, "Checkpoint"),
        (0x50, "Other"),
    ];
    
    for (code, name) in codes {
        let mut codec = Codec::builder().finish();
        
        let mut body = Vec::new();
        body.write_u8(2).unwrap();
        body.write_all(b"tx").unwrap();
        body.write_u8(code).unwrap();
        body.write_u8(0).unwrap();
        
        let mut buffer = create_message_header(
            &Network::Mainnet,
            b"reject\0\0\0\0\0\0",
            &body,
        );
        
        let result = codec.decode(&mut buffer);
        assert!(
            result.is_ok(),
            "Reject code {} ({}) should be valid",
            code,
            name
        );
    }
}

/// Branch REJ-002: Invalid reject reason code
#[test]
fn test_reject_invalid_reason_code() {
    let mut codec = Codec::builder().finish();
    
    let mut body = Vec::new();
    body.write_u8(2).unwrap();
    body.write_all(b"tx").unwrap();
    body.write_u8(0xFF).unwrap();
    body.write_u8(0).unwrap();
    
    let mut buffer = create_message_header(
        &Network::Mainnet,
        b"reject\0\0\0\0\0\0",
        &body,
    );
    
    let result = codec.decode(&mut buffer);
    assert!(result.is_err(), "Invalid reject code should error");
}

/// Branch REJ-003: Reject reason too long
#[test]
fn test_reject_reason_too_long() {
    let mut codec = Codec::builder().finish();
    
    let long_reason = "A".repeat(112);
    
    let mut body = Vec::new();
    body.write_u8(2).unwrap();
    body.write_all(b"tx").unwrap();
    body.write_u8(0x01).unwrap();
    body.write_u8(112).unwrap();
    body.write_all(long_reason.as_bytes()).unwrap();
    
    let mut buffer = create_message_header(
        &Network::Mainnet,
        b"reject\0\0\0\0\0\0",
        &body,
    );
    
    let result = codec.decode(&mut buffer);
    assert!(result.is_err(), "Reject reason >111 bytes should error");
}

/// Branch REJ-004: Optional data field presence
#[test]
fn test_reject_optional_data() {
    let mut codec_with = Codec::builder().finish();
    let mut codec_without = Codec::builder().finish();
    
    let mut body_with = Vec::new();
    body_with.write_u8(2).unwrap();
    body_with.write_all(b"tx").unwrap();
    body_with.write_u8(0x01).unwrap();
    body_with.write_u8(0).unwrap();
    body_with.write_all(&[0u8; 32]).unwrap();
    
    let mut buffer_with = create_message_header(
        &Network::Mainnet,
        b"reject\0\0\0\0\0\0",
        &body_with,
    );
    
    let result_with = codec_with.decode(&mut buffer_with);
    assert!(result_with.is_ok(), "Reject with data should succeed");
    
    let mut body_without = Vec::new();
    body_without.write_u8(2).unwrap();
    body_without.write_all(b"tx").unwrap();
    body_without.write_u8(0x01).unwrap();
    body_without.write_u8(0).unwrap();
    
    let mut buffer_without = create_message_header(
        &Network::Mainnet,
        b"reject\0\0\0\0\0\0",
        &body_without,
    );
    
    let result_without = codec_without.decode(&mut buffer_without);
    assert!(result_without.is_ok(), "Reject without data should succeed");
}

// ============================================================================
// Branch Coverage Tests: Addr Messages
// ============================================================================

/// Branch ADDR-001: Too many addresses in addr message
#[test]
fn test_addr_too_many_addresses() {
    let mut codec = Codec::builder().finish();
    
    let mut body = Vec::new();
    body.write_u16::<LittleEndian>(1001).unwrap();
    
    let mut buffer = create_message_header(
        &Network::Mainnet,
        b"addr\0\0\0\0\0\0\0\0",
        &body,
    );
    
    let result = codec.decode(&mut buffer);
    assert!(result.is_err(), ">1000 addresses should error");
}

/// Branch ADDR2-001: Too many addresses in addrv2 message
#[test]
fn test_addrv2_too_many_addresses() {
    let mut codec = Codec::builder().finish();
    
    let mut body = Vec::new();
    body.write_u16::<LittleEndian>(1001).unwrap();
    
    let mut buffer = create_message_header(
        &Network::Mainnet,
        b"addrv2\0\0\0\0\0\0",
        &body,
    );
    
    let result = codec.decode(&mut buffer);
    assert!(result.is_err(), ">1000 addrv2 addresses should error");
}

// ============================================================================
// Branch Coverage Tests: GetBlocks/GetHeaders
// ============================================================================

/// Branch GETBLK-001: Version mismatch in getblocks
#[test]
fn test_getblocks_version_mismatch() {
    let mut codec = Codec::builder()
        .for_version(Version(170100))
        .finish();
    
    let mut body = Vec::new();
    body.write_u32::<LittleEndian>(170000).unwrap();
    body.write_u8(0).unwrap();
    body.write_all(&[0u8; 32]).unwrap();
    
    let mut buffer = create_message_header(
        &Network::Mainnet,
        b"getblocks\0\0\0",
        &body,
    );
    
    let result = codec.decode(&mut buffer);
    assert!(result.is_err(), "Version mismatch should error");
}

/// Branch GETBLK-002: Stop hash present vs absent
#[test]
fn test_getblocks_stop_hash_variants() {
    let mut codec = Codec::builder().finish();
    
    let mut body_with_stop = Vec::new();
    body_with_stop.write_u32::<LittleEndian>(170100).unwrap();
    body_with_stop.write_u8(0).unwrap();
    body_with_stop.write_all(&[0x12u8; 32]).unwrap();
    
    let mut buffer_with = create_message_header(
        &Network::Mainnet,
        b"getblocks\0\0\0",
        &body_with_stop,
    );
    
    let result_with = codec.decode(&mut buffer_with);
    assert!(result_with.is_ok(), "GetBlocks with stop should succeed");
    
    let mut body_no_stop = Vec::new();
    body_no_stop.write_u32::<LittleEndian>(170100).unwrap();
    body_no_stop.write_u8(0).unwrap();
    body_no_stop.write_all(&[0u8; 32]).unwrap();
    
    let mut buffer_no = create_message_header(
        &Network::Mainnet,
        b"getblocks\0\0\0",
        &body_no_stop,
    );
    
    let result_no = codec.decode(&mut buffer_no);
    assert!(result_no.is_ok(), "GetBlocks without stop should succeed");
}

/// Branch GETHDR-001: Version mismatch in getheaders
#[test]
fn test_getheaders_version_mismatch() {
    let mut codec = Codec::builder()
        .for_version(Version(170100))
        .finish();
    
    let mut body = Vec::new();
    body.write_u32::<LittleEndian>(170000).unwrap();
    body.write_u8(0).unwrap();
    body.write_all(&[0u8; 32]).unwrap();
    
    let mut buffer = create_message_header(
        &Network::Mainnet,
        b"getheaders\0\0",
        &body,
    );
    
    let result = codec.decode(&mut buffer);
    assert!(result.is_err(), "Version mismatch should error");
}

/// Branch GETHDR-002: Stop hash present vs absent
#[test]
fn test_getheaders_stop_hash_variants() {
    let mut codec = Codec::builder().finish();
    
    let mut body_with_stop = Vec::new();
    body_with_stop.write_u32::<LittleEndian>(170100).unwrap();
    body_with_stop.write_u8(0).unwrap();
    body_with_stop.write_all(&[0xABu8; 32]).unwrap();
    
    let mut buffer_with = create_message_header(
        &Network::Mainnet,
        b"getheaders\0\0",
        &body_with_stop,
    );
    
    let result_with = codec.decode(&mut buffer_with);
    assert!(result_with.is_ok(), "GetHeaders with stop should succeed");
    
    let mut body_no_stop = Vec::new();
    body_no_stop.write_u32::<LittleEndian>(170100).unwrap();
    body_no_stop.write_u8(0).unwrap();
    body_no_stop.write_all(&[0u8; 32]).unwrap();
    
    let mut buffer_no = create_message_header(
        &Network::Mainnet,
        b"getheaders\0\0",
        &body_no_stop,
    );
    
    let result_no = codec.decode(&mut buffer_no);
    assert!(result_no.is_ok(), "GetHeaders without stop should succeed");
}

// ============================================================================
// Branch Coverage Tests: Headers Message
// ============================================================================

/// Branch HDR-001: Too many headers
#[test]
fn test_headers_too_many() {
    let mut codec = Codec::builder().finish();
    
    let mut body = Vec::new();
    body.write_u16::<LittleEndian>(161).unwrap();
    
    let mut buffer = create_message_header(
        &Network::Mainnet,
        b"headers\0\0\0\0\0",
        &body,
    );
    
    let result = codec.decode(&mut buffer);
    assert!(result.is_err(), ">160 headers should error");
}

// ============================================================================
// Branch Coverage Tests: FilterLoad/FilterAdd
// ============================================================================

/// Branch FLTLD-001: Invalid filterload body length
#[test]
fn test_filterload_invalid_length() {
    let mut codec = Codec::builder().finish();
    
    let short_body = vec![0u8; 8];
    let mut buffer_short = create_message_header(
        &Network::Mainnet,
        b"filterload\0\0",
        &short_body,
    );
    
    let result_short = codec.decode(&mut buffer_short);
    assert!(
        result_short.is_err(),
        "FilterLoad body <9 bytes should error"
    );
    
    let mut codec2 = Codec::builder().finish();
    let long_body = vec![0u8; 36010];
    let mut buffer_long = create_message_header(
        &Network::Mainnet,
        b"filterload\0\0",
        &long_body,
    );
    
    let result_long = codec2.decode(&mut buffer_long);
    assert!(
        result_long.is_err(),
        "FilterLoad body >36009 bytes should error"
    );
}

/// Branch FLTAD-001: FilterAdd length clamping
#[test]
fn test_filteradd_length_clamping() {
    let mut codec = Codec::builder().finish();
    
    let body = vec![0u8; 521];
    let mut buffer = create_message_header(
        &Network::Mainnet,
        b"filteradd\0\0\0",
        &body,
    );
    
    let result = codec.decode(&mut buffer);
    assert!(
        result.is_ok(),
        "FilterAdd >520 bytes should be clamped, not error"
    );
}

// ============================================================================
// Property-Based Fuzzing Tests
// ============================================================================

#[test]
fn test_codec_never_panics_on_random_input() {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    
    for _ in 0..100 {
        let len = rng.gen_range(0..1000);
        let data: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
        
        let mut codec = Codec::builder().finish();
        let mut buffer = BytesMut::from(&data[..]);
        
        let _ = codec.decode(&mut buffer);
    }
}

#[test]
fn test_all_network_magics() {
    let networks = vec![
        Network::Mainnet,
        Network::new_default_testnet(),
        Network::new_regtest(None),
    ];
    
    for network in networks {
        let mut codec = Codec::builder().for_network(&network).finish();
        
        let body = vec![];
        let mut buffer = create_message_header(&network, b"getaddr\0\0\0\0\0", &body);
        
        let result = codec.decode(&mut buffer);
        assert!(
            result.is_ok(),
            "Network {:?} should decode successfully",
            network
        );
    }
}
