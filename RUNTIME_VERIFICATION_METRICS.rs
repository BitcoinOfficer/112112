// Runtime Verification Metrics for Zebra Network Attack Surface
//
// This module should be integrated into zebra-network to track suspicious patterns
// and potential attacks in real-time.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

/// Tracks per-peer metrics to detect suspicious behavior
pub struct PeerMetrics {
    /// Per-peer state
    peers: Arc<RwLock<HashMap<SocketAddr, PeerState>>>,
}

/// Per-peer state tracking
#[derive(Clone)]
struct PeerState {
    /// Total messages received from this peer
    total_messages: u64,
    
    /// Messages received in the current second
    messages_this_second: u64,
    
    /// Start of the current second window
    current_second_start: Instant,
    
    /// Total bytes received from this peer
    total_bytes: u64,
    
    /// Bytes received in the current second
    bytes_this_second: u64,
    
    /// Time of last message
    last_message_time: Instant,
    
    /// Count of suspicious patterns detected
    suspicious_patterns: u32,
    
    /// Specific counters for message types
    message_type_counts: HashMap<&'static str, u64>,
}

impl PeerMetrics {
    pub fn new() -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Record a message received from a peer
    pub async fn record_message(
        &self,
        peer: SocketAddr,
        message_type: &'static str,
        byte_size: usize,
    ) -> bool {
        let mut peers = self.peers.write().await;
        let now = Instant::now();
        
        let state = peers.entry(peer).or_insert_with(|| PeerState {
            total_messages: 0,
            messages_this_second: 0,
            current_second_start: now,
            total_bytes: 0,
            bytes_this_second: 0,
            last_message_time: now,
            suspicious_patterns: 0,
            message_type_counts: HashMap::new(),
        });
        
        // Reset per-second counters if we've moved to a new second
        if now.duration_since(state.current_second_start) >= Duration::from_secs(1) {
            state.messages_this_second = 0;
            state.bytes_this_second = 0;
            state.current_second_start = now;
        }
        
        // Update counters
        state.total_messages += 1;
        state.messages_this_second += 1;
        state.total_bytes += byte_size as u64;
        state.bytes_this_second += byte_size as u64;
        state.last_message_time = now;
        
        *state.message_type_counts.entry(message_type).or_insert(0) += 1;
        
        // Check for rate limit violations
        let mut is_suspicious = false;
        
        // Rate limit: max 100 messages per second per peer
        if state.messages_this_second > 100 {
            state.suspicious_patterns += 1;
            is_suspicious = true;
            
            metrics::counter!("zcash.net.peer.rate_limit.messages_exceeded")
                .increment(1);
            
            tracing::warn!(
                peer = %peer,
                messages_this_second = state.messages_this_second,
                "peer exceeded message rate limit"
            );
        }
        
        // Rate limit: max 1MB per second per peer
        if state.bytes_this_second > 1_000_000 {
            state.suspicious_patterns += 1;
            is_suspicious = true;
            
            metrics::counter!("zcash.net.peer.rate_limit.bytes_exceeded")
                .increment(1);
            
            tracing::warn!(
                peer = %peer,
                bytes_this_second = state.bytes_this_second,
                "peer exceeded byte rate limit"
            );
        }
        
        // Pattern detection: repeated identical message types
        if let Some(&count) = state.message_type_counts.get(message_type) {
            // More than 50 of the same message type in a row is suspicious
            if count > 50 && state.total_messages - count < 10 {
                state.suspicious_patterns += 1;
                is_suspicious = true;
                
                metrics::counter!("zcash.net.peer.suspicious.repeated_messages")
                    .increment(1);
                
                tracing::warn!(
                    peer = %peer,
                    message_type,
                    count,
                    "peer sending repeated identical message types"
                );
            }
        }
        
        // Report metrics
        metrics::gauge!("zcash.net.peer.messages_per_second")
            .set(state.messages_this_second as f64);
        
        metrics::gauge!("zcash.net.peer.bytes_per_second")
            .set(state.bytes_this_second as f64);
        
        metrics::counter!("zcash.net.peer.total_messages")
            .increment(1);
        
        metrics::counter!("zcash.net.peer.total_bytes")
            .increment(byte_size as u64);
        
        is_suspicious
    }
    
    /// Check if a peer should be disconnected due to suspicious behavior
    pub async fn should_disconnect(&self, peer: SocketAddr) -> bool {
        let peers = self.peers.read().await;
        
        if let Some(state) = peers.get(&peer) {
            // Disconnect if we've detected multiple suspicious patterns
            if state.suspicious_patterns >= 3 {
                tracing::error!(
                    peer = %peer,
                    suspicious_patterns = state.suspicious_patterns,
                    "disconnecting peer due to repeated suspicious behavior"
                );
                
                metrics::counter!("zcash.net.peer.disconnected.suspicious_behavior")
                    .increment(1);
                
                return true;
            }
        }
        
        false
    }
    
    /// Clean up state for disconnected peers
    pub async fn remove_peer(&self, peer: SocketAddr) {
        let mut peers = self.peers.write().await;
        peers.remove(&peer);
    }
    
    /// Get statistics for all peers
    pub async fn get_stats(&self) -> PeerStats {
        let peers = self.peers.read().await;
        
        let total_peers = peers.len();
        let suspicious_peers = peers.values()
            .filter(|s| s.suspicious_patterns > 0)
            .count();
        
        let total_messages: u64 = peers.values()
            .map(|s| s.total_messages)
            .sum();
        
        let total_bytes: u64 = peers.values()
            .map(|s| s.total_bytes)
            .sum();
        
        PeerStats {
            total_peers,
            suspicious_peers,
            total_messages,
            total_bytes,
        }
    }
}

/// Aggregate statistics across all peers
pub struct PeerStats {
    pub total_peers: usize,
    pub suspicious_peers: usize,
    pub total_messages: u64,
    pub total_bytes: u64,
}

/// Track message processing time to detect CPU exhaustion attacks
pub struct MessageProcessingMetrics {
    /// Histogram of message processing times by type
    processing_times: HashMap<&'static str, Vec<Duration>>,
}

impl MessageProcessingMetrics {
    pub fn new() -> Self {
        Self {
            processing_times: HashMap::new(),
        }
    }
    
    /// Record the time taken to process a message
    pub fn record_processing_time(&mut self, message_type: &'static str, duration: Duration) {
        let times = self.processing_times
            .entry(message_type)
            .or_insert_with(Vec::new);
        
        times.push(duration);
        
        // Keep only recent times (last 1000)
        if times.len() > 1000 {
            times.drain(0..500);
        }
        
        // Calculate p99 processing time
        let mut sorted = times.clone();
        sorted.sort();
        
        if let Some(&p99) = sorted.get((sorted.len() * 99) / 100) {
            metrics::histogram!("zcash.net.message.processing_time.p99")
                .record(p99.as_secs_f64());
            
            // Warn if p99 is unusually high
            if p99 > Duration::from_millis(100) {
                tracing::warn!(
                    message_type,
                    p99_ms = p99.as_millis(),
                    "message processing time p99 exceeds threshold"
                );
                
                metrics::counter!("zcash.net.message.slow_processing")
                    .increment(1);
            }
        }
        
        metrics::histogram!("zcash.net.message.processing_time")
            .record(duration.as_secs_f64());
    }
}

// Example integration into message handler:
//
// async fn handle_message(
//     peer: SocketAddr,
//     message: Message,
//     metrics: &PeerMetrics,
// ) -> Result<(), Error> {
//     let start = Instant::now();
//     let message_type = message.command();
//     let byte_size = estimate_message_size(&message);
//     
//     // Record the message and check for suspicious behavior
//     let is_suspicious = metrics.record_message(peer, message_type, byte_size).await;
//     
//     if is_suspicious && metrics.should_disconnect(peer).await {
//         return Err(Error::SuspiciousPeer);
//     }
//     
//     // Process the message
//     let result = process_message_inner(message).await;
//     
//     // Record processing time
//     let duration = start.elapsed();
//     metrics.record_processing_time(message_type, duration).await;
//     
//     result
// }
