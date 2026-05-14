#![no_main]

use libfuzzer_sys::fuzz_target;
use bytes::BytesMut;
use tokio_util::codec::Decoder;

use zebra_network::protocol::external::Codec;
use zebra_chain::parameters::Network;

fuzz_target!(|data: &[u8]| {
    // Create a codec for mainnet
    let mut codec = Codec::builder()
        .for_network(&Network::Mainnet)
        .finish();
    
    // Try to decode the fuzzed data as a message
    let mut bytes = BytesMut::from(data);
    
    // We don't care about the result, just that it doesn't panic
    let _ = codec.decode(&mut bytes);
    
    // Also try testnet to cover both network magic values
    let mut codec_testnet = Codec::builder()
        .for_network(&Network::Testnet)
        .finish();
    
    let mut bytes_testnet = BytesMut::from(data);
    let _ = codec_testnet.decode(&mut bytes_testnet);
});
