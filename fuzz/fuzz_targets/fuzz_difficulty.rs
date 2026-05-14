#![no_main]

use libfuzzer_sys::fuzz_target;
use zebra_chain::work::difficulty::CompactDifficulty;

fuzz_target!(|data: &[u8]| {
    // CompactDifficulty is 4 bytes
    if data.len() >= 4 {
        let value = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let compact = CompactDifficulty(value);
        
        // Try to expand to 256-bit difficulty
        let _ = compact.to_expanded();
        
        // Try to convert to work
        let _ = compact.to_work();
        
        // Try round-trip if expansion succeeds
        if let Some(expanded) = compact.to_expanded() {
            let _ = expanded.to_compact();
        }
    }
});
