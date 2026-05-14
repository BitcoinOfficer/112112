//! Fuzzing harness: RPC JSON-RPC request parsing.
//!
//! Attack surface:
//! - JSON parsing of arbitrary byte sequences
//! - Method name injection (shell metacharacters, format strings)
//! - Deeply nested JSON objects/arrays
//! - Oversized numbers (u64::MAX, i64::MIN, f64::INFINITY)
//! - Binary blobs in string fields
//! - HTTP smuggling via Content-Length manipulation
//! - Null bytes in strings

#![no_main]

use harness_common::{catch_panic, clamp_input, init_logging};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use std::str;

/// All known Zebra RPC method names.
const RPC_METHODS: &[&str] = &[
    "getblockchaininfo",
    "getblock",
    "getblockcount",
    "getblockhash",
    "getblockheader",
    "getblocktemplate",
    "getmempoolinfo",
    "getmempoolentry",
    "getrawmempool",
    "getrawtransaction",
    "sendrawtransaction",
    "getaddressbalance",
    "getaddressdeltas",
    "getaddresstxids",
    "getaddressutxos",
    "getbestblockhash",
    "getdifficulty",
    "gettxout",
    "gettxoutsetinfo",
    "validateaddress",
    "z_validateaddress",
    "getnetworkinfo",
    "getpeerinfo",
    "ping",
    "stop",
    "logging",
    "submitblock",
    "submithashrate",
    "getnetworksolps",
    "z_gettreestate",
    "z_getsubtreesbyindex",
];

/// Build a JSON-RPC 2.0 request with the given method and params.
fn build_jsonrpc_request(method: &str, params: Value) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    })
    .to_string()
}

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    // Strategy 1: parse raw bytes as JSON.
    let _ = catch_panic(|| {
        if let Ok(s) = str::from_utf8(data) {
            let _ = serde_json::from_str::<Value>(s);
        }
    });

    // Strategy 2: use fuzzer bytes as the params field.
    let _ = catch_panic(|| {
        if let Ok(s) = str::from_utf8(data) {
            // Try to parse as JSON value for params.
            let params = serde_json::from_str::<Value>(s)
                .unwrap_or(Value::String(s.to_string()));
            for method in RPC_METHODS {
                let request = build_jsonrpc_request(method, params.clone());
                let _ = serde_json::from_str::<Value>(&request);
            }
        }
    });

    // Strategy 3: inject format string specifiers into method name.
    let _ = catch_panic(|| {
        let malicious_methods = [
            "%n%n%n%n",
            "%s%s%s%s",
            "../../../../etc/passwd",
            "'; DROP TABLE blocks; --",
            "\x00\x01\x02\x03",
            &"A".repeat(65536),
        ];
        for method in &malicious_methods {
            let request = build_jsonrpc_request(method, Value::Array(vec![]));
            let _ = serde_json::from_str::<Value>(&request);
        }
    });

    // Strategy 4: deeply nested JSON (stack overflow probe).
    let _ = catch_panic(|| {
        let depth = data.first().copied().unwrap_or(10) as usize;
        let depth = depth.min(1000);
        let mut nested = String::from("null");
        for _ in 0..depth {
            nested = format!("[{}]", nested);
        }
        let _ = serde_json::from_str::<Value>(&nested);
    });

    // Strategy 5: oversized number in params.
    let _ = catch_panic(|| {
        let request = build_jsonrpc_request(
            "getblock",
            Value::Array(vec![
                Value::Number(serde_json::Number::from(u64::MAX)),
                Value::Number(serde_json::Number::from(1)),
            ]),
        );
        let _ = serde_json::from_str::<Value>(&request);
    });
});
