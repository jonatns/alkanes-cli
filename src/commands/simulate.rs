use anyhow::{Context, Result};
use clap::Args;
use reqwest::Client;
use serde_json::json;

#[derive(Args)]
pub struct SimulateArgs {
    /// Target Alkane ID (format: block:tx, e.g., "2:1")
    #[arg(short, long)]
    pub target: String,

    /// Inputs/calldata (comma-separated). Numbers are passed as-is, text is encoded as strings.
    /// Example: "1,Alice" for opcode 1 with string arg "Alice"
    /// Example: "77" for just opcode 77
    /// Example: "1,100,200" for opcode 1 with numeric args
    #[arg(short, long, value_delimiter = ',')]
    pub inputs: Vec<String>,

    /// Alkane tokens to include (format: block:tx:amount, comma-separated)
    /// Example: "2:1:1000,2:2:500"
    #[arg(short, long, value_delimiter = ',')]
    pub alkanes: Option<Vec<String>>,

    /// RPC URL for Alkanes indexer
    #[arg(long, default_value = "http://127.0.0.1:18888")]
    pub rpc_url: String,

    /// RPC User
    #[arg(long, default_value = "user")]
    pub rpc_user: String,

    /// RPC Password
    #[arg(long, default_value = "password")]
    pub rpc_password: String,

    /// Output raw JSON response
    #[arg(long, default_value_t = false)]
    pub raw: bool,
}

/// Encode a string as null-terminated u128 values (little-endian)
/// This matches how alkanes-runtime decodes strings
fn encode_string_as_u128s(s: &str) -> Vec<u128> {
    let mut bytes: Vec<u8> = s.as_bytes().to_vec();
    bytes.push(0); // null terminator

    let mut result = Vec::new();

    // Pack bytes into u128 values (16 bytes each)
    for chunk in bytes.chunks(16) {
        let mut arr = [0u8; 16];
        arr[..chunk.len()].copy_from_slice(chunk);
        let value = u128::from_le_bytes(arr);
        result.push(value);
    }

    result
}

/// Parse an input value - if it's a valid number, return it as u128
/// Otherwise, encode it as a string (null-terminated u128 values)
fn parse_input(input: &str) -> Vec<u128> {
    // Try to parse as number first
    if let Ok(num) = input.parse::<u128>() {
        return vec![num];
    }

    // Otherwise treat as string
    encode_string_as_u128s(input)
}

/// Decode return data and display in multiple formats
fn decode_return_data(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }

    // Try as u128 (16 bytes, little-endian)
    if bytes.len() == 16 {
        let arr: [u8; 16] = bytes.try_into().unwrap();
        let value = u128::from_le_bytes(arr);
        println!("   As u128: {}", value);
    }

    // Try as u64 (8 bytes, little-endian) 
    if bytes.len() >= 8 {
        let arr: [u8; 8] = bytes[..8].try_into().unwrap();
        let value = u64::from_le_bytes(arr);
        if bytes.len() == 8 || (bytes.len() > 8 && bytes[8..].iter().all(|&b| b == 0)) {
            println!("   As u64: {}", value);
        }
    }

    // Try as u32 (4 bytes, little-endian)
    if bytes.len() >= 4 {
        let arr: [u8; 4] = bytes[..4].try_into().unwrap();
        let value = u32::from_le_bytes(arr);
        if bytes.len() == 4 || (bytes.len() > 4 && bytes[4..].iter().all(|&b| b == 0)) {
            println!("   As u32: {}", value);
        }
    }

    // Try as UTF-8 string (filter out null bytes for display)
    let clean_bytes: Vec<u8> = bytes.iter().cloned().take_while(|&b| b != 0).collect();
    if !clean_bytes.is_empty() {
        if let Ok(s) = String::from_utf8(clean_bytes.clone()) {
            if s.chars().all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()) {
                println!("   As String: \"{}\"", s);
            }
        }
    }

    // Try as AlkaneId (two u128s = 32 bytes)
    if bytes.len() == 32 {
        let block = u128::from_le_bytes(bytes[..16].try_into().unwrap());
        let tx = u128::from_le_bytes(bytes[16..32].try_into().unwrap());
        println!("   As AlkaneId: [{}, {}]", block, tx);
    }

    // Try as bool
    if bytes.len() >= 1 {
        if bytes[0] == 0 && bytes[1..].iter().all(|&b| b == 0) {
            println!("   As bool: false");
        } else if bytes[0] == 1 && bytes[1..].iter().all(|&b| b == 0) {
            println!("   As bool: true");
        }
    }

    // Show raw bytes if small enough
    if bytes.len() <= 64 {
        println!("   Raw bytes: {:?}", bytes);
    } else {
        println!("   Raw bytes: [{} bytes]", bytes.len());
    }
}

pub async fn run(args: SimulateArgs) -> Result<()> {
    // Parse target
    let parts: Vec<&str> = args.target.split(':').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid target format. Expected block:tx (e.g., '2:1')");
    }
    let target_block = parts[0];
    let target_tx = parts[1];

    // Build full inputs: parse each input as number or string
    let all_inputs: Vec<String> = args
        .inputs
        .iter()
        .flat_map(|input| parse_input(input))
        .map(|v| v.to_string())
        .collect();

    // Parse alkanes if provided
    let alkanes: Vec<serde_json::Value> = args
        .alkanes
        .unwrap_or_default()
        .iter()
        .filter_map(|s| {
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() == 3 {
                Some(json!({
                    "id": { "block": parts[0], "tx": parts[1] },
                    "value": parts[2]
                }))
            } else {
                eprintln!(
                    "Warning: Invalid alkane format '{}', expected block:tx:amount",
                    s
                );
                None
            }
        })
        .collect();

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    let request = json!({
        "jsonrpc": "2.0",
        "id": "alkanes-cli",
        "method": "alkanes_simulate",
        "params": [{
            "alkanes": alkanes,
            "transaction": "0x",
            "block": "0x",
            "height": "20000",
            "txindex": 0,
            "target": {
                "block": target_block,
                "tx": target_tx
            },
            "inputs": all_inputs,
            "pointer": 0,
            "refundPointer": 0,
            "vout": 0
        }]
    });

    // Show user-friendly inputs
    println!(
        "Simulating call to [{}, {}] with inputs: {:?}",
        target_block, target_tx, args.inputs
    );

    let res = client
        .post(&args.rpc_url)
        .basic_auth(&args.rpc_user, Some(&args.rpc_password))
        .json(&request)
        .send()
        .await
        .context("Failed to send RPC request")?;

    let status = res.status();
    let text = res.text().await.context("Failed to read response")?;

    if !status.is_success() {
        anyhow::bail!("RPC failed with status {}: {}", status, text);
    }

    let body: serde_json::Value =
        serde_json::from_str(&text).context(format!("Failed to parse JSON: {}", text))?;

    if let Some(error) = body.get("error") {
        if !error.is_null() {
            let error_msg = error
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("Unknown error");
            anyhow::bail!("Simulation error: {}", error_msg);
        }
    }

    if let Some(result) = body.get("result") {
        if args.raw {
            println!("{}", serde_json::to_string_pretty(result)?);
        } else {
            // Parse and display execution results
            println!("\n=== Simulation Result ===");

            if let Some(execution) = result.get("execution") {
                if let Some(error) = execution.get("error") {
                    if !error.is_null() && error.as_str() != Some("") {
                        println!("❌ Execution Error: {}", error);
                    }
                }

                if let Some(data) = execution.get("data") {
                    if let Some(data_str) = data.as_str() {
                        if !data_str.is_empty() && data_str != "0x" {
                            println!("📦 Return Data (hex): {}", data_str);
                            if let Some(hex_data) = data_str.strip_prefix("0x") {
                                if let Ok(bytes) = hex::decode(hex_data) {
                                    decode_return_data(&bytes);
                                }
                            }
                        }
                    }
                }

                if let Some(alkanes) = execution.get("alkanes") {
                    if let Some(arr) = alkanes.as_array() {
                        if !arr.is_empty() {
                            println!("🪙 Alkanes Output:");
                            for alkane in arr {
                                println!("   {:?}", alkane);
                            }
                        }
                    }
                }
            }

            if let Some(gas_used) = result.get("gasUsed") {
                println!("⛽ Gas Used: {}", gas_used);
            }

            println!("\n(Use --raw for full JSON response)");
        }
    } else {
        println!("No result in response");
        println!("{}", serde_json::to_string_pretty(&body)?);
    }

    Ok(())
}
