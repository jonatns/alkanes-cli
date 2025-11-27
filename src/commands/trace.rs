use anyhow::{Context, Result};
use clap::Args;
use reqwest::Client;
use serde_json::json;

#[derive(Args)]
pub struct TraceArgs {
    /// Transaction ID to trace
    #[arg(long)]
    pub txid: String,

    /// Vout index (default: 0)
    #[arg(long, default_value = "0")]
    pub vout: u32,

    /// RPC URL
    #[arg(long, default_value = "http://127.0.0.1:18888")]
    pub rpc_url: String,

    /// RPC User
    #[arg(long, default_value = "user")]
    pub rpc_user: String,

    /// RPC Password
    #[arg(long, default_value = "password")]
    pub rpc_password: String,

    /// Show verbose debugging information
    #[arg(long, default_value_t = false)]
    pub verbose: bool,
}

pub async fn run(args: TraceArgs) -> Result<()> {
    println!("Tracing transaction: {}", args.txid);

    // IMPORTANT: The alkanes_trace RPC requires the txid to be reversed (byte-order reversed)
    // This matches the TypeScript SDK: Buffer.from(txid, 'hex').reverse().toString('hex')
    // Bitcoin txids are typically displayed in big-endian, but the RPC expects little-endian
    let txid_bytes = hex::decode(&args.txid).context("Failed to decode txid as hex")?;
    if txid_bytes.len() != 32 {
        anyhow::bail!(
            "Invalid txid length: expected 32 bytes (64 hex chars), got {} bytes",
            txid_bytes.len()
        );
    }
    // Reverse the byte array in-place (equivalent to Buffer.reverse() in TypeScript)
    let mut reversed_txid = txid_bytes;
    reversed_txid.reverse();
    let reversed_txid_hex = hex::encode(reversed_txid);

    if args.verbose {
        println!("Reversed txid: {}", reversed_txid_hex);
        println!("Vout: {}", args.vout);
    }

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    let request = json!({
        "jsonrpc": "1.0",
        "id": "alkanes-cli",
        "method": "alkanes_trace",
        "params": [{
            "txid": reversed_txid_hex,
            "vout": args.vout
        }]
    });

    if args.verbose {
        println!("RPC Request:");
        println!("{}", serde_json::to_string_pretty(&request)?);
        println!("RPC URL: {}", args.rpc_url);
    }

    let res = client
        .post(&args.rpc_url)
        .basic_auth(&args.rpc_user, Some(&args.rpc_password))
        .json(&request)
        .send()
        .await
        .context("Failed to send RPC request for alkanes_trace")?;

    let status = res.status();
    let text = res.text().await.context("Failed to read response body")?;

    if args.verbose {
        println!("HTTP Status: {}", status);
        println!("Response body: {}", text);
    }

    if !status.is_success() {
        eprintln!("HTTP Status: {}", status);
        eprintln!("Response body: {}", text);
        anyhow::bail!("RPC failed with status {}: {}", status, text);
    }

    let body: serde_json::Value =
        serde_json::from_str(&text).context(format!("Failed to parse JSON response: {}", text))?;

    if args.verbose {
        println!("Parsed response:");
        println!("{}", serde_json::to_string_pretty(&body)?);
    }

    // Debug: show full response if verbose or if there's an issue
    if let Some(error) = body.get("error") {
        if !error.is_null() {
            let error_msg = error
                .get("message")
                .and_then(|m| m.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("{:?}", error));
            eprintln!("Error tracing transaction: {}", error_msg);
            eprintln!(
                "Full error object: {}",
                serde_json::to_string_pretty(error)?
            );
            eprintln!("\nRequest details:");
            eprintln!("  Txid (original): {}", args.txid);
            eprintln!("  Txid (reversed): {}", reversed_txid_hex);
            eprintln!("  Vout: {}", args.vout);
            eprintln!("\nNote: The transaction may need to be confirmed in a block before tracing is available.");
            eprintln!(
                "Check transaction status with: cargo run -- tx-status --txid {}",
                args.txid
            );
            anyhow::bail!("Trace failed: {}", error_msg);
        }
    }

    if let Some(result) = body.get("result") {
        if result.is_null() {
            eprintln!("Trace result is null.");
            eprintln!("\nRequest details:");
            eprintln!("  Txid (original): {}", args.txid);
            eprintln!("  Txid (reversed): {}", reversed_txid_hex);
            eprintln!("  Vout: {}", args.vout);
            eprintln!("\nNote: The transaction may need to be confirmed in a block before tracing is available.");
            eprintln!(
                "Check transaction status with: cargo run -- tx-status --txid {}",
                args.txid
            );
            anyhow::bail!("Trace returned null result");
        } else if result.is_array() {
            let array = result.as_array().unwrap();
            if array.is_empty() {
                eprintln!("Trace result is an empty array (transaction not indexed yet).");
                eprintln!("\nRequest details:");
                eprintln!("  Txid (original): {}", args.txid);
                eprintln!("  Txid (reversed): {}", reversed_txid_hex);
                eprintln!("  Vout: {}", args.vout);
                eprintln!("\nPossible reasons:");
                eprintln!("  1. Transaction not confirmed in a block yet");
                eprintln!("  2. Metashrew hasn't indexed the transaction yet");
                eprintln!("  3. Protostone encoding may be incorrect");
                eprintln!("\nTry:");
                eprintln!(
                    "  1. Check transaction status: cargo run -- tx-status --txid {}",
                    args.txid
                );
                eprintln!("  2. If in regtest, mine blocks: cargo run -- gen-blocks --count 2");
                eprintln!("  3. Wait a few seconds and try tracing again");
                eprintln!("  4. Verify the protostone was correctly encoded in the transaction");
                anyhow::bail!("Trace returned empty array - transaction may not be indexed yet");
            } else {
                println!("Trace result:");
                println!("{}", serde_json::to_string_pretty(result)?);
            }
        } else if result.is_object() && result.as_object().unwrap().is_empty() {
            eprintln!("Trace result is an empty object.");
            eprintln!("\nRequest details:");
            eprintln!("  Txid (original): {}", args.txid);
            eprintln!("  Txid (reversed): {}", reversed_txid_hex);
            eprintln!("  Vout: {}", args.vout);
            eprintln!("\nNote: The transaction may need to be confirmed in a block before tracing is available.");
            eprintln!(
                "Check transaction status with: cargo run -- tx-status --txid {}",
                args.txid
            );
            anyhow::bail!("Trace returned empty result");
        } else {
            println!("Trace result:");
            println!("{}", serde_json::to_string_pretty(result)?);
        }
    } else {
        eprintln!("No 'result' field found in response.");
        eprintln!("Full response: {}", serde_json::to_string_pretty(&body)?);
        eprintln!("\nRequest details:");
        eprintln!("  Txid (original): {}", args.txid);
        eprintln!("  Txid (reversed): {}", reversed_txid_hex);
        eprintln!("  Vout: {}", args.vout);
        anyhow::bail!("No result field in response");
    }

    Ok(())
}
