use anyhow::{Context, Result};
use clap::Args;
use reqwest::Client;
use serde_json::json;

#[derive(Args)]
pub struct TxStatusArgs {
    /// Transaction ID to check
    #[arg(long)]
    pub txid: String,

    /// RPC URL
    #[arg(long, default_value = "http://127.0.0.1:18888")]
    pub rpc_url: String,

    /// RPC User
    #[arg(long, default_value = "user")]
    pub rpc_user: String,

    /// RPC Password
    #[arg(long, default_value = "password")]
    pub rpc_password: String,
}

pub async fn run(args: TxStatusArgs) -> Result<()> {
    println!("Checking transaction status: {}", args.txid);

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    let res = client
        .post(&args.rpc_url)
        .basic_auth(&args.rpc_user, Some(&args.rpc_password))
        .json(&json!({
            "jsonrpc": "1.0",
            "id": "alkanes-cli",
            "method": "esplora_tx::status",
            "params": [args.txid]
        }))
        .send()
        .await
        .context("Failed to send RPC request for esplora_tx::status")?;

    let status = res.status();
    let text = res.text().await.context("Failed to read response body")?;

    if !status.is_success() {
        anyhow::bail!("RPC failed with status {}: {}", status, text);
    }

    let body: serde_json::Value =
        serde_json::from_str(&text).context(format!("Failed to parse JSON response: {}", text))?;

    if let Some(error) = body.get("error") {
        if !error.is_null() {
            println!("Error fetching transaction: {:?}", error);
            return Ok(());
        }
    }

    if let Some(result) = body.get("result") {
        println!("{}", serde_json::to_string_pretty(result)?);
    } else {
        println!("No result found in response");
    }

    Ok(())
}
