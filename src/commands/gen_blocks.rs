use crate::wallet::{default_wallet_path, Wallet};
use anyhow::{Context, Result};
use clap::Args;
use serde_json::json;

#[derive(Args)]
pub struct GenBlocksArgs {
    /// Number of blocks to generate
    #[arg(short, long, default_value = "1")]
    pub count: u64,

    /// Address to mine to (optional)
    #[arg(short, long)]
    pub address: Option<String>,

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

pub async fn run(args: GenBlocksArgs) -> Result<()> {
    println!("Generating {} blocks...", args.count);

    let client = reqwest::Client::new();

    // If address is not provided, try to get from local wallet, then RPC
    let address = if let Some(addr) = args.address {
        addr
    } else {
        // Try local wallet first
        let wallet_path = default_wallet_path()?;
        if wallet_path.exists() {
            let wallet = Wallet::load(&wallet_path)?;
            wallet.get_address(0)?.to_string()
        } else {
            anyhow::bail!("No address provided and no local wallet found.\nPlease create a wallet with 'wallet new' or provide an address with --address.");
        }
    };

    println!("Mining to address: {}", address);

    let res = client
        .post(&args.rpc_url)
        .basic_auth(&args.rpc_user, Some(&args.rpc_password))
        .json(&json!({
            "jsonrpc": "1.0",
            "id": "alkanes-cli",
            "method": "btc_generatetoaddress",
            "params": [args.count, address]
        }))
        .send()
        .await
        .context("Failed to send RPC request for generatetoaddress")?;

    let body: serde_json::Value = res.json().await.context("Failed to parse JSON response")?;

    if let Some(error) = body.get("error") {
        if !error.is_null() {
            println!("Error generating blocks: {:?}", error);
            return Ok(());
        }
    }

    if let Some(result) = body.get("result") {
        println!("Generated blocks: {:?}", result);
    }

    Ok(())
}
