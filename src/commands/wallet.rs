use crate::wallet::{default_wallet_path, Wallet};
use anyhow::{Context, Result};
use bitcoin::Network;
use clap::{Args, Subcommand};

#[derive(Args)]
pub struct WalletArgs {
    #[command(subcommand)]
    command: WalletCommands,
}

#[derive(Subcommand)]
pub enum WalletCommands {
    /// Generate a new wallet
    New {
        /// Network (bitcoin, testnet, signet, regtest)
        #[arg(long, default_value = "regtest")]
        network: String,
    },
    /// Import a wallet from mnemonic
    Import {
        /// Mnemonic phrase
        #[arg(long)]
        mnemonic: String,
        /// Network (bitcoin, testnet, signet, regtest)
        #[arg(long, default_value = "regtest")]
        network: String,
    },
    /// Show wallet info
    Info,
    /// Fund wallet (Regtest only: mines blocks to address)
    Fund {
        /// Number of blocks to mine
        #[arg(long, default_value = "1")]
        blocks: u64,
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:18888")]
        rpc_url: String,
        /// RPC User
        #[arg(long, default_value = "user")]
        rpc_user: String,
        /// RPC Password
        #[arg(long, default_value = "password")]
        rpc_password: String,
    },
    /// Check wallet balance
    Balance {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:18888")]
        rpc_url: String,
        /// RPC User
        #[arg(long, default_value = "user")]
        rpc_user: String,
        /// RPC Password
        #[arg(long, default_value = "password")]
        rpc_password: String,
    },
}

pub async fn run(args: WalletArgs) -> Result<()> {
    let wallet_path = default_wallet_path()?;

    match args.command {
        WalletCommands::New { network } => {
            let net = parse_network(&network);
            let wallet = Wallet::new(net)?;
            wallet.save(&wallet_path)?;
            println!("Wallet created at {:?}", wallet_path);
            println!("Mnemonic: {}", wallet.mnemonic);
            println!("Address (index 0): {}", wallet.get_address(0)?);
        }
        WalletCommands::Import { mnemonic, network } => {
            let net = parse_network(&network);
            let wallet = Wallet::from_mnemonic(&mnemonic, net)?;
            wallet.save(&wallet_path)?;
            println!("Wallet imported to {:?}", wallet_path);
            println!("Address (index 0): {}", wallet.get_address(0)?);
        }
        WalletCommands::Info => {
            if !wallet_path.exists() {
                println!(
                    "No wallet found at {:?}. Run 'wallet new' or 'wallet import' first.",
                    wallet_path
                );
                return Ok(());
            }
            let wallet = Wallet::load(&wallet_path)?;
            println!("Wallet loaded from {:?}", wallet_path);
            println!("Network: {}", wallet.network);
            println!("Address (index 0): {}", wallet.get_address(0)?);
        }
        WalletCommands::Fund {
            blocks,
            rpc_url,
            rpc_user,
            rpc_password,
        } => {
            if !wallet_path.exists() {
                println!(
                    "No wallet found at {:?}. Run 'wallet new' or 'wallet import' first.",
                    wallet_path
                );
                return Ok(());
            }
            let wallet = Wallet::load(&wallet_path)?;
            let address = wallet.get_address(0)?;

            println!("Funding wallet address: {}", address);
            println!("Mining {} blocks...", blocks);

            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()?;

            let res = client
                .post(&rpc_url)
                .basic_auth(&rpc_user, Some(&rpc_password))
                .json(&serde_json::json!({
                    "jsonrpc": "1.0",
                    "id": "alkanes-cli",
                    "method": "btc_generatetoaddress",
                    "params": [blocks, address.to_string()]
                }))
                .send()
                .await
                .context("Failed to send RPC request for generatetoaddress")?;

            let status = res.status();
            let text = res.text().await.context("Failed to read response body")?;

            if !status.is_success() {
                anyhow::bail!("RPC failed with status {}: {}", status, text);
            }

            if text.trim().is_empty() {
                anyhow::bail!("RPC returned empty response");
            }

            let body: serde_json::Value = serde_json::from_str(&text)
                .context(format!("Failed to parse JSON response: {}", text))?;

            if let Some(error) = body.get("error") {
                if !error.is_null() {
                    println!("Error generating blocks: {:?}", error);
                    return Ok(());
                }
            }

            if let Some(result) = body.get("result") {
                println!("Generated blocks: {:?}", result);
                println!("Funds added to wallet!");
            }
        }
        WalletCommands::Balance {
            rpc_url,
            rpc_user,
            rpc_password,
        } => {
            if !wallet_path.exists() {
                println!(
                    "No wallet found at {:?}. Run 'wallet new' or 'wallet import' first.",
                    wallet_path
                );
                return Ok(());
            }
            let wallet = Wallet::load(&wallet_path)?;
            let address = wallet.get_address(0)?;

            println!("Checking balance for address: {}", address);

            println!("Checking balance for address: {}", address);

            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?;

            let res = client
                .post(&rpc_url)
                .basic_auth(&rpc_user, Some(&rpc_password))
                .json(&serde_json::json!({
                    "jsonrpc": "1.0",
                    "id": "alkanes-cli",
                    "method": "esplora_address::utxo",
                    "params": [address.to_string()]
                }))
                .send()
                .await
                .context("Failed to send RPC request for esplora_address::utxo")?;

            if !res.status().is_success() {
                let status = res.status();
                let text = res.text().await.unwrap_or_default();
                anyhow::bail!("RPC failed with status {}: {}", status, text);
            }

            let body: serde_json::Value =
                res.json().await.context("Failed to parse JSON response")?;

            if let Some(error) = body.get("error") {
                if !error.is_null() {
                    println!("Error fetching UTXOs: {:?}", error);
                    return Ok(());
                }
            }

            let utxos = body["result"]
                .as_array()
                .context("No result found in response")?;

            let mut total_sats: u64 = 0;
            for utxo in utxos {
                if let Some(val) = utxo["value"].as_u64() {
                    total_sats += val;
                }
            }

            let total_btc = total_sats as f64 / 100_000_000.0;
            println!("Balance: {} sats ({} BTC)", total_sats, total_btc);
        }
    }

    Ok(())
}

fn parse_network(network: &str) -> Network {
    match network {
        "bitcoin" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        _ => Network::Regtest,
    }
}
