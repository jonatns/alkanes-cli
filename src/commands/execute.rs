use crate::wallet::{default_wallet_path, Wallet};
use anyhow::{Context, Result};
use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::key::TapTweak;
use bitcoin::sighash::{SighashCache, TapSighashType};
use bitcoin::{OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use clap::Args;
use reqwest::Client;
use serde_json::json;
use std::path::PathBuf;

#[derive(Args)]
pub struct ExecuteArgs {
    /// Target Alkane ID (format: block:tx, e.g., "2:1")
    #[arg(short, long)]
    pub target: String,

    /// Inputs/calldata (comma-separated). Numbers are passed as-is, text is encoded as strings.
    /// Example: "1,Alice" for opcode 1 with string arg "Alice"
    /// Example: "77" for just opcode 77
    #[arg(short, long, value_delimiter = ',')]
    pub inputs: Vec<String>,

    /// Path to wallet file (default: ~/.alkanes/wallet.json)
    #[arg(short, long)]
    pub wallet: Option<PathBuf>,

    /// Fee rate in sat/vB
    #[arg(long, default_value = "10")]
    pub fee_rate: u64,

    /// RPC URL (Alkanes indexer)
    #[arg(long, default_value = "http://127.0.0.1:18888")]
    pub rpc_url: String,

    /// RPC User
    #[arg(long, default_value = "user")]
    pub rpc_user: String,

    /// RPC Password
    #[arg(long, default_value = "password")]
    pub rpc_password: String,

    /// Simulate only (don't broadcast)
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
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

pub async fn run(args: ExecuteArgs) -> Result<String> {
    // Parse target
    let parts: Vec<&str> = args.target.split(':').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid target format. Expected block:tx (e.g., '2:1')");
    }
    let target_block: u128 = parts[0].parse().context("Invalid block number")?;
    let target_tx: u128 = parts[1].parse().context("Invalid tx number")?;

    // Load wallet
    let wallet_path = args
        .wallet
        .clone()
        .unwrap_or_else(|| default_wallet_path().unwrap());
    let wallet = Wallet::load(&wallet_path).context("Failed to load wallet")?;

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let private_key = wallet.get_privkey(0).context("Failed to get private key")?;
    let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &private_key.inner);
    let address = wallet.get_address(0).context("Failed to get address")?;
    let address_str = address.to_string();

    println!("Executing on target [{}, {}]", target_block, target_tx);
    println!("Inputs: {:?}", args.inputs);
    println!("From address: {}", address_str);

    // Get UTXOs
    let client = Client::new();
    let utxos = get_utxos(&client, &args, &address_str).await?;
    if utxos.is_empty() {
        anyhow::bail!("No UTXOs available for address {}", address_str);
    }

    let (utxo_txid, utxo_vout, utxo_value) = &utxos[0];
    println!(
        "Using UTXO: {}:{} ({} sats)",
        utxo_txid, utxo_vout, utxo_value
    );

    let mut calldata: Vec<u128> = vec![target_block, target_tx];
    for input in &args.inputs {
        calldata.extend(parse_input(input));
    }

    use protorune_support::protostone::{split_bytes, Protostone};
    use protorune_support::utils::encode_varint_list;

    let message = encode_varint_list(&calldata);

    let protostone = Protostone {
        burn: None,
        message,
        pointer: Some(0),
        edicts: vec![],
        refund: Some(0),
        from: None,
        protocol_tag: 1,
    };

    let protostone_varints = protostone
        .to_integers()
        .context("Failed to convert protostone to integers")?;

    let mut enciphered_values = Vec::<u128>::new();
    enciphered_values.push(protostone.protocol_tag);
    enciphered_values.push(protostone_varints.len() as u128);
    enciphered_values.extend(&protostone_varints);

    println!("Enciphered values (u128s): {:?}", enciphered_values);

    let mut enciphered_varints = encode_varint_list(&enciphered_values);
    println!("Enciphered varints (bytes): {:?}", enciphered_varints);

    // Pad to multiple of 15 bytes
    let remainder = enciphered_varints.len() % 15;
    if remainder != 0 {
        enciphered_varints.resize(enciphered_varints.len() + (15 - remainder), 0);
    }

    let protostone_chunks = split_bytes(&enciphered_varints);

    // Build Runestone data
    fn encode_varint(mut value: u128) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            let mut byte = (value & 0x7F) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            bytes.push(byte);
            if value == 0 {
                break;
            }
        }
        bytes
    }

    let mut runestone_data = Vec::new();
    for chunk in &protostone_chunks {
        runestone_data.extend(encode_varint(16383)); // Tag PROTOCOL
        runestone_data.extend(encode_varint(*chunk));
    }

    // Build OP_RETURN script
    let mut protostone_script = bitcoin::script::Builder::new()
        .push_opcode(bitcoin::opcodes::all::OP_RETURN)
        .push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_13);

    for chunk in runestone_data.chunks(520) {
        let push_bytes = bitcoin::script::PushBytesBuf::try_from(chunk.to_vec())?;
        protostone_script = protostone_script.push_slice(push_bytes.as_push_bytes());
    }

    let runestone_script = protostone_script.into_script();

    // Estimate fee
    let estimated_vsize = 200;
    let fee = estimated_vsize * args.fee_rate;
    let change = utxo_value.saturating_sub(fee);

    if change < 546 {
        anyhow::bail!(
            "Insufficient funds. Need at least {} sats, have {}",
            fee + 546,
            utxo_value
        );
    }

    // Build transaction
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: utxo_txid.parse().context("Invalid UTXO txid")?,
                vout: *utxo_vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        }],
        output: vec![
            // Output 0: Pointer target (dust to self)
            TxOut {
                value: bitcoin::Amount::from_sat(546),
                script_pubkey: address.script_pubkey(),
            },
            // Output 1: OP_RETURN with Protostone
            TxOut {
                value: bitcoin::Amount::ZERO,
                script_pubkey: runestone_script,
            },
            // Output 2: Change
            TxOut {
                value: bitcoin::Amount::from_sat(change - 546),
                script_pubkey: address.script_pubkey(),
            },
        ],
    };

    // Sign transaction
    let tweaked_keypair = keypair.tap_tweak(&secp, None);
    let mut signed_tx = tx.clone();

    let prevouts = vec![TxOut {
        value: bitcoin::Amount::from_sat(*utxo_value),
        script_pubkey: address.script_pubkey(),
    }];

    let mut sighash_cache = SighashCache::new(&tx);
    let sighash = sighash_cache
        .taproot_key_spend_signature_hash(
            0,
            &bitcoin::sighash::Prevouts::All(&prevouts),
            TapSighashType::Default,
        )
        .context("Failed to compute sighash")?;

    let msg = bitcoin::secp256k1::Message::from_digest_slice(sighash.as_ref())
        .context("Failed to create message")?;
    #[allow(deprecated)]
    let signature =
        secp.sign_schnorr_with_rng(&msg, &tweaked_keypair.to_inner(), &mut rand::thread_rng());

    let mut witness = Witness::new();
    witness.push(signature.as_ref());
    signed_tx.input[0].witness = witness;

    let tx_hex = serialize_hex(&signed_tx);
    let txid = signed_tx.compute_txid();

    println!("\n=== Transaction Built ===");
    println!("Txid: {}", txid);
    println!("Size: {} vbytes (estimated)", estimated_vsize);
    println!("Fee: {} sats ({} sat/vB)", fee, args.fee_rate);

    if args.dry_run {
        println!("\n[DRY RUN] Transaction not broadcast");
        println!("Raw tx: {}", tx_hex);
        return Ok(txid.to_string());
    }

    // Broadcast
    let broadcast_result = broadcast_tx(&client, &args, &tx_hex).await?;
    println!("\n✅ Transaction broadcast!");
    println!("Txid: {}", broadcast_result);
    println!("\nTrace with: alkanes trace --txid {} --vout 4", txid);

    Ok(broadcast_result)
}

async fn get_utxos(
    client: &Client,
    args: &ExecuteArgs,
    address: &str,
) -> Result<Vec<(String, u32, u64)>> {
    // Use esplora_address::utxo (same as deploy.rs)
    let res = client
        .post(&args.rpc_url)
        .basic_auth(&args.rpc_user, Some(&args.rpc_password))
        .json(&json!({
            "jsonrpc": "1.0",
            "id": "alkanes-cli",
            "method": "esplora_address::utxo",
            "params": [address]
        }))
        .send()
        .await
        .context(format!("Failed to connect to RPC at {}", args.rpc_url))?;

    let body: serde_json::Value = res.json().await.context("Failed to parse response")?;

    if let Some(error) = body.get("error") {
        if !error.is_null() {
            anyhow::bail!("RPC error: {:?}", error);
        }
    }

    let unspents = body["result"]
        .as_array()
        .context("No UTXOs found in response")?;

    let utxos: Vec<(String, u32, u64)> = unspents
        .iter()
        .filter_map(|u| {
            let txid = u["txid"].as_str()?.to_string();
            let vout = u["vout"].as_u64()? as u32;
            let value = u["value"].as_u64()?;
            // Only use UTXOs > 1000 sats to avoid dust
            if value > 1000 {
                Some((txid, vout, value))
            } else {
                None
            }
        })
        .collect();

    Ok(utxos)
}

async fn broadcast_tx(client: &Client, args: &ExecuteArgs, tx_hex: &str) -> Result<String> {
    // Use btc_sendrawtransaction via Alkanes RPC (same as deploy.rs)
    let res = client
        .post(&args.rpc_url)
        .basic_auth(&args.rpc_user, Some(&args.rpc_password))
        .json(&json!({
            "jsonrpc": "1.0",
            "id": "alkanes-cli",
            "method": "btc_sendrawtransaction",
            "params": [tx_hex]
        }))
        .send()
        .await
        .context("Failed to broadcast")?;

    let body: serde_json::Value = res.json().await?;

    if let Some(error) = body.get("error") {
        if !error.is_null() {
            let msg = format!("{:?}", error);
            anyhow::bail!("Broadcast failed: {}", msg);
        }
    }

    body.get("result")
        .and_then(|r| r.as_str())
        .map(|s| s.to_string())
        .context("No txid in response")
}
