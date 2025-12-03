use crate::wallet::{default_wallet_path, Wallet};
use anyhow::{anyhow, Context, Result};
use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::key::TapTweak;
use bitcoin::sighash::{SighashCache, TapSighashType};
use bitcoin::{Address, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Witness};
use bitcoin::{Amount, Sequence};
use clap::Args;
use reqwest::Client;
use serde_json::json;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use tokio::time::sleep;

#[derive(Args)]
pub struct DeployArgs {
    /// Path to the WASM file
    #[arg(short, long)]
    pub wasm: PathBuf,

    /// Output path for the compressed WASM (optional)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Deploy as a factory contract (default: single)
    #[arg(long, default_value_t = false)]
    pub factory: bool,

    /// RPC URL
    #[arg(long, default_value = "http://127.0.0.1:18888")]
    pub rpc_url: String,

    /// RPC User
    #[arg(long, default_value = "user")]
    pub rpc_user: String,

    /// RPC Password
    #[arg(long, default_value = "password")]
    pub rpc_password: String,

    /// Reserved transaction ID for factory deployments (uses CREATE2-like deterministic addressing)
    #[arg(long)]
    pub reserved_tx: Option<u128>,

    /// Salt for factory deployments (default: 50)
    #[arg(long)]
    pub salt: Option<u128>,

    /// Custom calldata (comma-separated u128 values). Overrides factory/single defaults.
    /// Example: "3,16005,32767,4,16002,1"
    #[arg(long)]
    pub calldata: Option<String>,
}

pub async fn run(args: DeployArgs) -> Result<()> {
    // 1. Load Wallet
    let wallet_path = default_wallet_path()?;
    if !wallet_path.exists() {
        anyhow::bail!("No wallet found. Run 'wallet new' or 'wallet import' first.");
    }
    let wallet = Wallet::load(&wallet_path)?;
    let address = wallet.get_address(0)?;
    println!("Using address: {}", address);

    let client = Client::new();

    // Standard Deployment
    let deploy_type = if args.factory { "Factory" } else { "Single" };
    println!("Deploying {} contract from {:?}", deploy_type, args.wasm);

    // Load WASM
    let mut file = File::open(&args.wasm).context("Failed to open WASM file")?;
    let mut wasm_buffer = Vec::new();
    file.read_to_end(&mut wasm_buffer)
        .context("Failed to read WASM file")?;

    let calldata = if let Some(custom_calldata) = &args.calldata {
        // Parse custom calldata
        custom_calldata
            .split(',')
            .map(|s| s.trim().parse::<u128>())
            .collect::<Result<Vec<u128>, _>>()
            .context("Failed to parse calldata - must be comma-separated u128 values")?
    } else if args.factory {
        // Factory deploy: [3, reserved_tx, salt]
        let reserved_tx = args.reserved_tx.unwrap_or(0);
        let salt = args.salt.unwrap_or(50);
        vec![3u128, reserved_tx, salt]
    } else {
        // Single deploy: [1, 0]
        vec![1u128, 0u128]
    };

    let (txid, vout) =
        deploy_contract(wasm_buffer, calldata, &args, &wallet, &client, deploy_type).await?;

    println!("\nContract Deployed!");
    println!("TxID: {}", txid);
    println!("Vout: {}", vout);

    // Mine blocks to confirm the transaction
    mine_blocks(
        &client,
        &args.rpc_url,
        (&args.rpc_user, &args.rpc_password),
        &address.to_string(),
        1,
    )
    .await?;

    // Trace to get the contract ID
    println!("⏳ Waiting for trace to get Contract ID...");
    let (contract_block, contract_tx) = trace_and_get_id(
        &client,
        &args.rpc_url,
        (&args.rpc_user, &args.rpc_password),
        &txid,
        vout,
    )
    .await?;

    println!("\n✅ Contract ID: {}:{}", contract_block, contract_tx);
    println!("\nTo execute on this contract, use:");
    println!(
        "  cargo run -- execute --target {}:{} --inputs <inputs>",
        contract_block, contract_tx
    );

    Ok(())
}

pub async fn deploy_contract(
    wasm_buffer: Vec<u8>,
    calldata: Vec<u128>,
    args: &DeployArgs,
    wallet: &Wallet,
    client: &Client,
    label: &str,
) -> Result<(String, u32)> {
    let address = wallet.get_address(0)?;

    println!("[{}] WASM size: {} bytes", label, wasm_buffer.len());

    // 3. Fetch UTXOs
    let res = client
        .post(&args.rpc_url)
        .basic_auth(&args.rpc_user, Some(&args.rpc_password))
        .json(&json!({
            "jsonrpc": "1.0",
            "id": "alkanes-cli",
            "method": "esplora_address::utxo",
            "params": [address.to_string()]
        }))
        .send()
        .await
        .context("Failed to fetch UTXOs")?;

    let body: serde_json::Value = res.json().await?;
    if let Some(error) = body.get("error") {
        if !error.is_null() {
            anyhow::bail!("Error fetching UTXOs: {:?}", error);
        }
    }

    let unspents = body["result"]
        .as_array()
        .context("No unspents array in response")?;
    if unspents.is_empty() {
        anyhow::bail!("No UTXOs found for address {}", address);
    }

    // Fetch current height once (used for coinbase maturity)
    let current_height = {
        let res = client
            .post(&args.rpc_url)
            .basic_auth(&args.rpc_user, Some(&args.rpc_password))
            .json(&json!({
                "jsonrpc": "1.0",
                "id": "alkanes-cli",
                "method": "btc_getblockcount",
                "params": []
            }))
            .send()
            .await
            .context("Failed to fetch blockcount")?;
        let body: serde_json::Value = res.json().await?;
        body["result"].as_u64().unwrap_or(0)
    };

    // UTXO Selection
    let fee_rate: u64 = 2;
    let commit_fee = 200 * fee_rate;

    // be pessimistic: assume compressed ~ same as original
    let estimated_compressed_size = wasm_buffer.len() as u64;
    // fairly generous overestimation for reveal size
    let reveal_fee = (estimated_compressed_size / 2 + 300) * fee_rate;

    let total_needed = commit_fee + reveal_fee + 1000; // buffer for safety

    let mut selected_utxo = None;
    for utxo in unspents {
        let val = utxo["value"].as_u64().context("Invalid value")?;
        if val < total_needed {
            continue;
        }

        // Check maturity only for coinbase outputs
        if let Some(status) = utxo.get("status") {
            let confirmed = status
                .get("confirmed")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            if confirmed {
                let block_height = status
                    .get("block_height")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                // Esplora uses "coinbase" bool
                let is_coinbase = utxo
                    .get("coinbase")
                    .and_then(|v| v.as_bool())
                    .or_else(|| utxo.get("is_coinbase").and_then(|v| v.as_bool()))
                    .unwrap_or(false);

                if is_coinbase && current_height != 0 {
                    // coinbase maturity: 100 blocks
                    if current_height.saturating_sub(block_height) + 1 < 100 {
                        continue;
                    }
                }
            }
        }

        selected_utxo = Some(utxo);
        break;
    }

    let utxo = selected_utxo.context("No sufficient UTXO found")?;
    let txid = utxo["txid"].as_str().context("Invalid txid")?;
    let vout = utxo["vout"].as_u64().context("Invalid vout")? as u32;
    let amount_sats = utxo["value"].as_u64().context("Invalid value")?;
    let script_pubkey = address.script_pubkey();

    // 4. Prepare Commit-Reveal
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let privkey = wallet.get_privkey(0)?;
    let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &privkey.inner);
    let (internal_key, _) = keypair.x_only_public_key();

    use alkanes_support::envelope::RawEnvelope;
    use alkanes_support::gz::compress;
    let compressed_wasm = compress(wasm_buffer.clone()).context("Failed to compress WASM")?;
    println!(
        "[{}] Compressed WASM size: {} bytes",
        label,
        compressed_wasm.len()
    );

    // Build the tapleaf script using the shared envelope helper so parsing matches the runtime
    // (BIN tag, empty body tag, payload compressed inside).
    let envelope = RawEnvelope::from(wasm_buffer.clone());
    let script = envelope.append_reveal_script(
        bitcoin::script::Builder::new()
            .push_x_only_key(&internal_key)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG),
        true, // compress payload inside the envelope
    );

    let taproot_builder = bitcoin::taproot::TaprootBuilder::new().add_leaf(0, script.clone())?;
    let taproot_spend_info = taproot_builder
        .finalize(&secp, internal_key)
        .map_err(|_| anyhow!("Failed to finalize taproot"))?;
    let commit_address = Address::p2tr_tweaked(taproot_spend_info.output_key(), wallet.network);

    // 5. Construct Commit Tx
    let commit_input = TxIn {
        previous_output: OutPoint::new(bitcoin::Txid::from_str(txid)?, vout),
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };

    // commit_value funds the reveal input + dust
    let commit_value = reveal_fee + 546;
    let change_value = amount_sats
        .checked_sub(commit_value)
        .and_then(|v| v.checked_sub(commit_fee))
        .context("Insufficient funds in selected UTXO for commit + reveal + change")?;

    // avoid dust change
    if change_value < 546 {
        anyhow::bail!(
            "Change output would be dust ({} sats). Use a larger UTXO or adjust fee assumptions.",
            change_value
        );
    }

    let commit_output = TxOut {
        value: Amount::from_sat(commit_value),
        script_pubkey: commit_address.script_pubkey(),
    };
    let change_output = TxOut {
        value: Amount::from_sat(change_value),
        script_pubkey: address.script_pubkey(),
    };

    let mut commit_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![commit_input],
        output: vec![commit_output, change_output],
    };

    let mut sighash_cache = SighashCache::new(&mut commit_tx);
    let sighash = sighash_cache.taproot_key_spend_signature_hash(
        0,
        &bitcoin::sighash::Prevouts::All(&[TxOut {
            value: Amount::from_sat(amount_sats),
            script_pubkey: script_pubkey.clone(),
        }]),
        TapSighashType::Default,
    )?;
    let msg = bitcoin::secp256k1::Message::from_digest_slice(&sighash[..])?;
    let tweaked_keypair = keypair.tap_tweak(&secp, None);
    let signature = secp.sign_schnorr_no_aux_rand(&msg, &tweaked_keypair.to_keypair());
    commit_tx.input[0].witness.push(signature.as_ref());

    let commit_tx_hex = serialize_hex(&commit_tx);

    // 6. Construct Reveal Tx
    let reveal_input = TxIn {
        previous_output: OutPoint::new(commit_tx.compute_txid(), 0),
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };

    let reveal_output = TxOut {
        value: Amount::from_sat(546),
        script_pubkey: address.script_pubkey(),
    };

    use protorune_support::protostone::{split_bytes, Protostone};
    use protorune_support::utils::encode_varint_list;

    let message = encode_varint_list(&calldata);

    let protostone = Protostone {
        burn: None,
        message,
        edicts: vec![],
        refund: Some(0),
        pointer: Some(0),
        from: None,
        protocol_tag: 1,
    };

    let protostone_varints = protostone.to_integers()?;
    let mut enciphered_values = Vec::<u128>::new();
    enciphered_values.push(protostone.protocol_tag);
    enciphered_values.push(protostone_varints.len() as u128);
    enciphered_values.extend(&protostone_varints);

    let mut enciphered_varints = encode_varint_list(&enciphered_values);

    // Pad to 15-byte chunks (same behavior as execute.rs) so split_bytes
    // produces deterministic chunking and the decoder doesn't run out of data.
    let remainder = enciphered_varints.len() % 15;
    if remainder != 0 {
        enciphered_varints.resize(enciphered_varints.len() + (15 - remainder), 0);
    }

    let protostone_chunks = split_bytes(&enciphered_varints);

    let mut runestone_data = Vec::new();
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

    for chunk in &protostone_chunks {
        // 16383 is the Protostone "edict" marker
        runestone_data.extend(encode_varint(16383));
        runestone_data.extend(encode_varint(*chunk));
    }

    let mut protostone_script = bitcoin::script::Builder::new()
        .push_opcode(bitcoin::opcodes::all::OP_RETURN)
        .push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_13);
    for chunk in runestone_data.chunks(520) {
        let push_bytes = bitcoin::script::PushBytesBuf::try_from(chunk.to_vec())?;
        protostone_script = protostone_script.push_slice(push_bytes.as_push_bytes());
    }

    let protostone_output = TxOut {
        value: Amount::ZERO,
        script_pubkey: protostone_script.into_script(),
    };

    let mut reveal_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![reveal_input],
        output: vec![reveal_output, protostone_output],
    };

    let mut sighash_cache = SighashCache::new(&mut reveal_tx);
    let leaf_hash = bitcoin::taproot::TapLeafHash::from_script(
        &script,
        bitcoin::taproot::LeafVersion::TapScript,
    );
    let sighash = sighash_cache.taproot_script_spend_signature_hash(
        0,
        &bitcoin::sighash::Prevouts::All(&[TxOut {
            value: Amount::from_sat(commit_value),
            script_pubkey: commit_address.script_pubkey(),
        }]),
        leaf_hash,
        TapSighashType::Default,
    )?;
    let msg = bitcoin::secp256k1::Message::from_digest_slice(&sighash[..])?;
    let signature = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

    let mut witness = Witness::new();
    // [ sig, tapscript, control_block ]
    witness.push(signature.as_ref());
    witness.push(script.as_bytes());
    witness.push(
        taproot_spend_info
            .control_block(&(script.clone(), bitcoin::taproot::LeafVersion::TapScript))
            .unwrap()
            .serialize(),
    );
    reveal_tx.input[0].witness = witness;

    // Sanity check: ensure witness contains decodable compressed WASM
    if let Some(payload) = alkanes_support::witness::find_witness_payload(&reveal_tx, 0) {
        match alkanes_support::gz::decompress(payload.clone()) {
            Ok(decoded) => {
                println!(
                    "[{}] Witness payload check: compressed {} bytes, decoded {} bytes (original wasm {} bytes)",
                    label,
                    payload.len(),
                    decoded.len(),
                    wasm_buffer.len()
                );
            }
            Err(e) => {
                println!(
                    "[{}] Witness payload decompress failed: {} (payload {} bytes)",
                    label,
                    e,
                    payload.len()
                );
            }
        }
    } else {
        println!("[{}] Witness payload missing (could not extract envelope)", label);
    }

    let reveal_tx_hex = serialize_hex(&reveal_tx);

    // 7. Broadcast
    println!("[{}] Broadcasting Commit Transaction...", label);
    client
        .post(&args.rpc_url)
        .basic_auth(&args.rpc_user, Some(&args.rpc_password))
        .json(&json!({
            "jsonrpc": "1.0",
            "id": "alkanes-cli",
            "method": "btc_sendrawtransaction",
            "params": [commit_tx_hex]
        }))
        .send()
        .await
        .context("Failed to broadcast commit tx")?;

    println!("[{}] Waiting 3 seconds for commit propagation...", label);
    sleep(Duration::from_secs(3)).await;

    println!("[{}] Broadcasting Reveal Transaction...", label);
    let res = client
        .post(&args.rpc_url)
        .basic_auth(&args.rpc_user, Some(&args.rpc_password))
        .json(&json!({
            "jsonrpc": "1.0",
            "id": "alkanes-cli",
            "method": "btc_sendrawtransaction",
            "params": [reveal_tx_hex]
        }))
        .send()
        .await
        .context("Failed to broadcast reveal tx")?;

    let body: serde_json::Value = res.json().await?;
    if let Some(error) = body.get("error") {
        if !error.is_null() {
            anyhow::bail!("Error broadcasting Reveal Tx: {:?}", error);
        }
    }
    let reveal_txid = body["result"].as_str().unwrap_or("unknown").to_string();

    // The protostone OP_RETURN is the second output (index 1)
    let trace_vout = 1u32;

    Ok((reveal_txid, trace_vout))
}

pub async fn mine_blocks(
    client: &Client,
    rpc_url: &str,
    auth: (&str, &str),
    address: &str,
    num_blocks: u64,
) -> Result<()> {
    println!("⛏️  Mining {} block(s)...", num_blocks);
    let res = client
        .post(rpc_url)
        .basic_auth(auth.0, Some(auth.1))
        .json(&json!({
            "jsonrpc": "1.0",
            "id": "alkanes-cli",
            "method": "btc_generatetoaddress",
            "params": [num_blocks, address]
        }))
        .send()
        .await?;

    let body: serde_json::Value = res.json().await?;
    if let Some(error) = body.get("error") {
        if !error.is_null() {
            anyhow::bail!("Error mining blocks: {:?}", error);
        }
    }
    println!("✅ Mined {} block(s)", num_blocks);
    Ok(())
}

pub async fn trace_and_get_id(
    client: &Client,
    rpc_url: &str,
    auth: (&str, &str),
    txid: &str,
    vout: u32,
) -> Result<(u128, u128)> {
    println!("Polling for trace of {} (vout {})...", txid, vout);

    // Reverse txid for alkanes_trace RPC
    let txid_bytes = hex::decode(txid).context("Failed to decode txid")?;
    let mut reversed_txid = txid_bytes;
    reversed_txid.reverse();
    let reversed_txid_hex = hex::encode(reversed_txid);

    loop {
        let res = client
            .post(rpc_url)
            .basic_auth(auth.0, Some(auth.1))
            .json(&json!({
                "jsonrpc": "1.0",
                "id": "alkanes-cli",
                "method": "alkanes_trace",
                "params": [{
                    "txid": reversed_txid_hex,
                    "vout": vout
                }]
            }))
            .send()
            .await?;

        let body: serde_json::Value = res.json().await?;

        if let Some(result) = body.get("result") {
            if !result.is_null() {
                if let Some(array) = result.as_array() {
                    if array.is_empty() {
                        println!("Trace is empty, retrying...");
                    }

                    // Check for revert first
                    for item in array {
                        if let Some(event) = item.get("event").and_then(|e| e.as_str()) {
                            if event == "return" {
                                if let Some(data) = item.get("data") {
                                    if let Some(status) =
                                        data.get("status").and_then(|s| s.as_str())
                                    {
                                        if status == "revert" {
                                            println!("⚠️  Transaction reverted (may be expected for Factory deployment): {:?}", data);
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Look for create event
                    for item in array {
                        if let Some(event) = item.get("event").and_then(|e| e.as_str()) {
                            if event == "create" {
                                if let Some(data) = item.get("data") {
                                    let block =
                                        data.get("block").and_then(|b| b.as_str()).unwrap_or("0");
                                    let tx = data.get("tx").and_then(|t| t.as_str()).unwrap_or("0");

                                    let block_u128 =
                                        u128::from_str_radix(block.trim_start_matches("0x"), 16)
                                            .unwrap_or(0);
                                    let tx_u128 =
                                        u128::from_str_radix(tx.trim_start_matches("0x"), 16)
                                            .unwrap_or(0);

                                    if block_u128 != 0 || tx_u128 != 0 {
                                        return Ok((block_u128, tx_u128));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        sleep(Duration::from_secs(5)).await;
    }
}
