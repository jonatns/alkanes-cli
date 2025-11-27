use crate::wallet::{default_wallet_path, Wallet};
use anyhow::{Context, Result};
use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::key::TapTweak;
use bitcoin::sighash::{SighashCache, TapSighashType};
use bitcoin::{Address, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use clap::Args;
use reqwest::Client;
use serde_json::json;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::str::FromStr;

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
}

pub async fn run(args: DeployArgs) -> Result<()> {
    let deploy_type = if args.factory { "Factory" } else { "Single" };
    println!("Deploying {} contract from {:?}", deploy_type, args.wasm);

    // 1. Load Wallet
    let wallet_path = default_wallet_path()?;
    if !wallet_path.exists() {
        anyhow::bail!("No wallet found. Run 'wallet new' or 'wallet import' first.");
    }
    let wallet = Wallet::load(&wallet_path)?;
    let address = wallet.get_address(0)?;
    println!("Using address: {}", address);

    // 2. Load WASM (uncompressed - RawEnvelope will compress it)
    let mut file = File::open(&args.wasm).context("Failed to open WASM file")?;
    let mut wasm_buffer = Vec::new();
    file.read_to_end(&mut wasm_buffer)
        .context("Failed to read WASM file")?;
    println!("WASM size: {} bytes", wasm_buffer.len());

    // 3. Fetch UTXOs
    let client = Client::new();
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

    // Handle potential error in response
    if let Some(error) = body.get("error") {
        if !error.is_null() {
            anyhow::bail!("Error fetching UTXOs: {:?}", error);
        }
    }

    let unspents = body["result"].as_array().context("No unspents found")?;

    if unspents.is_empty() {
        anyhow::bail!("No UTXOs found for address {}", address);
    }

    // UTXO Selection (Simple: take first that covers fees)
    // We need enough for Commit Tx fees + Reveal Tx fees + Dust limit
    // Also filter out immature coinbase outputs (need 100 confirmations)
    let fee_rate = 2; // sats/vbyte
    let commit_fee = 200 * fee_rate; // Estimate
                                     // Estimate reveal fee: compressed WASM is typically 30-50% of original size
    let estimated_compressed_size = wasm_buffer.len() / 2;
    let reveal_fee = (estimated_compressed_size as u64 / 4 + 200) * fee_rate; // Witness data is discounted
    let total_needed = commit_fee + reveal_fee + 1000; // Buffer

    let mut selected_utxo = None;
    for utxo in unspents {
        let val = utxo["value"].as_u64().context("Invalid value")?;

        // Skip if not enough value
        if val < total_needed {
            continue;
        }

        // Check if this is a coinbase UTXO and if it has matured (100 confirmations required)
        // The "status" field contains confirmation info from esplora
        if let Some(status) = utxo.get("status") {
            if let Some(confirmed) = status.get("confirmed").and_then(|v| v.as_bool()) {
                if confirmed {
                    if let Some(block_height) = status.get("block_height").and_then(|v| v.as_u64())
                    {
                        // Get current block height to calculate confirmations
                        let current_height_res = client
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
                            .context("Failed to get block count")?;

                        let current_height_body: serde_json::Value =
                            current_height_res.json().await?;
                        if let Some(current_height) = current_height_body["result"].as_u64() {
                            let confirmations = current_height - block_height + 1;

                            // Check if this might be a coinbase by checking if vout is from a transaction
                            // Coinbase transactions have only one input with null txid
                            // We'll check confirmations - if less than 100, we'll be cautious and skip it
                            if confirmations < 100 {
                                println!("Skipping UTXO {}:{} with {} confirmations (may be immature coinbase)", 
                                    utxo["txid"].as_str().unwrap_or("unknown"), 
                                    utxo["vout"].as_u64().unwrap_or(0),
                                    confirmations);
                                continue;
                            }
                        }
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

    println!("Selected UTXO: {}:{} ({} sats)", txid, vout, amount_sats);

    // 4. Prepare Commit-Reveal Data
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let privkey = wallet.get_privkey(0)?;
    let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &privkey.inner);
    let (internal_key, _) = keypair.x_only_public_key();

    // Compress WASM using alkanes-support's compress function
    use alkanes_support::gz::compress;
    let compressed_wasm = compress(wasm_buffer.clone()).context("Failed to compress WASM")?;
    println!("Compressed size: {} bytes", compressed_wasm.len());

    // Construct the script matching RawEnvelope::append_reveal_script EXACTLY:
    // <pubkey> OP_CHECKSIG OP_FALSE OP_IF <"BIN"> <BODY_TAG> <compressed_wasm_chunks> OP_ENDIF
    //
    // Key insight: RawEnvelope uses:
    // - push_opcode(OP_FALSE) for envelope boundary (byte 0x00)
    // - push_slice(BODY_TAG) for body tag (empty, also byte 0x00)
    // Both produce byte 0x00, which is interpreted as PushBytes(&[]) when iterating
    use bitcoin::blockdata::constants::MAX_SCRIPT_ELEMENT_SIZE;

    let mut script_builder = bitcoin::script::Builder::new()
        .push_x_only_key(&internal_key)
        .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
        .push_opcode(bitcoin::opcodes::OP_FALSE) // Envelope boundary - matches RawEnvelope
        .push_opcode(bitcoin::opcodes::all::OP_IF)
        .push_slice(b"BIN"); // PROTOCOL_ID

    // BODY_TAG: Use push_slice with empty PushBytes to match RawEnvelope
    // push_slice(&[]) produces byte 0x00 (OP_0), which is interpreted as PushBytes([])
    let empty_body_tag: &bitcoin::script::PushBytes =
        <&bitcoin::script::PushBytes>::try_from(&[][..])
            .expect("Empty slice should convert to PushBytes");
    script_builder = script_builder.push_slice(empty_body_tag);

    // Chunk and push compressed WASM
    let num_chunks = compressed_wasm.len().div_ceil(MAX_SCRIPT_ELEMENT_SIZE);
    println!(
        "  Compressed WASM: {} chunks of up to {} bytes",
        num_chunks, MAX_SCRIPT_ELEMENT_SIZE
    );

    for (i, chunk) in compressed_wasm.chunks(MAX_SCRIPT_ELEMENT_SIZE).enumerate() {
        let push_bytes: &bitcoin::script::PushBytes = chunk
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to convert chunk {} to PushBytes", i))?;
        script_builder = script_builder.push_slice(push_bytes);
        if i == 0 {
            println!(
                "  First chunk: {} bytes (starts with: {})",
                chunk.len(),
                hex::encode(&chunk[..chunk.len().min(10)])
            );
        }
    }

    let script = script_builder
        .push_opcode(bitcoin::opcodes::all::OP_ENDIF)
        .into_script();

    println!("  Script length: {} bytes", script.len());

    // Create Taproot Tree
    let taproot_builder = bitcoin::taproot::TaprootBuilder::new().add_leaf(0, script.clone())?;
    let taproot_spend_info = taproot_builder
        .finalize(&secp, internal_key)
        .map_err(|_| anyhow::anyhow!("Failed to finalize taproot"))?;
    let commit_address = Address::p2tr_tweaked(taproot_spend_info.output_key(), wallet.network);

    println!("Commit Address: {}", commit_address);

    // 5. Construct Commit Transaction
    let commit_input = TxIn {
        previous_output: OutPoint::new(bitcoin::Txid::from_str(txid)?, vout),
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };

    let commit_value = reveal_fee + 546; // Enough for reveal fee + dust
    let change_value = amount_sats - commit_value - commit_fee;

    let commit_output = TxOut {
        value: bitcoin::Amount::from_sat(commit_value),
        script_pubkey: commit_address.script_pubkey(),
    };

    let change_output = TxOut {
        value: bitcoin::Amount::from_sat(change_value),
        script_pubkey: address.script_pubkey(),
    };

    let mut commit_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![commit_input],
        output: vec![commit_output, change_output],
    };

    // Sign Commit Tx (Key Path Spend of Wallet UTXO)
    let mut sighash_cache = SighashCache::new(&mut commit_tx);
    let sighash = sighash_cache.taproot_key_spend_signature_hash(
        0,
        &bitcoin::sighash::Prevouts::All(&[TxOut {
            value: bitcoin::Amount::from_sat(amount_sats),
            script_pubkey: script_pubkey.clone(),
        }]),
        TapSighashType::Default,
    )?;
    let msg = bitcoin::secp256k1::Message::from_digest_slice(&sighash[..])?;
    let tweaked_keypair = keypair.tap_tweak(&secp, None);
    let signature = secp.sign_schnorr_no_aux_rand(&msg, &tweaked_keypair.to_keypair());
    commit_tx.input[0].witness.push(signature.as_ref());

    let commit_tx_hex = serialize_hex(&commit_tx);
    println!("Commit Tx Hex: {}", commit_tx_hex);

    // 6. Construct Reveal Transaction
    let reveal_input = TxIn {
        previous_output: OutPoint::new(commit_tx.compute_txid(), 0),
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };

    let reveal_output = TxOut {
        value: bitcoin::Amount::from_sat(546), // Dust
        script_pubkey: address.script_pubkey(),
    };

    // Create Protostone using protorune-support library
    use protorune_support::protostone::{split_bytes, Protostone};
    use protorune_support::utils::encode_varint_list;

    // Build calldata based on deploy type
    // For CREATE (single deploy): target = [block=1, tx=0], inputs = [opcode]
    // For FACTORY deploy: target = [block=3, tx=factory_id], inputs = [opcode]
    let calldata = if args.factory {
        // Factory deploy: [3, 0, 0] - target.block=3, target.tx=0, opcode=0
        vec![3u128, 0u128, 0u128]
    } else {
        // Single deploy: [1, 0, 0] - target.block=1 (CREATE), target.tx=0, opcode=0 (Initialize)
        vec![1u128, 0u128, 0u128]
    };

    // Encode calldata as varints
    let encoded_calldata = encode_varint_list(&calldata);

    // CRITICAL: Prefix with length byte to survive split_bytes/join_to_bytes roundtrip
    // The roundtrip pads each 15-byte chunk to 15 bytes, adding trailing zeros.
    // By prefixing with the actual length, the runtime can truncate before decoding.
    let mut message_with_length = Vec::with_capacity(encoded_calldata.len() + 1);
    message_with_length.push(encoded_calldata.len() as u8);
    message_with_length.extend(&encoded_calldata);

    // Create Protostone struct
    let protostone = Protostone {
        burn: None,
        message: message_with_length.clone(),
        edicts: vec![],
        refund: Some(0),
        pointer: Some(0),
        from: None,
        protocol_tag: 1, // Alkanes protocol
    };

    // Encipher the protostone to get u128 chunks (matches protostones.encipher())
    // This creates: [protocol_tag, length, ...varints] encoded as varints, then split to u128 chunks
    let protostone_varints = protostone
        .to_integers()
        .context("Failed to convert protostone to integers")?;

    // Build the enciphered format: [protocol_tag, length, ...varints]
    let mut enciphered_values = Vec::<u128>::new();
    enciphered_values.push(protostone.protocol_tag);
    enciphered_values.push(protostone_varints.len() as u128);
    enciphered_values.extend(&protostone_varints);

    // Encode as varints and split to u128 chunks (matches encipher() implementation)
    let mut enciphered_varints = encode_varint_list(&enciphered_values);

    // CRITICAL: Pad to multiple of 15 bytes with TRAILING zeros
    // The split_bytes/join_to_bytes round-trip expects 15-byte chunks.
    // Without padding, short data gets leading zeros which decode as varint 0,
    // causing the protostone parser to stop early (protocol_tag=0 means end).
    let remainder = enciphered_varints.len() % 15;
    if remainder != 0 {
        enciphered_varints.resize(enciphered_varints.len() + (15 - remainder), 0);
    }

    let protostone_chunks = split_bytes(&enciphered_varints);

    // Build Runestone data manually (since ordinals 0.0.9 may not have protocol field)
    // Format: OP_RETURN OP_13 <tag16383: each protostone chunk>
    // Each u128 chunk from protostone_chunks gets encoded with Tag::Protocol (16383)
    let mut runestone_data = Vec::new();

    // Helper to encode a single varint
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

    // Encode each protostone chunk with Tag::Protocol (16383)
    for chunk in &protostone_chunks {
        runestone_data.extend(encode_varint(16383)); // Tag PROTOCOL (2^14 - 1)
        runestone_data.extend(encode_varint(*chunk)); // Protostone chunk value
    }

    // Build OP_RETURN script
    let mut protostone_script = bitcoin::script::Builder::new()
        .push_opcode(bitcoin::opcodes::all::OP_RETURN)
        .push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_13); // Runestone magic number

    // Push the runestone data
    for chunk in runestone_data.chunks(520) {
        let push_bytes = bitcoin::script::PushBytesBuf::try_from(chunk.to_vec())?;
        protostone_script = protostone_script.push_slice(push_bytes.as_push_bytes());
    }

    let runestone_script = protostone_script.into_script();

    // Use the runestone script directly (it's already in the correct format)
    let protostone_output = TxOut {
        value: bitcoin::Amount::ZERO,
        script_pubkey: runestone_script.clone(),
    };

    let mut reveal_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![reveal_input],
        output: vec![reveal_output, protostone_output],
    };

    // Sign Reveal Tx (Script Path Spend)
    let mut sighash_cache = SighashCache::new(&mut reveal_tx);
    let leaf_hash = bitcoin::taproot::TapLeafHash::from_script(
        &script,
        bitcoin::taproot::LeafVersion::TapScript,
    );
    let sighash = sighash_cache.taproot_script_spend_signature_hash(
        0,
        &bitcoin::sighash::Prevouts::All(&[TxOut {
            value: bitcoin::Amount::from_sat(commit_value),
            script_pubkey: commit_address.script_pubkey(),
        }]),
        leaf_hash,
        TapSighashType::Default,
    )?;
    let msg = bitcoin::secp256k1::Message::from_digest_slice(&sighash[..])?;
    let signature = secp.sign_schnorr_no_aux_rand(&msg, &keypair); // Sign with internal key (untweaked)

    // Construct Witness: [Signature, Script, ControlBlock]
    let mut witness = Witness::new();
    witness.push(signature.as_ref());
    witness.push(script.as_bytes());
    witness.push(
        taproot_spend_info
            .control_block(&(script.clone(), bitcoin::taproot::LeafVersion::TapScript))
            .context("No control block")?
            .serialize(),
    );
    reveal_tx.input[0].witness = witness;

    let reveal_tx_hex = serialize_hex(&reveal_tx);

    // 7. Broadcast
    println!("Broadcasting Commit Transaction...");
    let res = client
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
        .context("Failed to broadcast Commit Tx")?;

    let body: serde_json::Value = res.json().await?;
    if let Some(error) = body.get("error") {
        if !error.is_null() {
            println!("Error broadcasting Commit Tx: {:?}", error);
            return Ok(());
        }
    }
    let commit_txid = body["result"].as_str().unwrap_or("unknown");
    println!("Commit Tx Broadcasted: {}", commit_txid);

    // Wait for the commit transaction to propagate in the mempool
    // This matches the TypeScript SDK pattern: await timeout(3000)
    // The reveal transaction needs to reference the commit output, so we wait
    // to ensure the commit is accepted into the mempool before broadcasting reveal
    println!("Waiting 3 seconds for commit transaction to propagate...");
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    println!("Broadcasting Reveal Transaction...");
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
        .context("Failed to broadcast Reveal Tx")?;

    let body: serde_json::Value = res.json().await?;
    if let Some(error) = body.get("error") {
        if !error.is_null() {
            let error_str = format!("{:?}", error);
            println!("Error broadcasting Reveal Tx: {}", error_str);

            // Check for common errors that indicate we need to wait
            if error_str.contains("non-BIP68-final")
                || error_str.contains("missing-inputs")
                || error_str.contains("bad-txns-inputs-missingorspent")
            {
                println!(
                    "\n⚠️  The reveal transaction was rejected because the commit transaction"
                );
                println!("   hasn't been accepted into the mempool yet.");
                println!("\nTry:");
                println!("   1. Wait a few seconds and manually broadcast the reveal:");
                println!("      cargo run -- execute --reveal-tx-hex <reveal_tx_hex>");
                println!("   2. Or mine a block to confirm the commit:");
                println!("      cargo run -- gen-blocks --count 1");
                println!("   3. Then broadcast the reveal transaction");
            }
            return Ok(());
        }
    }
    let reveal_txid = body["result"].as_str().unwrap_or("unknown");
    println!("Reveal Tx Broadcasted: {}", reveal_txid);

    // Verify the transaction was actually accepted
    println!("\n🔍 Verifying transaction was accepted...");
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Try to get the transaction to verify it's in the mempool
    let verify_res = client
        .post(&args.rpc_url)
        .basic_auth(&args.rpc_user, Some(&args.rpc_password))
        .json(&json!({
            "jsonrpc": "1.0",
            "id": "alkanes-cli",
            "method": "btc_getrawtransaction",
            "params": [reveal_txid, false]
        }))
        .send()
        .await;

    match verify_res {
        Ok(res) => {
            let verify_body: serde_json::Value = res.json().await.unwrap_or_default();
            if verify_body.get("result").is_some() {
                println!("✅ Transaction found in mempool/blockchain");
            } else {
                println!("⚠️  Transaction not found yet (may still be propagating)");
            }
        }
        Err(_) => {
            println!("⚠️  Could not verify transaction (this is OK, it may still be propagating)");
        }
    }

    // Debug: Print transaction structure
    println!("\n📋 Reveal Transaction Structure:");
    let num_outputs = reveal_tx.output.len();
    println!(
        "  Output 0: {} sats to {}",
        reveal_tx.output[0].value, address
    );
    println!("  Output 1: OP_RETURN (Protostone)");
    // The protomessage vout is num_outputs + 1 (real outputs + 1 for the protostone virtual output)
    let trace_vout = num_outputs + 1;

    println!("  Total real outputs: {}", num_outputs);
    println!("  Protostone virtual vout: {}", trace_vout);

    println!("\nContract Deployed!");
    println!(
        "Deploy Type: {}",
        if args.factory { "Factory" } else { "Single" }
    );
    println!("\nTo check transaction status, use:");
    println!("  cargo run -- tx-status --txid {}", reveal_txid);
    println!("\nTo trace the deployed contract (after confirmation):");
    println!(
        "  cargo run -- trace --txid {} --vout {}",
        reveal_txid, trace_vout
    );
    println!("\nFor debugging, use the --verbose flag:");
    println!(
        "  cargo run -- trace --txid {} --vout {} --verbose",
        reveal_txid, trace_vout
    );
    println!(
        "\nNote: The transaction may need to be confirmed in a block before tracing is available."
    );

    Ok(())
}
