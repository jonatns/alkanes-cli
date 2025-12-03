use crate::commands::deploy::{deploy_contract, mine_blocks, trace_and_get_id, DeployArgs};
use crate::commands::execute::{self, ExecuteArgs};
use crate::commands::trace::{self, TraceArgs};
use crate::wallet::{default_wallet_path, Wallet};
use anyhow::{Context, Result};
use clap::Args;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

#[derive(Args)]
pub struct ApplyArgs {
    /// Path to the manifest file
    #[arg(long, default_value = "alkanes.yaml")]
    pub manifest: PathBuf,
}

#[derive(Deserialize, Debug)]
struct Manifest {
    settings: Settings,
    deployments: Vec<Deployment>,
}

#[derive(Deserialize, Debug)]
struct Settings {
    rpc_url: String,
    #[serde(default = "default_rpc_user")]
    rpc_user: String,
    #[serde(default = "default_rpc_password")]
    rpc_password: String,
    #[serde(default = "default_fee_rate")]
    fee_rate: u64,
    #[serde(default)]
    mining_blocks: u64,
}

fn default_rpc_user() -> String {
    "user".to_string()
}

fn default_rpc_password() -> String {
    "password".to_string()
}

fn default_fee_rate() -> u64 {
    10
}

#[derive(Deserialize, Debug)]
struct Deployment {
    id: String,
    wasm: Option<String>,
    #[serde(default)]
    calldata: Vec<String>, // Strings to allow variables like ${id.block}
    #[serde(rename = "type")]
    deploy_type: Option<String>, // "factory", "beacon", "proxy", "context_proxy", or "contract" (default)
    reserved_tx: Option<u128>,
    deploy_opcode: Option<u128>,
    logic: Option<String>,          // For "beacon" type
    implementation: Option<String>, // For "context_proxy" type
    auth_token: Option<u128>,       // For "beacon" and "context_proxy" types
    initialize: Option<Initialization>,
}

#[derive(Deserialize, Debug)]
struct Initialization {
    inputs: Vec<String>,
}

struct ContractInfo {
    block: u128,
    tx: u128,
}

pub async fn run(args: ApplyArgs) -> Result<()> {
    // 1. Load Manifest
    let mut file = File::open(&args.manifest).context("Failed to open manifest file")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let manifest: Manifest = serde_yaml::from_str(&contents).context("Failed to parse manifest")?;

    // 2. Load Wallet
    let wallet_path = default_wallet_path()?;
    if !wallet_path.exists() {
        anyhow::bail!("No wallet found. Run 'wallet new' or 'wallet import' first.");
    }
    let wallet = Wallet::load(&wallet_path)?;
    let address = wallet.get_address(0)?;
    println!("Using address: {}", address);

    let client = Client::new();
    let mut context: HashMap<String, ContractInfo> = HashMap::new();

    // 3. Validate Manifest
    validate_manifest(&manifest)?;

    // 4. Execute Deployments
    for deployment in manifest.deployments {
        println!("\n🚀 Processing deployment: {}", deployment.id);

        // Resolve WASM path
        let wasm_bytes = if let Some(wasm_path) = &deployment.wasm {
            if wasm_path == "embedded" {
                // Explicit embedded request
                if deployment.id.contains("beacon") {
                    include_bytes!("../assets/alkanes_std_upgradeable_beacon.wasm").to_vec()
                } else if deployment.id.contains("proxy") {
                    include_bytes!("../assets/alkanes_std_beacon_proxy.wasm").to_vec()
                } else {
                    anyhow::bail!("Unknown embedded WASM for {}", deployment.id);
                }
            } else {
                let mut file = File::open(wasm_path)
                    .context(format!("Failed to open WASM file: {}", wasm_path))?;
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer)?;
                buffer
            }
        } else {
            // Default based on type
            match deployment.deploy_type.as_deref() {
                Some("beacon") => {
                    include_bytes!("../assets/alkanes_std_upgradeable_beacon.wasm").to_vec()
                }
                Some("proxy") => include_bytes!("../assets/alkanes_std_beacon_proxy.wasm").to_vec(),
                _ => anyhow::bail!("WASM path required for deployment {}", deployment.id),
            }
        };

        // Resolve Calldata
        let mut resolved_calldata = Vec::new();

        // Check if explicit calldata is provided, otherwise generate based on type
        let calldata_source = if !deployment.calldata.is_empty() {
            deployment.calldata
        } else {
            match deployment.deploy_type.as_deref() {
                Some("factory") => {
                    let reserved_tx = deployment
                        .reserved_tx
                        .context("Factory deployment requires 'reserved_tx'")?;
                    let mut inputs = vec!["3".to_string(), reserved_tx.to_string()];
                    if let Some(opcode) = deployment.deploy_opcode {
                        inputs.push(opcode.to_string());
                    }
                    inputs
                }
                Some("beacon") => {
                    let reserved_tx = deployment
                        .reserved_tx
                        .context("Beacon deployment requires 'reserved_tx'")?;
                    let logic_id = deployment
                        .logic
                        .as_ref()
                        .context("Beacon deployment requires 'logic' (contract ID)")?;
                    let logic_id = strip_variable_wrapper(logic_id);
                    let auth_token = deployment.auth_token.unwrap_or(1);
                    vec![
                        "3".to_string(),
                        reserved_tx.to_string(),
                        "32767".to_string(), // 0x7fff (Salt)
                        format!("${{{}.block}}", logic_id),
                        format!("${{{}.tx}}", logic_id),
                        auth_token.to_string(),
                    ]
                }
                Some("proxy") => {
                    let reserved_tx = deployment
                        .reserved_tx
                        .context("Proxy deployment requires 'reserved_tx'")?;
                    vec![
                        "3".to_string(),
                        reserved_tx.to_string(),
                        "36863".to_string(), // 0x8fff (Salt)
                    ]
                }
                Some("context_proxy") => {
                    let reserved_tx = deployment
                        .reserved_tx
                        .context("Context Proxy deployment requires 'reserved_tx'")?;
                    let implementation_id = deployment.implementation.as_ref().context(
                        "Context Proxy deployment requires 'implementation' (contract ID)",
                    )?;
                    let implementation_id = strip_variable_wrapper(implementation_id);
                    let auth_token = deployment.auth_token.unwrap_or(1);

                    vec![
                        "3".to_string(),
                        reserved_tx.to_string(),
                        "32767".to_string(), // 0x7fff (Salt)
                        format!("${{{}.block}}", implementation_id),
                        format!("${{{}.tx}}", implementation_id),
                        auth_token.to_string(),
                    ]
                }
                _ => {
                    // Default "contract" type: [1, 0]
                    vec!["1".to_string(), "0".to_string()]
                }
            }
        };

        for item in calldata_source {
            let val = resolve_variable(&item, &context)?;
            resolved_calldata.push(val);
        }

        // Construct DeployArgs (dummy values for unused fields)
        let deploy_args = DeployArgs {
            wasm: PathBuf::from(deployment.wasm.as_deref().unwrap_or("embedded")),
            output: None,
            factory: deployment.deploy_type.as_deref() == Some("factory"),
            rpc_url: manifest.settings.rpc_url.clone(),
            rpc_user: manifest.settings.rpc_user.clone(),
            rpc_password: manifest.settings.rpc_password.clone(),
            reserved_tx: deployment.reserved_tx,
            salt: deployment.deploy_opcode,
            calldata: None, // We pass calldata directly
        };

        let label = match deployment.deploy_type.as_deref() {
            Some("factory") => "Factory",
            Some("beacon") => "Beacon",
            Some("proxy") => "Proxy",
            Some("context_proxy") => "ContextProxy",
            _ => "Contract",
        };

        // Deploy
        let (txid, vout) = deploy_contract(
            wasm_bytes,
            resolved_calldata,
            &deploy_args,
            &wallet,
            &client,
            label,
        )
        .await?;

        println!("✅ Deployed {} at {}:{}", deployment.id, txid, vout);

        // Mine blocks if configured
        if manifest.settings.mining_blocks > 0 {
            mine_blocks(
                &client,
                &manifest.settings.rpc_url,
                (&manifest.settings.rpc_user, &manifest.settings.rpc_password),
                &address.to_string(),
                manifest.settings.mining_blocks,
            )
            .await?;
        }

        // Trace
        println!("⏳ Waiting for trace...");
        let (block, tx) = trace_and_get_id(
            &client,
            &manifest.settings.rpc_url,
            (&manifest.settings.rpc_user, &manifest.settings.rpc_password),
            &txid,
            vout,
        )
        .await?;

        println!("✅ Resolved ID for {}: {}:{}", deployment.id, block, tx);
        context.insert(deployment.id.clone(), ContractInfo { block, tx });

        // Initialize if needed
        if let Some(init) = deployment.initialize {
            println!("🔧 Initializing {}...", deployment.id);

            let mut resolved_inputs = Vec::new();
            for item in init.inputs {
                // If it resolves to a number, keep it as string representation of number
                // If it's a raw string, keep it
                // resolve_variable returns u128. We need to handle string inputs too?
                // The DSL plan said inputs are strings.
                // But resolve_variable returns u128.
                // Let's modify resolve_variable to return String, and parse if needed.

                if item.starts_with("${") && item.ends_with("}") {
                    let val = resolve_variable(&item, &context)?;
                    resolved_inputs.push(val.to_string());
                } else {
                    resolved_inputs.push(item);
                }
            }

            let exec_args = ExecuteArgs {
                target: format!("{}:{}", block, tx),
                inputs: resolved_inputs,
                wallet: None,
                fee_rate: manifest.settings.fee_rate,
                rpc_url: manifest.settings.rpc_url.clone(),
                rpc_user: manifest.settings.rpc_user.clone(),
                rpc_password: manifest.settings.rpc_password.clone(),
                dry_run: false,
            };

            let txid = execute::run(exec_args).await?;

            // Mine block for initialization if configured
            if manifest.settings.mining_blocks > 0 {
                mine_blocks(
                    &client,
                    &manifest.settings.rpc_url,
                    (&manifest.settings.rpc_user, &manifest.settings.rpc_password),
                    &address.to_string(),
                    manifest.settings.mining_blocks,
                )
                .await?;

                // Trace initialization to ensure success
                println!("⏳ Verifying initialization...");
                let trace_args = TraceArgs {
                    txid: txid.clone(),
                    vout: 4, // Vout 4 is the protocol output for execution
                    rpc_url: manifest.settings.rpc_url.clone(),
                    rpc_user: manifest.settings.rpc_user.clone(),
                    rpc_password: manifest.settings.rpc_password.clone(),
                    verbose: false,
                };

                // We need to wait a bit for the indexer to catch up
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;

                match trace::run(trace_args).await {
                    Ok(trace_output) => {
                        if let Some(status) = trace_output.status {
                            if status != 0 {
                                anyhow::bail!(
                                    "❌ Initialization failed with status {}: {}",
                                    status,
                                    trace_output.error.unwrap_or_default()
                                );
                            }
                        } else {
                            // If status is missing but we got a trace, it might be an issue or just how trace works
                            // But usually trace returns status.
                            // If trace is empty/null, trace::run usually errors or returns None?
                            // trace::run returns Result<TraceResponse>
                        }
                    }
                    Err(e) => {
                        anyhow::bail!("❌ Failed to trace initialization transaction: {}", e);
                    }
                }
            }
            println!("✅ Initialization confirmed.");
        }
    }

    Ok(())
}

fn validate_manifest(manifest: &Manifest) -> Result<()> {
    let defined_ids: std::collections::HashSet<&String> =
        manifest.deployments.iter().map(|d| &d.id).collect();

    for deployment in &manifest.deployments {
        // Validate explicit calldata
        for item in &deployment.calldata {
            validate_variable(item, &defined_ids)?;
        }

        // Validate typed fields
        if let Some(logic) = &deployment.logic {
            validate_variable(logic, &defined_ids)?;
        }
        if let Some(implementation) = &deployment.implementation {
            validate_variable(implementation, &defined_ids)?;
        }

        // Validate initialization inputs
        if let Some(init) = &deployment.initialize {
            for item in &init.inputs {
                validate_variable(item, &defined_ids)?;
            }
        }
    }
    Ok(())
}

fn validate_variable(input: &str, defined_ids: &std::collections::HashSet<&String>) -> Result<()> {
    if input.starts_with("${") && input.ends_with("}") {
        let content = &input[2..input.len() - 1];
        let parts: Vec<&str> = content.split('.').collect();

        let id = if parts.len() == 2 {
            parts[0]
        } else if parts.len() == 1 {
            parts[0]
        } else {
            anyhow::bail!("Invalid variable format: {}", input);
        };

        if !defined_ids.contains(&id.to_string()) {
            anyhow::bail!("Reference to unknown contract ID: {}", id);
        }
    }
    Ok(())
}

fn strip_variable_wrapper(input: &str) -> &str {
    if input.starts_with("${") && input.ends_with("}") {
        &input[2..input.len() - 1]
    } else {
        input
    }
}

fn resolve_variable(input: &str, context: &HashMap<String, ContractInfo>) -> Result<u128> {
    if input.starts_with("${") && input.ends_with("}") {
        let content = &input[2..input.len() - 1];
        let parts: Vec<&str> = content.split('.').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid variable format: {}", input);
        }
        let id = parts[0];
        let field = parts[1];

        let info = context
            .get(id)
            .context(format!("Unknown contract ID: {}", id))?;
        match field {
            "block" => Ok(info.block),
            "tx" => Ok(info.tx),
            _ => anyhow::bail!("Unknown field: {}", field),
        }
    } else {
        input
            .parse::<u128>()
            .context(format!("Invalid number: {}", input))
    }
}
