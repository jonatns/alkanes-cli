use alkanes_support::cellpack::Cellpack;
use alkanes_support::id::AlkaneId;
use anyhow::{Context, Result};
use clap::Args;

#[derive(Args)]
pub struct ExecuteArgs {
    /// Target Alkane ID (format: block:tx)
    #[arg(short, long)]
    pub target: String,

    /// Inputs (space separated u128 values)
    #[arg(short, long, value_delimiter = ' ')]
    pub inputs: Vec<u128>,
}

pub async fn run(args: ExecuteArgs) -> Result<()> {
    println!("Executing message on target: {}", args.target);

    let parts: Vec<&str> = args.target.split(':').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid Alkane ID format. Expected block:tx");
    }

    let block: u128 = parts[0].parse().context("Invalid block number")?;
    let tx: u128 = parts[1].parse().context("Invalid tx index")?;
    let target_id = AlkaneId { block, tx };

    let cellpack = Cellpack {
        target: target_id,
        inputs: args.inputs.clone(),
    };

    // Serialize the cellpack to bytes (if Cellpack supports it, or manually)
    // For now, we'll just print the structure
    println!("Constructed Cellpack:");
    println!("Target: {:?}", cellpack.target);
    println!("Inputs: {:?}", cellpack.inputs);

    // TODO: Serialize to actual protocol format and print hex
    // This requires knowing the exact serialization format of Cellpack which is likely in alkanes-support
    // Assuming standard serialization if available, otherwise just debug print.

    println!(
        "To execute this, you would construct a transaction with this payload in the witness data."
    );

    Ok(())
}
