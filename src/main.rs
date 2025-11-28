use anyhow::Result;
use clap::{Parser, Subcommand};

mod commands;
mod wallet;

#[derive(Parser)]
#[command(name = "alkanes-cli")]
#[command(about = "CLI tool for Alkanes smart contract development", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Deploy a contract
    Deploy(commands::deploy::DeployArgs),
    /// Execute a message on a contract (broadcasts tx)
    Execute(commands::execute::ExecuteArgs),
    /// Simulate a contract call (dry-run via RPC, no tx)
    Simulate(commands::simulate::SimulateArgs),
    /// Generate blocks (Regtest only)
    GenBlocks(commands::gen_blocks::GenBlocksArgs),
    /// Trace an Alkane transaction
    Trace(commands::trace::TraceArgs),
    /// Get transaction status
    TxStatus(commands::tx_status::TxStatusArgs),
    /// Manage wallet
    Wallet(commands::wallet::WalletArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Deploy(args) => commands::deploy::run(args).await?,
        Commands::Execute(args) => commands::execute::run(args).await?,
        Commands::Simulate(args) => commands::simulate::run(args).await?,
        Commands::GenBlocks(args) => commands::gen_blocks::run(args).await?,
        Commands::Trace(args) => commands::trace::run(args).await?,
        Commands::TxStatus(args) => commands::tx_status::run(args).await?,
        Commands::Wallet(args) => commands::wallet::run(args).await?,
    }

    Ok(())
}
