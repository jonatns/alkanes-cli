# Alkanes CLI

A command-line tool for deploying, executing, and managing Alkanes smart contracts on Bitcoin.

## Overview

Alkanes CLI provides a complete toolkit for interacting with the Alkanes protocol, including:

- Deploying smart contracts (single or factory)
- Executing contract messages
- Tracing transaction execution
- Managing wallets
- Simulating contract execution
- Generating blocks (regtest only)

## Installation

### Quick Install (macOS/Linux)

```bash
curl -sSf https://raw.githubusercontent.com/jonatns/alkanes-cli/main/install.sh | bash
```

### Using Cargo

```bash
# From crates.io (when published)
cargo install alkanes-cli

# From git
cargo install --git https://github.com/jonatns/alkanes-cli
```

### Download Pre-built Binaries

Download the latest release for your platform from the [Releases page](https://github.com/jonatns/alkanes-cli/releases).

### Build from Source

```bash
git clone https://github.com/jonatns/alkanes-cli.git
cd alkanes-cli
cargo build --release
```

The binary will be available at `target/release/alkanes`.

### Prerequisites

- Bitcoin Core or compatible node running with RPC enabled
- Metashrew indexer running (for tracing and transaction status)

### Development

For development, you can run commands directly with Cargo:

```bash
cargo run -- <command> [args...]
```

## Quick Start

1. **Create a wallet:**

   ```bash
   alkanes wallet new --network regtest
   ```

2. **Deploy a contract:**

   ```bash
   cargo run -- deploy --wasm path/to/contract.wasm
   ```

3. **Trace a transaction:**
   ```bash
   cargo run -- trace --txid <txid> --vout 4
   ```

## Commands

### Wallet Management

#### Create a new wallet

```bash
cargo run -- wallet new [--network <network>]
```

Creates a new wallet with a generated mnemonic phrase. The wallet is stored locally.

**Options:**

- `--network`: Network to use (`bitcoin`, `testnet`, `signet`, `regtest`). Default: `regtest`

**Example:**

```bash
cargo run -- wallet new --network regtest
```

#### Import a wallet from mnemonic

```bash
cargo run -- wallet import --mnemonic "<phrase>" [--network <network>]
```

Imports an existing wallet from a mnemonic phrase.

**Example:**

```bash
cargo run -- wallet import --mnemonic "word1 word2 ... word12" --network regtest
```

#### Show wallet information

```bash
cargo run -- wallet info
```

Displays wallet address and other information.

### Deploy Contract

Deploy a smart contract using the commit-reveal scheme.

```bash
cargo run -- deploy --wasm <path> [options]
```

**Options:**

- `--wasm <path>`: Path to the WASM file (required)
- `--output <path>`: Optional path to save compressed WASM
- `--factory`: Deploy as a factory contract (default: single contract)
- `--rpc-url <url>`: RPC URL (default: `http://127.0.0.1:18888`)
- `--rpc-user <user>`: RPC username (default: `user`)
- `--rpc-password <password>`: RPC password (default: `password`)

**Examples:**

Deploy a single contract:

```bash
cargo run -- deploy --wasm ./contract.wasm
```

Deploy a factory contract:

```bash
cargo run -- deploy --wasm ./factory.wasm --factory
```

Deploy with custom RPC settings:

```bash
cargo run -- deploy --wasm ./contract.wasm \
  --rpc-url http://localhost:8332 \
  --rpc-user myuser \
  --rpc-password mypassword
```

**What it does:**

1. Loads your wallet
2. Compresses the WASM file
3. Creates a commit transaction (locking funds to a Taproot address)
4. Creates a reveal transaction (spending the commit output with the contract code)
5. Broadcasts both transactions
6. Provides the transaction IDs for tracing

**Note:** After deployment, wait for the transactions to be confirmed before tracing. Use `gen-blocks` on regtest to mine blocks.

### Execute Contract

Construct a message to execute on a deployed contract.

```bash
cargo run -- execute --target <block:tx> --inputs <values...>
```

**Options:**

- `--target <block:tx>`: Target Alkane ID in format `block:tx` (required)
- `--inputs <values...>`: Space-separated u128 input values

**Example:**

```bash
cargo run -- execute --target 1:0 --inputs 42 100 0
```

### Trace Transaction

Retrieve the execution trace of an Alkane transaction.

```bash
cargo run -- trace --txid <txid> [--vout <index>] [options]
```

**Options:**

- `--txid <txid>`: Transaction ID to trace (required)
- `--vout <index>`: Output index (default: `0`, typically `4` for deployments)
- `--rpc-url <url>`: RPC URL (default: `http://127.0.0.1:18888`)
- `--rpc-user <user>`: RPC username (default: `user`)
- `--rpc-password <password>`: RPC password (default: `password`)
- `--verbose`: Show verbose debugging information

**Examples:**

Trace a deployment transaction:

```bash
cargo run -- trace --txid 439f12c851d0c6e62f2b425918a --vout 4
```

Trace with verbose output:

```bash
cargo run -- trace --txid <txid> --vout 4 --verbose
```

**Note:** The transaction ID must be byte-order reversed for the RPC call. The CLI handles this automatically.

### Transaction Status

Check the status of a Bitcoin transaction.

```bash
cargo run -- tx-status --txid <txid> [options]
```

**Options:**

- `--txid <txid>`: Transaction ID to check (required)
- `--rpc-url <url>`: RPC URL (default: `http://127.0.0.1:18888`)
- `--rpc-user <user>`: RPC username (default: `user`)
- `--rpc-password <password>`: RPC password (default: `password`)

**Example:**

```bash
cargo run -- tx-status --txid 439f12c851d0c6e62f2b425918a
```

### Generate Blocks (Regtest Only)

Generate blocks on a regtest network.

```bash
cargo run -- gen-blocks [--count <n>] [--address <addr>] [options]
```

**Options:**

- `--count <n>`: Number of blocks to generate (default: `1`)
- `--address <addr>`: Address to mine to (optional, uses wallet address if not provided)
- `--rpc-url <url>`: RPC URL (default: `http://127.0.0.1:18888`)
- `--rpc-user <user>`: RPC username (default: `user`)
- `--rpc-password <password>`: RPC password (default: `password`)

**Examples:**

Generate one block:

```bash
cargo run -- gen-blocks
```

Generate multiple blocks:

```bash
cargo run -- gen-blocks --count 6
```

Generate blocks to a specific address:

```bash
cargo run -- gen-blocks --count 1 --address bcrt1p...
```

### Simulate Contract

Validate and simulate a WASM contract locally.

```bash
cargo run -- simulate --wasm <path>
```

**Options:**

- `--wasm <path>`: Path to the WASM file (required)

**Example:**

```bash
cargo run -- simulate --wasm ./contract.wasm
```

This command validates that the WASM file is a valid WebAssembly module and shows its exports. Full execution simulation requires mocking the Alkanes host environment.

## Configuration

### RPC Settings

Most commands support custom RPC settings via command-line arguments:

- `--rpc-url`: Bitcoin RPC endpoint
- `--rpc-user`: RPC username
- `--rpc-password`: RPC password

Default values:

- URL: `http://127.0.0.1:18888`
- User: `user`
- Password: `password`

### Wallet Storage

Wallets are stored in the platform-specific application data directory:

- **macOS**: `~/Library/Application Support/alkanes-cli/wallet.json`
- **Linux**: `~/.local/share/alkanes-cli/wallet.json`
- **Windows**: `%APPDATA%\alkanes-cli\wallet.json`

## Workflow Example

Here's a complete workflow for deploying and testing a contract on regtest:

```bash
# 1. Create a wallet
cargo run -- wallet new --network regtest

# 2. Get some funds (if needed, mine to your address)
cargo run -- gen-blocks --count 100

# 3. Deploy your contract
cargo run -- deploy --wasm ./my_contract.wasm

# 4. Wait for confirmation (mine a block)
cargo run -- gen-blocks --count 1

# 5. Trace the deployment
cargo run -- trace --txid <reveal_txid> --vout 4

# 6. Check transaction status
cargo run -- tx-status --txid <reveal_txid>
```

## Troubleshooting

### "No wallet found"

Create a wallet first:

```bash
cargo run -- wallet new
```

### "Failed to fill whole buffer" error

This indicates the WASM binary wasn't correctly extracted from the witness. Ensure:

- The reveal transaction is confirmed
- You're using the correct `--vout` (typically `4` for deployments)
- The transaction was properly indexed by Metashrew

### Empty trace results

If tracing returns an empty array:

1. Check the transaction status: `cargo run -- tx-status --txid <txid>`
2. Ensure the transaction is confirmed (mine blocks if on regtest)
3. Wait a few seconds for indexing
4. Verify you're using the correct `--vout` parameter

### Transaction not found

- Ensure your Bitcoin node is synced
- Check that the transaction was broadcast successfully
- Verify the transaction ID is correct

### RPC connection errors

- Verify your Bitcoin node is running
- Check RPC credentials match your `bitcoin.conf`
- Ensure the RPC port is accessible
- For regtest, default port is `18888`

## Development

### Project Structure

```
alkanes-cli/
├── src/
│   ├── main.rs           # CLI entry point
│   ├── wallet.rs         # Wallet management
│   └── commands/
│       ├── deploy.rs     # Contract deployment
│       ├── execute.rs     # Contract execution
│       ├── trace.rs       # Transaction tracing
│       ├── tx_status.rs   # Transaction status
│       ├── gen_blocks.rs  # Block generation
│       ├── simulate.rs   # Contract simulation
│       └── wallet.rs      # Wallet commands
└── Cargo.toml
```

### Dependencies

Key dependencies:

- `bitcoin`: Bitcoin protocol support
- `alkanes-runtime`: Alkanes runtime
- `alkanes-support`: Alkanes support libraries
- `protorune-support`: Protostone encoding
- `metashrew-support`: Metashrew indexer support
- `wasmtime`: WebAssembly runtime
- `clap`: Command-line argument parsing

## License

[Add your license information here]

## Contributing

[Add contribution guidelines here]

## Support

For issues and questions, please open an issue on the GitHub repository.
