use anyhow::{Context, Result};
use bip39::{Mnemonic, Language};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::bip32::{Xpriv, DerivationPath};
use bitcoin::{Network, Address, PrivateKey};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::fs;
use rand::RngCore;

#[derive(Serialize, Deserialize)]
pub struct WalletData {
    pub mnemonic: String,
    pub network: String,
}

pub struct Wallet {
    pub mnemonic: Mnemonic,
    pub network: Network,
}

impl Wallet {
    pub fn new(network: Network) -> Result<Self> {
        let mut rng = rand::thread_rng();
        let mut entropy = [0u8; 16]; // 128 bits for 12 words
        rng.fill_bytes(&mut entropy);
        // bip39 v2 from_entropy takes only entropy, language is implied or not needed for generation from entropy in this version
        let mnemonic = Mnemonic::from_entropy(&entropy)
            .context("Failed to generate mnemonic")?;
        Ok(Self { mnemonic, network })
    }

    pub fn from_mnemonic(phrase: &str, network: Network) -> Result<Self> {
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)
            .context("Invalid mnemonic phrase")?;
        Ok(Self { mnemonic, network })
    }

    pub fn save(&self, path: &PathBuf) -> Result<()> {
        let data = WalletData {
            mnemonic: self.mnemonic.to_string(),
            network: self.network.to_string(),
        };
        let json = serde_json::to_string_pretty(&data)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, json)?;
        Ok(())
    }

    pub fn load(path: &PathBuf) -> Result<Self> {
        let content = fs::read_to_string(path).context("Failed to read wallet file")?;
        let data: WalletData = serde_json::from_str(&content).context("Failed to parse wallet file")?;
        
        let network = match data.network.as_str() {
            "bitcoin" => Network::Bitcoin,
            "testnet" => Network::Testnet,
            "signet" => Network::Signet,
            "regtest" => Network::Regtest,
            _ => Network::Regtest,
        };

        Self::from_mnemonic(&data.mnemonic, network)
    }

    pub fn get_address(&self, index: u32) -> Result<Address> {
        let seed = self.mnemonic.to_seed("");
        let secp = Secp256k1::new();
        let root = Xpriv::new_master(self.network, &seed)?;
        
        // Derivation path: m/86'/1'/0'/0/index (BIP86 for Taproot on Testnet/Regtest)
        let coin_type = if self.network == Network::Bitcoin { 0 } else { 1 };
        let path_str = format!("m/86'/{}'/0'/0/{}", coin_type, index);
        let path: DerivationPath = path_str.parse()?;
        
        let child_priv = root.derive_priv(&secp, &path)?;
        let private_key = PrivateKey::new(child_priv.private_key, self.network);
        let pubkey = private_key.public_key(&secp);
        let xonly = pubkey.inner.x_only_public_key().0;
        let address = Address::p2tr(&secp, xonly, None, self.network);
        
        Ok(address)
    }
    
    pub fn get_privkey(&self, index: u32) -> Result<PrivateKey> {
        let seed = self.mnemonic.to_seed("");
        let secp = Secp256k1::new();
        let root = Xpriv::new_master(self.network, &seed)?;
        
        let coin_type = if self.network == Network::Bitcoin { 0 } else { 1 };
        let path_str = format!("m/86'/{}'/0'/0/{}", coin_type, index);
        let path: DerivationPath = path_str.parse()?;
        
        let child_priv = root.derive_priv(&secp, &path)?;
        Ok(PrivateKey::new(child_priv.private_key, self.network))
    }
}

pub fn default_wallet_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not find home directory")?;
    Ok(home.join(".alkanes").join("wallet.json"))
}
