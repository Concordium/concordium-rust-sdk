//! Basic example that shows how to send transactions related to encrypted
//! transfers, encrypting, decrypting, and sending encrypted transfers.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    common::{
        types::{Amount, TransactionTime},
        SerdeDeserialize, SerdeSerialize,
    },
    id,
    id::types::{AccountAddress, AccountKeys},
    types::{transactions::send, EncryptedAmountDecryptionContext},
    v2,
};
use std::{path::PathBuf, str::FromStr};
use structopt::*;

#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
/// Account address and keys that will be supplied in a JSON file.
/// The transaction will be signed with the given keys.
struct AccountData {
    account_keys:          AccountKeys,
    address:               AccountAddress,
    encryption_secret_key: id::elgamal::SecretKey<id::constants::ArCurve>,
}

enum Receiver {
    Encrypt,
    Decrypt,
    Transfer(AccountAddress),
}

impl FromStr for Receiver {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "encrypt" => Self::Encrypt,
            "decrypt" => Self::Decrypt,
            s => Self::Transfer(s.parse()?),
        })
    }
}

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10001"
    )]
    endpoint:  v2::Endpoint,
    #[structopt(long = "account", help = "Path to the account key file.")]
    keys_path: PathBuf,
    #[structopt(
        long = "amount",
        help = "Amount to send or encrypt/decrypt.",
        default_value = "1.0"
    )]
    amount:    Amount,
    #[structopt(
        long = "receiver",
        help = "Receiver, one of `encrypt`, `decrypt` or an account address."
    )]
    receiver:  Receiver,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };
    let mut client = v2::Client::new(app.endpoint)
        .await
        .context("Cannot connect.")?;

    // load account keys and sender address from a file
    let keys: AccountData = serde_json::from_str(&std::fs::read_to_string(app.keys_path).context(
        "Could not read the keys
    file.",
    )?)
    .context("Could not parse the keys file.")?;

    // Get the initial nonce at the last finalized block.
    let ai = client
        .get_account_info(&keys.address.into(), &v2::BlockIdentifier::LastFinal)
        .await?;

    let block = ai.block_hash;

    let nonce = ai.response.account_nonce;
    // set expiry to now + 5min
    let expiry: TransactionTime =
        TransactionTime::from_seconds((chrono::Utc::now().timestamp() + 300) as u64);

    let ctx = client.get_cryptographic_parameters(block).await?.response;

    let mut rng = rand::thread_rng();

    let tx = match app.receiver {
        Receiver::Decrypt => {
            let amount = ai.response.account_encrypted_amount;
            let table = EncryptedAmountDecryptionContext::new(&ctx);
            let data = amount.make_transfer_to_public_data(
                &table,
                &keys.encryption_secret_key,
                app.amount,
                &mut rng,
            )?;
            send::transfer_to_public(&keys.account_keys, keys.address, nonce, expiry, data)
        }
        Receiver::Encrypt => {
            send::transfer_to_encrypted(&keys.account_keys, keys.address, nonce, expiry, app.amount)
        }
        Receiver::Transfer(addr) => {
            let receiver = client.get_account_info(&addr.into(), block).await?;

            let table = EncryptedAmountDecryptionContext::new(&ctx);
            let amount = ai.response.account_encrypted_amount;
            let data = amount.make_encrypted_transfer_data(
                &table,
                &keys.encryption_secret_key,
                app.amount,
                &receiver.response.account_encryption_key,
                &mut rng,
            )?;
            send::encrypted_transfer(&keys.account_keys, keys.address, nonce, expiry, addr, data)
        }
    };

    let transaction_hash = client.send_account_transaction(tx).await?;
    println!(
        "Transaction {} submitted (nonce = {}).",
        transaction_hash, nonce,
    );
    println!("Waiting until finalized.");
    let (bh, bs) = client.wait_until_finalized(&transaction_hash).await?;
    println!("Transaction finalized in block {}.", bh);
    println!("The outcome is {:#?}", bs);

    Ok(())
}
