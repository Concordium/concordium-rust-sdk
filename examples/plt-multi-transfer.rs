//! Example that shows how to transfer (PLT) tokens.
use anyhow::Context;
use clap::AppSettings;
use concordium_base::{
    base::Energy,
    contracts_common::AccountAddress,
    protocol_level_tokens::{
        meta_operations::meta_operations, ConversionRule, TokenAmount, TokenId,
    },
    transactions::{construct, cost},
};
use concordium_rust_sdk::{
    common::types::TransactionTime,
    types::{transactions::BlockItem, WalletAccount},
    v2::{self, BlockIdentifier},
};
use rust_decimal::Decimal;
use std::{path::PathBuf, str::FromStr};
use structopt::*;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "V2 GRPC interface of the node.",
        default_value = "http://localhost:20000"
    )]
    endpoint: v2::Endpoint,
    #[structopt(long = "sender", help = "Path to the sender account key file.")]
    account: PathBuf,
    #[structopt(long = "receiver", help = "Default receiver address.")]
    receiver: Option<String>,
    #[structopt(parse(try_from_str), help = "amount:token[:receiver]")]
    transfers: Vec<Transfer>,
}

#[derive(Debug)]
struct Transfer {
    amount: Decimal,
    token: String,
    receiver: Option<AccountAddress>,
}

impl FromStr for Transfer {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() < 2 || parts.len() > 3 {
            anyhow::bail!("Invalid transfer format. Expected amount:token[:receiver]");
        }
        let amount = Decimal::from_str(parts[0])?;
        let token = parts[1].to_string();
        let receiver = if parts.len() == 3 {
            Some(AccountAddress::from_str(parts[2])?)
        } else {
            None
        };
        Ok(Transfer {
            amount,
            token,
            receiver,
        })
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };
    let mut client = v2::Client::new(app.endpoint).await?;

    let mut token_decimals_cache = std::collections::HashMap::<TokenId, u8>::new();
    let mut transfers = Vec::with_capacity(app.transfers.len());

    for transfer in app.transfers {
        // Token id of the PLT token to transfer
        let token_id = TokenId::try_from(transfer.token.clone())?;

        // Token info, we need the number of decimals in the token amount representation
        let decimals = if let Some(decimals) = token_decimals_cache.get(&token_id) {
            *decimals
        } else {
            let info = client
                .get_token_info(token_id.clone(), BlockIdentifier::LastFinal)
                .await?
                .response;
            token_decimals_cache.insert(token_id.clone(), info.token_state.decimals);
            info.token_state.decimals
        };

        // Amount of tokens to send. The number of decimals in the TokenAmount
        // must be the same as the number of decimals in the TokenInfo
        let token_amount = TokenAmount::try_from_rust_decimal(
            transfer.amount,
            decimals,
            ConversionRule::AllowRounding,
        )?;
        println!("Token amount: {}", token_amount,);

        // Receiver of the tokens
        let receiver_address = if let Some(addr) = transfer.receiver {
            addr
        } else if let Some(addr) = &app.receiver {
            AccountAddress::from_str(addr)?
        } else {
            anyhow::bail!("No receiver specified for transfer.");
        };

        println!(
            "Transfer {} {} to {}",
            token_amount, token_id, receiver_address
        );
        let transfer = meta_operations::transfer_tokens(token_id, receiver_address, token_amount);
        transfers.push(transfer);
    }

    // Load account keys and sender address from a file
    let keys: WalletAccount = WalletAccount::from_json_file(app.account)
        .context("Could not read the account keys file.")?;

    // Get the initial nonce at the last finalized block.
    let nonce = client
        .get_next_account_sequence_number(&keys.address)
        .await?
        .nonce;

    // Set expiry to now + 5min
    let expiry: TransactionTime =
        TransactionTime::from_seconds((chrono::Utc::now().timestamp() + 300) as u64);

    let energy = construct::GivenEnergy::Add {
        num_sigs: transfers.len() as u32,
        energy: cost::META_UPDATE_TRANSACTIONS
            + Energy {
                energy: cost::PLT_TRANSFER.energy * transfers.len() as u64,
            },
    };
    let txn = construct::meta_update_operations(
        energy,
        keys.address,
        nonce,
        expiry,
        &transfers.into_iter().collect(),
    )
    .sign(&keys);

    let item = BlockItem::AccountTransaction(txn);

    // Submit the transaction to the chain
    let transaction_hash = client.send_block_item(&item).await?;
    println!(
        "Transaction {} submitted (nonce = {}).",
        transaction_hash, nonce,
    );
    let (bh, bs) = client.wait_until_finalized(&transaction_hash).await?;
    println!("Transaction finalized in block {}.", bh);
    println!("The outcome is {:#?}", bs);

    Ok(())
}
