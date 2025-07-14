//! Example that shows how to use the TokenClient
use anyhow::Context;
use clap::AppSettings;
use concordium_base::{
    contracts_common::AccountAddress,
    protocol_level_tokens::{ConversionRule, TokenAmount, TokenId},
};
use concordium_rust_sdk::{
    common::types::TransactionTime,
    protocol_level_tokens::token_client::{self, TransactionMetadata, TransferTokens},
    types::WalletAccount,
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
    account:  PathBuf,
    #[structopt(long = "receiver", help = "Target account address.")]
    receiver: String,
    #[structopt(long = "token", help = "Token id of token.")]
    token_id: String,
    #[structopt(
        long = "amount",
        help = "Optional amount to send/mint/burn.",
        default_value = "100.0"
    )]
    amount:   Decimal,
    #[structopt(subcommand)]
    cmd:      Action,
}

/// TokenClient operations
#[derive(StructOpt)]
enum Action {
    Mint,
    Burn,
    Transfer,
    AddAllow,
    RemoveAllow,
    AddDeny,
    RemoveDeny,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };
    let mut client = v2::Client::new(app.endpoint).await?;

    // Token id of the PLT token to transfer
    let token_id = TokenId::try_from(app.token_id.clone())?;

    // The convenience wrapper for interactions with a PLT.
    let mut token_client =
        token_client::TokenClient::init_from_token_id(client.clone(), token_id).await?;

    // Amount of tokens to send/mint/burn. The number of decimals in the TokenAmount
    // must be the same as the number of decimals in the TokenInfo
    let token_amount = TokenAmount::try_from_rust_decimal(
        app.amount,
        token_client.token_info().token_state.decimals,
        ConversionRule::AllowRounding,
    )?;
    println!("Token amount: {}", token_amount,);

    // Target address of the action.
    let target_address = AccountAddress::from_str(&app.receiver)?;

    // Load account keys and sender address from a file
    let keys: WalletAccount = WalletAccount::from_json_file(app.account)
        .context("Could not read the account keys file.")?;

    // Set expiry to now + 5min
    let expiry: Option<TransactionTime> = Some(TransactionTime::from_seconds(
        (chrono::Utc::now().timestamp() + 300) as u64,
    ));

    let meta = Some(TransactionMetadata {
        expiry,
        nonce: None,
        validate: None,
    });

    // Check the ballance of the sender
    let ballance = token_client
        .balance_of(&keys.address.into(), None::<BlockIdentifier>)
        .await?;
    if let Some(ballance) = ballance {
        println!("The sender has {}{} available", ballance, app.token_id,);
    }

    // Submit the transaction to the chain
    let transaction_hash = match app.cmd {
        Action::Mint => {
            token_client.validate_governance_operation(keys.address)?;
            token_client.mint(&keys, vec![token_amount], meta).await
        }
        Action::Burn => {
            token_client.validate_governance_operation(keys.address)?;
            token_client.burn(&keys, vec![token_amount], meta).await
        }
        Action::Transfer => {
            let payload = TransferTokens {
                amount:    token_amount,
                recipient: target_address,
                memo:      None,
            };
            token_client
                .validate_transfer(keys.address, vec![payload.clone()])
                .await?;
            token_client.transfer(&keys, vec![payload], meta).await
        }
        Action::AddAllow => {
            token_client.validate_governance_operation(keys.address)?;
            token_client
                .add_allow_list(&keys, vec![target_address], meta)
                .await
        }
        Action::RemoveAllow => {
            token_client.validate_governance_operation(keys.address)?;
            token_client
                .remove_allow_list(&keys, vec![target_address], meta)
                .await
        }
        Action::AddDeny => {
            token_client.validate_governance_operation(keys.address)?;
            token_client
                .add_deny_list(&keys, vec![target_address], meta)
                .await
        }
        Action::RemoveDeny => {
            token_client.validate_governance_operation(keys.address)?;
            token_client
                .remove_deny_list(&keys, vec![target_address], meta)
                .await
        }
    }?;
    println!("Transaction {} submitted.", transaction_hash,);

    let (bh, bs) = client.wait_until_finalized(&transaction_hash).await?;
    println!("Transaction finalized in block {}.", bh);
    println!("The outcome is {:#?}", bs);

    Ok(())
}
