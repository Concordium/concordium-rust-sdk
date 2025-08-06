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
    #[structopt(long = "token", help = "Token id of the token.")]
    token_id: String,
    #[structopt(subcommand)]
    cmd:      Action,
}

/// TokenClient operations
#[derive(StructOpt)]
enum Action {
    Mint {
        #[structopt(long = "amount", help = "Amount of token to mint.")]
        amount: Decimal,
    },
    Burn {
        #[structopt(long = "amount", help = "Amount of token to burn.")]
        amount: Decimal,
    },
    Transfer {
        #[structopt(long = "receiver", help = "Target account address.")]
        receiver: String,
        #[structopt(long = "amount", help = "Amount of token to transfer.")]
        amount:   Decimal,
    },
    AddAllow {
        #[structopt(long = "target", help = "Account address to add to allow list.")]
        target: String,
    },
    RemoveAllow {
        #[structopt(long = "target", help = "Account address to remove from allow list.")]
        target: String,
    },
    AddDeny {
        #[structopt(long = "target", help = "Account address to add to deny list.")]
        target: String,
    },
    RemoveDeny {
        #[structopt(long = "target", help = "Account address to remove from deny list.")]
        target: String,
    },
    Pause,
    Unpause,
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

    // Check the balance of the sender
    let balance = token_client
        .balance_of(&keys.address.into(), None::<BlockIdentifier>)
        .await?;
    if let Some(balance) = balance {
        println!("The sender has {}{} available", balance, app.token_id,);
    }

    // Submit the transaction to the chain
    let transaction_hash = match app.cmd {
        Action::Mint { amount } => {
            let token_amount = TokenAmount::try_from_rust_decimal(
                amount,
                token_client.token_info().token_state.decimals,
                ConversionRule::AllowRounding,
            )?;
            token_client.validate_governance_operation(keys.address)?;
            token_client.mint(&keys, token_amount, meta).await
        }
        Action::Burn { amount } => {
            let token_amount = TokenAmount::try_from_rust_decimal(
                amount,
                token_client.token_info().token_state.decimals,
                ConversionRule::AllowRounding,
            )?;
            token_client.validate_governance_operation(keys.address)?;
            token_client.burn(&keys, token_amount, meta).await
        }
        Action::Transfer { receiver, amount } => {
            let token_amount = TokenAmount::try_from_rust_decimal(
                amount,
                token_client.token_info().token_state.decimals,
                ConversionRule::AllowRounding,
            )?;
            let target_address = AccountAddress::from_str(&receiver)?;

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
        Action::AddAllow { target } => {
            let target_address = AccountAddress::from_str(&target)?;

            token_client.validate_governance_operation(keys.address)?;
            token_client
                .add_allow_list(&keys, vec![target_address], meta)
                .await
        }
        Action::RemoveAllow { target } => {
            let target_address = AccountAddress::from_str(&target)?;

            token_client.validate_governance_operation(keys.address)?;
            token_client
                .remove_allow_list(&keys, vec![target_address], meta)
                .await
        }
        Action::AddDeny { target } => {
            let target_address = AccountAddress::from_str(&target)?;

            token_client.validate_governance_operation(keys.address)?;
            token_client
                .add_deny_list(&keys, vec![target_address], meta)
                .await
        }
        Action::RemoveDeny { target } => {
            let target_address = AccountAddress::from_str(&target)?;

            token_client.validate_governance_operation(keys.address)?;
            token_client
                .remove_deny_list(&keys, vec![target_address], meta)
                .await
        }
        Action::Pause => {
            token_client.validate_governance_operation(keys.address)?;
            token_client.pause(&keys, meta).await
        }
        Action::Unpause => {
            token_client.validate_governance_operation(keys.address)?;
            token_client.unpause(&keys, meta).await
        }
    }?;

    println!("Transaction {} submitted.", transaction_hash,);

    let (bh, bs) = client.wait_until_finalized(&transaction_hash).await?;
    println!("Transaction finalized in block {}.", bh);
    println!("The outcome is {:#?}", bs);

    Ok(())
}
