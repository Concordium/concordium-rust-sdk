//! Example that shows how to use the TokenClient
use anyhow::{anyhow, Context};
use clap::AppSettings;
use concordium_base::{
    contracts_common::AccountAddress,
    hashes::HashBytes,
    protocol_level_tokens::{ConversionRule, MetadataUrl, TokenAdminRole, TokenAmount, TokenId},
};
use concordium_rust_sdk::{
    common::types::TransactionTime,
    protocol_level_tokens::token_client::{self, TransactionMetadata, TransferTokens, Validation},
    types::WalletAccount,
    v2::{self, BlockIdentifier},
};
use rust_decimal::Decimal;
use std::{collections::HashMap, path::PathBuf, str::FromStr};
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
    #[structopt(long = "token", help = "Token id of the token.")]
    token_id: String,
    #[structopt(subcommand)]
    cmd: Action,
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
        amount: Decimal,
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
    AssignAdminRoles {
        #[structopt(long = "target", help = "Account address to assign admin roles to.")]
        target: String,
        #[structopt(long = "roles", help = "Roles to assign.")]
        roles: Vec<String>,
    },
    RevokeAdminRoles {
        #[structopt(long = "target", help = "Account address to revoke admin roles from.")]
        target: String,
        #[structopt(long = "roles", help = "Roles to revoke.")]
        roles: Vec<String>,
    },
    UpdateMetadata {
        #[structopt(long = "metadata_url", help = "Metadata url to update for a token.")]
        metadata_url: String,
        #[structopt(long = "checksum_sha_256", help = "Hash checksum to update.")]
        checksum_sha_256: Option<String>,
    },
}

// Helper function to parse the role from a string
fn parse_role(s: &str) -> Result<TokenAdminRole, anyhow::Error> {
    match s {
        "updateAdminRoles" => Ok(TokenAdminRole::UpdateAdminRoles),
        "mint" => Ok(TokenAdminRole::Mint),
        "burn" => Ok(TokenAdminRole::Burn),
        "updateAllowList" => Ok(TokenAdminRole::UpdateAllowList),
        "updateDenyList" => Ok(TokenAdminRole::UpdateDenyList),
        "pause" => Ok(TokenAdminRole::Pause),
        "updateMetadata" => Ok(TokenAdminRole::UpdateMetadata),
        _ => Err(anyhow!("role provided does not match: {}", s)),
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
            // manually validating the mint operation
            token_client.validate_mint(token_amount).await?;

            token_client
                .mint(&keys, token_amount, meta, Validation::NoValidation)
                .await
        }
        Action::Burn { amount } => {
            let token_amount = TokenAmount::try_from_rust_decimal(
                amount,
                token_client.token_info().token_state.decimals,
                ConversionRule::AllowRounding,
            )?;
            // manually validating the burn operation
            token_client
                .validate_burn(token_amount, keys.address)
                .await?;

            token_client
                .burn(&keys, token_amount, meta, Validation::NoValidation)
                .await
        }
        Action::Transfer { receiver, amount } => {
            let token_amount = TokenAmount::try_from_rust_decimal(
                amount,
                token_client.token_info().token_state.decimals,
                ConversionRule::AllowRounding,
            )?;
            let target_address = AccountAddress::from_str(&receiver)?;

            let payload = TransferTokens {
                amount: token_amount,
                recipient: target_address,
                memo: None,
            };
            // manually validating the transfer operation
            token_client
                .validate_transfer(keys.address, vec![payload.clone()])
                .await?;

            token_client
                .transfer(&keys, vec![payload], meta, Validation::NoValidation)
                .await
        }
        Action::AddAllow { target } => {
            let target_address = AccountAddress::from_str(&target)?;
            // manually validating the allow list update operation
            token_client.validate_allow_list_update().await?;

            token_client
                .add_allow_list(&keys, vec![target_address], meta, Validation::NoValidation)
                .await
        }
        Action::RemoveAllow { target } => {
            let target_address = AccountAddress::from_str(&target)?;
            // manually validating the allow list update operation
            token_client.validate_allow_list_update().await?;

            token_client
                .remove_allow_list(&keys, vec![target_address], meta, Validation::NoValidation)
                .await
        }
        Action::AddDeny { target } => {
            let target_address = AccountAddress::from_str(&target)?;
            // manually validating the deny list update operation
            token_client.validate_deny_list_update().await?;

            token_client
                .add_deny_list(&keys, vec![target_address], meta, Validation::NoValidation)
                .await
        }
        Action::RemoveDeny { target } => {
            let target_address = AccountAddress::from_str(&target)?;
            // manually validating the deny list update operation
            token_client.validate_deny_list_update().await?;

            token_client
                .remove_deny_list(&keys, vec![target_address], meta, Validation::NoValidation)
                .await
        }
        Action::Pause => token_client.pause(&keys, meta).await,
        Action::Unpause => token_client.unpause(&keys, meta).await,
        Action::AssignAdminRoles { target, roles } => {
            let target_address = AccountAddress::from_str(&target)?;

            let token_admin_roles: Vec<TokenAdminRole> = roles
                .iter()
                .map(|s| parse_role(s))
                .collect::<Result<Vec<_>, _>>()?;

            token_client
                .assign_admin_roles(&keys, meta, target_address, token_admin_roles)
                .await
        }
        Action::RevokeAdminRoles { target, roles } => {
            let target_address = AccountAddress::from_str(&target)?;

            let token_admin_roles: Vec<TokenAdminRole> = roles
                .iter()
                .map(|s| parse_role(s))
                .collect::<Result<Vec<_>, _>>()?;

            token_client
                .revoke_admin_roles(&keys, meta, target_address, token_admin_roles)
                .await
        }
        Action::UpdateMetadata {
            metadata_url,
            checksum_sha_256,
        } => {
            let checksum = checksum_sha_256
                .map(|s| HashBytes::from_str(&s))
                .transpose()?;

            let metadata = MetadataUrl {
                additional: HashMap::new(),
                checksum_sha_256: checksum,
                url: metadata_url,
            };

            token_client.update_metadata(&keys, meta, metadata).await
        }
    }?;

    println!("Transaction {} submitted.", transaction_hash,);

    let (bh, bs) = client.wait_until_finalized(&transaction_hash).await?;
    println!("Transaction finalized in block {}.", bh);
    println!("The outcome is {:#?}", bs);

    Ok(())
}
