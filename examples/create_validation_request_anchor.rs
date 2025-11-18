// todo are look through example

//! Example that shows how to generate a verification request anchor.
//!
//! You can run this example as follows:
//! cargo run --example create_validation_request_anchor -- --node http://localhost:20100 --account 3nhMYfA59MWaxBRjfHPKSYH9S4W5HdZZ721jozVdeToBGvXTU8.export
use anyhow::Context as AnyhowContext;
use clap::AppSettings;
use concordium_base::web3id::v1::anchor::{
    CredentialType, IdentityProviderMethod, RequestedIdentitySubjectClaims, RequestedStatement,
    UnfilledContextInformation, VerificationRequestData,
};
use concordium_base::web3id::Web3IdAttribute;
use concordium_base::{
    common::cbor,
    id::id_proof_types::AttributeInRangeStatement,
    web3id::{
        did::Network,
        // Web3IdAttribute,
    },
};
use concordium_rust_sdk::web3id::v1::anchor;
use concordium_rust_sdk::web3id::v1::anchor::AnchorTransactionMetadata;
use concordium_rust_sdk::{
    common::types::TransactionTime,
    types::WalletAccount,
    v2::{self},
};
use rand::Rng;
use std::{collections::HashMap, marker::PhantomData, path::PathBuf};
use structopt::*;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:20100"
    )]
    endpoint: v2::Endpoint,
    #[structopt(long = "account", help = "Path to the account key file.")]
    keys_path: PathBuf,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };
    let mut client = v2::Client::new(app.endpoint).await?;

    // Load account keys and sender address from a file
    let keys: WalletAccount =
        WalletAccount::from_json_file(app.keys_path).context("Could not read the keys file.")?;

    // Get the initial nonce at the last finalized block.
    let account_sequence_number = client
        .get_next_account_sequence_number(&keys.address)
        .await?;
    let account_sequence_number = account_sequence_number.nonce;

    // Set expiry to now + 5min
    let expiry: TransactionTime =
        TransactionTime::from_seconds((chrono::Utc::now().timestamp() + 300) as u64);

    // First we generate the verification request.
    //
    // Generating the `context` and `credential_statements` will normally happen server-side.
    let mut rng = rand::thread_rng();
    let nonce: [u8; 32] = rng.gen(); // Note: This nonce has to be generated fresh/randomly for each request.
    let connection_id = "MyWalletConnectTopic".to_string(); // Note: Use the wallet connect topic in production.
    let context_string = "MyGreateApp".to_string();
    let context = UnfilledContextInformation::new_simple(nonce, connection_id, context_string);

    let attribute_in_range_statement =
        RequestedStatement::AttributeInRange(AttributeInRangeStatement {
            attribute_tag: 17.into(),
            lower: Web3IdAttribute::Numeric(80),
            upper: Web3IdAttribute::Numeric(1237),
            _phantom: PhantomData,
        });

    let verification_request_data = VerificationRequestData::new(context)
        .add_subject_claim_request(
            RequestedIdentitySubjectClaims::default()
                .add_issuer(IdentityProviderMethod::new(0u32, Network::Testnet))
                .add_source(CredentialType::IdentityCredential)
                .add_statement(attribute_in_range_statement),
        );

    let mut public_info = HashMap::new();
    public_info.insert("key".to_string(), cbor::value::Value::Positive(4u64));

    let anchor_transaction_metadata = AnchorTransactionMetadata {
        signer: &keys,
        sender: keys.address,
        account_sequence_number,
        expiry,
    };

    let verification_request = anchor::create_verification_request_and_submit_anchor(
        &mut client,
        anchor_transaction_metadata,
        verification_request_data,
        Some(public_info),
    )
    .await?;

    println!(
        "Verification request anchor transaction hash: {}",
        verification_request.anchor_transaction_hash
    );

    let (bh, bs) = client
        .wait_until_finalized(&verification_request.anchor_transaction_hash)
        .await?;

    println!("Verification request anchor finalized in block {}.", bh);
    println!("The outcome is {:#?}", bs);

    println!(
        "Generated Verification Request to be sent to the wallet/idApp: {:#?}",
        verification_request
    );

    Ok(())
}
