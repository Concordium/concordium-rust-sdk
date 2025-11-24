//! Example that shows how to verify a verifiable presentation
//! together with the verification request. See
//! [`crate::web3id::v1`].
//!
//! You can run this example as follows:
//! cargo run --example verify_presentation -- --node http://localhost:20100 --account 3nhMYfA59MWaxBRjfHPKSYH9S4W5HdZZ721jozVdeToBGvXTU8.export
use anyhow::Context as AnyhowContext;
use clap::AppSettings;
use concordium_base::web3id::v1::anchor;
use concordium_base::web3id::v1::anchor::{
    IdentityCredentialType, IdentityProviderDid, RequestedIdentitySubjectClaimsBuilder,
    RequestedStatement, UnfilledContextInformationBuilder, VerifiablePresentationV1,
    VerificationRequest, VerificationRequestDataBuilder,
};
use concordium_rust_sdk::v2::BlockIdentifier;
use concordium_rust_sdk::web3id::v1::{AnchorTransactionMetadata, AuditRecordArgument};
use concordium_rust_sdk::{
    base::{
        common::cbor,
        id::id_proof_types::AttributeInRangeStatement,
        web3id::{did::Network, Web3IdAttribute},
    },
    common::types::TransactionTime,
    types::WalletAccount,
    v2::{self},
    web3id,
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
    let network = Network::Testnet;

    // Load account keys and sender address from a file
    let keys: WalletAccount =
        WalletAccount::from_json_file(app.keys_path).context("Could not read the keys file.")?;

    // Get the next account nonce
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
    let nonce_bytes: [u8; 32] = rng.gen(); // todo ar use nonce bytes or hash, change back?
    let nonce = anchor::Nonce(nonce_bytes); // Note: This nonce has to be generated fresh/randomly for each request.
    let connection_id = "MyWalletConnectTopic".to_string(); // Note: Use the wallet connect topic in production.
    let context_string = "MyGreateApp".to_string();
    let context =
        UnfilledContextInformationBuilder::new_simple(nonce, connection_id, context_string).build();

    let attribute_in_range_statement =
        RequestedStatement::AttributeInRange(AttributeInRangeStatement {
            attribute_tag: 17.into(),
            lower: Web3IdAttribute::Numeric(80),
            upper: Web3IdAttribute::Numeric(1237),
            _phantom: PhantomData,
        });

    let verification_request_data = VerificationRequestDataBuilder::new(context)
        .subject_claim(
            RequestedIdentitySubjectClaimsBuilder::default()
                .issuer(IdentityProviderDid::new(0u32, network))
                .source(IdentityCredentialType::IdentityCredential)
                .statement(attribute_in_range_statement)
                .build(),
        )
        .build();

    let mut public_info = HashMap::new();
    public_info.insert("key".to_string(), cbor::value::Value::Positive(4u64));

    let anchor_transaction_metadata = AnchorTransactionMetadata {
        signer: &keys,
        sender: keys.address,
        account_sequence_number,
        expiry,
    };

    let verification_request = web3id::v1::create_verification_request_and_submit_anchor(
        &mut client,
        anchor_transaction_metadata,
        verification_request_data,
        Some(public_info.clone()),
    )
    .await?;

    println!("Verification request: {:#?}", verification_request);

    println!(
        "Verification request anchor transaction hash: {}",
        verification_request.anchor_transaction_hash
    );

    let (bh, _) = client
        .wait_until_finalized(&verification_request.anchor_transaction_hash)
        .await?;

    println!("Verification request anchor finalized in block {}.", bh);

    /// Send the verification request to the wallet/ID app and obtain the
    /// verifiable presentation.
    ///
    /// The wallet/ID app fills in the requested context in [`VerificationRequest::context`]
    /// and selects and identity in order to form a
    /// [`VerifiablePresentationRequestV1`](concordium_base::web3id::v1::anchor::VerifiablePresentationRequestV1).
    /// that is then used to generate and prove a [`VerifiablePresentationV1`].
    async fn send_request_and_receive_presentation(
        _request: VerificationRequest,
    ) -> VerifiablePresentationV1 {
        todo!("send verification request to wallet/ID app and receive verifiable presentation")
    }

    let presentation = send_request_and_receive_presentation(verification_request.clone()).await;

    let audit_record_id = "UUID".to_string();

    let audit_record_anchor_transaction_metadata = AnchorTransactionMetadata {
        signer: &keys,
        sender: keys.address,
        account_sequence_number: account_sequence_number.next(), // We have to increase the nonce as this is the second anchor tx.
        expiry,
    };

    let audit_record_argument = AuditRecordArgument {
        audit_record_id,
        audit_record_anchor_transaction_metadata,
        public_info: Some(public_info),
    };

    let verification_data = web3id::v1::verify_presentation_and_submit_audit_anchor(
        &mut client,
        network,
        BlockIdentifier::LastFinal,
        verification_request,
        presentation,
        audit_record_argument,
    )
    .await?;

    println!(
        "Verification result: {:#?}",
        verification_data.verification_result
    );

    println!(
        "Generated anchored verification audit record to be stored in database: {:#?}",
        verification_data.audit_record
    );

    if let Some(anchor_transaction_hash) = &verification_data.anchor_transaction_hash {
        println!(
            "Verifiable audit anchor transaction hash: {}",
            anchor_transaction_hash
        );

        let (bh, bs) = client
            .wait_until_finalized(&anchor_transaction_hash)
            .await?;

        println!("Verification request anchor finalized in block {}.", bh);
        println!("The outcome is {:#?}", bs);
    };

    Ok(())
}
