//! Generate initial account transactions and send them to the chain.
//! Generated account keys are stored in the `created-accounts` directory.
use anyhow::Context;
use clap::AppSettings;
use common::base16_encode_string;
use concordium_rust_sdk::{
    common::{
        self,
        types::{KeyIndex, TransactionTime},
    },
    endpoints::{self, Endpoint},
    id,
    id::{
        constants::{ArCurve, IpPairing},
        curve_arithmetic::Curve,
        dodis_yampolskiy_prf::SecretKey,
        types::{
            AccountCredential, AccountCredentialMessage, AccountKeys, AttributeList,
            CredentialData, CredentialPublicKeys, IpData, PublicCredentialData,
            PublicInformationForIp, SignatureThreshold, YearMonth,
        },
    },
    types::transactions::{BlockItem, Payload},
};
use id::{
    constants::AttributeKind,
    curve_arithmetic::Value,
    pedersen_commitment::Randomness,
    types::{account_address_from_registration_id, AttributeTag},
};
use rand::thread_rng;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10000"
    )]
    endpoint: Endpoint,
    #[structopt(long = "identity-provider")]
    idp:      PathBuf,
    #[structopt(long = "tps")]
    tps:      u16,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap()
            // .setting(AppSettings::ArgRequiredElseHelp)
            .global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    let ip_data: IpData<IpPairing> = serde_json::from_str(
        &std::fs::read_to_string(app.idp).context("Could not read the keys file.")?,
    )
    .context("Could not parse the identity provider file.")?;

    let mut client = endpoints::Client::connect(app.endpoint, "rpcadmin".to_string()).await?;
    let last_final = client.get_consensus_status().await?.last_finalized_block;
    let global_context = client.get_cryptographic_parameters(&last_final).await?;

    // Create a channel between the task signing and the task sending transactions.
    let (sender, mut rx) = tokio::sync::mpsc::channel(100);
    let tps = app.tps;
    let generator = async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_micros(
            1_000_000 / u64::from(tps),
        ));
        loop {
            interval.tick().await;

            let expiry: TransactionTime = TransactionTime::from_seconds(
                100 / u64::from(tps) + (chrono::Utc::now().timestamp() + 3600) as u64,
            );
            let created_at = YearMonth::now();
            let alist = AttributeList {
                valid_to: YearMonth {
                    year:  created_at.year + 1,
                    month: created_at.month,
                },
                created_at,
                max_accounts: 100,
                alist: vec![
                    (AttributeTag(0), AttributeKind("A".into())),
                    (AttributeTag(1), AttributeKind("B".into())),
                    (AttributeTag(2), AttributeKind("C".into())),
                    (AttributeTag(3), AttributeKind("D".into())),
                    (AttributeTag(4), AttributeKind("EE".into())),
                    (AttributeTag(5), AttributeKind("FFF".into())),
                    (AttributeTag(6), AttributeKind("GGGG".into())),
                ]
                .into_iter()
                .collect(),
                _phantom: Default::default(),
            };
            let data = {
                let mut csprng = thread_rng();
                let cdata = CredentialData {
                    keys:      vec![(
                        KeyIndex::from(0),
                        common::types::KeyPair::generate(&mut csprng),
                    )]
                    .into_iter()
                    .collect(),
                    threshold: SignatureThreshold(1),
                };
                let prf_key = SecretKey::<ArCurve>::generate_non_zero(&mut csprng);
                let cred_id_exponent = prf_key.prf_exponent(0).expect("We were very unlucky.");
                // RegId as well as Prf key commitments must be computed
                // with the same generators as in the commitment key.
                let cred_id = global_context
                    .on_chain_commitment_key
                    .hide(
                        &Value::<ArCurve>::new(cred_id_exponent),
                        &Randomness::zero(),
                    )
                    .0;

                let pub_info_for_ip = PublicInformationForIp {
                    id_cred_pub: ArCurve::generate(&mut csprng),
                    reg_id:      cred_id,
                    vk_acc:      CredentialPublicKeys {
                        keys:      cdata.get_public_keys(),
                        threshold: cdata.get_threshold(),
                    },
                };
                let address = account_address_from_registration_id(&pub_info_for_ip.reg_id);
                let icdi = id::identity_provider::create_initial_cdi(
                    &ip_data.public_ip_info,
                    pub_info_for_ip,
                    &alist,
                    expiry,
                    &ip_data.ip_cdi_secret_key,
                );

                let keys = AccountKeys::from(cdata);
                let item = BlockItem::<Payload>::from(AccountCredentialMessage {
                    message_expiry: expiry,
                    credential:     AccountCredential::Initial { icdi },
                });
                (address, item, keys, cred_id_exponent)
            };
            if sender.send(data).await.is_err() {
                panic!("Error enqueuing.")
            }
        }
    };

    // Spawn it to run in the background.
    let _handle = tokio::spawn(generator);

    let mut count: u64 = 0;
    while let Some((address, item, keys, enc_key)) = rx.recv().await {
        let transaction_hash = client.send_block_item(&item).await?;
        println!("{}:{}", count, transaction_hash);
        count += 1;
        serde_json::to_writer_pretty(
            std::fs::File::create(format!("created-accounts/{}.json", address))
                .context("Could not write created account keys.")?,
            &serde_json::json!({"address": address, "keys": keys, "encryptionSecretKey": base16_encode_string(&enc_key), "transactionHash": transaction_hash}),
        )?;
    }
    Ok(())
}
