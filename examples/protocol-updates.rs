//! An example showing how to do the first 4 protocol updates.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    common::{
        base16_encode_string,
        derive::Serialize,
        to_bytes,
        types::{Amount, TransactionTime},
        Buffer, Deserial, ParseResult, ReadBytesExt, SerdeDeserialize, SerdeSerialize, Serial,
    },
    endpoints::{self, Client, Endpoint},
    types::{
        transactions::{update, BlockItem, Payload},
        AccessStructure, BlockSummary, CommissionRanges, CommissionRates, CooldownParameters,
        Epoch, InclusiveRange, LeverageFactor, OpenStatus, PoolParameters, ProtocolUpdate,
        ProtocolVersion, TimeParameters, UpdateKeyPair, UpdatePayload,
    },
};
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
    #[structopt(
        long = "rpc-token",
        help = "GRPC interface access token for accessing the node.",
        default_value = "rpcadmin"
    )]
    token:    String,
    #[structopt(long = "key", help = "Path to update keys to use.")]
    keys:     Vec<PathBuf>,
}

/// Parameter data type for the 'P3' to 'P4' protocol update.
/// This is provided as a parameter to the protocol update chain update
/// instruction.
#[derive(SerdeSerialize, SerdeDeserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ProtocolUpdateData {
    /// The commission rate to apply to bakers on migration.
    pub update_default_commission_rate: CommissionRates,
    /// The state of a baking pool on migration.
    pub update_default_pool_state: OpenStatus,
    /// Access structure defining the keys and threshold for cooldown parameter
    /// updates.
    pub update_cooldown_parameters_access_structure: AccessStructure,
    /// Access structure defining the keys and threshold for time parameter
    /// updates.
    pub update_time_parameters_access_structure: AccessStructure,
    /// New cooldown parameters.
    pub update_cooldown_parameters: CooldownParameters,
    /// New time parameters.
    pub update_time_parameters: TimeParameters,
    /// New pool parameters
    pub update_pool_parameters: PoolParameters,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app: App = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    let kps: Vec<UpdateKeyPair> = app
        .keys
        .iter()
        .map(|p| {
            serde_json::from_reader(std::fs::File::open(p).context("Could not open file.")?)
                .context("Could not read keys from file.")
        })
        .collect::<anyhow::Result<_>>()?;

    let mut client = endpoints::Client::connect(app.endpoint, app.token).await?;

    let consensus_status = client
        .get_consensus_status()
        .await
        .context("Could not obtain status of consensus.")?;

    // Get the key indices, as well as the next sequence number from the last
    // finalized block.
    let summary: BlockSummary = client
        .get_block_summary(&consensus_status.last_finalized_block)
        .await
        .context("Could not obtain last finalized block")?;

    // find the key indices to sign with
    let signer = summary
        .common_update_keys()
        .construct_update_signer(&summary.common_update_keys().protocol, kps)
        .context("Could not construct signer.")?;

    let mut seq_number = match &summary {
        BlockSummary::V0 { data, .. } => data.updates.update_queues.protocol.next_sequence_number,
        BlockSummary::V1 { data, .. } => data.updates.update_queues.protocol.next_sequence_number,
    };

    println!("Sequence number = {}", seq_number);

    let effective_time: TransactionTime = 0.into(); // immediate effect
    let p2 = ProtocolUpdate {
        message: "Update to P2".into(),
        specification_url:
            "https://github.com/Concordium/concordium-update-proposals/blob/main/updates/P2.txt"
                .into(),
        specification_hash: "9b1f206bbe230fef248c9312805460b4f1b05c1ef3964946981a8d4abb58b923"
            .parse()?,
        specification_auxiliary_data: Vec::new(),
    };
    let p3 = ProtocolUpdate {
        message: "Update to P3".into(),
        specification_url:
            "https://github.com/Concordium/concordium-update-proposals/blob/main/updates/P3.txt"
                .into(),
        specification_hash: "ec9f7733e872ed0b8f1f386d12c5c725379fc609ce246ffdce28cfb9163ea350"
            .parse()?,
        specification_auxiliary_data: Vec::new(),
    };

    let params = ProtocolUpdateData {
        update_default_commission_rate: CommissionRates {
            finalization: "1".parse().unwrap(),
            baking:       "0.1".parse().unwrap(),
            transaction:  "0.1".parse().unwrap(),
        },
        update_default_pool_state: OpenStatus::ClosedForAll,
        update_cooldown_parameters_access_structure: summary
            .common_update_keys()
            .pool_parameters
            .clone(),
        update_time_parameters_access_structure: summary
            .common_update_keys()
            .pool_parameters
            .clone(),
        update_cooldown_parameters: CooldownParameters {
            pool_owner_cooldown: 1500.into(),
            delegator_cooldown:  1200.into(),
        },
        update_time_parameters: TimeParameters {
            reward_period_length: Epoch::from(4u64).into(),
            mint_per_payday:      "0.00000261157877".parse().unwrap(),
        },
        update_pool_parameters: PoolParameters {
            passive_finalization_commission: "1".parse()?,
            passive_baking_commission:       "0.12".parse()?,
            passive_transaction_commission:  "0.12".parse()?,
            commission_bounds:               CommissionRanges {
                finalization: InclusiveRange {
                    min: "1".parse()?,
                    max: "1".parse()?,
                },
                baking:       InclusiveRange {
                    min: "0.1".parse()?,
                    max: "0.1".parse()?,
                },
                transaction:  InclusiveRange {
                    min: "0.1".parse()?,
                    max: "0.1".parse()?,
                },
            },
            minimum_equity_capital:          Amount::from_ccd(14_000),
            capital_bound:                   "0.1".parse()?,
            leverage_bound:                  LeverageFactor::new_integral(3),
        },
    };

    println!("{:#?}", params);
    println!("{}", serde_json::to_string_pretty(&params).unwrap());
    println!("{}", base16_encode_string(&params));
    {
        std::fs::write("p4-payload.bin", &to_bytes(&params))?;
    }

    let p4 = ProtocolUpdate {
        message: "Enable delegation and updated smart contracts".into(),
        specification_url:
            "https://github.com/Concordium/concordium-update-proposals/blob/main/updates/P4.txt"
                .into(),
        specification_hash: "20c6f246713e573fb5bfdf1e59c0a6f1a37cded34ff68fda4a60aa2ed9b151aa"
            .parse()?,
        specification_auxiliary_data: to_bytes(&params),
    };

    let p5 = ProtocolUpdate {
        message: "Update to P5".into(),
        specification_url:
            "https://github.com/Concordium/concordium-update-proposals/blob/main/updates/P5.txt"
                .into(),
        specification_hash: "af5684e70c1438e442066d017e4410af6da2b53bfa651a07d81efa2aa668db20"
            .parse()?,
        specification_auxiliary_data: Vec::new(),
    };

    let block_item: BlockItem<Payload> = update::update(
        &signer,
        seq_number,
        effective_time,
        TransactionTime::from_seconds(chrono::offset::Utc::now().timestamp() as u64 + 300), // 5min expiry.
        UpdatePayload::Protocol(p2),
    )
    .into();

    let sent = send_and_wait(&mut client, &block_item, ProtocolVersion::P1).await?;
    if sent {
        seq_number.next_mut();
    }
    let block_item: BlockItem<Payload> = update::update(
        &signer,
        seq_number,
        effective_time,
        TransactionTime::from_seconds(chrono::offset::Utc::now().timestamp() as u64 + 300), // 5min expiry.
        UpdatePayload::Protocol(p3),
    )
    .into();

    let sent = send_and_wait(&mut client, &block_item, ProtocolVersion::P2).await?;
    if sent {
        seq_number.next_mut();
    }

    let effective_time: TransactionTime = 0.into(); // immediate effect
    let block_item: BlockItem<Payload> = update::update(
        &signer,
        seq_number,
        effective_time,
        TransactionTime::from_seconds(chrono::offset::Utc::now().timestamp() as u64 + 300), // 5min expiry.,
        UpdatePayload::Protocol(p4),
    )
    .into();

    let sent = send_and_wait(&mut client, &block_item, ProtocolVersion::P3).await?;
    if sent {
        seq_number.next_mut();
    }

    let block_item: BlockItem<Payload> = update::update(
        &signer,
        seq_number,
        effective_time,
        TransactionTime::from_seconds(chrono::offset::Utc::now().timestamp() as u64 + 300), // 5min expiry.,
        UpdatePayload::Protocol(p5),
    )
    .into();

    send_and_wait(&mut client, &block_item, ProtocolVersion::P4).await?;

    Ok(())
}

// Send the protocol update transaction if consensus is at the right protocol
// version at the time. Wait until the protocol update takes effect.
//
// Return whether the protocol update has taken effect.
async fn send_and_wait(
    client: &mut Client,
    block_item: &BlockItem<Payload>,
    pv: ProtocolVersion,
) -> anyhow::Result<bool> {
    let ci = client.get_consensus_status().await?;
    if ci.protocol_version == pv {
        let submission_id = client
            .send_block_item(block_item)
            .await
            .context("Could not send transaction.")?;
        println!("Submitted update with hash {}", submission_id);

        let status = client
            .wait_until_finalized(&submission_id)
            .await
            .context("Submission {} not finalized.")?;
        println!(
            "Update with hash {} has been finalized with status {:?}.",
            submission_id, status
        );

        // wait until the protocol version changes
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            let ci = client.get_consensus_status().await?;
            if ci.protocol_version > pv {
                break;
            }
        }
        Ok(true)
    } else {
        Ok(false)
    }
}
