//! List all account creations in a given time span.
use clap::AppSettings;
use concordium_rust_sdk::{
    indexer::{TransactionIndexer, TraverseConfig},
    types::{AbsoluteBlockHeight, BlockItemSummary, BlockItemSummaryDetails, CredentialType},
    v2,
};
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:20000"
    )]
    endpoint: v2::Endpoint,
    #[structopt(
        long = "num",
        help = "Number of parallel queries to make.",
        default_value = "4"
    )]
    num: usize,
    #[structopt(long = "from", help = "Starting time. Defaults to genesis time.")]
    from: Option<chrono::DateTime<chrono::Utc>>,
    #[structopt(long = "to", help = "End time. Defaults to infinity.")]
    to: Option<chrono::DateTime<chrono::Utc>>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    let mut client = v2::Client::new(app.endpoint.clone()).await?;

    let h = if let Some(start_time) = app.from {
        let start = client
            .find_first_finalized_block_no_earlier_than(.., start_time)
            .await?;
        start.block_height
    } else {
        AbsoluteBlockHeight::from(0u64)
    };

    let (sender, mut receiver) = tokio::sync::mpsc::channel(2 * app.num);
    let handle = tokio::spawn(
        TraverseConfig::new_single(app.endpoint, h)
            .set_max_parallel(app.num)
            .traverse(TransactionIndexer, sender),
    );

    while let Some((bi, summaries)) = receiver.recv().await {
        if let Some(to) = app.to {
            if to < bi.block_slot_time {
                break;
            }
        }
        for BlockItemSummary { details, .. } in summaries {
            match details {
                BlockItemSummaryDetails::AccountTransaction(_) => {}
                BlockItemSummaryDetails::AccountCreation(x) => {
                    let acc_type = match x.credential_type {
                        CredentialType::Initial => "initial",
                        CredentialType::Normal => "normal",
                    };
                    println!(
                        "{}, {}, {}, {}",
                        x.address, bi.block_hash, bi.block_slot_time, acc_type
                    );
                }
                BlockItemSummaryDetails::Update(_) => (),
                BlockItemSummaryDetails::TokenCreationDetails(_) => (),
            }
        }
    }
    handle.abort();
    Ok(())
}
