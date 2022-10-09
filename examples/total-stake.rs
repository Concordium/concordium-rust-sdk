//! List total equity, total delegated stake, and effective stake.
use clap::AppSettings;
use concordium_rust_sdk::{
    common::types::Amount,
    endpoints::{self, Endpoint},
    types::{hashes::BlockHash, BakerPoolStatus, PoolStatus},
};
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
        long = "block",
        help = "Block to query the data in. Defaults to last finalized block."
    )]
    block:    Option<BlockHash>,
    #[structopt(long = "token", help = "GRPC login token", default_value = "rpcadmin")]
    token:    String,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    let mut client = endpoints::Client::connect(app.endpoint, app.token).await?;

    let consensus_info = client.get_consensus_status().await?;

    let block = app.block.unwrap_or(consensus_info.last_finalized_block);

    let mut equity: u64 = 0;
    let mut delegated: u64 = 0;
    let mut effective: u64 = 0;

    let birk_params = client.get_birk_parameters(&block).await?;

    let mut active_bakers: u32 = 0;
    for baker in birk_params.bakers {
        let pool = client.get_pool_status(Some(baker.baker_id), &block).await?;
        if let PoolStatus::BakerPool {
            status:
                BakerPoolStatus {
                    current_payday_status: Some(current_payday_status),
                    ..
                },
        } = pool
        {
            active_bakers += 1;
            equity += current_payday_status.baker_equity_capital.micro_ccd();
            delegated += current_payday_status.delegated_capital.micro_ccd();
            effective += current_payday_status.effective_stake.micro_ccd();
        }
    }
    println!("There are {} bakers.", active_bakers);
    println!(
        "Total effective stake is {} CCD",
        Amount::from_micro_ccd(effective)
    );
    println!(
        "Total equity capital is {} CCD",
        Amount::from_micro_ccd(equity)
    );
    println!(
        "Total delegated stake is {} CCD",
        Amount::from_micro_ccd(delegated)
    );

    Ok(())
}
