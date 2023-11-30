//! List total equity, total delegated stake, and effective stake.
use clap::AppSettings;
use concordium_rust_sdk::{common::types::Amount, v2, v2::BlockIdentifier};
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
        long = "block",
        default_value = "lastfinal",
        help = "Block to query the data in. Defaults to last finalized block."
    )]
    block:    BlockIdentifier,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    let mut client = v2::Client::new(app.endpoint).await?;

    let mut equity: u64 = 0;
    let mut delegated: u64 = 0;
    let mut effective: u64 = 0;

    let birk_params = client.get_election_info(app.block).await?;
    let block = birk_params.block_hash;

    let mut active_bakers: u32 = 0;
    for baker in birk_params.response.bakers {
        let pool = client.get_pool_info(&block, baker.baker_id).await?.response;
        if let Some(current_payday_status) = pool.current_payday_status {
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
