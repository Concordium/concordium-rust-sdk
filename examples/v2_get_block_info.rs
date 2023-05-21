//! Test the `GetBlockInfo` endpoint.
use anyhow::Context;
use clap::AppSettings;
use concordium_base::base::AbsoluteBlockHeight;
use structopt::StructOpt;

use concordium_rust_sdk::v2;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:20000"
    )]
    endpoint: v2::Endpoint,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    let mut client = v2::Client::new(app.endpoint)
        .await
        .context("Cannot connect.")?;

    {
        let ai = client.get_block_info(&v2::BlockIdentifier::Best).await?;
        println!("Best block {:#?}", ai);
    }

    {
        let ai = client
            .get_block_info(&v2::BlockIdentifier::LastFinal)
            .await?;
        println!("Last finalized {:#?}", ai);
    }

    {
        let identifier = AbsoluteBlockHeight::from(0);
        let ai = client.get_block_info(identifier).await?;
        println!("Block at absolute height {:?} {:#?}", identifier, ai);
    }

    {
        let identifier = v2::RelativeBlockHeight {
            genesis_index: 0.into(),
            height:        0.into(),
            restrict:      true,
        };
        let ai = client.get_block_info(identifier).await?;
        println!("Block at relative height {:?} {:#?}", identifier, ai);
    }

    Ok(())
}
