/// Test the `GetAccountInfo` endpoint.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{
    id::types::AccountAddress,
    v2::{block_hash_input, BlockHashInput},
};
use structopt::StructOpt;

use concordium_rust_sdk::v2;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10001"
    )]
    endpoint: tonic::transport::Endpoint,
    #[structopt(long = "address", help = "Account address to query.")]
    address:  AccountAddress,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    let mut client = concordium_rust_sdk::v2::queries_client::QueriesClient::connect(app.endpoint)
        .await
        .context("Cannot connect.")?;

    {
        let mut request = v2::AccountInfoRequest::default();
        let addr = v2::AccountAddress {
            value: app.address.0.to_vec(),
        };
        let ai = v2::account_info_request::AccountIdentifier::Address(addr);
        request.account_identifier = Some(ai);
        request.block_hash = Some(BlockHashInput {
            block_hash_input: Some(block_hash_input::BlockHashInput::LastFinal(
                Default::default(),
            )),
        });

        let ai = client.get_account_info(request).await?;
        println!("{:#?}", ai);
    }

    {
        let mut request = v2::AccountInfoRequest::default();
        let addr = v2::AccountAddress {
            value: app.address.0.to_vec(),
        };
        let ai = v2::account_info_request::AccountIdentifier::Address(addr);
        request.account_identifier = Some(ai);
        request.block_hash = Some(BlockHashInput {
            block_hash_input: Some(block_hash_input::BlockHashInput::Best(Default::default())),
        });

        let ai = client.get_account_info(request).await?;
        println!("{:#?}", ai);
    }

    Ok(())
}
