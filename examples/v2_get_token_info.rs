//! Test the `GetTokenInfo` endpoint.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{protocol_level_tokens, v2};
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:20000"
    )]
    endpoint: v2::Endpoint,
    #[structopt(long = "token", help = "ID of the token to query")]
    token:    protocol_level_tokens::TokenId,
    #[structopt(long = "block", help = "Block to query the token info in.")]
    block:    Option<v2::BlockIdentifier>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };
    let block_ident = app.block.unwrap_or(v2::BlockIdentifier::LastFinal);
    let mut client = v2::Client::new(app.endpoint)
        .await
        .context("Cannot connect.")?;
    let response = client.get_token_info(app.token, &block_ident).await?;
    println!("{:#?}", response.response);
    let module_state = response.response.token_state.decode_module_state()?;
    println!("{:#?}", module_state);
    Ok(())
}
