//! Test the `GetModuleSource` endpoint.
use anyhow::Context;
use clap::AppSettings;
use concordium_rust_sdk::{types::smart_contracts::ModuleRef, v2};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:10001"
    )]
    endpoint: v2::Endpoint,
    #[structopt(long = "module", help = "Module reference to query.")]
    module:   ModuleRef,
    #[structopt(long = "out", help = "File path to write the module into.")]
    out:      Option<PathBuf>,
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

    let res = client
        .get_module_source(&app.module, &v2::BlockIdentifier::LastFinal)
        .await?;
    println!("Block hash: {}", res.block_hash);
    let module = res.response;
    println!("Module version: {}", module.version);
    if let Some(out) = app.out {
        // write out the Wasm source to the provided file.
        std::fs::write(&out, module.source.as_ref())?;
        println!("Module source written to {}", out.display());
    }

    Ok(())
}
