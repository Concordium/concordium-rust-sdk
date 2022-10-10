//! A simple script to check how many bytes in an address are needed to
//! distinguish accounts. The script gets the account list from the node.
use clap::AppSettings;
use concordium_rust_sdk::{
    endpoints::{self, Endpoint},
    id::types::AccountAddress,
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
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    let mut client = endpoints::Client::connect(app.endpoint, "rpcadmin".to_string()).await?;

    let consensus_info = client.get_consensus_status().await?;

    let cb = consensus_info.best_block;
    let bi = client.get_account_list(&cb).await?;
    println!("There are {} accounts.", bi.len());
    for i in 0..32 {
        let mut tmp = bi.clone();
        let compare = |l: &AccountAddress, r: &AccountAddress| {
            let l_bytes: &[u8] = l.as_ref();
            let r_bytes: &[u8] = r.as_ref();
            l_bytes[0..i].cmp(&r_bytes[0..i])
        };
        tmp.sort_by(compare);
        tmp.dedup_by(|l, r| compare(l, r).is_eq());
        if tmp.len() < bi.len() {
            println!("Clashes at prefix of length {}.", i);
        } else {
            println!(
                "The first {} bytes of the address uniquely determine the account.",
                i
            );
            break;
        }
    }

    Ok(())
}
