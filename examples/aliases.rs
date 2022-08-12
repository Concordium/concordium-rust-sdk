//! A utility to check whether a list of accounts are all aliases of each other.
use clap::AppSettings;
use concordium_rust_sdk::id::types::AccountAddress;
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(long = "address", help = "Account address.")]
    addresses: Vec<AccountAddress>,
}

fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    if let Some((head, rest)) = app.addresses.split_first() {
        for addr in rest {
            anyhow::ensure!(addr.is_alias(head), "{} is not an alias of {}.", addr, head);
        }
    }

    println!("All addresses are aliases.");

    Ok(())
}
