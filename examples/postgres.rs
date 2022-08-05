use clap::AppSettings;
use concordium_rust_sdk::{
    id::types::AccountAddress,
    postgres::{DatabaseClient, QueryOrder},
    types::ContractAddress,
};
use futures::StreamExt;
use structopt::StructOpt;
use tokio_postgres::NoTls;

#[derive(StructOpt)]
struct App {
    #[structopt(long = "account")]
    account: AccountAddress,
    #[structopt(
        long = "db",
        default_value = "host=localhost dbname=transaction-outcome user=postgres \
                         password=password port=5432",
        help = "Database connection string."
    )]
    config:  tokio_postgres::Config,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap()
            // .setting(AppSettings::ArgRequiredElseHelp)
            .global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    let config = app.config;

    let db = DatabaseClient::create(config, NoTls).await?;
    let addr: AccountAddress = app.account;
    let rows = db
        .query_account(&addr, 50, QueryOrder::Ascending { start: None })
        .await?;
    rows.for_each(|entry| async move {
        println!("{:?}", entry.id);
    })
    .await;

    let rows = db
        .query_contract(ContractAddress::new(0, 0), 20, QueryOrder::Ascending {
            start: None,
        })
        .await?;
    rows.for_each(|entry| async move {
        println!("{:?}", entry);
    })
    .await;

    let rows = db
        .query_account(&addr, 20, QueryOrder::Descending { start: None })
        .await?;
    rows.for_each(|entry| async move {
        println!("{:?}", entry);
    })
    .await;

    let rows = db
        .query_contract(ContractAddress::new(0, 0), 20, QueryOrder::Descending {
            start: None,
        })
        .await?;
    rows.for_each(|entry| async move {
        println!("{:?}", entry);
    })
    .await;

    let rows = db.iterate_account(&addr, None).await?;
    rows.for_each(|entry| async move {
        println!("{:?}", entry.id);
    })
    .await;

    Ok(())
}
