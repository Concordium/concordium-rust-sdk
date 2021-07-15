use clap::AppSettings;
use concordium_rust_sdk::{
    postgres::{create_client, QueryOrder},
    types::ContractAddress,
};
use futures::StreamExt;
use id::types::AccountAddress;
use structopt::StructOpt;
use tokio_postgres::NoTls;

#[derive(StructOpt)]
struct App {
    #[structopt(long = "account")]
    account: AccountAddress,
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

    let config = "host=localhost dbname=transaction-outcome user=postgres password=password \
                  port=5432"
        .parse()?;

    let db = create_client(config, NoTls).await?;
    let addr: AccountAddress = app.account;
    let rows = db
        .query_account(&addr, 50, QueryOrder::Ascending { start: 0 })
        .await?;
    rows.for_each(|entry| async move {
        println!("{:?}", entry.id);
    })
    .await;

    let rows = db
        .query_contract(
            ContractAddress::new(0.into(), 0.into()),
            20,
            QueryOrder::Ascending { start: 0 },
        )
        .await?;
    rows.for_each(|entry| async move {
        println!("{:?}", entry);
    })
    .await;

    let rows = db
        .query_account(&addr, 20, QueryOrder::Descending { start: 0 })
        .await?;
    rows.for_each(|entry| async move {
        println!("{:?}", entry);
    })
    .await;

    let rows = db
        .query_contract(
            ContractAddress::new(0.into(), 0.into()),
            20,
            QueryOrder::Descending { start: 0 },
        )
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
