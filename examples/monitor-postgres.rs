//! Monitor a given account for incoming transactions.
//! This example uses a simple polling method to query account transactions in a
//! postgres database.
//!
//! For accounts with less activity it is likely going to be better to make use
//! of postgres notifications to avoid queries which will mostly return nothing.

use clap::AppSettings;
use concordium_rust_sdk::{
    id::types::AccountAddress,
    postgres::{DatabaseClient, QueryOrder},
};
use futures::StreamExt;
use structopt::StructOpt;
use tokio_postgres::NoTls;

#[derive(StructOpt)]
struct App {
    #[structopt(long = "account")]
    account:   AccountAddress,
    #[structopt(
        long = "db",
        default_value = "host=localhost dbname=transaction-outcome user=postgres \
                         password=password port=5432",
        help = "Database connection string."
    )]
    config:    tokio_postgres::Config,
    #[structopt(
        long = "wait-time",
        help = "Database polling interval in ms.",
        default_value = "2000"
    )]
    wait_time: u32,
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

    let db = DatabaseClient::create(app.config, NoTls).await?;
    let addr: AccountAddress = app.account;
    // get the ID where new events will start at.
    let start_id = {
        let rows = db
            .query_account(&addr, 1, QueryOrder::Descending { start: None })
            .await?;
        rows.fold(0, |_, row| async move { row.id + 1 }).await
    };

    let (sender, mut receiver) = tokio::sync::mpsc::channel(100);

    let wait_time = std::time::Duration::from_millis(app.wait_time.into());

    // Repeatedly poll for new data, and send it over.
    let poller = async move {
        let mut next_start_id = start_id;
        loop {
            let rows = db
                .query_account(&addr, 100, QueryOrder::Ascending {
                    start: Some(next_start_id),
                })
                .await?;
            // in the fold closure below we only need a reference to the channel
            // but we need to capture count and rows by value, so we need to use move
            // the following line makes it so that the reference to the sender channel
            // is moved, but we retain ownership of the channel.
            let sender = &sender;
            let (num_rows, new_start) = rows
                .fold((0, start_id), |(count, _), row| async move {
                    let new_start_id = row.id + 1;
                    sender.send(row).await.unwrap();
                    (count + 1, new_start_id)
                })
                .await;
            if num_rows == 0 {
                // If we did not get any rows don't query again for a bit.
                tokio::time::sleep(wait_time).await
            }
            next_start_id = new_start;
        }
        // we only use the Ok to specify the return type of the async block
        // But it is unreachable.
        #[allow(unreachable_code)]
        Ok::<(), tokio_postgres::Error>(())
    };

    let _handle = tokio::spawn(poller);

    while let Some(row) = receiver.recv().await {
        if row.summary.sender_account().as_ref() != Some(&addr) {
            println!("Incoming transaction: {:?}", row)
        }
    }

    Ok(())
}
