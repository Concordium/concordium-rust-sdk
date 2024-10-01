//! A simple example of an indexer that indexes all CCD transfers (transfers and
//! transfers with memo) and stores them into an sqlite database.
use clap::AppSettings;
use concordium_rust_sdk::{
    indexer::{self, ProcessorConfig, TransactionIndexer, TraverseConfig},
    types::{
        queries::BlockInfo, AbsoluteBlockHeight, AccountTransactionEffects, BlockItemSummary,
        BlockItemSummaryDetails,
    },
    v2,
};
use std::path::PathBuf;
use structopt::StructOpt;
use tracing::Level;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "GRPC interface of the node.",
        default_value = "http://localhost:20000"
    )]
    endpoint: v2::Endpoint,
    #[structopt(long = "from", help = "Starting time. Defaults to genesis time.")]
    from:     Option<chrono::DateTime<chrono::Utc>>,
    #[structopt(
        long = "db-path",
        help = "Path to the location of the SQLITE database.",
        default_value = "./transfers-db.sqlite"
    )]
    db_path:  std::path::PathBuf,
}

/// A handler for storing transactions. This implements the
/// `indexer::ProcessEvent` trait to store transfers in the database.
struct StoreTransfers {
    /// A database connection string, used for reconnects.
    conn_string: PathBuf,
    /// An active connection to the sqlite database.
    db_conn:     sqlite::Connection,
}

#[indexer::async_trait]
impl indexer::ProcessEvent for StoreTransfers {
    type Data = (BlockInfo, Vec<BlockItemSummary>);
    type Description = String;
    type Error = anyhow::Error;

    async fn process(
        &mut self,
        (block_info, txs): &Self::Data,
    ) -> Result<Self::Description, Self::Error> {
        // It is typically easiest to reason about a database if blocks are inserted in
        // a single database transaction. So we do that.
        self.db_conn.execute("BEGIN")?;
        for tx in txs {
            let BlockItemSummaryDetails::AccountTransaction(at) = &tx.details else {
                continue;
            };
            // we only look at transfers or transfers with memo.
            let (amount, to) = match at.effects {
                AccountTransactionEffects::AccountTransfer { amount, to } => (amount, to),
                AccountTransactionEffects::AccountTransferWithMemo {
                    amount,
                    to,
                    memo: _,
                } => (amount, to),
                _ => continue,
            };
            let mut statement = self.db_conn.prepare(
                "INSERT INTO transfers (sender, amount, receiver) VALUES (:sender, :amount, \
                 :receiver)",
            )?;
            statement.bind((":sender", at.sender.to_string().as_str()))?;
            statement.bind((":receiver", to.to_string().as_str()))?;
            statement.bind((":amount", amount.to_string().as_str()))?;
            while statement.next()? != sqlite::State::Done {}
        }
        self.db_conn.execute("COMMIT")?;
        // We return an informative message that will be logged by the `process_events`
        // method of the indexer.
        Ok(format!(
            "Processed block {} at height {} with timestamp {}.",
            block_info.block_hash, block_info.block_height, block_info.block_slot_time
        ))
    }

    async fn on_failure(
        &mut self,
        error: Self::Error,
        _failed_attempts: u32,
    ) -> Result<bool, Self::Error> {
        tracing::error!("Encountered error {error}");
        drop(std::mem::replace(
            &mut self.db_conn,
            sqlite::open(self.conn_string.as_path())?,
        ));
        Ok(true)
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    {
        use tracing_subscriber::prelude::*;
        let log_filter = tracing_subscriber::filter::Targets::new()
            .with_target(module_path!(), Level::INFO)
            .with_target("ccd_indexer", Level::INFO)
            .with_target("ccd_event_processor", Level::INFO);
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .with(log_filter)
            .init();
    }

    let mut client = v2::Client::new(app.endpoint.clone()).await?;

    // Find the block to start at.
    let h = if let Some(start_time) = app.from {
        let start = client
            .find_first_finalized_block_no_earlier_than(.., start_time)
            .await?;
        start.block_height
    } else {
        AbsoluteBlockHeight::from(0u64)
    };

    let traverse_config = TraverseConfig::new_single(app.endpoint, h).set_max_parallel(2); // 2 parallel queries at most

    let processor_config = ProcessorConfig::new();

    let db_conn = sqlite::open(app.db_path.as_path())?;
    db_conn.execute("CREATE TABLE transfers (sender TEXT, amount TEXT, receiver TEXT)")?;

    let transfers = StoreTransfers {
        db_conn,
        conn_string: app.db_path,
    };

    // The program terminates only
    // when the processor terminates, which in this example can only happen if
    // there are sufficiently many errors when attempting to write to the
    // database.
    indexer::traverse_and_process(
        traverse_config,
        TransactionIndexer,
        processor_config,
        transfers,
    )
    .await?;
    Ok(())
}
