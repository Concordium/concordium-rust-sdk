use crate::types::{
    hashes::BlockHash, BlockItemSummary, ContractAddress, SpecialTransactionOutcome,
};
use crypto_common::{types::Timestamp, SerdeDeserialize, SerdeSerialize};
use futures::StreamExt;
use id::types::AccountAddress;
use std::convert::TryInto;
use tokio::task::{JoinError, JoinHandle};
use tokio_postgres::types::ToSql;
pub use tokio_postgres::{Config, Error, NoTls};

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
pub enum DatabaseSummaryEntry {
    #[serde(rename = "Left")]
    /// An item that is explicitly included in the block. This is always a
    /// result of user actions, e.g., transfers, account creations.
    BlockItem(BlockItemSummary),
    #[serde(rename = "Right")]
    /// Protocol genereated event, such as baking and finalization rewards, and
    /// minting.
    ProtocolEvent(SpecialTransactionOutcome),
}

#[derive(Debug, Clone, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
/// Row returned from the Postgres database, either from the
/// account transaction index, or from the contract transaction index.
/// Each row corresponds to one transaction that affected the given item
/// (account or contract).
pub struct DatabaseRow {
    /// Internal id of the row. This can be used in repeated queries to get more
    /// pages of results.
    pub id:         i64,
    /// Hash of the block the row applies to.
    pub block_hash: BlockHash,
    /// Slot time of the block the row applies to.
    pub block_time: Timestamp,
    /// Summary of the item. Either a user-generated transaction, or a protocol
    /// event that affected the account or contract.
    pub summary:    DatabaseSummaryEntry,
}

impl DatabaseSummaryEntry {
    /// Get the sender account of the transaction. The sender account only
    /// exists for normal transactions and does not exist for
    /// - credential deployments that create accounts
    /// - chain updates and special outcomes
    pub fn sender_account(&self) -> Option<AccountAddress> {
        match self {
            DatabaseSummaryEntry::BlockItem(bi) => bi.sender_account(),
            DatabaseSummaryEntry::ProtocolEvent(_) => None,
        }
    }
}

/// The database client for interfacing with the Postgres database.
/// Some common queries are provided as methods on this struct. If these do not
/// provide enough flexibility then the `AsRef<tokio_postgres::Client>` trait
/// implementation provides a way to use the database client to make queries
/// directly on the underlying client.
///
/// The correct way to close the database connection is to call
/// [DatabaseClient::stop]. This will make sure that the background connection
/// task is correctly shut down.
pub struct DatabaseClient {
    /// Connection handle that can be used to drop the connection.
    /// The connection is spawned in a background tokio task.
    connection_handle:             JoinHandle<Result<(), tokio_postgres::Error>>,
    database_client:               tokio_postgres::Client,
    /// Prepared statement that is used to query accounts in ascending order.
    /// It has 3 placeholders, for account address, `id` start and limit.
    query_account_statement_asc:   tokio_postgres::Statement,
    /// Prepared statement that is used to query contracts in ascending order.
    /// It has 4 placeholders, for contract index and subindex, `id` start and
    /// limit.
    query_contract_statement_asc:  tokio_postgres::Statement,
    /// Prepared statement that is used to query contracts in descending order.
    /// It has 3 placeholders, for account address, `id` start and limit.
    query_account_statement_desc:  tokio_postgres::Statement,
    /// Prepared statement that is used to query contracts in descending order.
    /// It has 4 placeholders, for contract index and subindex, `id` start and
    /// limit.
    query_contract_statement_desc: tokio_postgres::Statement,
}

impl DatabaseClient {
    /// Close the connection to the database and drop the client.
    pub async fn stop(self) -> Result<Result<(), tokio_postgres::Error>, JoinError> {
        self.connection_handle.abort();
        self.connection_handle.await
    }
}

/// This implementation enables direct queries on the underlying database
/// client.
impl AsRef<tokio_postgres::Client> for DatabaseClient {
    fn as_ref(&self) -> &tokio_postgres::Client { &self.database_client }
}

impl DatabaseClient {
    pub async fn create<T: tokio_postgres::tls::MakeTlsConnect<tokio_postgres::Socket>>(
        config: tokio_postgres::Config,
        tls: T,
    ) -> Result<DatabaseClient, tokio_postgres::Error>
    where
        T::Stream: Send + 'static, {
        let (database_client, connection) = config.connect(tls).await?;
        let connection_handle = tokio::spawn(connection);

        // NB before changing the queries.
        // In these queries we add a semantically unnecessary ORDER BY
        // summaries.id. This is added to increase performance of the queries.
        // Otherwise queries with small limits take a lot more time (<0.5s vs 7s). The
        // reason for this appears to be the postgresql query planner which chooses
        // a wrong approach for small limits for the database we have.
        let query_account_statement_asc = {
            let statement = "SELECT ati.id, summaries.block, summaries.timestamp, \
                             summaries.summary
 FROM ati JOIN summaries ON ati.summary = summaries.id
 WHERE ati.account = $1 AND ati.id >= $2
 ORDER BY ati.id ASC, summaries.id ASC LIMIT $3";
            database_client.prepare(statement).await?
        };

        let query_contract_statement_asc = {
            let statement = "SELECT cti.id, summaries.block, summaries.timestamp, \
                             summaries.summary
 FROM cti JOIN summaries ON cti.summary = summaries.id
 WHERE cti.index = $1 AND cti.subindex = $2 AND cti.id >= $3
 ORDER BY cti.id ASC, summaries.id ASC LIMIT $4";
            database_client.prepare(statement).await?
        };

        let query_account_statement_desc = {
            let statement = "SELECT ati.id, summaries.block, summaries.timestamp, \
                             summaries.summary
 FROM ati JOIN summaries ON ati.summary = summaries.id
 WHERE ati.account = $1 AND ati.id <= $2
 ORDER BY ati.id DESC, summaries.id DESC LIMIT $3";
            database_client.prepare(statement).await?
        };

        let query_contract_statement_desc = {
            let statement = "SELECT cti.id, summaries.block, summaries.timestamp, \
                             summaries.summary
 FROM cti JOIN summaries ON cti.summary = summaries.id
 WHERE cti.index = $1 AND cti.subindex = $2 AND cti.id <= $3
 ORDER BY cti.id DESC, summaries.id DESC LIMIT $4";
            database_client.prepare(statement).await?
        };

        Ok(DatabaseClient {
            connection_handle,
            database_client,
            query_account_statement_asc,
            query_contract_statement_asc,
            query_account_statement_desc,
            query_contract_statement_desc,
        })
    }
}

#[derive(Debug, Clone, Copy)]
/// Return results in the given order.
pub enum QueryOrder {
    Ascending {
        /// Return results where the row ID is `start` or higher.
        /// If `start` is not given assume starting from the beginning.
        start: Option<i64>,
    },
    Descending {
        /// Return results where the row ID is `start` or lower.
        /// If `start` is not given assume starting from the end.
        start: Option<i64>,
    },
}

impl DatabaseClient {
    /// Get the list of transactions affecting the given account.
    /// The return value is a stream of rows that have been parsed.
    ///
    /// The `limit` value limits the number of rows that will be returned.
    pub async fn query_account<'a>(
        &'a self,
        acc: &'a AccountAddress,
        limit: i64,
        order: QueryOrder,
    ) -> Result<impl futures::stream::Stream<Item = DatabaseRow>, tokio_postgres::Error> {
        let (statement, start) = match order {
            QueryOrder::Ascending { start } => {
                (&self.query_account_statement_asc, start.unwrap_or(i64::MIN))
            }
            QueryOrder::Descending { start } => (
                &self.query_account_statement_desc,
                start.unwrap_or(i64::MAX),
            ),
        };

        // This type, and the trait implementation below, are necessary
        // because tokio_postgres API is not flexible enough to allow supplying
        // tuples of values of different type as parameters.
        //
        // In principle this could be solvable by supplying an array of [&dyn ToSql]
        // values, but that causes problems when, for example, the Future (that
        // is the result of this function) is shipped off to a background task.
        // The information that the type that is in that array is Sync is lost.
        // Ideally we'd like to have [&dyn ToSql + Sync] but this does
        // not work either due to obscure reasons.
        //
        // Hence we have this private type.
        #[derive(Debug)]
        enum Helper<'a> {
            Array(&'a AccountAddress),
            Int(i64),
        }

        impl<'a> ToSql for Helper<'a> {
            tokio_postgres::types::to_sql_checked!();

            fn to_sql(
                &self,
                ty: &tokio_postgres::types::Type,
                out: &mut prost::bytes::BytesMut,
            ) -> Result<tokio_postgres::types::IsNull, Box<dyn std::error::Error + Sync + Send>>
            where
                Self: Sized, {
                match self {
                    Helper::Array(acc) => acc.as_ref().as_ref().to_sql(ty, out),
                    Helper::Int(start) => start.to_sql(ty, out),
                }
            }

            fn accepts(ty: &tokio_postgres::types::Type) -> bool
            where
                Self: Sized, {
                ty == &tokio_postgres::types::Type::BYTEA
                    || ty == &tokio_postgres::types::Type::INT8
            }
        }

        let params = [Helper::Array(acc), Helper::Int(start), Helper::Int(limit)];

        let rows = self.as_ref().query_raw(statement, &params).await?;
        Ok(rows.filter_map(|row_or_err| async move { construct_row(row_or_err) }))
    }

    /// Get the list of transactions affecting the given contract.
    /// The return value is a stream of rows that have been parsed.
    ///
    /// The `limit` value limits the number of rows that will be returned.
    pub async fn query_contract(
        &self,
        c: ContractAddress,
        limit: i64,
        order: QueryOrder,
    ) -> Result<impl futures::stream::Stream<Item = DatabaseRow>, tokio_postgres::Error> {
        let (statement, start) = match order {
            QueryOrder::Ascending { start } => (
                &self.query_contract_statement_asc,
                start.unwrap_or(i64::MIN),
            ),
            QueryOrder::Descending { start } => (
                &self.query_contract_statement_desc,
                start.unwrap_or(i64::MAX),
            ),
        };

        let params: [i64; 4] = [
            u64::from(c.index) as i64,
            u64::from(c.subindex) as i64,
            start,
            limit,
        ];

        let rows = self.as_ref().query_raw(statement, &params).await?;
        Ok(rows.filter_map(|row_or_err| async move { construct_row(row_or_err) }))
    }

    /// Return all transactions affecting the account, starting with the given
    /// row id.
    pub async fn iterate_account(
        &self,
        acc: &AccountAddress,
        start: Option<i64>,
    ) -> Result<impl futures::stream::Stream<Item = DatabaseRow>, tokio_postgres::Error> {
        self.query_account(acc, i64::MAX, QueryOrder::Ascending { start })
            .await
    }

    /// Return all transactions affecting the contract, starting with the given
    /// row id.
    pub async fn iterate_contract(
        &self,
        addr: ContractAddress,
        start: Option<i64>,
    ) -> Result<impl futures::stream::Stream<Item = DatabaseRow>, tokio_postgres::Error> {
        self.query_contract(addr, i64::MAX, QueryOrder::Ascending { start })
            .await
    }
}

/// Try to parse a row returned from the database.
/// This deliberately turns all errors into `None` since in the context it is
/// used errors should not occur.
fn construct_row(
    row_or_error: Result<tokio_postgres::Row, tokio_postgres::Error>,
) -> Option<DatabaseRow> {
    let row = row_or_error.ok()?;
    let id = row.get(0);
    let hash_bytes: &[u8] = row.get(1);
    let block_hash = BlockHash::new(hash_bytes.try_into().ok()?);
    let block_time = Timestamp::from(row.get::<_, i64>(2) as u64);
    let summary = serde_json::from_value::<DatabaseSummaryEntry>(row.get(3)).ok()?;
    Some(DatabaseRow {
        id,
        block_hash,
        block_time,
        summary,
    })
}
