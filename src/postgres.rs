use crate::types::{
    hashes::BlockHash, AbsoluteBlockHeight, BlockItemSummary, ContractAddress,
    SpecialTransactionOutcome,
};
use concordium_base::{
    common::{types::Timestamp, SerdeDeserialize, SerdeSerialize},
    id::types::AccountAddress,
};
use futures::StreamExt;
use std::convert::TryInto;
use tokio::task::{JoinError, JoinHandle};
use tokio_postgres::{
    types::{BorrowToSql, ToSql},
    RowStream,
};
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
    pub id:           i64,
    /// Hash of the block the row applies to.
    pub block_hash:   BlockHash,
    /// Slot time of the block the row applies to.
    pub block_time:   Timestamp,
    /// Block height stored in the database.
    pub block_height: AbsoluteBlockHeight,
    /// Summary of the item. Either a user-generated transaction, or a protocol
    /// event that affected the account or contract.
    pub summary:      DatabaseSummaryEntry,
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

/// A helper to enable support both for prepared and raw statements.
/// Prepared statements can be more efficient, but they require the database
/// tables to already exist when establishing the database connection.
enum QueryStatement {
    Raw(&'static str),
    Prepared(tokio_postgres::Statement),
}

struct QueryStatements {
    /// Prepared statement that is used to query accounts in ascending order.
    /// It has 3 placeholders, for account address, `id` start and limit.
    query_account_statement_asc:   QueryStatement,
    /// Prepared statement that is used to query contracts in ascending order.
    /// It has 4 placeholders, for contract index and subindex, `id` start and
    /// limit.
    query_contract_statement_asc:  QueryStatement,
    /// Prepared statement that is used to query contracts in descending order.
    /// It has 3 placeholders, for account address, `id` start and limit.
    query_account_statement_desc:  QueryStatement,
    /// Prepared statement that is used to query contracts in descending order.
    /// It has 4 placeholders, for contract index and subindex, `id` start and
    /// limit.
    query_contract_statement_desc: QueryStatement,
}

impl QueryStatements {
    pub async fn create(
        client: &tokio_postgres::Client,
        prepared: bool,
    ) -> Result<Self, tokio_postgres::Error> {
        // NB before changing the queries.
        // In these queries we add a semantically unnecessary ORDER BY
        // summaries.id. This is added to increase performance of the queries.
        // Otherwise queries with small limits take a lot more time (<0.5s vs 7s). The
        // reason for this appears to be the postgresql query planner which chooses
        // a wrong approach for small limits for the database we have.
        let query_account_statement_asc = {
            let statement = "SELECT ati.id, summaries.block, summaries.timestamp, \
                             summaries.height, summaries.summary
 FROM ati JOIN summaries ON ati.summary = summaries.id
 WHERE ati.account = $1 AND ati.id >= $2
 ORDER BY ati.id ASC, summaries.id ASC LIMIT $3";
            if prepared {
                QueryStatement::Prepared(client.prepare(statement).await?)
            } else {
                QueryStatement::Raw(statement)
            }
        };

        let query_contract_statement_asc = {
            let statement = "SELECT cti.id, summaries.block, summaries.timestamp, \
                             summaries.height, summaries.summary
 FROM cti JOIN summaries ON cti.summary = summaries.id
 WHERE cti.index = $1 AND cti.subindex = $2 AND cti.id >= $3
 ORDER BY cti.id ASC, summaries.id ASC LIMIT $4";
            if prepared {
                QueryStatement::Prepared(client.prepare(statement).await?)
            } else {
                QueryStatement::Raw(statement)
            }
        };

        let query_account_statement_desc = {
            let statement = "SELECT ati.id, summaries.block, summaries.timestamp, \
                             summaries.height, summaries.summary
 FROM ati JOIN summaries ON ati.summary = summaries.id
 WHERE ati.account = $1 AND ati.id <= $2
 ORDER BY ati.id DESC, summaries.id DESC LIMIT $3";
            if prepared {
                QueryStatement::Prepared(client.prepare(statement).await?)
            } else {
                QueryStatement::Raw(statement)
            }
        };

        let query_contract_statement_desc = {
            let statement = "SELECT cti.id, summaries.block, summaries.timestamp, \
                             summaries.height, summaries.summary
 FROM cti JOIN summaries ON cti.summary = summaries.id
 WHERE cti.index = $1 AND cti.subindex = $2 AND cti.id <= $3
 ORDER BY cti.id DESC, summaries.id DESC LIMIT $4";
            if prepared {
                QueryStatement::Prepared(client.prepare(statement).await?)
            } else {
                QueryStatement::Raw(statement)
            }
        };
        Ok(Self {
            query_account_statement_asc,
            query_contract_statement_asc,
            query_account_statement_desc,
            query_contract_statement_desc,
        })
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
    connection_handle: JoinHandle<Result<(), tokio_postgres::Error>>,
    database_client:   tokio_postgres::Client,
    statements:        QueryStatements,
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

/// This implementation enables direct queries on the underlying database
/// client such as [Client::transaction](https://docs.rs/tokio-postgres/*/tokio_postgres/struct.Client.html#method.transaction)
/// that require mutable access to the underlying client
impl AsMut<tokio_postgres::Client> for DatabaseClient {
    fn as_mut(&mut self) -> &mut tokio_postgres::Client { &mut self.database_client }
}

impl DatabaseClient {
    /// Create a connection to the database. This does not create any prepared
    /// statements. If the database and its tables already exist prefer
    /// [DatabaseClient::create_prepared], however if the database tables do not
    /// yet exist then use this method to build it.
    pub async fn create<T: tokio_postgres::tls::MakeTlsConnect<tokio_postgres::Socket>>(
        config: tokio_postgres::Config,
        tls: T,
    ) -> Result<DatabaseClient, tokio_postgres::Error>
    where
        T::Stream: Send + 'static, {
        let (database_client, connection) = config.connect(tls).await?;
        let connection_handle = tokio::spawn(connection);
        let statements = QueryStatements::create(&database_client, false).await?;
        Ok(DatabaseClient {
            connection_handle,
            database_client,
            statements,
        })
    }

    /// Like [DatabaseClient::create] but creates prepared statements and thus
    /// requires all the necessary database tables to already exist. Use this
    /// when using the database in read-only mode.
    pub async fn create_prepared<T: tokio_postgres::tls::MakeTlsConnect<tokio_postgres::Socket>>(
        config: tokio_postgres::Config,
        tls: T,
    ) -> Result<DatabaseClient, tokio_postgres::Error>
    where
        T::Stream: Send + 'static, {
        let (database_client, connection) = config.connect(tls).await?;
        let connection_handle = tokio::spawn(connection);
        let statements = QueryStatements::create(&database_client, true).await?;
        Ok(DatabaseClient {
            connection_handle,
            database_client,
            statements,
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
    async fn query<P, I>(&self, st: &QueryStatement, params: I) -> Result<RowStream, Error>
    where
        P: BorrowToSql,
        I: IntoIterator<Item = P>,
        I::IntoIter: ExactSizeIterator, {
        match st {
            QueryStatement::Raw(r) => self.as_ref().query_raw(*r, params).await,
            QueryStatement::Prepared(p) => self.as_ref().query_raw(p, params).await,
        }
    }

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
            QueryOrder::Ascending { start } => (
                &self.statements.query_account_statement_asc,
                start.unwrap_or(i64::MIN),
            ),
            QueryOrder::Descending { start } => (
                &self.statements.query_account_statement_desc,
                start.unwrap_or(i64::MAX),
            ),
        };
        let acc_raw: &[u8] = acc.as_ref();
        let params = [
            &acc_raw as &(dyn ToSql + Sync),
            &start as &(dyn ToSql + Sync),
            &limit as &(dyn ToSql + Sync),
        ];

        let rows = self.query(statement, params).await?;
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
                &self.statements.query_contract_statement_asc,
                start.unwrap_or(i64::MIN),
            ),
            QueryOrder::Descending { start } => (
                &self.statements.query_contract_statement_desc,
                start.unwrap_or(i64::MAX),
            ),
        };

        let params: [i64; 4] = [c.index as i64, c.subindex as i64, start, limit];

        let rows = self.query(statement, &params).await?;
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
    let block_height = AbsoluteBlockHeight::from(row.get::<_, i64>(3) as u64);
    let summary = serde_json::from_value::<DatabaseSummaryEntry>(row.get(4)).ok()?;
    Some(DatabaseRow {
        id,
        block_hash,
        block_time,
        block_height,
        summary,
    })
}
