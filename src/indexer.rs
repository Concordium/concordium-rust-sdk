//! Support for writing indexers using the Rust SDK.
//!
//! The main indexer entrypoint is the [`TraverseConfig::traverse`] method
//! which will start chain traversal, calling methods of the [`Indexer`] trait
//! for each finalized block it discovers.
use crate::{
    types::{queries::BlockInfo, BlockItemSummary, ExecutionTree},
    v2,
    v2::{FinalizedBlockInfo, QueryResult},
};
use concordium_base::{base::AbsoluteBlockHeight, contracts_common::ContractAddress, smart_contracts::OwnedReceiveName};
use futures::{stream::FuturesOrdered, StreamExt, TryStreamExt as _};
use std::time::Duration;
pub use tonic::async_trait;

/// Configuration for an indexer.
pub struct TraverseConfig {
    endpoints:       Vec<v2::Endpoint>,
    max_parallel:    usize,
    max_behind:      std::time::Duration,
    wait_after_fail: std::time::Duration,
    start_height:    AbsoluteBlockHeight,
}

#[async_trait]
/// A trait intended to be implemented by indexers that traverse the chain and
/// extract information of interest to store for efficient retrieval.
///
/// The main method of this trait is [`on_finalized`](Indexer::on_finalized)
/// which will be called by the [`traverse`](TraverseConfig::traverse) method
/// for each finalized block. The other two methods are meant for signalling and
/// bookkeeping.
///
/// Note that this trait has `async` methods, which is why the type signatures
/// are daunting. The intended way of implementing it is to use the
/// `async_trait` macro like so
///
/// ```
/// # use concordium_rust_sdk::{indexer::*, v2::{self, FinalizedBlockInfo, QueryResult}};
/// use concordium_rust_sdk::indexer::async_trait;
/// # struct MyIndexer;
/// #[async_trait]
/// impl Indexer for MyIndexer {
///     type Context = ();
///     type Data = ();
///
///     async fn on_connect<'a>(
///         &mut self,
///         endpoint: v2::Endpoint,
///         client: &'a mut v2::Client,
///     ) -> QueryResult<Self::Context> {
///         unimplemented!("Implement me.")
///     }
///
///     async fn on_finalized<'a>(
///         &self,
///         client: v2::Client,
///         ctx: &'a Self::Context,
///         fbi: FinalizedBlockInfo,
///     ) -> QueryResult<Self::Data> {
///         unimplemented!("Implement me.")
///     }
///
///     async fn on_failure(
///         &mut self,
///         ep: v2::Endpoint,
///         successive_failures: u64,
///         err: String,
///     ) -> bool {
///         unimplemented!("Implement me.")
///     }
/// }
/// ```

pub trait Indexer {
    /// The data that is retrieved upon connecting to the endpoint and supplied
    /// to each call of [`on_finalized`](Self::on_finalized).
    type Context: Send + Sync;
    /// The data returned by the [`on_finalized`](Self::on_finalized) call.
    type Data: Send + Sync;

    /// Called when a new connection is established to the given endpoint.
    /// The return value from this method is passed to each call of
    /// [`on_finalized`](Self::on_finalized).
    async fn on_connect<'a>(
        &mut self,
        endpoint: v2::Endpoint,
        client: &'a mut v2::Client,
    ) -> QueryResult<Self::Context>;

    /// The main method of this trait. It is called for each finalized block
    /// that the indexer discovers. Note that the indexer might call this
    /// concurrently for multiple blocks at the same time to speed up indexing.
    ///
    /// This method is meant to return errors that are unexpected, and if it
    /// does return an error the indexer will attempt to reconnect to the
    /// next endpoint.
    async fn on_finalized<'a>(
        &self,
        client: v2::Client,
        ctx: &'a Self::Context,
        fbi: FinalizedBlockInfo,
    ) -> QueryResult<Self::Data>;

    /// Called when either connecting to the node or querying the node fails.
    /// The number of successive failures without progress is passed to the
    /// method which should return whether to stop indexing ([`true`]) or not
    /// ([`false`]).
    ///
    /// The `err` passed to this method will contain a description of the error.
    async fn on_failure(
        &mut self,
        endpoint: v2::Endpoint,
        successive_failures: u64,
        err: String,
    ) -> bool;
}

impl TraverseConfig {
    /// A configuration with a single endpoint starting at the given block
    /// height.
    pub fn new_single(endpoint: v2::Endpoint, start_height: AbsoluteBlockHeight) -> Self {
        Self {
            endpoints: vec![endpoint],
            max_parallel: 4,
            max_behind: Duration::from_secs(60),
            wait_after_fail: Duration::from_secs(1),
            start_height,
        }
    }

    /// A configuration with a given list of endpoints and starting height.
    /// Returns [`None`] if the list of endpoints is empty.
    pub fn new(endpoints: Vec<v2::Endpoint>, start_height: AbsoluteBlockHeight) -> Option<Self> {
        if endpoints.is_empty() {
            return None;
        }
        Some(Self {
            endpoints,
            max_parallel: 4,
            max_behind: Duration::from_secs(60),
            wait_after_fail: Duration::from_secs(1),
            start_height,
        })
    }

    /// Set the maximum number of time the last finalized block of the node can
    /// be behind before it is deemed too far behind, and another node is
    /// tried.
    ///
    /// The default value is 60 seconds.
    pub fn set_max_behind(self, max_behind: Duration) -> Self { Self { max_behind, ..self } }

    /// After each failure the indexer will pause a bit before trying another
    /// node to avoid overloading the node. Defaults to 1 second.
    pub fn set_wait_after_failure(self, wait_after_fail: Duration) -> Self {
        Self {
            wait_after_fail,
            ..self
        }
    }

    /// Add an additional endpoint to the list of endpoints the indexer will
    /// use. This is added to the end of the list, so the endpoint is only tried
    /// in case of failure of previous queries.
    pub fn push_endpoint(mut self, endpoint: v2::Endpoint) -> Self {
        self.endpoints.push(endpoint);
        self
    }

    /// Set the maximum number of blocks that will be queried in parallel, if
    /// they are available. Defaults to 4 if not set explicitly.
    pub fn set_max_parallel(self, max_parallel: usize) -> Self {
        Self {
            max_parallel,
            ..self
        }
    }

    /// Traverse the chain according to the supplied configuration, invoking
    /// [`on_finalized`](Indexer::on_finalized) for each finalized block.
    ///
    /// Multiple [`on_finalized`](Indexer::on_finalized) calls might be executed
    /// concurrently, but their responses will be written to the provided
    /// [`tokio::sync::mpsc::Sender`] in the increasing order of block height,
    /// with no gaps.
    ///
    /// If a query fails, either due to timeout or node not being available the
    /// indexer will attempt the next endpoint it is configured with.
    ///
    /// For robust indexing it is crucial that the supplied
    /// [`Endpoints`](v2::Endpoint) are configured with timeouts so that the
    /// indexer may make progress.
    ///
    /// The [`traverse`](Self::traverse) method will return either when
    /// signalled so by the [`on_failure`](Indexer::on_failure) method or
    /// when the receiver part of the supplied [`tokio::sync::mpsc::Sender`]
    /// is closed. Typically this method should run in a task spawned via
    /// [`tokio::spawn`].
    pub async fn traverse<I: Indexer>(
        self,
        mut indexer: I,
        sender: tokio::sync::mpsc::Sender<I::Data>,
    ) -> QueryResult<()> {
        let TraverseConfig {
            endpoints,
            max_parallel,
            max_behind,
            wait_after_fail,
            start_height: mut height,
        } = self;
        let mut successive_failures: u64 = 0;
        for node_ep in endpoints.into_iter().cycle() {
            if sender.is_closed() {
                return Ok(());
            }
            if successive_failures > 0 {
                tokio::time::sleep(wait_after_fail).await
            }
            let mut node = match v2::Client::new(node_ep.clone()).await {
                Ok(v) => v,
                Err(e) => {
                    successive_failures += 1;
                    let should_stop = indexer
                        .on_failure(
                            node_ep,
                            successive_failures + 1,
                            format!("Failed to connect to node due to: {e}"),
                        )
                        .await;
                    if should_stop {
                        return Ok(());
                    } else {
                        continue;
                    }
                }
            };

            let a = match indexer.on_connect(node_ep.clone(), &mut node).await {
                Ok(a) => a,
                Err(e) => {
                    successive_failures += 1;
                    let should_stop = indexer
                        .on_failure(
                            node_ep,
                            successive_failures + 1,
                            format!("Failed to run on_connect handler due to: {e}"),
                        )
                        .await;
                    if should_stop {
                        return Ok(());
                    } else {
                        continue;
                    }
                }
            };
            let mut finalized_blocks = match node.get_finalized_blocks_from(height).await {
                Ok(v) => v,
                Err(e) => {
                    successive_failures += 1;
                    let should_stop = indexer
                        .on_failure(
                            node_ep,
                            successive_failures + 1,
                            format!("Failed to get finalized blocks due to: {e}"),
                        )
                        .await;
                    if should_stop {
                        return Ok(());
                    } else {
                        continue;
                    }
                }
            };

            'node_loop: loop {
                let last_height = height;
                let (has_error, chunks) = match finalized_blocks
                    .next_chunk_timeout(max_parallel, max_behind)
                    .await
                {
                    Ok(v) => v,
                    Err(e) => {
                        successive_failures += 1;
                        let should_stop = indexer
                            .on_failure(
                                node_ep,
                                successive_failures + 1,
                                format!("Failed to query next finalized blocks with due to: {e}",),
                            )
                            .await;
                        if should_stop {
                            return Ok(());
                        } else {
                            break 'node_loop;
                        }
                    }
                };

                let mut futs = FuturesOrdered::new();
                for fb in chunks {
                    futs.push_back(indexer.on_finalized(node.clone(), &a, fb));
                }
                while let Some(data) = futs.next().await {
                    let data = match data {
                        Ok(v) => v,
                        Err(e) => {
                            drop(futs);
                            successive_failures += 1;
                            let should_stop = indexer
                                .on_failure(
                                    node_ep,
                                    successive_failures + 1,
                                    format!("Failed to query due to: {e}"),
                                )
                                .await;
                            if should_stop {
                                return Ok(());
                            } else {
                                break 'node_loop;
                            }
                        }
                    };
                    if sender.send(data).await.is_err() {
                        return Ok(()); // the listener ended the stream, meaning
                                       // we
                                       // should stop.
                    }
                    height = height.next();
                }

                if height > last_height {
                    successive_failures = 0;
                }

                if has_error {
                    // we have processed the blocks we can, but further queries on the same stream
                    // will fail since the stream signalled an error.
                    break 'node_loop;
                }
            }
        }
        Ok(()) // unreachable
    }
}

/// An indexer that retrieves account transaction outcomes.
///
/// The [`on_connect`](Indexer::on_connect) and
/// [`on_failure`](Indexer::on_failure) methods of the [`Indexer`] trait only
/// log the events on `info` and `warn` levels, respectively, using the
/// [`tracing`](https://docs.rs/tracing/latest/tracing/) crate. The [target](https://docs.rs/tracing/latest/tracing/struct.Metadata.html#method.target)
/// of the log is `ccd_indexer` which may be used to filter the logs.
pub struct AccountTransactionIndexer;

#[async_trait]
impl Indexer for AccountTransactionIndexer {
    type Context = ();
    type Data = (BlockInfo, Vec<BlockItemSummary>);

    async fn on_connect<'a>(
        &mut self,
        endpoint: v2::Endpoint,
        _client: &'a mut v2::Client,
    ) -> QueryResult<()> {
        tracing::info!(
            target = "ccd_indexer",
            "Connected to endpoint {}.",
            endpoint.uri()
        );
        Ok(())
    }

    async fn on_finalized<'a>(
        &self,
        mut client: v2::Client,
        _ctx: &'a (),
        fbi: FinalizedBlockInfo,
    ) -> QueryResult<Self::Data> {
        let bi = client.get_block_info(fbi.height).await?.response;
        if bi.transaction_count != 0 {
            let summary = client
                .get_block_transaction_events(fbi.height)
                .await?
                .response
                .try_collect::<Vec<_>>()
                .await?;
            Ok((bi, summary))
        } else {
            Ok((bi, Vec::new()))
        }
    }

    async fn on_failure(
        &mut self,
        endpoint: v2::Endpoint,
        successive_failures: u64,
        err: String,
    ) -> bool {
        tracing::warn!(
            target = "ccd_indexer",
            successive_failures,
            "Failed when querying endpoint {}: {err}",
            endpoint.uri()
        );
        false
    }
}

/// An indexer that retrieves smart contract updates where the specific entrypoint
/// of a contract was triggered.
///
/// The [`on_connect`](Indexer::on_connect) and
/// [`on_failure`](Indexer::on_failure) methods of the [`Indexer`] trait only
/// log the events on `info` and `warn` levels, respectively, using the
/// [`tracing`](https://docs.rs/tracing/latest/tracing/) crate. The [target](https://docs.rs/tracing/latest/tracing/struct.Metadata.html#method.target)
/// of the log is `ccd_indexer` which may be used to filter the logs.
pub struct ContractUpdateIndexer {
    pub target_address: ContractAddress,
    pub entrypoint: OwnedReceiveName,
}

#[async_trait]
impl Indexer for ContractUpdateIndexer {
    type Context = ();
    type Data = (BlockInfo, Vec<ExecutionTree>);

    async fn on_connect<'a>(
        &mut self,
        endpoint: v2::Endpoint,
        _client: &'a mut v2::Client,
    ) -> QueryResult<()> {
        tracing::info!(
            target = "ccd_indexer",
            "Connected to endpoint {}.",
            endpoint.uri()
        );
        Ok(())
    }

    async fn on_finalized<'a>(
        &self,
        mut client: v2::Client,
        _ctx: &'a (),
        fbi: FinalizedBlockInfo,
    ) -> QueryResult<Self::Data> {
        let bi = client.get_block_info(fbi.height).await?.response;
        if bi.transaction_count != 0 {
            let summary = client
                .get_block_transaction_events(fbi.height)
                .await?
                .response
                .try_filter_map(|summary| async move {
                    let tree = summary.contract_update()?;
                    
                })
                .try_collect::<Vec<_>>()
                .await?;
            Ok((bi, summary))
        } else {
            Ok((bi, Vec::new()))
        }
    }

    async fn on_failure(
        &mut self,
        endpoint: v2::Endpoint,
        successive_failures: u64,
        err: String,
    ) -> bool {
        tracing::warn!(
            target = "ccd_indexer",
            successive_failures,
            "Failed when querying endpoint {}: {err}",
            endpoint.uri()
        );
        false
    }
}
