//! Support for writing indexers using the Rust SDK.
//!
//! The main indexer entrypoint is the [`TraverseConfig::traverse`] method
//! which will start chain traversal, calling methods of the [`Indexer`] trait
//! for each finalized block it discovers.
use crate::{
    types::{
        execution_tree, queries::BlockInfo, AccountTransactionEffects, BlockItemSummary,
        BlockItemSummaryDetails, ExecutionTree, SpecialTransactionOutcome,
    },
    v2::{self, FinalizedBlockInfo, QueryError, QueryResult},
};
use concordium_base::{
    base::{AbsoluteBlockHeight, Energy},
    contracts_common::{AccountAddress, Amount, ContractAddress, OwnedEntrypointName},
    hashes::TransactionHash,
    smart_contracts::OwnedReceiveName,
};
use futures::{stream::FuturesOrdered, StreamExt, TryStreamExt as _};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};
use tokio::time::error::Elapsed;
pub use tonic::async_trait;

/// Configuration for an indexer.
pub struct TraverseConfig {
    endpoints:       Vec<v2::Endpoint>,
    max_parallel:    usize,
    max_behind:      std::time::Duration,
    wait_after_fail: std::time::Duration,
    start_height:    AbsoluteBlockHeight,
}

#[derive(Debug, thiserror::Error)]
/// An error encountered during chain traversal and passed to the
/// [`Indexer`].
pub enum TraverseError {
    #[error("Failed to connect: {0}")]
    Connect(#[from] tonic::transport::Error),
    #[error("Failed to query: {0}")]
    Query(#[from] QueryError),
    #[error("Timed out waiting for finalized blocks.")]
    Elapsed(#[from] Elapsed),
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
///         err: TraverseError,
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
    async fn on_failure(
        &mut self,
        endpoint: v2::Endpoint,
        successive_failures: u64,
        err: TraverseError,
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
                        .on_failure(node_ep, successive_failures, e.into())
                        .await;
                    if should_stop {
                        return Ok(());
                    } else {
                        continue;
                    }
                }
            };

            let context = match indexer.on_connect(node_ep.clone(), &mut node).await {
                Ok(a) => a,
                Err(e) => {
                    successive_failures += 1;
                    let should_stop = indexer
                        .on_failure(node_ep, successive_failures, e.into())
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
                        .on_failure(node_ep, successive_failures, e.into())
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
                            .on_failure(node_ep, successive_failures, e.into())
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
                    futs.push_back(indexer.on_finalized(node.clone(), &context, fb));
                }
                while let Some(data) = futs.next().await {
                    let data = match data {
                        Ok(v) => v,
                        Err(e) => {
                            drop(futs);
                            successive_failures += 1;
                            let should_stop = indexer
                                .on_failure(node_ep, successive_failures, e.into())
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

/// An indexer that retrieves all transaction outcomes.
///
/// The [`on_connect`](Indexer::on_connect) and
/// [`on_failure`](Indexer::on_failure) methods of the [`Indexer`] trait only
/// log the events on `info` and `warn` levels, respectively, using the
/// [`tracing`](https://docs.rs/tracing/latest/tracing/) crate. The [target](https://docs.rs/tracing/latest/tracing/struct.Metadata.html#method.target)
/// of the log is `ccd_indexer` which may be used to filter the logs.
pub struct TransactionIndexer;

#[async_trait]
impl Indexer for TransactionIndexer {
    type Context = ();
    type Data = (BlockInfo, Vec<BlockItemSummary>);

    async fn on_connect<'a>(
        &mut self,
        endpoint: v2::Endpoint,
        _client: &'a mut v2::Client,
    ) -> QueryResult<()> {
        tracing::info!(
            target: "ccd_indexer",
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
        err: TraverseError,
    ) -> bool {
        tracing::warn!(
            target: "ccd_indexer",
            successive_failures,
            "Failed when querying endpoint {}: {err}",
            endpoint.uri()
        );
        false
    }
}

/// An indexer that retrieves smart contract updates where the specific
/// entrypoint of a contract was triggered as the top-level entrypoint.
///
/// The [`on_connect`](Indexer::on_connect) and
/// [`on_failure`](Indexer::on_failure) methods of the [`Indexer`] trait only
/// log the events on `info` and `warn` levels, respectively, using the
/// [`tracing`](https://docs.rs/tracing/latest/tracing/) crate. The [target](https://docs.rs/tracing/latest/tracing/struct.Metadata.html#method.target)
/// of the log is `ccd_indexer` which may be used to filter the logs.
pub struct ContractUpdateIndexer {
    pub target_address: ContractAddress,
    pub entrypoint:     OwnedEntrypointName,
}

pub struct ContractUpdateInfo {
    /// The execution tree generated by the call.
    pub execution_tree:   ExecutionTree,
    /// The amount of energy charged for the transaction.
    pub energy_cost:      Energy,
    /// The cost, in CCD, of the transaction.
    pub cost:             Amount,
    /// The hash of the transaction from which this update stems.
    pub transaction_hash: TransactionHash,
    /// The sender of the transaction.
    pub sender:           AccountAddress,
}

fn update_info(summary: BlockItemSummary) -> Option<ContractUpdateInfo> {
    let BlockItemSummaryDetails::AccountTransaction(at) = summary.details else {
        return None;
    };

    let AccountTransactionEffects::ContractUpdateIssued { effects } = at.effects else {
        return None;
    };

    Some(ContractUpdateInfo {
        execution_tree:   execution_tree(effects)?,
        energy_cost:      summary.energy_cost,
        cost:             at.cost,
        transaction_hash: summary.hash,
        sender:           at.sender,
    })
}

#[async_trait]
impl Indexer for ContractUpdateIndexer {
    type Context = ();
    type Data = (BlockInfo, Vec<ContractUpdateInfo>);

    async fn on_connect<'a>(
        &mut self,
        endpoint: v2::Endpoint,
        _client: &'a mut v2::Client,
    ) -> QueryResult<()> {
        tracing::info!(
            target: "ccd_indexer",
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
                    let Some(info) = update_info(summary) else {
                        return Ok(None);
                    };
                    if info.execution_tree.address() == self.target_address
                        && info.execution_tree.entrypoint() == self.entrypoint.as_entrypoint_name()
                    {
                        Ok(Some(info))
                    } else {
                        Ok(None)
                    }
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
        err: TraverseError,
    ) -> bool {
        tracing::warn!(
            target: "ccd_indexer",
            successive_failures,
            "Failed when querying endpoint {}: {err}",
            endpoint.uri()
        );
        false
    }
}

/// An indexer that retrieves smart contract updates where the specific
/// contracts were affected. The configuration can choose to require any or all
/// to be updated.
///
/// The [`on_connect`](Indexer::on_connect) and
/// [`on_failure`](Indexer::on_failure) methods of the [`Indexer`] trait only
/// log the events on `info` and `warn` levels, respectively, using the
/// [`tracing`](https://docs.rs/tracing/latest/tracing/) crate. The [target](https://docs.rs/tracing/latest/tracing/struct.Metadata.html#method.target)
/// of the log is `ccd_indexer` which may be used to filter the logs.
pub struct AffectedContractIndexer {
    pub addresses: BTreeSet<ContractAddress>,
    /// Require all contract addreseses in the `addresses` set to be updated.
    pub all:       bool,
}

#[async_trait]
impl Indexer for AffectedContractIndexer {
    type Context = ();
    type Data = (
        BlockInfo,
        Vec<(
            ContractUpdateInfo,
            BTreeMap<ContractAddress, BTreeSet<OwnedReceiveName>>,
        )>,
    );

    async fn on_connect<'a>(
        &mut self,
        endpoint: v2::Endpoint,
        _client: &'a mut v2::Client,
    ) -> QueryResult<()> {
        tracing::info!(
            target: "ccd_indexer",
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
                    let Some(info) = update_info(summary) else {
                        return Ok(None);
                    };
                    let affected_addresses = info.execution_tree.affected_addresses();
                    if (self.all
                        && self
                            .addresses
                            .iter()
                            .all(|addr| affected_addresses.contains_key(addr)))
                        || self
                            .addresses
                            .iter()
                            .any(|addr| affected_addresses.contains_key(addr))
                    {
                        Ok(Some((info, affected_addresses)))
                    } else {
                        Ok(None)
                    }
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
        err: TraverseError,
    ) -> bool {
        tracing::warn!(
            target: "ccd_indexer",
            successive_failures,
            "Failed when querying endpoint {}: {err}",
            endpoint.uri()
        );
        false
    }
}

/// An indexer that retrieves all events in a block, transaction outcomes
/// and special transaction outcomes.
///
/// The [`on_connect`](Indexer::on_connect) and
/// [`on_failure`](Indexer::on_failure) methods of the [`Indexer`] trait only
/// log the events on `info` and `warn` levels, respectively, using the
/// [`tracing`](https://docs.rs/tracing/latest/tracing/) crate. The [target](https://docs.rs/tracing/latest/tracing/struct.Metadata.html#method.target)
/// of the log is `ccd_indexer` which may be used to filter the logs.
pub struct BlockEventsIndexer;

#[async_trait]
impl Indexer for BlockEventsIndexer {
    type Context = ();
    type Data = (
        BlockInfo,
        Vec<BlockItemSummary>,
        Vec<SpecialTransactionOutcome>,
    );

    async fn on_connect<'a>(
        &mut self,
        endpoint: v2::Endpoint,
        client: &'a mut v2::Client,
    ) -> QueryResult<()> {
        TransactionIndexer.on_connect(endpoint, client).await
    }

    async fn on_finalized<'a>(
        &self,
        client: v2::Client,
        ctx: &'a (),
        fbi: FinalizedBlockInfo,
    ) -> QueryResult<Self::Data> {
        let mut special_client = client.clone();
        let special = async move {
            let events = special_client
                .get_block_special_events(fbi.height)
                .await?
                .response
                .try_collect()
                .await?;
            Ok(events)
        };
        let ((bi, summary), special) =
            futures::try_join!(TransactionIndexer.on_finalized(client, ctx, fbi), special)?;
        Ok((bi, summary, special))
    }

    async fn on_failure(
        &mut self,
        endpoint: v2::Endpoint,
        successive_failures: u64,
        err: TraverseError,
    ) -> bool {
        TransactionIndexer
            .on_failure(endpoint, successive_failures, err)
            .await
    }
}

#[async_trait]
/// Handle an individual event. This trait is designed to be used together with
/// the [`Processor`]. These two together are designed to ease the work of
/// writing the part of indexers where data is to be stored in a database.
pub trait ProcessEvent {
    /// The type of events that are to be processed. Typically this will be all
    /// of the transactions of interest for a single block.
    type Data;
    /// An error that can be signalled.
    type Error: std::fmt::Display + std::fmt::Debug;
    /// A description returned by the [`process`](ProcessEvent::process) method.
    /// This message is logged by the [`Processor`] and is intended to describe
    /// the data that was just processed.
    type Description: std::fmt::Display;

    /// Process a single item. This should work atomically in the sense that
    /// either the entire `data` is processed or none of it is in case of an
    /// error. This property is relied upon by the [`Processor`] to retry failed
    /// attempts.
    async fn process(&mut self, data: &Self::Data) -> Result<Self::Description, Self::Error>;

    /// The `on_failure` method is invoked by the [`Processor`] when it fails to
    /// process an event. It is meant to retry to recreate the resources,
    /// such as a database connection, that might have been dropped. The
    /// return value should signal if the handler process should continue
    /// (`true`) or not.
    ///
    /// The function takes the `error` that occurred at the latest
    /// [`process`](Self::process) call that just failed, and the number of
    /// attempts of calling `process` that failed.
    async fn on_failure(
        &mut self,
        error: Self::Error,
        failed_attempts: u32,
    ) -> Result<bool, Self::Error>;
}

pub struct ProcessorConfig {
    /// The amount of time to wait after a failure to process an event.
    wait_after_fail: std::time::Duration,
    /// A future to be signalled to stop processing.
    stop:            std::pin::Pin<Box<dyn std::future::Future<Output = ()>>>,
}

impl ProcessorConfig {
    /// After each failure the [`Processor`] will pause a bit before trying
    /// again. Defaults to 5 seconds.
    pub fn set_wait_after_failure(self, wait_after_fail: Duration) -> Self {
        Self {
            wait_after_fail,
            ..self
        }
    }

    /// Set the stop signal for the processor. This accepts a future which will
    /// be polled and if the future yields ready the `process_events` method
    /// will terminate.
    ///
    /// An example of such a future would be the `Receiver` end of a oneshot
    /// channel.
    pub fn set_stop_signal(self, stop: impl std::future::Future<Output = ()> + 'static) -> Self {
        Self {
            stop: Box::pin(stop),
            ..self
        }
    }

    /// Construct a new [`Processor`] that will retry the given number of times.
    /// The default wait after a failure is 5 seconds.
    pub fn new() -> Self {
        Self {
            wait_after_fail: std::time::Duration::from_secs(5),
            stop:            Box::pin(std::future::pending()),
        }
    }

    /// Process events that are coming in on the provided channel.
    ///
    /// This handler will only terminate in the case of
    ///
    /// - the [`on_failure`](ProcessEvent::on_failure) method indicates so.
    /// - the sender part of the `events` channel has been dropped
    /// - the [`ProcessorConfig`] was configured with a termination signal that
    ///   was triggered.
    ///
    /// The function will log progress using the `tracing` library with the
    /// target set to `ccd_event_processor`.
    pub async fn process_events<P: ProcessEvent>(
        mut self,
        mut process: P,
        mut events: tokio::sync::mpsc::Receiver<P::Data>,
    ) {
        while let Some(event) = tokio::select! {
            biased;
            _ = &mut self.stop => None,
            r = events.recv() => r,
        } {
            let mut try_number: u32 = 0;
            'outer: loop {
                let start = tokio::time::Instant::now();
                let response = process.process(&event).await;
                let end = tokio::time::Instant::now();
                let duration = end.duration_since(start).as_millis();
                match response {
                    Ok(descr) => {
                        tracing::info!(
                            target: "ccd_event_processor",
                            "{descr} in {duration}ms."
                        );
                        break 'outer;
                    }
                    Err(e) => {
                        tracing::error!(
                            target: "ccd_event_processor",
                            "Failed to process event: {e}. Took {duration}ms to fail."
                        );
                        tracing::info!(
                            target: "ccd_event_processor",
                            "Retrying in {}ms.",
                            self.wait_after_fail.as_millis()
                        );
                        // Wait before calling on_failure with the idea that whatever caused the
                        // failure is more likely to be fixed if we try
                        // after a bit of time rather than immediately.
                        tokio::time::sleep(self.wait_after_fail).await;
                        match process.on_failure(e, try_number + 1).await {
                            Ok(true) => {
                                // do nothing, continue.
                            }
                            Ok(false) => return,
                            Err(e) => {
                                tracing::warn!("Failed to restart: {e}.");
                            }
                        }
                        try_number += 1;
                    }
                }
            }
        }
        tracing::info!(
            target: "ccd_event_processor",
            "Terminating process_events due to channel closing."
        );
    }
}

/// Given a configuration for traversing the chain and processing generated
/// events start a process to traverse the chain and index events.
///
/// This process will only stop when the `stop_signal` future completes, when
/// [`traverse`](TraverseConfig::traverse) completes, or when
/// [`process_events`](ProcessorConfig::process_events) completes.
pub async fn traverse_and_process<I: Indexer, P: ProcessEvent<Data = I::Data>>(
    config: TraverseConfig,
    i: I,
    processor: ProcessorConfig,
    p: P,
) -> Result<(), QueryError> {
    let (sender, receiver) = tokio::sync::mpsc::channel(10);
    let fut1 = config.traverse(i, sender);
    let fut2 = processor.process_events(p, receiver);
    let (r1, ()) = futures::join!(fut1, fut2);
    r1
}
