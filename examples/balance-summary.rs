//! List accounts with the most liquid balance, and total stake, total amount,
//! and total liquid amount of accounts. Additionally list contracts with at
//! most CCD owned.
use clap::AppSettings;
use concordium_rust_sdk::{
    common::types::Amount,
    v2::{self, BlockIdentifier},
};
use futures::{Future, TryStreamExt};
use structopt::StructOpt;

#[derive(StructOpt)]
struct App {
    #[structopt(
        long = "node",
        help = "V2 GRPC interface of the node.",
        default_value = "http://localhost:20000"
    )]
    endpoint: v2::Endpoint,
    #[structopt(
        long = "lastfinal",
        help = "Block to query the data in. Defaults to last finalized block."
    )]
    block:    BlockIdentifier,
    #[structopt(
        long = "num",
        help = "How many queries to make in parallel.",
        default_value = "1"
    )]
    num:      usize,
}

async fn make_queries<
    J: Send + 'static,
    I: IntoIterator<Item = J> + Send,
    Chunks: IntoIterator<Item = I> + Send + 'static,
    A: Send + 'static,
    F: Future<Output = A> + Send + 'static,
>(
    iter: Chunks,
    query: impl (Fn(J) -> F) + Send + Sync + 'static,
    n: usize,
) -> (tokio::task::JoinHandle<()>, tokio::sync::mpsc::Receiver<A>)
where
    Chunks::IntoIter: Send,
    I::IntoIter: Send, {
    let (sender, receiver) = tokio::sync::mpsc::channel::<A>(n);
    let sender = async move {
        'outer: for chunk in iter {
            let mut handles = Vec::with_capacity(n);
            for j in chunk {
                handles.push(tokio::spawn(query(j)));
            }
            for res in futures::future::join_all(handles).await {
                match res {
                    Ok(v) => {
                        if sender.send(v).await.is_err() {
                            break 'outer;
                        }
                    }
                    Err(_) => break 'outer,
                }
            }
        }
    };
    let cancel_handle = tokio::spawn(sender);
    (cancel_handle, receiver)
}

async fn make_queries_vec<
    J: Send + Sync + 'static + Clone,
    A: Send + 'static,
    F: Future<Output = A> + Send + 'static,
>(
    chunks: &[J],
    query: impl (Fn(J) -> F) + Send + Sync + 'static,
    n: usize,
) -> (tokio::task::JoinHandle<()>, tokio::sync::mpsc::Receiver<A>) {
    let iter = chunks.chunks(n).map(Vec::from).collect::<Vec<_>>();
    make_queries(iter, query, n).await
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let app = {
        let app = App::clap().global_setting(AppSettings::ColoredHelp);
        let matches = app.get_matches();
        App::from_clap(&matches)
    };

    let mut client = v2::Client::new(app.endpoint).await?;

    let block = app.block;
    println!("Listing accounts in block {}.", block);

    let accounts_response = client.get_account_list(&block).await?;
    let accounts = accounts_response.response.try_collect::<Vec<_>>().await?;
    let block: BlockIdentifier = accounts_response.block_hash.into();

    let total_accounts = accounts.len();
    let closure_client = client.clone();
    // this is copying account addresses, but this is cheap compared to query times
    let (_cancel, mut receiver) = make_queries_vec(
        &accounts,
        move |acc| {
            let mut client = closure_client.clone();
            async move {
                let info = client.get_account_info(&acc.into(), &block).await?.response;
                let additional_stake = info
                    .account_stake
                    .map_or(Amount::zero(), |baker_delegator| {
                        baker_delegator.staked_amount()
                    });
                let additional_liquid_amount = info.account_amount
                    - std::cmp::max(additional_stake, info.account_release_schedule.total);
                Ok::<_, anyhow::Error>((
                    acc,
                    additional_stake,
                    info.account_amount,
                    info.account_release_schedule.total,
                    additional_liquid_amount,
                ))
            }
        },
        app.num,
    )
    .await;
    let mut out = Vec::new();
    let mut staked_amount = Amount::zero();
    let mut total_amount = Amount::zero();
    let mut locked_amount = Amount::zero();
    let mut liquid_amount = Amount::zero();

    while let Some(res) = receiver.recv().await {
        let (acc, additional_stake, additional_amount, additional_scheduled, additional_liquid) =
            res?;
        staked_amount += additional_stake;
        total_amount += additional_amount;
        locked_amount += additional_scheduled;
        liquid_amount += additional_liquid;

        out.push((acc, additional_liquid, additional_amount));
    }

    // sort by decreasing liquid amount.
    out.sort_by(|l, r| r.1.cmp(&l.1));

    println!(
        "There are in total {} accounts in block {}.",
        total_accounts, block
    );
    println!("Total public CCD = {}", total_amount);
    println!("Staked CCD = {}", staked_amount);
    println!("CCD locked in schedules = {}", locked_amount);
    println!("Liquid CCD = {}", liquid_amount);

    println!("20 accounts with most liquid balance");
    for (acc, lb, tb) in out.iter().take(20) {
        println!("{}: {} liquid out of {} total", acc, lb, tb);
    }

    // Now also handle contracts.
    let mut total_contract_amount = Amount::zero();
    let contracts = client
        .get_instance_list(&block)
        .await?
        .response
        .try_collect::<Vec<_>>()
        .await?;
    let mut cout = Vec::new();
    for ccs in contracts.chunks(app.num).map(Vec::from) {
        let mut handles = Vec::with_capacity(app.num);
        for contract in ccs {
            let mut client = client.clone();
            handles.push(tokio::spawn(async move {
                let info = client.get_instance_info(contract, &block).await?.response;
                Ok::<_, anyhow::Error>((contract, info))
            }));
        }
        for res in futures::future::join_all(handles).await {
            let (addr, info) = res??;
            total_contract_amount += info.amount();

            cout.push((addr, info));
        }
    }
    println!("Total contract owned CCD = {}", total_contract_amount);
    cout.sort_by(|(_, l), (_, r)| r.amount().cmp(&l.amount()));
    for (addr, info) in cout.iter().take(20) {
        println!(
            "{}: at <{}, {}> owns {}",
            info.name().as_contract_name().get_chain_name(),
            addr.index,
            addr.subindex,
            info.amount()
        );
    }

    Ok(())
}
