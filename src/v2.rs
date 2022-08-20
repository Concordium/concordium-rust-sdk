use crate::{
    endpoints,
    types::{hashes::BlockHash, AbsoluteBlockHeight},
};
use concordium_contracts_common::AccountAddress;
use futures::{Stream, StreamExt};
use tonic::IntoRequest;

mod generated {
    tonic::include_proto!("concordium.v2");

    impl TryFrom<AccountAddress> for super::AccountAddress {
        type Error = tonic::Status;

        fn try_from(value: AccountAddress) -> Result<Self, Self::Error> {
            match value.value.try_into() {
                Ok(addr) => Ok(Self(addr)),
                Err(_) => Err(tonic::Status::internal(
                    "Unexpected account address format.",
                )),
            }
        }
    }

    impl TryFrom<BlockHash> for super::BlockHash {
        type Error = tonic::Status;

        fn try_from(value: BlockHash) -> Result<Self, Self::Error> {
            match value.value.try_into() {
                Ok(hash) => Ok(Self::new(hash)),
                Err(_) => Err(tonic::Status::internal("Unexpected block hash format.")),
            }
        }
    }

    impl From<AbsoluteBlockHeight> for super::AbsoluteBlockHeight {
        fn from(abh: AbsoluteBlockHeight) -> Self { Self { height: abh.value } }
    }
}

#[derive(Clone, Debug)]
/// Client that can perform queries.
/// All endpoints take a `&mut self` as an argument which means that a single
/// instance cannot be used concurrently. However instead of putting the Client
/// behind a Mutex, the intended way to use it is to clone it. Cloning is very
/// cheap and will reuse the underlying connection.
pub struct Client {
    client: generated::queries_client::QueriesClient<tonic::transport::Channel>,
}

#[derive(Clone, Copy, Debug)]
pub struct QueryResponse<A> {
    /// Block hash for which the query applies.
    pub block_hash: BlockHash,
    pub response:   A,
}

/// A block identifier used in queries.
#[derive(Copy, Clone, Debug)]
pub enum BlockIdentifier {
    /// Query in the context of the best block.
    Best,
    /// Query in the context of the last finalized block at the time of the
    /// query.
    LastFinal,
    /// Query in the context of a specific block hash.
    Given(BlockHash),
}

#[derive(Copy, Clone, Debug)]
pub struct FinalizedBlockInfo {
    pub block_hash: BlockHash,
    pub height:     AbsoluteBlockHeight,
}

impl IntoRequest<generated::BlockHashInput> for &BlockIdentifier {
    fn into_request(self) -> tonic::Request<generated::BlockHashInput> {
        let block_hash_input = match self {
            BlockIdentifier::Best => {
                generated::block_hash_input::BlockHashInput::Best(Default::default())
            }
            BlockIdentifier::LastFinal => {
                generated::block_hash_input::BlockHashInput::LastFinal(Default::default())
            }
            BlockIdentifier::Given(h) => {
                generated::block_hash_input::BlockHashInput::Given(generated::BlockHash {
                    value: h.as_ref().to_vec(),
                })
            }
        };
        let v = generated::BlockHashInput {
            block_hash_input: Some(block_hash_input),
        };
        tonic::Request::new(v)
    }
}

impl Client {
    pub async fn new<E: Into<tonic::transport::Endpoint>>(
        endpoint: E,
    ) -> Result<Self, tonic::transport::Error> {
        let client = generated::queries_client::QueriesClient::connect(endpoint).await?;
        Ok(Self { client })
    }

    pub async fn get_account_list(
        &mut self,
        bi: &BlockIdentifier,
    ) -> endpoints::QueryResult<
        QueryResponse<impl Stream<Item = Result<AccountAddress, tonic::Status>>>,
    > {
        let response = self.client.get_account_list(bi).await?;
        let block_hash = extract_metadata(&response)?;
        let stream = response.into_inner().map(|x| x.and_then(TryFrom::try_from));
        Ok(QueryResponse {
            block_hash,
            response: stream,
        })
    }

    pub async fn get_finalized_blocks(
        &mut self,
    ) -> endpoints::QueryResult<impl Stream<Item = Result<FinalizedBlockInfo, tonic::Status>>> {
        let response = self
            .client
            .get_finalized_blocks(generated::Empty::default())
            .await?;
        let stream = response.into_inner().map(|x| match x {
            Ok(v) => {
                let block_hash = v.hash.require_owned().and_then(TryFrom::try_from)?;
                let height = v.height.require_owned()?.into();
                Ok(FinalizedBlockInfo { block_hash, height })
            }
            Err(x) => Err(x),
        });
        Ok(stream)
    }
}

fn extract_metadata<T>(response: &tonic::Response<T>) -> endpoints::RPCResult<BlockHash> {
    match response.metadata().get("blockhash") {
        Some(bytes) => {
            let bytes = bytes.as_bytes();
            if bytes.len() == 64 {
                let mut hash = [0u8; 32];
                if let Err(_) = hex::decode_to_slice(bytes, &mut hash) {
                    tonic::Status::unknown("Response does correctly encode the block hash.");
                }
                Ok(hash.into())
            } else {
                Err(endpoints::RPCError::CallError(tonic::Status::unknown(
                    "Response does not include the expected metadata.",
                )))
            }
        }
        None => Err(endpoints::RPCError::CallError(tonic::Status::unknown(
            "Response does not include the expected metadata.",
        ))),
    }
}

/// A helper trait to make it simpler to require specific fields when parsing a
/// protobuf message by allowing us to use method calling syntax and
/// constructing responses that match the calling context, allowing us to use
/// the `?` syntax.
///
/// The main reason for needing this is that in proto3 all fields are optional,
/// so it is up to the application to validate inputs if they are required.
trait Require<E> {
    type A;
    fn require(&self) -> Result<&Self::A, E>;
    fn require_owned(self) -> Result<Self::A, E>;
}

impl<A> Require<tonic::Status> for Option<A> {
    type A = A;

    fn require(&self) -> Result<&Self::A, tonic::Status> {
        match self {
            Some(v) => Ok(v),
            None => Err(tonic::Status::invalid_argument("missing field")),
        }
    }

    fn require_owned(self) -> Result<Self::A, tonic::Status> {
        match self {
            Some(v) => Ok(v),
            None => Err(tonic::Status::invalid_argument("missing field")),
        }
    }
}
