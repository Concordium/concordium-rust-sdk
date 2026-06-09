// This file follows the same structure as tonic-generated output.
// It is written by hand because the health proto is compiled separately from
// the main concordium.v2 service proto.  When proto-generate is re-run it will
// regenerate this file automatically (see proto-generate/src/main.rs).

/// Parameters to the node health query.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeHealthRequest {}

/// Response to the health check.
///
/// An `OK` RPC status means the node is healthy. Errors are communicated via
/// RPC status codes rather than fields in this message.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeHealthResponse {}

/// Generated gRPC client for the `concordium.health.Health` service.
pub mod health_client {
    #![allow(
        unused_variables,
        dead_code,
        missing_docs,
        clippy::wildcard_imports,
        clippy::let_unit_value
    )]
    use tonic::codegen::*;
    use tonic::codegen::http::Uri;

    #[derive(Debug, Clone)]
    pub struct HealthClient<T> {
        inner: tonic::client::Grpc<T>,
    }

    impl HealthClient<tonic::transport::Channel> {
        /// Attempt to create a new client by connecting to a given endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }

    impl<T> HealthClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + std::marker::Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + std::marker::Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }

        pub fn with_origin(inner: T, origin: Uri) -> Self {
            let inner = tonic::client::Grpc::with_origin(inner, origin);
            Self { inner }
        }

        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> HealthClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T::ResponseBody: Default,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<http::Request<tonic::body::BoxBody>>>::Error:
                Into<StdError> + std::marker::Send + std::marker::Sync,
        {
            HealthClient::new(InterceptedService::new(inner, interceptor))
        }

        /// Check the health of the node.
        ///
        /// Returns `Ok` when the node reports itself healthy; returns an error
        /// status otherwise (e.g. `Status::unavailable` when the node is not
        /// reachable or is not yet caught up).
        pub async fn check(
            &mut self,
            request: impl tonic::IntoRequest<super::NodeHealthRequest>,
        ) -> std::result::Result<tonic::Response<super::NodeHealthResponse>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::unknown(format!("Service was not ready: {}", e.into()))
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/concordium.health.Health/Check",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("concordium.health.Health", "Check"));
            self.inner.unary(req, path, codec).await
        }
    }
}
