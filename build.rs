fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "generate-protos")]
    {
        tonic_build::configure()
            .build_client(true)
            .build_server(false)
            .out_dir("./src/v1/generated")
            .compile(
                &["concordium-base/concordium-grpc-api/concordium_p2p_rpc.proto"],
                &["concordium-base/concordium-grpc-api/"],
            )?;

        tonic_build::configure()
            .build_client(true)
            .build_server(false)
            .out_dir("./src/v2/generated")
            .compile(
                &["concordium-base/concordium-grpc-api/v2/concordium/service.proto"],
                &["concordium-base/concordium-grpc-api/"],
            )?;
    }
    Ok(())
}
