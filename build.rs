fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("concordium-base/concordium-grpc-api/concordium_p2p_rpc.proto")?;

    // Compile
    tonic_build::configure()
        .build_client(true)
        .build_server(false)
        .compile(
            &["concordium-base/concordium-grpc-api/v2/concordium/service.proto"],
            &["concordium-base/concordium-grpc-api/"],
        )?;
    Ok(())
}
