fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("concordium-grpc-api/concordium_p2p_rpc.proto")?;
    Ok(())
}
