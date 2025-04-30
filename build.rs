fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "generate-protos")]
    {
        tonic_build::configure()
            .build_client(true)
            .build_server(false)
            .out_dir("./src/v2/generated")
            .compile_protos(
                &["concordium-base/concordium-grpc-api/v2/concordium/service.proto"],
                &["concordium-base/concordium-grpc-api/"],
            )?;

        use git2::Repository;
        let repo = Repository::open("concordium-base/concordium-grpc-api/")?;
        let spec = repo.revparse_single("HEAD")?.id();
        std::fs::write(
            "./src/v2/proto_schema_version.rs",
            format!("pub const PROTO_SCHEMA_VERSION: &str = \"{}\";\n", spec),
        )?;
    }
    Ok(())
}
