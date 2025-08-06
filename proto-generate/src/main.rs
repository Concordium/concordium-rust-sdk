fn main() {
    tonic_build::configure()
        .build_client(true)
        .build_server(false)
        .out_dir("../src/v2/generated")
        .include_file("mod.rs")
        .compile_protos(
            &["../concordium-base/concordium-grpc-api/v2/concordium/service.proto"],
            &["../concordium-base/concordium-grpc-api/"],
        )
        .expect("compile protos");

    use git2::Repository;
    let repo = Repository::open("../concordium-base/concordium-grpc-api/").expect("open repo");
    let spec = repo.revparse_single("HEAD").unwrap().id();
    std::fs::write(
        "../src/v2/proto_schema_version.rs",
        format!("pub const PROTO_SCHEMA_VERSION: &str = \"{}\";\n", spec),
    )
    .expect("write proto schema version file");
}
