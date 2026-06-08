fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let proto_root = manifest.parent().unwrap().join("proto");

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(false)
        .compile_protos(
            &[proto_root.join("pathvector/v1/management.proto")],
            &[proto_root],
        )?;

    Ok(())
}
