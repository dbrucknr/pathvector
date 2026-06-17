fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")?;
    // GoBGP v4 protos import each other as "api/<name>.proto", so the include
    // root must be proto/ (with the files living at proto/api/*.proto).
    let proto_dir = std::path::Path::new(&manifest).join("proto");
    let api_dir = proto_dir.join("api");

    tonic_prost_build::configure()
        .build_server(false)
        .compile_protos(
            &[
                api_dir.join("gobgp.proto"),
                api_dir.join("attribute.proto"),
                api_dir.join("nlri.proto"),
            ],
            &[proto_dir],
        )?;

    Ok(())
}
