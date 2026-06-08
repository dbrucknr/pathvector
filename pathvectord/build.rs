//! Code generation for the gRPC management API.
//!
//! Requires `protoc` on `PATH`.  On macOS: `brew install protobuf`.
//! On Debian/Ubuntu: `apt install -y protobuf-compiler`.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")?;
    let out_dir = std::env::var("OUT_DIR")?;
    let proto_root = std::path::Path::new(&manifest)
        .parent()
        .expect("pathvectord crate must live inside a workspace directory")
        .join("proto");

    tonic_prost_build::configure()
        .build_client(false)
        .file_descriptor_set_path(
            std::path::Path::new(&out_dir).join("pathvector_descriptor.bin"),
        )
        .compile_protos(
            &[proto_root.join("pathvector/v1/management.proto")],
            &[proto_root],
        )?;

    Ok(())
}
