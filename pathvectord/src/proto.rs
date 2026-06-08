// Generated protobuf/gRPC types.  All clippy lints are suppressed because
// this file is controlled by tonic_prost_build — we cannot fix what it emits.
#![allow(clippy::all)]

tonic::include_proto!("pathvector.v1");

/// Binary file descriptor set emitted by `build.rs`.
///
/// Used by the gRPC server reflection service so clients (e.g. `grpcurl`)
/// can discover all services and their schemas without needing `--proto`
/// flags.
pub(crate) const FILE_DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/pathvector_descriptor.bin"));
