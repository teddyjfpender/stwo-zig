//! MetalBackend conformance against the CPU reference backend.
//!
//! The decisive gate is proof byte-equality: a proof produced on the GPU must be identical,
//! bit for bit, to the reference backend's proof of the same statement.

use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sMerkleChannel};
use stwo_backend_metal::MetalBackend;

#[test]
fn metal_backend_conformance() {
    stwo_backend_testkit::assert_backend_conformance::<MetalBackend, Blake2sMerkleChannel>();
}

#[test]
fn metal_backend_conformance_m31_channel() {
    stwo_backend_testkit::assert_backend_conformance::<MetalBackend, Blake2sM31MerkleChannel>();
}
