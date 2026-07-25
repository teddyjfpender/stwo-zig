//! Non-negotiable final correctness gates for exact CUDA Blake.

const std = @import("std");

pub const pinned_repository = "https://github.com/starkware-libs/stwo";
pub const pinned_commit = "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2";
pub const pinned_source_tree_sha256 =
    "23a89cdd06a606c905b64e4bcbf7ed9f72e2c526ffa2576a6c7c0535416e3c16";
pub const provenance =
    "tools/stwo-interop-rs/upstream_blake_provenance.json";

pub const Gate = enum {
    exact_cpu_cuda_canonical_bytes,
    pinned_rust_verifier_acceptance,
    zero_cpu_fallback,
};

/// Promotion ordering is deliberate: Rust acceptance remains the final
/// semantic authority after exact CPU/CUDA byte parity is established.
pub const promotion_gates = [_]Gate{
    .exact_cpu_cuda_canonical_bytes,
    .zero_cpu_fallback,
    .pinned_rust_verifier_acceptance,
};

test "pinned Rust Stwo remains the final exact Blake oracle" {
    try std.testing.expectEqual(
        Gate.pinned_rust_verifier_acceptance,
        promotion_gates[promotion_gates.len - 1],
    );
    try std.testing.expectEqual(@as(usize, 40), pinned_commit.len);
    try std.testing.expectEqual(
        @as(usize, 64),
        pinned_source_tree_sha256.len,
    );
}
