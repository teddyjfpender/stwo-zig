//! Host-side configuration of the multiverifier (fold) circuit.
//!
//! Ports `SharedConfig` and `shared_config` of
//! `crates/circuit_multiverifier/src/verify.rs`, and step 1 of
//! `CanonicalCircuit::build` in
//! `crates/stwo_run_and_prove_recursive_tree/src/canonical.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230). The fold topology depends only
//! on the registry's target sizes and circuit FRI config (design §3.5).
//! `build_multiverifier_circuit` (one Context over the children L then R,
//! Blake preimage last) runs through the builder and lands with it.

const std = @import("std");
const core = @import("stwo_core");
const finalize = @import("../common/finalize.zig");
const preprocessed = @import("../common/preprocessed.zig");
const proof = @import("../stark_verifier/proof.zig");
const circuit_statement = @import("circuit_statement.zig");

const FriConfigV2 = core.pcs.config_v2.FriConfigV2;
const PcsConfigV2 = core.pcs.config_v2.PcsConfigV2;

/// `SharedConfig`: the configuration shared by every circuit a
/// multiverifier verifies and by their proofs.
pub const SharedConfig = struct {
    pcs_config: PcsConfigV2,
    proof_config: proof.ProofConfig,
    preprocessed_column_log_sizes: preprocessed.ColumnLayout,

    pub fn deinit(self: *SharedConfig, allocator: std.mem.Allocator) void {
        self.proof_config.deinit(allocator);
        self.* = undefined;
    }
};

/// `shared_config`.
pub fn sharedConfig(
    allocator: std.mem.Allocator,
    layout: preprocessed.ColumnLayout,
    pcs_config: PcsConfigV2,
) proof.ConfigError!SharedConfig {
    return .{
        .pcs_config = pcs_config,
        .proof_config = try circuit_statement.circuitVerifierProofConfig(allocator, &layout, pcs_config),
        .preprocessed_column_log_sizes = layout,
    };
}

/// `CanonicalCircuit::build` step 1: the shared config of a fold tree whose
/// circuits are all padded to `target_sizes` and proven with `fri_config`.
pub fn foldSharedConfig(
    allocator: std.mem.Allocator,
    target_sizes: finalize.ComponentSizes,
    fri_config: FriConfigV2,
) (preprocessed.Error || proof.ConfigError)!SharedConfig {
    const layout = try preprocessed.ColumnLayout.fromComponentSizes(target_sizes);
    const pcs_config = PcsConfigV2.fromFriAndTraceSize(fri_config, layout.traceLogSize());
    return sharedConfig(allocator, layout, pcs_config);
}
