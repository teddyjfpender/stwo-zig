//! Host-side configuration of the circuit-verifier statement.
//!
//! Ports `circuit_verifier_proof_config` and `circuit_component_log_sizes`
//! of `crates/circuit_verifier/src/statement.rs` and `CircuitConfig` of
//! `verify.rs` (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230). `CircuitStatement` itself
//! (guess order output_digest, preprocessed_root, statement, proof; the
//! public logup sum; the in-circuit circuit hash) emits gates through the
//! builder and the M4 evaluators and lands with them.

const std = @import("std");
const core = @import("stwo_core");
const component_list = @import("../common/component_list.zig");
const preprocessed = @import("../common/preprocessed.zig");
const proof = @import("../stark_verifier/proof.zig");

const PcsConfigV2 = core.pcs.config_v2.PcsConfigV2;

/// `CircuitConfig`: the PCS config and preprocessed layout of a verified
/// circuit.
pub const CircuitConfig = struct {
    config: PcsConfigV2,
    preprocessed_column_log_sizes: preprocessed.ColumnLayout,
};

/// `circuit_component_log_sizes`: the static log size of every circuit
/// component under `layout`.
pub fn circuitComponentLogSizes(
    layout: *const preprocessed.ColumnLayout,
) component_list.LogSizeError!component_list.PerComponent(u32) {
    return component_list.circuitComponentLogSizes(layout);
}

/// The component shapes in `CircuitStatement::new` iteration order.
pub fn circuitComponentShapes() [component_list.N_COMPONENTS]proof.ComponentShape {
    var shapes: [component_list.N_COMPONENTS]proof.ComponentShape = undefined;
    for (component_list.component_facts.toArray(), &shapes) |facts, *shape| {
        shape.* = .{ .trace_columns = facts.trace_columns, .interaction_columns = facts.interaction_columns };
    }
    return shapes;
}

/// `circuit_verifier_proof_config`: the `ProofConfig` of proofs of a circuit
/// with this preprocessed layout, verified by the circuit verifier.
pub fn circuitVerifierProofConfig(
    allocator: std.mem.Allocator,
    layout: *const preprocessed.ColumnLayout,
    pcs_config: PcsConfigV2,
) proof.ConfigError!proof.ProofConfig {
    const shapes = circuitComponentShapes();
    return proof.ProofConfig.init(
        allocator,
        &shapes,
        layout.entries.len,
        pcs_config,
        component_list.INTERACTION_POW_BITS,
    );
}
