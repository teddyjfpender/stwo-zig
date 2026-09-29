//! The leaf verifier configuration: `leaf_verifier_config` and
//! `leaf_verifier_components` of `crates/leaf_prover/src/prove_leaf.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230), design §5.3.
//!
//! The component set is every `all_components()` slot minus the variant's
//! disabled components (`stwo_core.cairo_air_layout`), taken in the Cairo slot
//! order of the M4 projection table, whose entries carry each evaluator's
//! trace and interaction column counts. The `ProofConfig` is M5's port of
//! `ProofConfig::new`; nothing here restates a shape.
//!
//! What this does not build yet: the leaf circuit itself
//! (`build_cairo_verifier_circuit`: `CairoStatement::new`, `empty_proof`
//! guess, `verify`, `finalize`, `pad_to_targets`, preprocessing and the
//! registry circuit-hash check). That needs the M2 builder and M5's
//! gate-emitting `verify`.

const std = @import("std");
const core = @import("stwo_core");
const component_table = @import("../air_eval/component_table.zig");
const proof = @import("../stark_verifier/proof.zig");

const layout = core.cairo_air_layout;
const FriConfigV2 = core.pcs.config_v2.FriConfigV2;
const PcsConfigV2 = core.pcs.config_v2.PcsConfigV2;

pub const cairo_slot_count = 83;

pub const LeafVerifierConfig = struct {
    proof_config: proof.ProofConfig,
    /// `leaf_verifier_components(..).enabled_bits`, in slot order.
    enabled_bits: [cairo_slot_count]bool,
    n_enabled_components: usize,

    pub fn deinit(self: *LeafVerifierConfig, allocator: std.mem.Allocator) void {
        self.proof_config.deinit(allocator);
        self.* = undefined;
    }
};

pub const Error = layout.Error || proof.ConfigError || error{CairoSlotCountMismatch};

/// `leaf_verifier_config(variant, pcs_config, ..)` with `pcs_config` the
/// Cairo proof's FRI config lifted to `trace_log_size + log_blowup_factor`
/// (`PcsConfig::from_fri_and_trace_size`), as the leaf prover builds it from
/// the registry's `cairo_prover_params` and the leaf entry's trace log size.
pub fn leafVerifierConfig(
    allocator: std.mem.Allocator,
    cairo_table: *const component_table.Table,
    variant: layout.Variant,
    fri: FriConfigV2,
    trace_log_size: u32,
) Error!LeafVerifierConfig {
    if (cairo_table.entries.len != cairo_slot_count) return error.CairoSlotCountMismatch;
    var names: [cairo_slot_count][]const u8 = undefined;
    for (&names, cairo_table.entries) |*name, entry| name.* = entry.name;
    var result: LeafVerifierConfig = undefined;
    result.n_enabled_components = try layout.leafEnabledBits(variant, &names, &result.enabled_bits);

    var shapes: [cairo_slot_count]proof.ComponentShape = undefined;
    var n_shapes: usize = 0;
    for (cairo_table.entries, result.enabled_bits) |entry, enabled| {
        if (!enabled) continue;
        shapes[n_shapes] = .{ .trace_columns = entry.trace_columns, .interaction_columns = entry.interaction_columns };
        n_shapes += 1;
    }
    result.proof_config = try proof.ProofConfig.init(
        allocator,
        shapes[0..n_shapes],
        variant.columnCount(),
        PcsConfigV2.fromFriAndTraceSize(fri, trace_log_size),
        layout.interaction_pow_bits,
    );
    return result;
}

test {
    _ = @import("cairo_leaf_config_test.zig");
}
