//! The leaf verifier configuration: `leaf_verifier_config` and
//! `leaf_verifier_components` of `crates/leaf_prover/src/prove_leaf.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230), design §5.3.
//!
//! The component set is every `all_components()` slot minus the variant's
//! disabled components (`stwo_core.cairo_air_layout`), taken in the Cairo slot
//! order of the projection's evaluator table, whose entries carry each evaluator's
//! trace and interaction column counts. The `ProofConfig` is `stark_verifier.proof`'s port of
//! `ProofConfig::new`; nothing here restates a shape.
//!
//! `LeafVerifierConfig.verifierConfig` completes `leaf_verifier_config`
//! with the program, the Cairo preprocessed root and the ZK blinding amount;
//! `cairo_verifier.zig` builds the leaf circuit from the result.

const std = @import("std");
const core = @import("stwo_core");
const component_table = @import("../air_eval/component_table.zig");
const proof = @import("../stark_verifier/proof.zig");
const cairo_verifier = @import("cairo_verifier.zig");

const layout = core.cairo_air_layout;
const FriConfigV2 = core.pcs.config_v2.FriConfigV2;
const PcsConfigV2 = core.pcs.config_v2.PcsConfigV2;

pub const cairo_slot_count = 83;

pub const LeafVerifierConfig = struct {
    variant: layout.Variant,
    proof_config: proof.ProofConfig,
    /// `leaf_verifier_components(..).enabled_bits`, in slot order.
    enabled_bits: [cairo_slot_count]bool,
    n_enabled_components: usize,

    pub fn deinit(self: *LeafVerifierConfig, allocator: std.mem.Allocator) void {
        self.proof_config.deinit(allocator);
        self.* = undefined;
    }

    /// `leaf_verifier_config`'s `CairoVerifierConfig`: borrows this config
    /// and `program`, which must outlive the result.
    pub fn verifierConfig(
        self: *const LeafVerifierConfig,
        program: []const layout.ProgramFelt,
        preprocessed_root: [8]u32,
        zk_blinding_amount: ?usize,
    ) cairo_verifier.CairoVerifierConfig {
        return .{
            .proof_config = self.proof_config,
            .enabled_bits = &self.enabled_bits,
            .program = program,
            .preprocessed_root = preprocessed_root,
            .variant = self.variant,
            .zk_blinding_amount = zk_blinding_amount,
        };
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
    result.variant = variant;
    result.n_enabled_components = try layout.leafEnabledBits(variant, &names, &result.enabled_bits);

    var shapes: [cairo_slot_count]proof.ComponentShape = undefined;
    var n_shapes: usize = 0;
    for (cairo_table.entries, result.enabled_bits) |entry, enabled| {
        if (!enabled) continue;
        shapes[n_shapes] = .{ .trace_columns = entry.shape.trace_columns, .interaction_columns = entry.shape.interaction_columns };
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
