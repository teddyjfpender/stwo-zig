//! The Cairo leaf lane: `prove_cairo::<Blake2sM31MerkleChannel>` under a
//! circuit registry's `cairo_prover_params`.
//!
//! https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230 proves a leaf's Cairo run with
//! `crates/prover/src/prover.rs::prove_cairo`. Against the existing official
//! lane (stwo-cairo 82f2125) the AIR, witness and claim are unchanged; the
//! lane differs only in protocol parameters, all selected at runtime by a
//! `Lane` passed to `transaction.proveFixtureForLane`:
//!
//! - the `proving_5a7c5ed` PCS revision: the FRI config mixed as two felts,
//!   PoW bits inside it, explicit tree heights (`LiftingSizePolicy`);
//! - `include_all_preprocessed_columns`;
//! - `opt_n_id_to_big_components` zero-padding `memory_id_to_big` instances;
//! - the channel salt (`transcript.mixChannelSalt`).
//!
//! The Merkle channel is the engine's comptime parameter; the leaf lane
//! requires a channel profile (`core.vcs_lifted.channel_profile`) of revision
//! `proving_5a7c5ed`. Its grinds reproduce upstream's `SimdBackend::grind`, as
//! every Blake2s grind does (`core.channel.blake2s.pow_order`).
//!
//! The leaf prover's policy, `AtLeastPreprocessed`, and `Fixed` (every tree at
//! one height, which small programs need to exercise lifted trees) are
//! admitted, both with `include_all_preprocessed_columns`; `Auto` and
//! partial sampling are refused rather than proved under an untested
//! transcript.

const std = @import("std");
const core = @import("stwo_core");
/// The shared `ProverParameters` definition (`src/interop/cairo_prover_parameters.zig`),
/// read from a circuit registry by the circuit-recursion wire package's `registry.zig`.
pub const parameters = @import("interop_cairo_prover_parameters");
const preprocessed_variant = @import("../preprocessed/variant.zig");

pub const ProverParameters = parameters.ProverParameters;
pub const FriConfigV2 = core.pcs.config_v2.FriConfigV2;
pub const PcsConfigV2 = core.pcs.config_v2.PcsConfigV2;
pub const Variant = preprocessed_variant.Variant;

pub const Error = error{
    UnsupportedLiftingSizePolicy,
    LeafLaneRequiresAllPreprocessedColumns,
    InvalidIdToBigComponentCount,
    InvalidLiftingLogSize,
} || FriConfigV2.Error;

pub const Lane = struct {
    fri_config: FriConfigV2,
    channel_salt: u32,
    variant: Variant,
    /// `opt_n_id_to_big_components`; null keeps the natural count.
    memory_id_to_big_components: ?usize,
    /// Execution only: store coefficients for sampled-value evaluation.
    store_polynomials_coefficients: bool,
    /// `LiftingSizePolicy::Fixed`: every tree at this height (which includes
    /// the blowup); null is `AtLeastPreprocessed`, the leaf prover's policy.
    fixed_lifting_log_size: ?u32 = null,

    /// Admits a registry's `cairo_prover_params`. `channel_hash` is ignored,
    /// as upstream ignores it: the leaf prover fixes `Blake2sM31MerkleChannel`.
    pub fn fromParameters(params: ProverParameters) Error!Lane {
        const fixed_lifting_log_size: ?u32 = switch (params.lifting_size_policy) {
            .at_least_preprocessed => null,
            .fixed => |height| height,
            .auto => return Error.UnsupportedLiftingSizePolicy,
        };
        if (!params.include_all_preprocessed_columns) return Error.LeafLaneRequiresAllPreprocessedColumns;
        const fri = params.fri_config;
        const count: ?usize = if (params.opt_n_id_to_big_components) |n|
            if (n == 0) return Error.InvalidIdToBigComponentCount else std.math.cast(usize, n) orelse
                return Error.InvalidIdToBigComponentCount
        else
            null;
        return .{
            // The registry reader takes the config as written; `FriConfig::new`'s
            // range checks apply here, before anything is proved.
            .fri_config = try FriConfigV2.init(
                fri.pow_bits,
                fri.log_last_layer_degree_bound,
                fri.log_blowup_factor,
                fri.n_queries,
                fri.fold_step,
            ),
            .channel_salt = params.channel_salt,
            .variant = switch (params.preprocessed_trace) {
                .canonical => .canonical,
                .canonical_small => .canonical_small,
                .canonical_without_pedersen => .canonical_without_pedersen,
            },
            .memory_id_to_big_components = count,
            .store_polynomials_coefficients = params.store_polynomials_coefficients,
            .fixed_lifting_log_size = fixed_lifting_log_size,
        };
    }

    /// The proof's `PcsConfig` (`prove_cairo`): every tree, the preprocessed
    /// one included, at `max(trace domain, preprocessed domain)` under
    /// `AtLeastPreprocessed`, or at the fixed height, which must dominate both
    /// (`InvalidLiftingLogSizeError`). `max_claim_log_size` is the largest
    /// component log size of the claim, padding components included.
    pub fn pcsConfig(self: Lane, max_claim_log_size: u32) Error!PcsConfigV2 {
        const blowup = self.fri_config.log_blowup_factor;
        // `assert!(cairo_air_log_degree_bound <= log_blowup_factor)` with a
        // Cairo AIR log degree bound of 1.
        if (blowup < 1) return Error.InvalidLiftingLogSize;
        const trace_domain = std.math.add(u32, max_claim_log_size, blowup) catch return Error.InvalidLiftingLogSize;
        const preprocessed_domain = self.variant.maxLogSize() + blowup;
        const height = self.fixed_lifting_log_size orelse @max(trace_domain, preprocessed_domain);
        if (height < trace_domain or height < preprocessed_domain) return Error.InvalidLiftingLogSize;
        return PcsConfigV2.fromFriAndLiftingSize(self.fri_config, height);
    }
};

test "leaf lane: the canonical_small registry parameters" {
    const params = ProverParameters{
        .channel_hash = .blake2s,
        .channel_salt = 0,
        .fri_config = .{ .pow_bits = 16, .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 70, .fold_step = 1 },
        .preprocessed_trace = .canonical_small,
        .store_polynomials_coefficients = false,
        .include_all_preprocessed_columns = true,
        .opt_n_id_to_big_components = 16,
        .lifting_size_policy = .at_least_preprocessed,
    };
    const lane = try Lane.fromParameters(params);
    try std.testing.expectEqual(@as(?usize, 16), lane.memory_id_to_big_components);
    // A small trace is lifted to the preprocessed domain (canonical_small 20 + 1).
    const small = try lane.pcsConfig(17);
    try std.testing.expectEqual(@as(u32, 21), small.trace_lifting_log_size);
    try std.testing.expectEqual(@as(u32, 21), small.preprocessed_lifting_log_size);
    // A tall trace lifts the preprocessed tree to the trace domain.
    const tall = try lane.pcsConfig(23);
    try std.testing.expectEqual(@as(u32, 24), tall.trace_lifting_log_size);
    try std.testing.expectEqual(@as(u32, 24), tall.preprocessed_lifting_log_size);

    var fixed = params;
    fixed.lifting_size_policy = .{ .fixed = 22 };
    const lifted = try (try Lane.fromParameters(fixed)).pcsConfig(17);
    try std.testing.expectEqual(@as(u32, 22), lifted.trace_lifting_log_size);
    try std.testing.expectEqual(@as(u32, 22), lifted.preprocessed_lifting_log_size);
    try std.testing.expectError(Error.InvalidLiftingLogSize, (try Lane.fromParameters(fixed)).pcsConfig(21));
    fixed.lifting_size_policy = .{ .fixed = 20 };
    try std.testing.expectError(Error.InvalidLiftingLogSize, (try Lane.fromParameters(fixed)).pcsConfig(17));

    var refused = params;
    refused.lifting_size_policy = .auto;
    try std.testing.expectError(Error.UnsupportedLiftingSizePolicy, Lane.fromParameters(refused));
    refused = params;
    refused.include_all_preprocessed_columns = false;
    try std.testing.expectError(Error.LeafLaneRequiresAllPreprocessedColumns, Lane.fromParameters(refused));
    refused = params;
    refused.fri_config.fold_step = 0;
    try std.testing.expectError(error.InvalidFoldStep, Lane.fromParameters(refused));
}
