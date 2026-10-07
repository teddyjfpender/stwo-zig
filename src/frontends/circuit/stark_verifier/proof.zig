//! The shape of a circuit STARK proof: `ProofConfig` (the AIR and PCS
//! parameters a verifier circuit is built for) and `Proof(T)`.
//!
//! Ports `crates/stark_verifier/src/proof.rs` and the proof halves of
//! `fri_proof.rs`, `merkle.rs` and `oods.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230). `Proof(T)` is one structure
//! for proof values (`T = QM31`), topology placeholders (`T = NoValue`) and
//! circuit wires (`T = Var`); `guess` is its single traversal, in the Rust
//! `Guess` order. Its flat layout is the `CircuitSerialize` one of the wire
//! format, so a decoded proof converts without reordering. Column counts,
//! the FRI schedule and the size (`ProofInfo::total_bytes`,
//! `ProofConfig.serializedLen`) come from `core.circuit_proof_shape`, the
//! model the `CircuitSerialize` reader and writer use too.

const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const oods = @import("oods.zig");
const constraint_eval = @import("constraint_eval.zig");

const FriConfigV2 = core.pcs.config_v2.FriConfigV2;
const PcsConfigV2 = core.pcs.config_v2.PcsConfigV2;
const SECURE_EXTENSION_DEGREE = core.fields.qm31.SECURE_EXTENSION_DEGREE;
const proof_shape = core.circuit_proof_shape;

/// Committed trees: preprocessed, trace, interaction, composition.
pub const N_TRACES: usize = proof_shape.n_traces;

/// Trace and interaction column counts of one component.
pub const ComponentShape = proof_shape.ComponentShape;

pub const ConfigError = error{
    /// A component has fewer interaction columns than its cumulative sum.
    TooFewInteractionColumns,
    /// The preprocessed tree is lifted to a different height than the
    /// others; the circuit verifier checks every tree against one domain.
    MismatchedLiftingLogSizes,
    /// `trace_lifting_log_size < log_blowup_factor`.
    LiftingBelowBlowup,
} || std.mem.Allocator.Error;

/// `ProofConfig`: the structure of a proof.
pub const ProofConfig = struct {
    n_interaction_pow_bits: u32,
    n_preprocessed_columns: usize,
    n_trace_columns: usize,
    n_interaction_columns: usize,
    /// One entry per component, in the order the statement iterates its
    /// components in `compute_composition_polynomial`.
    component_shapes: []const ComponentShape,
    /// Per interaction column: whether it is a cumulative-sum column (and so
    /// also sampled at the previous point).
    cumulative_sum_columns: []const bool,
    log_trace_size: usize,
    fri: FriConfigV2,
    composition_log_split: u32,
    /// Verifier-owned main-tree mask, or the legacy singleton mask.
    trace_mask_offsets: ?[]const []const i8 = null,

    /// `ProofConfig::new`. Copies `component_shapes`; free with `deinit`.
    pub fn init(
        allocator: std.mem.Allocator,
        component_shapes: []const ComponentShape,
        n_preprocessed_columns: usize,
        pcs_config: PcsConfigV2,
        n_interaction_pow_bits: u32,
    ) ConfigError!ProofConfig {
        var n_trace_columns: usize = 0;
        var n_interaction_columns: usize = 0;
        for (component_shapes) |component| {
            if (component.interaction_columns != 0 and component.interaction_columns < SECURE_EXTENSION_DEGREE) return error.TooFewInteractionColumns;
            n_trace_columns += component.trace_columns;
            n_interaction_columns += component.interaction_columns;
        }
        if (pcs_config.trace_lifting_log_size != pcs_config.preprocessed_lifting_log_size)
            return error.MismatchedLiftingLogSizes;
        const log_trace_size = std.math.sub(
            u32,
            pcs_config.trace_lifting_log_size,
            pcs_config.fri_config.log_blowup_factor,
        ) catch return error.LiftingBelowBlowup;

        const shapes = try allocator.dupe(ComponentShape, component_shapes);
        errdefer allocator.free(shapes);
        const cumulative = try allocator.alloc(bool, n_interaction_columns);
        var at: usize = 0;
        for (component_shapes) |component| {
            // The last SECURE_EXTENSION_DEGREE interaction columns of every
            // component are its cumulative sum.
            if (component.interaction_columns == 0) continue;
            const plain = component.interaction_columns - SECURE_EXTENSION_DEGREE;
            @memset(cumulative[at..][0..plain], false);
            @memset(cumulative[at + plain ..][0..SECURE_EXTENSION_DEGREE], true);
            at += component.interaction_columns;
        }
        return .{
            .n_interaction_pow_bits = n_interaction_pow_bits,
            .n_preprocessed_columns = n_preprocessed_columns,
            .n_trace_columns = n_trace_columns,
            .n_interaction_columns = n_interaction_columns,
            .component_shapes = shapes,
            .cumulative_sum_columns = cumulative,
            .log_trace_size = log_trace_size,
            .fri = pcs_config.fri_config,
            .composition_log_split = 1,
            .trace_mask_offsets = null,
        };
    }

    pub fn deinit(self: *ProofConfig, allocator: std.mem.Allocator) void {
        allocator.free(self.component_shapes);
        allocator.free(self.cumulative_sum_columns);
        self.* = undefined;
    }

    pub fn nComponents(self: ProofConfig) usize {
        return self.component_shapes.len;
    }

    pub fn logEvaluationDomainSize(self: ProofConfig) usize {
        return self.log_trace_size + self.fri.log_blowup_factor;
    }

    pub fn nQueries(self: ProofConfig) usize {
        return self.fri.n_queries;
    }

    /// Columns of the preprocessed, trace, interaction and composition trees.
    pub fn nColumnsPerTrace(self: ProofConfig) [N_TRACES]usize {
        return .{
            self.n_preprocessed_columns,
            self.n_trace_columns,
            self.n_interaction_columns,
            self.shape().nCompositionColumns(),
        };
    }

    /// The byte-level shape of proofs under this config.
    pub fn shape(self: ProofConfig) proof_shape.ProofShape {
        return .{
            .n_preprocessed_columns = self.n_preprocessed_columns,
            .component_shapes = self.component_shapes,
            .log_trace_size = @intCast(self.log_trace_size),
            .fri = self.fri,
            .composition_log_split = self.composition_log_split,
            .trace_mask_offsets = self.trace_mask_offsets,
        };
    }

    /// Number of FRI inner layers (`compute_all_fold_steps(..).len()`).
    pub fn nFriLayers(self: ProofConfig) usize {
        return self.shape().nFriLayers();
    }

    /// `compute_all_fold_steps(log_trace_size - log_last_layer, fold_step)`,
    /// written into `buffer`.
    pub fn friFoldSteps(self: ProofConfig, buffer: *[MAX_FRI_LAYERS]u32) []const u32 {
        return self.shape().friFoldSteps(buffer);
    }

    /// `ProofInfo::from_config(config).total_bytes()`: the `CircuitSerialize`
    /// length of a proof.
    pub fn serializedLen(self: ProofConfig) usize {
        return self.shape().serializedLen();
    }
};

const Var = builder.Var;
const QM31 = core.fields.qm31.QM31;
const NoValue = builder.NoValue;
const HashValue = builder.blake.HashValue;
const M31Wrapper = builder.wrappers.M31Wrapper;
const InteractionAtOods = constraint_eval.InteractionAtOods;

/// Upper bound on FRI layers.
pub const MAX_FRI_LAYERS: usize = proof_shape.max_fri_layers;

pub const StructureError = error{
    /// A proof length differs from the one its config implies
    /// (`validate_structure`).
    ProofShapeMismatch,
};

/// `EvalDomainSamples<T>`: the M31 value of every column of every tree at
/// every query. Per tree, column-major: column `c` at query `q` is
/// `[c * n_queries + q]`.
pub fn EvalDomainSamples(comptime T: type) type {
    return struct {
        const Self = @This();
        n_queries: usize,
        data: [N_TRACES][]M31Wrapper(T),

        pub fn nColumns(self: *const Self, trace_idx: usize) usize {
            return self.data[trace_idx].len / self.n_queries;
        }

        /// `EvalDomainSamples::at`.
        pub fn at(self: *const Self, trace_idx: usize, column_idx: usize, query_idx: usize) M31Wrapper(T) {
            return self.data[trace_idx][column_idx * self.n_queries + query_idx];
        }
    };
}

/// `AuthPaths<T>`: per tree, per query, the authentication path, leaf
/// sibling first. Per tree, query-major: node `level` of query `q` is
/// `[q * depth + level]`.
pub fn AuthPaths(comptime T: type) type {
    return struct {
        const Self = @This();
        n_queries: usize,
        trees: [][]HashValue(T),

        pub fn depth(self: *const Self, tree_idx: usize) usize {
            return self.trees[tree_idx].len / self.n_queries;
        }

        /// `AuthPaths::at`.
        pub fn at(self: *const Self, tree_idx: usize, query_idx: usize) []const HashValue(T) {
            const d = self.depth(tree_idx);
            return self.trees[tree_idx][query_idx * d ..][0..d];
        }
    };
}

/// `FriProof<T>`: the layer commitments, the last layer, and per layer and
/// query the authentication path and the `2^fold_step` coset values
/// (query-major).
pub fn FriProof(comptime T: type) type {
    return struct {
        layer_commitments: []HashValue(T),
        last_layer_coefs: []T,
        auth_paths: AuthPaths(T),
        witness: [][]T,
    };
}

/// `Proof<T>`.
pub fn Proof(comptime T: type) type {
    return struct {
        const Self = @This();

        channel_salt: T,
        trace_root: HashValue(T),
        interaction_root: HashValue(T),
        composition_polynomial_root: HashValue(T),
        /// One per component.
        claimed_sums: []T,
        preprocessed_columns_at_oods: []T,
        trace_at_oods: []T,
        interaction_at_oods: []InteractionAtOods(T),
        composition_eval_at_oods: []T,
        eval_domain_samples: EvalDomainSamples(T),
        eval_domain_auth_paths: AuthPaths(T),
        pow_nonce: T,
        interaction_pow_nonce: T,
        fri: FriProof(T),

        /// `Proof::merkle_roots`: trace, interaction, composition.
        pub fn merkleRoots(self: *const Self) [N_TRACES - 1]HashValue(T) {
            return .{ self.trace_root, self.interaction_root, self.composition_polynomial_root };
        }

        /// `Proof::validate_structure`.
        pub fn validateStructure(self: *const Self, config: ProofConfig) StructureError!void {
            const n_queries = config.nQueries();
            try expectLen(self.claimed_sums.len, config.nComponents());
            try expectLen(self.preprocessed_columns_at_oods.len, config.n_preprocessed_columns);
            try expectLen(self.trace_at_oods.len, config.shape().nTraceOodsValues());
            try expectLen(self.interaction_at_oods.len, config.n_interaction_columns);
            try expectLen(self.composition_eval_at_oods.len, config.shape().nCompositionColumns());
            for (self.interaction_at_oods, config.cumulative_sum_columns) |column, is_cumulative_sum| {
                if ((column.at_prev != null) != is_cumulative_sum) return error.ProofShapeMismatch;
            }
            const columns = config.nColumnsPerTrace();
            const eval_depth = config.logEvaluationDomainSize();
            try expectLen(self.eval_domain_samples.n_queries, n_queries);
            try expectLen(self.eval_domain_auth_paths.n_queries, n_queries);
            try expectLen(self.eval_domain_auth_paths.trees.len, N_TRACES);
            for (0..N_TRACES) |tree| {
                try expectLen(self.eval_domain_samples.data[tree].len, columns[tree] * n_queries);
                try expectLen(self.eval_domain_auth_paths.trees[tree].len, eval_depth * n_queries);
            }

            var steps_buffer: [MAX_FRI_LAYERS]u32 = undefined;
            const fold_steps = config.friFoldSteps(&steps_buffer);
            const fri = self.fri;
            try expectLen(fri.layer_commitments.len, fold_steps.len);
            try expectLen(fri.last_layer_coefs.len, @as(usize, 1) << @intCast(config.fri.log_last_layer_degree_bound));
            try expectLen(fri.auth_paths.n_queries, n_queries);
            try expectLen(fri.auth_paths.trees.len, fold_steps.len);
            try expectLen(fri.witness.len, fold_steps.len);
            var layer_size = eval_depth;
            for (fold_steps, 0..) |step, layer| {
                layer_size -= step;
                try expectLen(fri.auth_paths.trees[layer].len, layer_size * n_queries);
                try expectLen(fri.witness[layer].len, n_queries << @intCast(step));
            }
        }
    };
}

fn expectLen(actual: usize, expected: usize) StructureError!void {
    if (actual != expected) return error.ProofShapeMismatch;
}

/// `empty_proof`: the topology-mode proof of `config`, allocated from
/// `allocator` (an arena: nothing is freed individually).
pub fn emptyProof(allocator: std.mem.Allocator, config: ProofConfig) std.mem.Allocator.Error!Proof(NoValue) {
    const n_queries = config.nQueries();
    const interaction = try allocator.alloc(InteractionAtOods(NoValue), config.n_interaction_columns);
    for (interaction, config.cumulative_sum_columns) |*column, is_cumulative_sum| {
        column.* = .{ .at_oods = .{}, .at_prev = if (is_cumulative_sum) NoValue{} else null };
    }
    const columns = config.nColumnsPerTrace();
    var samples: [N_TRACES][]M31Wrapper(NoValue) = undefined;
    const eval_trees = try allocator.alloc([]HashValue(NoValue), N_TRACES);
    for (&samples, eval_trees, columns) |*tree_samples, *tree_paths, n_columns| {
        tree_samples.* = try allocator.alloc(M31Wrapper(NoValue), n_columns * n_queries);
        tree_paths.* = try allocator.alloc(HashValue(NoValue), config.logEvaluationDomainSize() * n_queries);
    }

    var steps_buffer: [MAX_FRI_LAYERS]u32 = undefined;
    const fold_steps = config.friFoldSteps(&steps_buffer);
    const fri_trees = try allocator.alloc([]HashValue(NoValue), fold_steps.len);
    const witness = try allocator.alloc([]NoValue, fold_steps.len);
    var layer_size = config.logEvaluationDomainSize();
    for (fold_steps, fri_trees, witness) |step, *paths, *values| {
        layer_size -= step;
        paths.* = try allocator.alloc(HashValue(NoValue), layer_size * n_queries);
        values.* = try allocator.alloc(NoValue, n_queries << @intCast(step));
    }

    return .{
        .channel_salt = .{},
        .trace_root = undefined,
        .interaction_root = undefined,
        .composition_polynomial_root = undefined,
        .claimed_sums = try allocator.alloc(NoValue, config.nComponents()),
        .preprocessed_columns_at_oods = try allocator.alloc(NoValue, config.n_preprocessed_columns),
        .trace_at_oods = try allocator.alloc(NoValue, config.shape().nTraceOodsValues()),
        .interaction_at_oods = interaction,
        .composition_eval_at_oods = try allocator.alloc(NoValue, config.shape().nCompositionColumns()),
        .eval_domain_samples = .{ .n_queries = n_queries, .data = samples },
        .eval_domain_auth_paths = .{ .n_queries = n_queries, .trees = eval_trees },
        .pow_nonce = .{},
        .interaction_pow_nonce = .{},
        .fri = .{
            .layer_commitments = try allocator.alloc(HashValue(NoValue), fold_steps.len),
            .last_layer_coefs = try allocator.alloc(NoValue, @as(usize, 1) << @intCast(config.fri.log_last_layer_degree_bound)),
            .auth_paths = .{ .n_queries = n_queries, .trees = fri_trees },
            .witness = witness,
        },
    };
}

/// `Guess for Proof`: every value becomes a guessed wire, in the Rust field
/// order (roots, claimed sums, OODS samples, evaluation-domain samples and
/// paths, the two nonces, FRI, then the channel salt). The wires live in the
/// context's scratch arena.
pub fn guess(comptime V: type, ctx: *builder.Context(V), proof: *const Proof(V)) builder.context.Error!Proof(Var) {
    const scratch = ctx.scratch();
    var out: Proof(Var) = undefined;
    out.trace_root = try builder.blake.guessHash(V, ctx, proof.trace_root);
    out.interaction_root = try builder.blake.guessHash(V, ctx, proof.interaction_root);
    out.composition_polynomial_root = try builder.blake.guessHash(V, ctx, proof.composition_polynomial_root);
    out.claimed_sums = try guessValues(V, ctx, proof.claimed_sums);
    out.preprocessed_columns_at_oods = try guessValues(V, ctx, proof.preprocessed_columns_at_oods);
    out.trace_at_oods = try guessValues(V, ctx, proof.trace_at_oods);
    out.interaction_at_oods = try scratch.alloc(InteractionAtOods(Var), proof.interaction_at_oods.len);
    for (out.interaction_at_oods, proof.interaction_at_oods) |*wire, column| {
        const at_oods = try ctx.guess(column.at_oods);
        wire.* = .{ .at_oods = at_oods, .at_prev = if (column.at_prev) |at_prev| try ctx.guess(at_prev) else null };
    }
    out.composition_eval_at_oods = try guessValues(V, ctx, proof.composition_eval_at_oods);

    out.eval_domain_samples.n_queries = proof.eval_domain_samples.n_queries;
    for (&out.eval_domain_samples.data, proof.eval_domain_samples.data) |*wires, values| {
        wires.* = try scratch.alloc(M31Wrapper(Var), values.len);
        for (wires.*, values) |*wire, value| wire.* = try builder.wrappers.guessM31(V, ctx, value);
    }
    out.eval_domain_auth_paths = try guessAuthPaths(V, ctx, proof.eval_domain_auth_paths);
    out.pow_nonce = try ctx.guess(proof.pow_nonce);
    out.interaction_pow_nonce = try ctx.guess(proof.interaction_pow_nonce);

    out.fri.layer_commitments = try scratch.alloc(HashValue(Var), proof.fri.layer_commitments.len);
    for (out.fri.layer_commitments, proof.fri.layer_commitments) |*wire, root| wire.* = try builder.blake.guessHash(V, ctx, root);
    out.fri.last_layer_coefs = try guessValues(V, ctx, proof.fri.last_layer_coefs);
    out.fri.auth_paths = try guessAuthPaths(V, ctx, proof.fri.auth_paths);
    out.fri.witness = try scratch.alloc([]Var, proof.fri.witness.len);
    for (out.fri.witness, proof.fri.witness) |*wires, values| wires.* = try guessValues(V, ctx, values);

    out.channel_salt = try ctx.guess(proof.channel_salt);
    return out;
}

fn guessValues(comptime V: type, ctx: *builder.Context(V), values: []const V) builder.context.Error![]Var {
    const wires = try ctx.scratch().alloc(Var, values.len);
    for (wires, values) |*wire, value| wire.* = try ctx.guess(value);
    return wires;
}

fn guessAuthPaths(comptime V: type, ctx: *builder.Context(V), paths: AuthPaths(V)) builder.context.Error!AuthPaths(Var) {
    const trees = try ctx.scratch().alloc([]HashValue(Var), paths.trees.len);
    for (trees, paths.trees) |*wires, nodes| {
        wires.* = try ctx.scratch().alloc(HashValue(Var), nodes.len);
        for (wires.*, nodes) |*wire, node| wire.* = try builder.blake.guessHash(V, ctx, node);
    }
    return .{ .n_queries = paths.n_queries, .trees = trees };
}

test "proof config: cumulative-sum columns are the last four of each component" {
    const shapes = [_]ComponentShape{
        .{ .trace_columns = 3, .interaction_columns = 8 },
        .{ .trace_columns = 1, .interaction_columns = 4 },
    };
    const fri = try FriConfigV2.init(10, 0, 1, 3, 1);
    var config = try ProofConfig.init(std.testing.allocator, &shapes, 5, PcsConfigV2.fromFriAndTraceSize(fri, 6), 20);
    defer config.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 4), config.n_trace_columns);
    try std.testing.expectEqualSlices(bool, &.{
        false, false, false, false, true, true, true, true,
        true,  true,  true,  true,
    }, config.cumulative_sum_columns);
    try std.testing.expectEqual(@as(usize, 6), config.log_trace_size);
    try std.testing.expectEqual(@as(usize, 7), config.logEvaluationDomainSize());
    try std.testing.expectEqual([N_TRACES]usize{ 5, 4, 12, 8 }, config.nColumnsPerTrace());
}

test "proof config: rejects unequal lifting heights and short interaction traces" {
    const fri = try FriConfigV2.init(10, 0, 1, 3, 1);
    var pcs = PcsConfigV2.fromFriAndTraceSize(fri, 6);
    try std.testing.expectError(error.TooFewInteractionColumns, ProofConfig.init(
        std.testing.allocator,
        &.{.{ .trace_columns = 1, .interaction_columns = 3 }},
        0,
        pcs,
        0,
    ));
    pcs.preprocessed_lifting_log_size -= 1;
    try std.testing.expectError(error.MismatchedLiftingLogSizes, ProofConfig.init(std.testing.allocator, &.{}, 0, pcs, 0));
}
