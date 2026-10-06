//! The in-circuit STARK verifier: port of `crates/stark_verifier/src/verify.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230), private helpers included.
//!
//! `verify` replays the transcript, checks the statement's claim, the
//! composition polynomial at the OODS point, the Merkle decommitments and
//! FRI, emitting every builder call in the Rust order. A stage observer sees
//! the circuit after each stage (the R4 rung compares those prefixes with
//! the oracle's); `NoStages` ignores them.
//!
//! The statement is a comptime duck type with, over `Context(V)`:
//!
//! | member | Rust `Statement` |
//! |---|---|
//! | `preprocessedRoot(ctx) !HashValue(Var)` | `get_preprocessed_root` |
//! | `componentLogSizes() Simd` | `get_component_log_sizes` |
//! | `claimsToMix(ctx) ![]const []const U32Wrapper(Var)` | `claims_to_mix` |
//! | `publicLogupSum(ctx, [2]Var) !Var` | `public_logup_sum` |
//! | `publicParams(ctx, *ColumnMap(Var)) !void` | `public_params` |
//! | `preprocessedColumnIds() []const []const u8` | `get_preprocessed_column_ids` |
//! | `nComponents()`, `relationUsesPerRow(i)` | `get_components()` |
//! | `evaluateComponent(i, ctx, data, acc) !void` | `CircuitEval::evaluate` |
//! | `sortingRequired() bool` | `sorting_required` |
//! | `verifyClaim(ctx, []const Var, *const ShiftedRelationUses) !void` | `verify_claim` |

const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const component_list = @import("../common/component_list.zig");
const channel_mod = @import("channel.zig");
const constraint_eval = @import("constraint_eval.zig");
const fri = @import("fri.zig");
const merkle = @import("merkle.zig");
const oods = @import("oods.zig");
const proof_mod = @import("proof.zig");
const select_queries = @import("select_queries.zig");

const Var = builder.Var;
const Context = builder.Context;
const simd = builder.simd;
const Simd = simd.Simd;
const M31 = core.fields.m31.M31;
const M31Wrapper = builder.wrappers.M31Wrapper;
const ProofConfig = proof_mod.ProofConfig;

/// `COMPOSITION_LOG_SPLIT`: the composition polynomial's degree bound is
/// `log_trace_size + 1`.
const COMPOSITION_LOG_SPLIT = core.verifier_types.COMPOSITION_LOG_SPLIT;
/// Tree indices of the trace and interaction trees.
const ORIGINAL_TRACE_IDX: usize = 1;
const INTERACTION_TRACE_IDX: usize = 2;

const P: u64 = core.fields.m31.Modulus;

/// Bits of a component log size in the packed claim; `2^LOG_SIZE_BITS`
/// exceeds every log trace size up to 30.
pub const LOG_SIZE_BITS: u32 = 5;

/// Shift applied to component row counts in `check_relation_uses`.
pub const RELATION_USES_NUM_ROWS_SHIFT: u5 = 16;

pub const RelationUsesError = error{
    /// `sum(uses_per_row * (floor(P / DIV) + 1))` can reach P for some
    /// relation; upstream asserts this cannot happen for a valid statement.
    RelationUsesMayOverflow,
    TooManyRelations,
};

/// Upper bound on distinct relation ids of one statement (the Cairo AIR has
/// fewer than 64).
pub const MAX_RELATIONS: usize = 128;

/// The relation ids of a statement's components in the order
/// `check_relation_uses` packs their shifted use counts: sorted by `String`
/// (byte-lexicographic) order, each id once. `components` is a slice of
/// per-component `relation_uses_per_row` slices, in statement order.
pub const RelationKeys = struct {
    ids: [MAX_RELATIONS][]const u8 = undefined,
    len: usize = 0,

    pub fn slice(self: *const RelationKeys) []const []const u8 {
        return self.ids[0..self.len];
    }

    /// Index of `id` in the sorted order.
    pub fn indexOf(self: *const RelationKeys, id: []const u8) ?usize {
        for (self.slice(), 0..) |key, index| {
            if (std.mem.eql(u8, key, id)) return index;
        }
        return null;
    }
};

/// The static half of `check_relation_uses`: rejects a statement whose
/// worst-case shifted use count can reach P, and returns its relation keys
/// in packing order.
pub fn relationKeys(components: []const []const component_list.RelationUse) RelationUsesError!RelationKeys {
    var keys: RelationKeys = .{};
    var bounds: [MAX_RELATIONS]u64 = .{0} ** MAX_RELATIONS;
    const per_use_bound: u64 = (P >> RELATION_USES_NUM_ROWS_SHIFT) + 1;
    for (components) |uses| {
        for (uses) |relation_use| {
            const index = keys.indexOf(relation_use.relation_id) orelse blk: {
                if (keys.len == MAX_RELATIONS) return error.TooManyRelations;
                keys.ids[keys.len] = relation_use.relation_id;
                keys.len += 1;
                break :blk keys.len - 1;
            };
            const term = std.math.mul(u64, relation_use.uses, per_use_bound) catch return error.RelationUsesMayOverflow;
            bounds[index] = std.math.add(u64, bounds[index], term) catch return error.RelationUsesMayOverflow;
        }
    }
    for (bounds[0..keys.len]) |bound| {
        if (bound >= P) return error.RelationUsesMayOverflow;
    }
    // `sorted_by_key` over unique `String` keys: byte order.
    std.sort.insertion([]const u8, keys.ids[0..keys.len], {}, lessBytes);
    return keys;
}

fn lessBytes(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

/// The result of `check_relation_uses`: per relation (in `String` order), an
/// upper bound on its uses, shifted right by `RELATION_USES_NUM_ROWS_SHIFT`.
pub const ShiftedRelationUses = struct {
    keys: RelationKeys,
    values: [MAX_RELATIONS]Var,

    pub fn get(self: *const ShiftedRelationUses, relation_id: []const u8) ?Var {
        return self.values[self.keys.indexOf(relation_id) orelse return null];
    }
};

/// A verifier stage, for the stage observer.
pub const Stage = struct {
    /// The multiverifier child whose verification this is, if any.
    child: ?usize = null,
    /// Whether the stage is inside `verify`.
    in_verify: bool = false,
    name: []const u8,
};

/// The observer that ignores every stage.
pub const NoStages = struct {
    pub fn mark(_: NoStages, _: *const builder.Circuit, _: Stage) !void {}
};

/// `verify`: constrains `proof` (as guessed wires) to be a valid proof of
/// `statement` under `config`.
pub fn verify(
    comptime V: type,
    ctx: *Context(V),
    proof: *const proof_mod.Proof(Var),
    config: ProofConfig,
    statement: anytype,
    stages: anytype,
) !void {
    try proof.validateStructure(config);
    // The largest canonical coset, and so evaluation domain, is 2^30.
    if (config.logEvaluationDomainSize() > 30) return error.EvaluationDomainTooLarge;
    const log_trace_size = config.log_trace_size;
    var channel = channel_mod.Channel.init(V, ctx);
    // Profile-specific native provers mix their domain and source identity
    // before the channel salt. A statement that supplies this hook must
    // reproduce that exact prefix inside the verifier circuit.
    if (comptime @hasDecl(@TypeOf(statement.*), "mixProfile"))
        try statement.mixProfile(ctx, &channel);

    try channel.mixQm31s(V, ctx, &.{proof.channel_salt});
    try fri.mixFriConfig(V, ctx, &channel, config.fri);
    try stages.mark(&ctx.circuit, .{ .name = "channel_salt_and_fri_config" });

    const preprocessed_root = try statement.preprocessedRoot(ctx);
    try channel.mixCommitment(V, ctx, preprocessed_root);
    try stages.mark(&ctx.circuit, .{ .name = "preprocessed_root" });

    const component_log_sizes = statement.componentLogSizes();
    const component_sizes = try validateAndComputeComponentSizes(V, ctx, component_log_sizes, log_trace_size);
    // Sizes are at most 2^log_trace_size, which takes log_trace_size + 1 bits.
    const component_sizes_bits = try builder.extract_bits.extractBits(V, ctx, component_sizes, @intCast(log_trace_size + 1));
    try stages.mark(&ctx.circuit, .{ .name = "component_sizes" });

    for (try statement.claimsToMix(ctx)) |claim| try channel.mixU32s(V, ctx, claim);
    try stages.mark(&ctx.circuit, .{ .name = "claims_mixed" });

    try channel.mixCommitment(V, ctx, proof.trace_root);
    try channel.pow(V, ctx, config.n_interaction_pow_bits, proof.interaction_pow_nonce);
    try stages.mark(&ctx.circuit, .{ .name = "trace_root_and_interaction_pow" });

    const interaction_elements = try channel.drawTwoQm31s(V, ctx);
    try stages.mark(&ctx.circuit, .{ .name = "interaction_elements" });

    const public_logup_sum = try statement.publicLogupSum(ctx, interaction_elements);
    try validateLogupSum(V, ctx, public_logup_sum, proof.claimed_sums);
    try stages.mark(&ctx.circuit, .{ .name = "logup_sum" });

    try channel.mixQm31s(V, ctx, proof.claimed_sums);
    try channel.mixCommitment(V, ctx, proof.interaction_root);
    const composition_polynomial_coeff = try channel.drawQm31(V, ctx);
    try channel.mixCommitment(V, ctx, proof.composition_polynomial_root);
    const oods_point = try channel.drawPoint(V, ctx);
    try stages.mark(&ctx.circuit, .{ .name = "composition_coeff_and_oods_point" });

    const shifted_relation_uses = try checkRelationUses(V, ctx, statement, component_sizes_bits);
    try stages.mark(&ctx.circuit, .{ .name = "check_relation_uses" });
    const unpacked_component_sizes = try simd.unpack(V, ctx, component_sizes);
    try statement.verifyClaim(ctx, unpacked_component_sizes, &shifted_relation_uses);
    try stages.mark(&ctx.circuit, .{ .name = "verify_claim" });

    try mixOodsValues(V, ctx, &channel, proof);
    try stages.mark(&ctx.circuit, .{ .name = "oods_values_mixed" });

    const composition_eval = try constraint_eval.computeCompositionPolynomial(V, ctx, config.component_shapes, statement, .{
        .preprocessed_columns = proof.preprocessed_columns_at_oods,
        .trace = proof.trace_at_oods,
        .interaction = proof.interaction_at_oods,
        .pt = oods_point,
        .log_domain_size = log_trace_size,
        .composition_polynomial_coeff = composition_polynomial_coeff,
        .interaction_elements = interaction_elements,
        .claimed_sums = proof.claimed_sums,
        .component_sizes = unpacked_component_sizes,
        .n_instances_bits = component_sizes_bits,
    });
    try stages.mark(&ctx.circuit, .{ .name = "composition_polynomial" });
    const expected_composition_eval = try oods.extractExpectedCompositionEval(
        V,
        ctx,
        &proof.composition_eval_at_oods,
        oods_point,
        log_trace_size + COMPOSITION_LOG_SPLIT,
    );
    try ctx.eq(composition_eval, expected_composition_eval);
    try stages.mark(&ctx.circuit, .{ .name = "composition_check" });

    const oods_quotient_coef = try channel.drawQm31(V, ctx);
    const fri_alphas = try fri.friCommit(V, ctx, &channel, &proof.fri);
    try stages.mark(&ctx.circuit, .{ .name = "fri_commit" });
    try channel.pow(V, ctx, config.fri.pow_bits, proof.pow_nonce);
    try stages.mark(&ctx.circuit, .{ .name = "fri_pow" });

    const query_selection_input = try select_queries.getQuerySelectionInputFromChannel(V, ctx, &channel, config.nQueries());
    const queries = try select_queries.selectQueries(V, ctx, query_selection_input, config.logEvaluationDomainSize());
    try stages.mark(&ctx.circuit, .{ .name = "select_queries" });

    const bits = try ctx.scratch().alloc([]const Var, queries.bits.len);
    for (bits, queries.bits) |*unpacked, packed_bits| unpacked.* = try simd.unpack(V, ctx, packed_bits);
    const column_log_sizes_by_trace = try optColumnLogSizesByTrace(V, ctx, config, component_log_sizes, statement.sortingRequired());
    try stages.mark(&ctx.circuit, .{ .name = "query_bits" });
    const roots = proof.merkleRoots();
    try merkle.decommitEvalDomainSamples(
        V,
        ctx,
        config.nQueries(),
        column_log_sizes_by_trace,
        &proof.eval_domain_samples,
        &proof.eval_domain_auth_paths,
        bits,
        .{ preprocessed_root, roots[0], roots[1], roots[2] },
    );
    try stages.mark(&ctx.circuit, .{ .name = "merkle_decommit" });

    const oods_responses = try oods.collectOodsResponses(V, ctx, config, oods_point, component_sizes_bits, proof);
    try stages.mark(&ctx.circuit, .{ .name = "oods_responses" });
    const fri_input = try oods.computeFriInput(V, ctx, oods_responses, queries, &proof.eval_domain_samples, oods_quotient_coef);
    try stages.mark(&ctx.circuit, .{ .name = "fri_input" });
    try fri.friDecommit(V, ctx, &proof.fri, log_trace_size, config.fri, fri_input, bits, queries, fri_alphas);
    try stages.mark(&ctx.circuit, .{ .name = "fri_decommit" });
}

/// `validate_logup_sum`: the public sum plus every claimed sum is zero.
pub fn validateLogupSum(comptime V: type, ctx: *Context(V), public_logup_sum: Var, claimed_sums: []const Var) !void {
    var logup_sum = public_logup_sum;
    for (claimed_sums) |claimed_sum| logup_sum = try ctx.add(logup_sum, claimed_sum);
    try ctx.eq(logup_sum, ctx.zero());
}

/// Mixes the OODS samples: preprocessed, trace, interaction (a cumulative
/// sum's previous-row value before its OODS value), then composition.
fn mixOodsValues(comptime V: type, ctx: *Context(V), channel: *channel_mod.Channel, proof: *const proof_mod.Proof(Var)) !void {
    var values: std.ArrayListUnmanaged(Var) = .empty;
    try values.appendSlice(ctx.scratch(), proof.preprocessed_columns_at_oods);
    try values.appendSlice(ctx.scratch(), proof.trace_at_oods);
    for (proof.interaction_at_oods) |column| {
        if (column.at_prev) |at_prev| try values.append(ctx.scratch(), at_prev);
        try values.append(ctx.scratch(), column.at_oods);
    }
    try values.appendSlice(ctx.scratch(), &proof.composition_eval_at_oods);
    try channel.mixQm31s(V, ctx, values.items);
}

/// `validate_and_compute_component_sizes`: each log size and
/// `log_trace_size - log_size` fit in `LOG_SIZE_BITS` bits; returns
/// `2^log_size` per component.
fn validateAndComputeComponentSizes(comptime V: type, ctx: *Context(V), component_log_sizes: Simd, log_trace_size: usize) !Simd {
    comptime std.debug.assert(LOG_SIZE_BITS == 5);
    const log_size_bits = try builder.extract_bits.extractBits(V, ctx, component_log_sizes, LOG_SIZE_BITS);
    const log_trace = try simd.repeat(V, ctx, M31.fromCanonical(@intCast(log_trace_size)), component_log_sizes.len);
    const diff = try simd.sub(V, ctx, log_trace, component_log_sizes);
    _ = try builder.extract_bits.extractBits(V, ctx, diff, LOG_SIZE_BITS);
    return simd.pow2(V, ctx, log_size_bits);
}

/// `check_relation_uses`: no relation is used `P` times or more. Per
/// relation, `sum over components of (floor(rows / 2^16) + 1) * uses_per_row`
/// is range-checked to `31 - 16` bits.
fn checkRelationUses(comptime V: type, ctx: *Context(V), statement: anytype, component_sizes_bits: []const Simd) !ShiftedRelationUses {
    const n_components = statement.nComponents();
    const uses = try ctx.scratch().alloc([]const component_list.RelationUse, n_components);
    for (uses, 0..) |*component_uses, i| component_uses.* = statement.relationUsesPerRow(i);
    var result: ShiftedRelationUses = .{ .keys = try relationKeys(uses), .values = undefined };
    var assigned = [_]bool{false} ** MAX_RELATIONS;

    const shifted_component_sizes_p1 = if (component_sizes_bits.len > RELATION_USES_NUM_ROWS_SHIFT) blk: {
        const one = try simd.one(V, ctx, n_components);
        const shifted = try simd.combineBits(V, ctx, component_sizes_bits[RELATION_USES_NUM_ROWS_SHIFT..]);
        const res = try simd.add(V, ctx, shifted, one);
        try simd.markPartlyUsed(V, ctx, res);
        break :blk res;
    } else try simd.one(V, ctx, n_components);

    for (uses, 0..) |component_uses, i| {
        if (component_uses.len == 0) continue;
        const shifted_size_p1 = try simd.unpackIdx(V, ctx, shifted_component_sizes_p1, i);
        for (component_uses) |relation_use| {
            const uses_per_row = try ctx.constant(builder.ivalue.qm31FromU32s(@intCast(relation_use.uses), 0, 0, 0));
            const upper_bound = try ctx.mul(shifted_size_p1, uses_per_row);
            const slot = result.keys.indexOf(relation_use.relation_id).?;
            result.values[slot] = if (assigned[slot]) try ctx.add(result.values[slot], upper_bound) else upper_bound;
            assigned[slot] = true;
        }
    }

    const counts = try ctx.scratch().alloc(M31Wrapper(Var), result.keys.len);
    for (counts, result.values[0..result.keys.len]) |*count, value| count.* = .newUnsafe(value);
    const packed_counts = try simd.pack(V, ctx, counts);
    _ = try builder.extract_bits.extractBits(V, ctx, packed_counts, 31 - RELATION_USES_NUM_ROWS_SHIFT);
    return result;
}

/// `get_opt_column_log_sizes_by_trace`: when the statement's column order
/// differs from the committed one, each trace and interaction column's log
/// size wire, for sorting the query columns.
fn optColumnLogSizesByTrace(
    comptime V: type,
    ctx: *Context(V),
    config: ProofConfig,
    component_log_sizes: Simd,
    sorting_required: bool,
) ![proof_mod.N_TRACES]?[]const Var {
    var out: [proof_mod.N_TRACES]?[]const Var = @splat(null);
    if (!sorting_required) return out;
    const trace = try ctx.scratch().alloc(Var, config.n_trace_columns);
    const interaction = try ctx.scratch().alloc(Var, config.n_interaction_columns);
    const log_sizes = try simd.unpack(V, ctx, component_log_sizes);
    if (log_sizes.len != config.component_shapes.len) return error.ComponentCountMismatch;
    var trace_at: usize = 0;
    var interaction_at: usize = 0;
    for (config.component_shapes, log_sizes) |shape, log_size| {
        @memset(trace[trace_at..][0..shape.trace_columns], log_size);
        @memset(interaction[interaction_at..][0..shape.interaction_columns], log_size);
        trace_at += shape.trace_columns;
        interaction_at += shape.interaction_columns;
    }
    out[ORIGINAL_TRACE_IDX] = trace;
    out[INTERACTION_TRACE_IDX] = interaction;
    return out;
}

test "verify: circuit statement relation keys are in String order" {
    var uses: [component_list.N_COMPONENTS][]const component_list.RelationUse = undefined;
    for (component_list.component_facts.toArray(), &uses) |facts, *slot| slot.* = facts.relation_uses_per_row;
    const keys = try relationKeys(&uses);
    const expected = [_][]const u8{
        "Gate",
        "RangeCheck_16",
        "VerifyBitwiseXor_12",
        "VerifyBitwiseXor_4",
        "VerifyBitwiseXor_7",
        "VerifyBitwiseXor_8",
        "VerifyBitwiseXor_8_B",
        "VerifyBitwiseXor_9",
    };
    try std.testing.expectEqual(expected.len, keys.len);
    for (expected, keys.slice()) |want, got| try std.testing.expectEqualStrings(want, got);
}

test "verify: relation uses that can reach P are rejected" {
    // 65,536 uses per row times (floor(P / 2^16) + 1) = 2^31 > P.
    const heavy = [_]component_list.RelationUse{.{ .relation_id = "Gate", .uses = 1 << 16 }};
    try std.testing.expectError(error.RelationUsesMayOverflow, relationKeys(&.{&heavy}));
    const light = [_]component_list.RelationUse{.{ .relation_id = "Gate", .uses = (1 << 16) - 1 }};
    _ = try relationKeys(&.{&light});
}
