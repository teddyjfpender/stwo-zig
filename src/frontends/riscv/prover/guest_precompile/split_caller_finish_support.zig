//! Shared transcript, validation, and commitment support for the caller leaf.

const std = @import("std");
const fields = @import("stwo_core").fields;
const M31 = fields.m31.M31;
const QM31 = fields.qm31.QM31;
const pcs_core = @import("stwo_core").pcs;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const core_verifier = @import("stwo_core").verifier;
const ColumnEvaluation = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const work_pool = @import("stwo_prover_engine").work_pool;
const prover_api = @import("stwo_prover_api");
const stage_profile = prover_api.stage_profile;
const base_statement = @import("../../air/statement.zig");
const public_logup = @import("../../air/public_logup.zig");
const relation_challenges = @import("../../air/relation_challenges.zig");
const caller_component = @import("../../air/guest_precompile/caller_component.zig");
const component_registry = @import("../../air/guest_precompile/component_registry.zig");
const guest_interaction = @import("../../air/guest_precompile/interaction.zig");
const guest_interaction_plan = @import("../../air/guest_precompile/interaction_plan.zig");
const guest_main_trace = @import("../../air/guest_precompile/main_trace.zig");
const guest_proof_admission = @import("../../air/guest_precompile/proof_admission.zig");
const guest_relations = @import("../../air/guest_precompile/relation_challenges.zig");
const guest_statement = @import("../../air/guest_precompile/statement.zig");
const guest_transcript = @import("../../air/guest_precompile/proof_transcript.zig");
const aggregation_hash = @import("../../aggregation/hash.zig");
const aggregation_manifest = @import("../../aggregation/manifest.zig");
const aggregation_types = @import("../../aggregation/types.zig");
const commitment_witness = @import("../commitment_witness.zig");
const interaction_production = @import("../interaction_trace_plan_execution_production.zig");
const opcode_trace = @import("../opcode_trace.zig");
const preprocessed = @import("../preprocessed.zig");
const base_finalize = @import("../proof_finalize.zig");
const proof_workspace = @import("../proof_workspace.zig");
const production = @import("../main_trace_plan_execution_production.zig");
const statement_geometry = @import("../statement_geometry.zig");
const tree2_main_source = @import("../tree2_main_source.zig");
const types = @import("../types.zig");
const base_verifier = @import("../verifier.zig");
const split_component_assembly = @import("split_component_assembly.zig");
const split_leaf_prepare = @import("split_leaf_prepare.zig");
const split_leaf_statement = @import("split_leaf_statement.zig");
const split_pcs_prepare = @import("split_pcs_prepare.zig");

pub const LOCAL_BASE_RELATION_COUNT = relation_challenges.RELATION_COUNT;
pub const LOCAL_GUEST_RELATION_DRAWS = 0;

pub const tree_count: usize = 3;
pub const caller_interaction_columns: usize =
    guest_interaction.caller_column_count;
pub const caller_batch_count: usize = guest_interaction.caller_batch_count;

/// Mixed after the session envelope and before the caller-local base draw.
/// The shared guest relation has already been derived by the manifest and is
/// copied into the resulting relation bundle without another draw.
pub const caller_base_relation_domain_words = [6]u32{
    0x5357_5453, // "STWS"
    0x3152_4243, // "CBR1"
    split_pcs_prepare.format_version,
    @intFromEnum(aggregation_types.LeafRole.core_request),
    relation_challenges.RELATION_COUNT,
    LOCAL_GUEST_RELATION_DRAWS,
};

/// Exact Tree-2 claim frame. The canonical base aggregate is followed by all
/// base physical claims in statement order and all 77 caller batch claims.
pub const caller_claim_domain_words = [7]u32{
    0x5357_5453,
    0x3143_4943, // "CIC1"
    split_pcs_prepare.format_version,
    @intFromEnum(aggregation_types.LeafRole.core_request),
    caller_batch_count,
    caller_interaction_columns,
    0, // no leaf-local interaction PoW in this research protocol
};

pub fn drawCallerRelationsV1(
    allocator: std.mem.Allocator,
    channel: anytype,
    session: *const aggregation_manifest.PreparedSessionV1,
) !guest_relations.Poseidon2V1Relations {
    try session.challenge.validate();
    channel.mixU32s(&caller_base_relation_domain_words);
    const base = try relation_challenges.Relations.draw(allocator, channel);
    return split_component_assembly.bindSessionGuestRelation(
        session,
        .{
            .base = base,
            .guest_poseidon2_io = .dummy(),
        },
    );
}

pub fn mixCallerInteractionClaimV1(
    channel: anytype,
    core: *const base_statement.RiscVStatement,
    base_claim: *const base_statement.RiscVInteractionClaim,
    authority: component_registry.CallerConstruction,
    caller_claim: caller_component.Claim,
) !void {
    if (base_claim.interaction_pow != 0)
        return error.UnexpectedCallerInteractionPow;
    try caller_claim.validate(authority);
    const canonical = try base_claim.canonical(core);
    const detailed_count = try guest_transcript.detailedBaseClaimCount(core);

    channel.mixU32s(&caller_claim_domain_words);
    const canonical_view = canonical.view();
    canonical_view.mixInto(channel);
    channel.mixFelts(&.{caller_claim.component_sum});
    channel.mixU32s(&.{
        @intCast(detailed_count),
        caller_batch_count,
    });
    for (core.component_descs[0..core.n_components], 0..) |descriptor, index| {
        channel.mixFelts(try base_claim.opcodeClaims(descriptor.family, index));
    }
    for (core.infra_descs[0..core.n_infra], 0..) |descriptor, index| {
        channel.mixFelts(try base_claim.infraClaims(descriptor.kind, index));
    }
    channel.mixFelts(&caller_claim.batch_sums);
}

pub fn verifyCallerPreprocessedRootV1(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    core: *const base_statement.RiscVStatement,
    component: component_registry.Descriptor,
    expected: aggregation_hash.Digest,
) !void {
    try component.validate();
    if (component.kind != .guest_poseidon2_call_v1 or
        component.log_size >= @bitSizeOf(usize))
    {
        return error.InvalidCallerPreprocessedGeometry;
    }
    const base = try preprocessed.generate(allocator, core.*);
    var base_owned = true;
    errdefer if (base_owned) freeIndependentColumns(allocator, base);
    const columns = try allocator.alloc(ColumnEvaluation, base.len + 2);
    var initialized: usize = 0;
    var columns_owned = true;
    errdefer if (columns_owned) {
        for (columns[0..initialized]) |column_value| {
            allocator.free(@constCast(column_value.values));
        }
        allocator.free(columns);
    };
    @memcpy(columns[0..base.len], base);
    initialized = base.len;
    allocator.free(base);
    base_owned = false;
    columns[initialized] = .{
        .log_size = component.log_size,
        .values = try opcode_trace.generateIsFirst(allocator, component.log_size),
    };
    initialized += 1;
    columns[initialized] = .{
        .log_size = component.log_size,
        .values = try opcode_trace.generateIsActive(
            allocator,
            component.log_size,
            component.n_rows,
        ),
    };
    initialized += 1;

    var scheme = try Engine.init(allocator, pcs_config);
    defer Engine.deinit(&scheme, allocator);
    var channel = Engine.Channel{};
    columns_owned = false;
    try Engine.commit(&scheme, allocator, columns, null, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    var roots = try scheme.roots(allocator);
    defer roots.deinit(allocator);
    if (roots.items.len != 1 or
        !aggregation_hash.eql(roots.items[0], expected))
    {
        return error.InvalidCallerPreprocessedRoot;
    }
}

pub fn commitMergedCallerTree2(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    base_tree2: *interaction_production.Prepared,
    caller: anytype,
) !void {
    const base_columns = try base_tree2.takeColumns();
    var base_columns_owned = true;
    errdefer if (base_columns_owned)
        freeIndependentColumns(allocator, base_columns);
    const total_columns = try checkedAdd(
        base_columns.len,
        caller_interaction_columns,
    );
    const columns = try allocator.alloc(ColumnEvaluation, total_columns);
    errdefer allocator.free(columns);
    const backings = try allocator.alloc([]M31, base_columns.len + 1);
    errdefer allocator.free(backings);

    @memcpy(columns[0..base_columns.len], base_columns);
    for (base_columns, 0..) |column_value, index| {
        backings[index] = @constCast(column_value.values);
    }
    for (0..caller_interaction_columns) |index| {
        columns[base_columns.len + index] = .{
            .log_size = caller.log_size,
            .values = @constCast(caller.column(index)),
        };
    }
    backings[base_columns.len] = caller.storage;

    // Descriptor allocations are replaced, while every field-value buffer is
    // transferred exactly once through the combined backing list.
    allocator.free(base_columns);
    base_columns_owned = false;
    caller.storage = &.{};
    try Engine.commitWithBacking(
        scheme,
        allocator,
        columns,
        backings,
        recorder,
        channel,
    );
}

pub fn verifyCallerLocalClosure(
    core: *const base_statement.RiscVStatement,
    authority: component_registry.CallerConstruction,
    relations: *const guest_relations.Poseidon2V1Relations,
    base_claim: *const base_statement.RiscVInteractionClaim,
    caller_claim: caller_component.Claim,
) !void {
    const canonical = try base_claim.canonical(core);
    const boundary = try public_logup.sum(&core.public_data, &relations.base);
    try split_component_assembly.verifyCallerLocalRemainder(
        authority,
        canonical.view().total(),
        boundary,
        caller_claim,
    );
}

pub fn callerTree0LogSizes(
    allocator: std.mem.Allocator,
    core: *const base_statement.RiscVStatement,
    component: component_registry.Descriptor,
) ![]u32 {
    const base = try preprocessed.logSizes(allocator, core.*);
    defer allocator.free(base);
    const result = try allocator.alloc(u32, base.len + 2);
    @memcpy(result[0..base.len], base);
    @memset(result[base.len..], component.log_size);
    return result;
}

pub fn callerTree1LogSizes(
    allocator: std.mem.Allocator,
    core: *const base_statement.RiscVStatement,
    component: component_registry.Descriptor,
) ![]u32 {
    const count = try checkedAdd(core.nMainColumns(), caller_component.main_column_count);
    const result = try allocator.alloc(u32, count);
    var cursor: usize = 0;
    for (core.component_descs[0..core.n_components]) |descriptor| {
        @memset(result[cursor..][0..descriptor.n_columns], descriptor.log_size);
        cursor += descriptor.n_columns;
    }
    for (core.infra_descs[0..core.n_infra]) |descriptor| {
        @memset(result[cursor..][0..descriptor.n_columns], descriptor.log_size);
        cursor += descriptor.n_columns;
    }
    @memset(result[cursor..], component.log_size);
    return result;
}

pub fn callerTree2LogSizes(
    allocator: std.mem.Allocator,
    core: *const base_statement.RiscVStatement,
    base_claim: *const base_statement.RiscVInteractionClaim,
    component: component_registry.Descriptor,
) ![]u32 {
    const canonical = try base_claim.canonical(core);
    const base_logs = canonical.log_sizes[0..canonical.n_log_sizes];
    const result = try allocator.alloc(
        u32,
        try checkedAdd(base_logs.len, caller_interaction_columns),
    );
    @memcpy(result[0..base_logs.len], base_logs);
    @memset(result[base_logs.len..], component.log_size);
    return result;
}

pub fn countLogCellsFromClaim(
    core: *const base_statement.RiscVStatement,
    base_claim: *const base_statement.RiscVInteractionClaim,
) !usize {
    const canonical = try base_claim.canonical(core);
    var cells: usize = 0;
    for (canonical.log_sizes[0..canonical.n_log_sizes]) |log_size| {
        if (log_size >= @bitSizeOf(usize)) return error.CallerTree2ResourceOverflow;
        cells = try checkedAdd(cells, @as(usize, 1) << @intCast(log_size));
    }
    return cells;
}

pub fn validateBinding(
    session: *const aggregation_manifest.PreparedSessionV1,
    binding: split_pcs_prepare.SharedChallengeBindingV1,
) !void {
    if (!aggregation_hash.eql(binding.session_digest, session.session_digest) or
        !aggregation_hash.eql(
            binding.challenge_context_digest,
            session.challenge.challenge_context_digest,
        ) or
        !std.meta.eql(binding.guest_z, session.challenge.z) or
        !std.meta.eql(binding.guest_alpha, session.challenge.alpha))
    {
        return error.CallerSessionBindingMismatch;
    }
}

pub fn validateBindingRelation(
    binding: split_pcs_prepare.SharedChallengeBindingV1,
    relations: *const guest_relations.Poseidon2V1Relations,
) !void {
    try binding.guest_z.validate();
    try binding.guest_alpha.validate();
    const expected = @TypeOf(relations.guest_poseidon2_io).init(
        secureFromWire(binding.guest_z),
        secureFromWire(binding.guest_alpha),
    );
    if (!relations.guest_poseidon2_io.z.eql(expected.z) or
        !relations.guest_poseidon2_io.alpha.eql(expected.alpha))
    {
        return error.CallerSessionBindingMismatch;
    }
    for (relations.guest_poseidon2_io.alpha_powers, expected.alpha_powers) |actual, wanted| {
        if (!actual.eql(wanted)) return error.CallerSessionBindingMismatch;
    }
}

pub fn secureFromWire(value: aggregation_types.SecureFelt) QM31 {
    return QM31.fromU32Unchecked(
        value.limbs[0],
        value.limbs[1],
        value.limbs[2],
        value.limbs[3],
    );
}

pub fn readCallerRoots(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    scheme: *Engine.Scheme,
) ![tree_count]aggregation_hash.Digest {
    var roots = try scheme.roots(allocator);
    defer roots.deinit(allocator);
    if (roots.items.len != tree_count) return error.InvalidCallerTreeCount;
    return .{ roots.items[0], roots.items[1], roots.items[2] };
}

pub fn checkCancellation(
    cancellation: ?*const split_pcs_prepare.CancellationTokenV1,
) !void {
    if (cancellation) |token| {
        if (token.isRequested()) return error.SplitCallerFinishCancelled;
    }
}

pub fn freeIndependentColumns(
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
) void {
    for (columns) |column_value| allocator.free(@constCast(column_value.values));
    allocator.free(columns);
}

pub fn checkedAdd(left: usize, right: usize) !usize {
    return std.math.add(usize, left, right) catch
        return error.CallerTree2ResourceOverflow;
}

pub fn checkedMul(left: usize, right: usize) !usize {
    return std.math.mul(usize, left, right) catch
        return error.CallerTree2ResourceOverflow;
}
