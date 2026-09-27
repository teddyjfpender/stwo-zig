//! Shared base-prefix commitment hooks for authenticated external profiles.
//!
//! Ordinary and Poseidon proving paths retain their existing entrypoints and
//! byte order. New profiles borrow this module to commit the exact production
//! base prefix, then append typed extension blocks in statement order.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const prover_pcs = @import("stwo_prover_engine").pcs;
const stage_profile = @import("stwo_prover_api").stage_profile;
const table_counter = @import("../../air/lookups/tables/counter.zig");
const base_relations = @import("../../air/relation_challenges.zig");
const lookup_physical_v2 = @import("../../air/lang/lookup_physical_manifest_v2.zig");
const state_chain = @import("../../runner/state_chain.zig");
const trace_mod = @import("../../runner/trace.zig");
const commitment_witness = @import("../commitment_witness.zig");
const interaction_trace = @import("../interaction_trace.zig");
const lookup_sources = @import("../lookup_sources.zig");
const main_support = @import("../main_trace_support.zig");
const preprocessed = @import("../preprocessed.zig");
const proof_workspace = @import("../proof_workspace.zig");
const statement_geometry = @import("../statement_geometry.zig");
const tree2_main_source = @import("../tree2_main_source.zig");
const types = @import("../types.zig");
const native_provider_omit = @import("../memory_provider_shards/native_provider_omit_v1.zig");

const CommitmentWitness = commitment_witness.CommitmentWitness;
const Geometry = statement_geometry.Geometry;
const ProofWorkspace = proof_workspace.ProofWorkspace;

/// One statement-ordered block whose witness storage remains caller-owned.
pub const BorrowedBlock = struct {
    log_size: u32,
    columns: []const []const M31,
};

/// One generated Tree-2 column transferred into the PCS commitment.
pub const OwnedColumn = struct {
    log_size: u32,
    values: *[]M31,
};

/// Optional fixed-table registration performed after base opcode ingestion
/// and before the multiplicity columns are materialized.
pub const LookupRegistration = struct {
    context: *const anyopaque,
    register_fn: *const fn (*const anyopaque, *table_counter.Set) anyerror!void,

    pub fn register(
        self: LookupRegistration,
        counters: *table_counter.Set,
    ) !void {
        try self.register_fn(self.context, counters);
    }
};

pub const MainRetained = struct {
    lookup_source: lookup_sources.Result,

    pub fn deinit(
        self: *MainRetained,
        allocator: std.mem.Allocator,
        workspace: *ProofWorkspace,
    ) void {
        self.lookup_source.deinit(allocator);
        workspace.releaseOpcodeColumns(allocator);
        workspace.releaseClockMain(allocator);
        self.* = undefined;
    }
};

/// Commits canonical base preprocessed columns followed by borrowed extension
/// blocks. Extension buffers are copied because their traces remain live for
/// Tree 2; the base buffers move without copying.
pub fn commitPreprocessed(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    statement: *const types.RiscVStatement,
    blocks: []const BorrowedBlock,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
) !void {
    const columns = try generatePreprocessed(allocator, statement, blocks);
    var moved = false;
    errdefer if (!moved) freeColumns(allocator, columns);
    moved = true;
    try Engine.commit(scheme, allocator, columns, recorder, channel);
}

/// Reconstructs the exact Tree-0 values. Verifiers use the same function to
/// reject any prover-selected selector or fixed-table root.
pub fn generatePreprocessed(
    allocator: std.mem.Allocator,
    statement: *const types.RiscVStatement,
    blocks: []const BorrowedBlock,
) ![]prover_pcs.ColumnEvaluation {
    const base = try preprocessed.generate(allocator, statement.*);
    var base_owned = true;
    errdefer if (base_owned) freeColumns(allocator, base);
    var total = base.len;
    for (blocks) |block| total = std.math.add(
        usize,
        total,
        block.columns.len,
    ) catch return error.InvalidTraceShape;
    const result = try allocator.alloc(prover_pcs.ColumnEvaluation, total);
    var initialized: usize = 0;
    errdefer {
        for (result[0..initialized]) |column|
            allocator.free(@constCast(column.values));
        allocator.free(result);
    }
    @memcpy(result[0..base.len], base);
    initialized = base.len;
    allocator.free(base);
    base_owned = false;
    for (blocks) |block| for (block.columns) |values| {
        const expected = domainSize(block.log_size) catch
            return error.InvalidTraceShape;
        if (values.len != expected) return error.InvalidTraceShape;
        result[initialized] = .{
            .log_size = block.log_size,
            .values = try allocator.dupe(M31, values),
        };
        initialized += 1;
    };
    return result;
}

/// Generates and commits the exact production base Tree-1 prefix, then the
/// caller-supplied typed main blocks. Opcode work retains its existing overlap
/// with infrastructure generation; extension copies happen while that worker
/// is in flight.
pub fn commitMain(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    exec_trace: *const trace_mod.Trace,
    witness: *const CommitmentWitness,
    geometry: Geometry,
    opt_chain: ?*const state_chain.StateChainTracker,
    blocks: []const BorrowedBlock,
    registration: ?LookupRegistration,
) !MainRetained {
    return commitMainInternal(
        Engine,
        allocator,
        workspace,
        scheme,
        channel,
        recorder,
        exec_trace,
        witness,
        geometry,
        opt_chain,
        blocks,
        registration,
        null,
    );
}

/// Commits the joined Tree-1 while physically excluding the native 445-column
/// Poseidon provider. The projected statement determines the allocation size;
/// the typed geometry makes the omitted generator an explicit protocol path.
pub fn commitMainWithoutNativePoseidon(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    exec_trace: *const trace_mod.Trace,
    witness: *const CommitmentWitness,
    geometry: native_provider_omit.ProjectedGeometryV1,
    opt_chain: ?*const state_chain.StateChainTracker,
    blocks: []const BorrowedBlock,
    registration: ?LookupRegistration,
) !MainRetained {
    return commitMainInternal(
        Engine,
        allocator,
        workspace,
        scheme,
        channel,
        recorder,
        exec_trace,
        witness,
        .{
            .program_log_size = geometry.program_log_size,
            .merkle_log_size = geometry.merkle_log_size,
            .poseidon_log_size = 0,
            .clock_update_log = geometry.clock_update_log,
            .merkle_infra_index = geometry.merkle_infra_index,
            .poseidon_infra_index = std.math.maxInt(usize),
            .clock_infra_index = geometry.clock_infra_index,
        },
        opt_chain,
        blocks,
        registration,
        geometry,
    );
}

fn commitMainInternal(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    exec_trace: *const trace_mod.Trace,
    witness: *const CommitmentWitness,
    geometry: Geometry,
    opt_chain: ?*const state_chain.StateChainTracker,
    blocks: []const BorrowedBlock,
    registration: ?LookupRegistration,
    projected_geometry: ?native_provider_omit.ProjectedGeometryV1,
) !MainRetained {
    const statement = &workspace.statement;
    const n_opcode_main: usize = @intCast(statement.nOpcodeMainColumns());
    const n_base_main = n_opcode_main +
        @as(usize, @intCast(statement.nInfraColumns()));
    var n_main = n_base_main;
    for (blocks) |block| n_main = std.math.add(
        usize,
        n_main,
        block.columns.len,
    ) catch return error.InvalidTraceShape;
    var columns = try main_support.Columns.init(
        allocator,
        n_main,
        n_opcode_main,
        null,
        null,
    );
    defer columns.deinit(allocator);

    var opcode = try main_support.OpcodeGeneration.begin(
        workspace,
        allocator,
        exec_trace,
        recorder,
    );
    errdefer opcode.abandon(workspace, allocator);
    errdefer workspace.releaseClockMain(allocator);
    if (projected_geometry) |projected| {
        try main_support.generateInfrastructureWithoutNativePoseidon(
            allocator,
            workspace,
            &columns,
            witness,
            projected,
            opt_chain,
            recorder,
        );
    } else {
        try main_support.generateInfrastructure(
            allocator,
            workspace,
            &columns,
            witness,
            geometry,
            opt_chain,
            recorder,
        );
    }

    var extension_offset = n_base_main;
    for (blocks) |block| for (block.columns) |values| {
        const expected = domainSize(block.log_size) catch
            return error.InvalidTraceShape;
        if (values.len != expected) return error.InvalidTraceShape;
        try columns.putCopy(allocator, extension_offset, .{
            .log_size = block.log_size,
            .values = values,
        });
        extension_offset += 1;
    };
    if (extension_offset != n_main) return error.InvalidTraceShape;

    try opcode.finish(workspace);
    errdefer workspace.releaseOpcodeColumns(allocator);
    var lookup_source = try lookup_sources.ingest(
        allocator,
        statement.*,
        &workspace.opcode_columns,
        .{ .unrepresentable = .reject },
    );
    errdefer lookup_source.deinit(allocator);
    try main_support.registerLookupSources(&lookup_source, witness, workspace);
    if (registration) |external| try external.register(&lookup_source.counters);
    try main_support.appendLookupColumns(allocator, &columns, &lookup_source);
    try main_support.copyOpcodeColumns(allocator, workspace, &columns);
    if (columns.offset != n_base_main or !columns.allInitialized())
        return error.InvalidTraceShape;

    columns.moved = true;
    try Engine.commit(scheme, allocator, columns.values, recorder, channel);
    return .{ .lookup_source = lookup_source };
}

/// Commits the unchanged base Tree-2 prefix followed by already-generated
/// typed extension columns. Every `OwnedColumn` is disarmed at transfer, so a
/// later error cannot double-free a buffer consumed by the engine.
pub fn commitInteraction(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    witness: *const CommitmentWitness,
    geometry: Geometry,
    lookup_source: *const lookup_sources.Result,
    base_relation_set: *const base_relations.Relations,
    interaction_pow: u64,
    base_claim: *types.RiscVInteractionClaim,
    external_columns: []const OwnedColumn,
    mix_context: anytype,
    comptime mixClaim: anytype,
) !void {
    const statement = &workspace.statement;
    const n_base = statement.nInteractionColumns();
    const n_total = std.math.add(
        usize,
        n_base,
        external_columns.len,
    ) catch return error.InvalidTraceShape;
    base_claim.initZeroInto();
    base_claim.n_components = statement.n_components;
    base_claim.n_infra = statement.n_infra;
    base_claim.interaction_pow = interaction_pow;

    var columns = try interaction_trace.ExternalColumns.init(allocator, n_total);
    defer columns.deinit(allocator);
    const source = tree2_main_source.Source.fromLegacy(workspace, lookup_source);
    try source.validate(statement);
    try interaction_trace.generateExternalBase(
        allocator,
        workspace,
        &columns,
        recorder,
        witness,
        geometry,
        &source,
        base_relation_set,
        base_claim,
    );
    if (columns.filled != n_base) return error.InvalidTraceShape;
    for (external_columns) |column| {
        const expected = domainSize(column.log_size) catch
            return error.InvalidTraceShape;
        if (column.values.*.len != expected) return error.InvalidTraceShape;
        columns.append(column.log_size, column.values.*);
        column.values.* = &.{};
    }
    if (columns.filled != n_total) return error.InvalidTraceShape;
    try mixClaim(mix_context, channel, base_claim);
    columns.moved = true;
    try Engine.commit(scheme, allocator, columns.values, recorder, channel);
}

/// V2 twin of `commitInteraction`. The base prefix is generated and mixed
/// under the selected physical lookup authority; extension columns remain in
/// the exact same append-only order. Keeping this entrypoint separate prevents
/// any branch or byte drift in complete-execution external profiles.
pub fn commitInteractionAuthenticatedLookupV2(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    witness: *const CommitmentWitness,
    geometry: Geometry,
    lookup_source: *const lookup_sources.Result,
    base_relation_set: *const base_relations.Relations,
    interaction_pow: u64,
    base_claim: *types.RiscVInteractionClaim,
    external_columns: []const OwnedColumn,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated_statement: *const lookup_physical_v2.AuthenticatedStatement,
    mix_context: anytype,
    comptime mixClaim: anytype,
) !void {
    const statement = &workspace.statement;
    try authenticated_statement.validateAgainst(statement, manifest);
    const n_base = try authenticated_statement.totalInteractionColumns(
        statement,
        manifest,
    );
    const n_total = std.math.add(
        usize,
        n_base,
        external_columns.len,
    ) catch return error.InvalidTraceShape;
    base_claim.initZeroInto();
    base_claim.n_components = statement.n_components;
    base_claim.n_infra = statement.n_infra;
    base_claim.interaction_pow = interaction_pow;

    var columns = try interaction_trace.ExternalColumns.init(allocator, n_total);
    defer columns.deinit(allocator);
    const source = tree2_main_source.Source.fromLegacy(workspace, lookup_source);
    try source.validate(statement);
    try interaction_trace.generateExternalBaseAuthenticatedLookupV2(
        allocator,
        workspace,
        &columns,
        recorder,
        witness,
        geometry,
        &source,
        base_relation_set,
        base_claim,
        manifest,
        authenticated_statement,
    );
    if (columns.filled != n_base) return error.InvalidTraceShape;
    for (external_columns) |column| {
        const expected = domainSize(column.log_size) catch
            return error.InvalidTraceShape;
        if (column.values.*.len != expected) return error.InvalidTraceShape;
        columns.append(column.log_size, column.values.*);
        column.values.* = &.{};
    }
    if (columns.filled != n_total) return error.InvalidTraceShape;
    try mixClaim(mix_context, channel, base_claim);
    columns.moved = true;
    try Engine.commit(scheme, allocator, columns.values, recorder, channel);
}

/// V2 interaction commitment paired with `commitMainWithoutNativePoseidon`.
/// The base claim and allocation describe only the projected core; provider
/// claims are proved later by the independently committed ordered shards.
pub fn commitInteractionWithoutNativePoseidonAuthenticatedLookupV2(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    witness: *const CommitmentWitness,
    geometry: native_provider_omit.ProjectedGeometryV1,
    lookup_source: *const lookup_sources.Result,
    base_relation_set: *const base_relations.Relations,
    interaction_pow: u64,
    base_claim: *types.RiscVInteractionClaim,
    external_columns: []const OwnedColumn,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated_statement: *const lookup_physical_v2.AuthenticatedStatement,
    mix_context: anytype,
    comptime mixClaim: anytype,
) !void {
    const projected_statement = &workspace.statement;
    try authenticated_statement.validateAgainst(projected_statement, manifest);
    const n_base = try authenticated_statement.totalInteractionColumns(
        projected_statement,
        manifest,
    );
    const n_total = std.math.add(
        usize,
        n_base,
        external_columns.len,
    ) catch return error.InvalidTraceShape;
    base_claim.initZeroInto();
    base_claim.n_components = projected_statement.n_components;
    base_claim.n_infra = projected_statement.n_infra;
    base_claim.interaction_pow = interaction_pow;

    var columns = try interaction_trace.ExternalColumns.init(allocator, n_total);
    defer columns.deinit(allocator);
    const source = tree2_main_source.Source.fromLegacy(workspace, lookup_source);
    try source.validate(projected_statement);
    try interaction_trace.generateExternalBaseWithoutNativePoseidonAuthenticatedLookupV2(
        allocator,
        workspace,
        &columns,
        recorder,
        witness,
        geometry,
        &source,
        base_relation_set,
        base_claim,
        manifest,
        authenticated_statement,
    );
    if (columns.filled != n_base) return error.InvalidTraceShape;
    for (external_columns) |column| {
        const expected = domainSize(column.log_size) catch
            return error.InvalidTraceShape;
        if (column.values.*.len != expected) return error.InvalidTraceShape;
        columns.append(column.log_size, column.values.*);
        column.values.* = &.{};
    }
    if (columns.filled != n_total) return error.InvalidTraceShape;
    try mixClaim(mix_context, channel, base_claim);
    columns.moved = true;
    try Engine.commit(scheme, allocator, columns.values, recorder, channel);
}

pub fn appendLogSizes(
    allocator: std.mem.Allocator,
    base: []const u32,
    blocks: []const BorrowedBlock,
) ![]u32 {
    var total = base.len;
    for (blocks) |block| total = std.math.add(
        usize,
        total,
        block.columns.len,
    ) catch return error.InvalidTraceShape;
    const result = try allocator.alloc(u32, total);
    @memcpy(result[0..base.len], base);
    var cursor = base.len;
    for (blocks) |block| {
        @memset(result[cursor..][0..block.columns.len], block.log_size);
        cursor += block.columns.len;
    }
    return result;
}

fn domainSize(log_size: u32) error{InvalidLogSize}!usize {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

fn freeColumns(
    allocator: std.mem.Allocator,
    columns: []prover_pcs.ColumnEvaluation,
) void {
    for (columns) |column| allocator.free(@constCast(column.values));
    allocator.free(columns);
}
