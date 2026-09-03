//! Backend-neutral polynomial export for the degree-five Poseidon2 candidate.
//!
//! The candidate compiler remains the sole owner of the 224 permutation
//! constraints.  This module only translates its authenticated physical DAG
//! into the prover's resident base/lookup program contracts and appends the
//! three narrow-memory shell constraints in canonical component order.
//! Production activation remains false; this export preserves the candidate's
//! exact two-bit quotient expansion and only supplies a typed backend route.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const candidate_mod = @import("typed_poseidon2_degree_bounded_candidate.zig");
const component_mod = @import("typed_poseidon2_degree5_component.zig");
const direct_program = @import("materialization_direct_program.zig");
const entry = @import("../lookups/entry.zig");
const runtime_program = @import("../extract/runtime_program.zig");
const symbolic = @import("../extract/symbolic.zig");

pub const PRODUCTION_ACTIVATION = false;
pub const DIRECT_PARTITION_COUNT: usize = 4;

const materialized_column_namespace: u64 = @as(u64, 1) << 63;
const value_index_mask: u64 = std.math.maxInt(u32);

pub fn capability() prover_component.BackendCompositionCapability {
    return .{ .base_lookup_polynomial_v1 = .{
        .export_capabilities = exportCapabilitiesErased,
    } };
}

/// Adds the candidate-only resident polynomial capability without creating an
/// import cycle in the verifier-owned component module.
pub fn asProverComponent(
    component: *const component_mod.Component,
) prover_component.ComponentProver {
    var result = component.asProverComponent();
    result.backend_composition_capability = capability();
    return result;
}

pub fn exportCapabilities(
    component: *const component_mod.Component,
) !prover_component.BaseLookupPolynomialCapabilitiesV1 {
    try component.validate();
    var result = prover_component.BaseLookupPolynomialCapabilitiesV1{
        .base_partition_count = DIRECT_PARTITION_COUNT,
        .lookup = .{
            .program_id = programId(component.candidate, 0x4c, 0),
            .trace_log_size = component.log_size,
            .selector_tree_index = 0,
            .selector_column = component.is_first_col_idx,
            .main_tree_index = 1,
            .first_main_column = component.main_col_offset,
            .main_column_count = component_mod.MAIN_COLUMNS,
            .interaction_tree_index = 2,
            .first_interaction_column = component.interaction_col_offset,
            .interaction_column_count = component_mod.INTERACTION_COLUMNS,
            .export_program = exportLookupProgramErased,
            .export_parameters = exportParametersErased,
        },
        .lookup_constraints = .{
            .start = component_mod.DIRECT_CONSTRAINTS,
            .count = component_mod.LOGUP_CONSTRAINTS,
        },
    };
    const exporters = [_]*const fn (
        *const anyopaque,
        std.mem.Allocator,
    ) anyerror!prover_component.OwnedBasePolynomialProgram{
        exportDirectProgram0,
        exportDirectProgram1,
        exportDirectProgram2,
        exportDirectProgram3,
    };
    for (0..DIRECT_PARTITION_COUNT) |partition| {
        result.base_partitions[partition] = .{
            .capability = .{
                .program_id = programId(
                    component.candidate,
                    0x44,
                    @intCast(partition),
                ),
                .trace_log_size = component.log_size,
                .selector_tree_index = 0,
                .selector_column = component.is_active_col_idx,
                .main_tree_index = 1,
                .first_main_column = component.main_col_offset,
                .main_column_count = component_mod.MAIN_COLUMNS,
                .export_program = exporters[partition],
            },
            .constraints = directPartitionRange(partition),
        };
    }
    try result.validate(component_mod.CONSTRAINTS);
    return result;
}

pub fn directPartitionRange(
    partition: usize,
) prover_component.ComponentConstraintRangeV1 {
    std.debug.assert(partition < DIRECT_PARTITION_COUNT);
    const start = component_mod.DIRECT_CONSTRAINTS * partition /
        DIRECT_PARTITION_COUNT;
    const end = component_mod.DIRECT_CONSTRAINTS * (partition + 1) /
        DIRECT_PARTITION_COUNT;
    return .{ .start = start, .count = end - start };
}

pub fn exportDirectProgram(
    allocator: std.mem.Allocator,
    candidate: *const candidate_mod.Candidate,
    range: prover_component.ComponentConstraintRangeV1,
) !prover_component.OwnedBasePolynomialProgram {
    try candidate.validate();
    const range_end = std.math.add(usize, range.start, range.count) catch
        return error.InvalidCandidateBackendProgram;
    if (range.count == 0 or range_end > component_mod.DIRECT_CONSTRAINTS)
        return error.InvalidCandidateBackendProgram;

    const source = candidate.direct_program.nodes();
    const extra_nodes: usize = 5;
    const nodes = try allocator.alloc(
        prover_component.BasePolynomialNode,
        source.len + extra_nodes,
    );
    errdefer allocator.free(nodes);
    for (source, nodes[0..source.len]) |node, *destination| {
        destination.* = switch (node.op) {
            .constant => .{
                .op = .constant,
                .value = std.math.cast(u32, node.value) orelse
                    return error.InvalidCandidateBackendProgram,
            },
            .committed => .{
                .op = .column,
                .value = try committedColumn(candidate, node.value),
            },
            .fixed_committed => blk: {
                if (node.lhs != @intFromEnum(direct_program.CommitmentTree.main) or
                    node.value >= component_mod.MAIN_COLUMNS)
                {
                    return error.InvalidCandidateBackendProgram;
                }
                break :blk .{ .op = .column, .value = @intCast(node.value) };
            },
            .row_mask => return error.InvalidCandidateBackendProgram,
            .add => .{ .op = .add, .lhs = node.lhs, .rhs = node.rhs },
            .sub => .{ .op = .sub, .lhs = node.lhs, .rhs = node.rhs },
            .mul => .{ .op = .mul, .lhs = node.lhs, .rhs = node.rhs },
            .neg => .{ .op = .neg, .lhs = node.lhs },
        };
    }

    const main_zero: u32 = @intCast(source.len);
    const selector: u32 = main_zero + 1;
    const active_constraint: u32 = selector + 1;
    const wide: u32 = active_constraint + 1;
    const io: u32 = wide + 1;
    nodes[main_zero] = .{ .op = .column, .value = 0 };
    nodes[selector] = .{
        .op = .column,
        .value = component_mod.MAIN_COLUMNS,
    };
    nodes[active_constraint] = .{
        .op = .sub,
        .lhs = main_zero,
        .rhs = selector,
    };
    nodes[wide] = .{
        .op = .column,
        .value = component_mod.MAIN_COLUMNS - 2,
    };
    nodes[io] = .{
        .op = .column,
        .value = component_mod.MAIN_COLUMNS - 1,
    };

    const roots = try allocator.alloc(u32, range.count);
    errdefer allocator.free(roots);
    for (roots, range.start..) |*root, constraint| {
        root.* = if (constraint < component_mod.PERMUTATION_CONSTRAINTS)
            candidate.direct_program.roots()[constraint].node
        else switch (constraint - component_mod.PERMUTATION_CONSTRAINTS) {
            0 => active_constraint,
            1 => wide,
            2 => io,
            else => return error.InvalidCandidateBackendProgram,
        };
    }
    const result = prover_component.OwnedBasePolynomialProgram{
        .allocator = allocator,
        .nodes = nodes,
        .roots = roots,
        .column_count = component_mod.MAIN_COLUMNS + 1,
    };
    try result.validate();
    return result;
}

pub fn exportLookupProgram(
    allocator: std.mem.Allocator,
    candidate: *const candidate_mod.Candidate,
) !prover_component.OwnedLookupPolynomialProgram {
    try candidate.validate();
    var arena = symbolic.Arena.init(allocator);
    defer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();
    var main: [component_mod.MAIN_COLUMNS]symbolic.Scalar = undefined;
    for (&main) |*column| column.* = arena.column("main");
    var lookups = try component_mod.entriesGeneric(
        symbolic.Scalar,
        candidate,
        main,
    );
    return runtime_program.ownLookupProgram(
        allocator,
        &arena,
        &lookups,
        component_mod.MAIN_COLUMNS,
    );
}

pub fn exportParameters(
    allocator: std.mem.Allocator,
    component: *const component_mod.Component,
) ![]QM31 {
    try component.validate();
    const zero = QM31.zero();
    const main = [_]QM31{zero} ** component_mod.MAIN_COLUMNS;
    const lookups = try component_mod.entriesGeneric(
        QM31,
        component.candidate,
        main,
    );
    var parameters = std.ArrayList(QM31).empty;
    errdefer parameters.deinit(allocator);
    for (lookups.entries[0..lookups.len]) |lookup| {
        try entry.appendRelationParameters(
            &parameters,
            allocator,
            component.relations,
            lookup.domain,
        );
    }
    try parameters.appendSlice(allocator, &component.claims);
    return parameters.toOwnedSlice(allocator);
}

fn exportCapabilitiesErased(
    ctx: *const anyopaque,
) !prover_component.BaseLookupPolynomialCapabilitiesV1 {
    const component: *const component_mod.Component = @ptrCast(@alignCast(ctx));
    return exportCapabilities(component);
}

fn exportDirectProgramFor(
    ctx: *const anyopaque,
    allocator: std.mem.Allocator,
    comptime partition: usize,
) !prover_component.OwnedBasePolynomialProgram {
    const component: *const component_mod.Component = @ptrCast(@alignCast(ctx));
    return exportDirectProgram(
        allocator,
        component.candidate,
        directPartitionRange(partition),
    );
}

fn exportDirectProgram0(ctx: *const anyopaque, allocator: std.mem.Allocator) !prover_component.OwnedBasePolynomialProgram {
    return exportDirectProgramFor(ctx, allocator, 0);
}

fn exportDirectProgram1(ctx: *const anyopaque, allocator: std.mem.Allocator) !prover_component.OwnedBasePolynomialProgram {
    return exportDirectProgramFor(ctx, allocator, 1);
}

fn exportDirectProgram2(ctx: *const anyopaque, allocator: std.mem.Allocator) !prover_component.OwnedBasePolynomialProgram {
    return exportDirectProgramFor(ctx, allocator, 2);
}

fn exportDirectProgram3(ctx: *const anyopaque, allocator: std.mem.Allocator) !prover_component.OwnedBasePolynomialProgram {
    return exportDirectProgramFor(ctx, allocator, 3);
}

fn exportLookupProgramErased(
    ctx: *const anyopaque,
    allocator: std.mem.Allocator,
) !prover_component.OwnedLookupPolynomialProgram {
    const component: *const component_mod.Component = @ptrCast(@alignCast(ctx));
    return exportLookupProgram(allocator, component.candidate);
}

fn exportParametersErased(
    ctx: *const anyopaque,
    allocator: std.mem.Allocator,
) ![]QM31 {
    const component: *const component_mod.Component = @ptrCast(@alignCast(ctx));
    return exportParameters(allocator, component);
}

fn committedColumn(
    candidate: *const candidate_mod.Candidate,
    encoded: u64,
) !u32 {
    if (encoded & ~(materialized_column_namespace | value_index_mask) != 0)
        return error.InvalidCandidateBackendProgram;
    const value: @import("types.zig").ValueId = @enumFromInt(
        @as(u32, @intCast(encoded & value_index_mask)),
    );
    const column = component_mod.physicalColumn(candidate, value) orelse
        return error.InvalidCandidateBackendProgram;
    const materialized = encoded & materialized_column_namespace != 0;
    if (materialized != (column >= candidate_mod.MATERIALIZATION_COLUMN_START and
        column < component_mod.MAIN_COLUMNS - 2))
    {
        return error.InvalidCandidateBackendProgram;
    }
    return @intCast(column);
}

fn programId(
    candidate: *const candidate_mod.Candidate,
    kind: u8,
    partition: u8,
) u64 {
    return std.mem.readInt(u64, candidate.identity[0..8], .little) ^
        (@as(u64, kind) << 56) ^ (@as(u64, partition) << 48);
}

comptime {
    if (component_mod.DIRECT_CONSTRAINTS != 227 or
        component_mod.LOGUP_CONSTRAINTS != 2 or
        component_mod.MAIN_COLUMNS != 239 or
        component_mod.INTERACTION_COLUMNS != 8 or
        component_mod.QUOTIENT_EXPANSION_BITS != 2)
    {
        @compileError("degree-five backend export geometry drifted");
    }
}
