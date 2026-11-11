//! Runtime export of the exact production semantic polynomial DAG.
//!
//! The formal extractor normally fixes `is_active = 1` because it proves row
//! uniqueness only on active rows. A proving backend must instead read the
//! committed selector. This module instantiates the same production
//! `Builder.buildDirect` with one additional symbolic input and translates the
//! resulting DAG into the backend-neutral prover capability.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const local_zero = @import("../x0_native_envelope.zig");
const opcode_entries = @import("../lookups/opcode_entries.zig");
const constraint_program = @import("../constraint_program.zig");
const entry = @import("../lookups/entry.zig");
const semantic_eval = @import("../semantic_eval.zig");
const typed_lui_authority = @import("../lang/typed_lui_authority.zig");
const prover_component = @import("stwo_prover_engine").air.component_prover;
const model = @import("model.zig");
const symbolic = @import("symbolic.zig");
const trace = @import("../../runner/trace.zig");

const Builder = constraint_program.Builder(symbolic.Scalar);
const SymbolicLookupList = entry.Builder(symbolic.Scalar).List;

pub fn build(
    allocator: std.mem.Allocator,
    family: trace.OpcodeFamily,
) !prover_component.OwnedBasePolynomialProgram {
    var arena = symbolic.Arena.initRecoverable(allocator);
    defer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();

    const main_column_count = Builder.mainColumnCount(family);
    var columns: [trace.MAX_FAMILY_COLUMNS]symbolic.Scalar = undefined;
    try model.declareColumns(&arena, family, columns[0..main_column_count]);
    try arena.checkAllocation();
    const selector = arena.column("is_active");
    const direct = (try Builder.buildDirect(
        family,
        columns[0..main_column_count],
        selector,
    )).direct_constraints;

    return ownDirectProgram(
        allocator,
        &arena,
        direct.values[0..direct.len],
        main_column_count,
    );
}

/// Shadow activation seam for the LUI runtime direct program. The scalar DAG
/// is emitted through the same authenticated capability used by retirement
/// and witness projection; ownership conversion is shared with production.
pub fn buildLuiFromAuthority(
    allocator: std.mem.Allocator,
    compiled: *const typed_lui_authority.Authority,
) !prover_component.OwnedBasePolynomialProgram {
    var arena = symbolic.Arena.initRecoverable(allocator);
    defer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();

    var columns: [typed_lui_authority.MAIN_COLUMN_COUNT]symbolic.Scalar = undefined;
    try model.declareColumns(&arena, .lui, &columns);
    try arena.checkAllocation();
    const selector = arena.column("is_active");
    const direct = try compiled.evaluateDirect(
        symbolic.Scalar,
        &columns,
        selector,
    );
    return ownDirectProgram(
        allocator,
        &arena,
        &direct.values,
        typed_lui_authority.MAIN_COLUMN_COUNT,
    );
}

pub fn ownDirectProgram(
    allocator: std.mem.Allocator,
    arena: *const symbolic.Arena,
    direct: []const symbolic.Scalar,
    main_column_count: usize,
) !prover_component.OwnedBasePolynomialProgram {
    // Scalar arithmetic cannot return allocation errors. Never read/copy its
    // inert fallback IDs, validate them or publish ownership after latched OOM.
    try arena.checkAllocation();
    const nodes = try allocator.alloc(
        prover_component.BasePolynomialNode,
        arena.nodes.items.len,
    );
    errdefer allocator.free(nodes);
    for (arena.nodes.items, nodes) |source, *destination| {
        destination.* = .{
            .op = @enumFromInt(@intFromEnum(source.op)),
            .lhs = source.lhs,
            .rhs = source.rhs,
            .value = source.value,
        };
    }

    const roots = try allocator.alloc(u32, direct.len);
    errdefer allocator.free(roots);
    for (direct, roots) |constraint, *root|
        root.* = constraint.id;

    const result = prover_component.OwnedBasePolynomialProgram{
        .allocator = allocator,
        .nodes = nodes,
        .roots = roots,
        .column_count = main_column_count + 1,
    };
    try result.validate();
    return result;
}

pub fn buildLookups(
    allocator: std.mem.Allocator,
    family: trace.OpcodeFamily,
) !prover_component.OwnedLookupPolynomialProgram {
    var arena = symbolic.Arena.initRecoverable(allocator);
    defer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();

    const main_column_count = Builder.mainColumnCount(family);
    var columns: [trace.MAX_FAMILY_COLUMNS]symbolic.Scalar = undefined;
    try model.declareColumns(&arena, family, columns[0..main_column_count]);
    try arena.checkAllocation();
    const lookups = (try Builder.buildLookups(
        family,
        columns[0..main_column_count],
    )).lookup_entries;

    return ownLookupProgram(
        allocator,
        &arena,
        &lookups,
        main_column_count,
    );
}

/// Shadow activation seam for the LUI runtime relation program. The fixed
/// writer stores directly into caller-owned lookup storage before the common
/// ownership conversion.
pub fn buildLuiLookupsFromAuthority(
    allocator: std.mem.Allocator,
    compiled: *const typed_lui_authority.Authority,
) !prover_component.OwnedLookupPolynomialProgram {
    var arena = symbolic.Arena.initRecoverable(allocator);
    defer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();

    var columns: [typed_lui_authority.MAIN_COLUMN_COUNT]symbolic.Scalar = undefined;
    try model.declareColumns(&arena, .lui, &columns);
    try arena.checkAllocation();
    var lookups: SymbolicLookupList = undefined;
    try compiled.buildLookupsInto(symbolic.Scalar, &columns, &lookups);
    return ownLookupProgram(
        allocator,
        &arena,
        &lookups,
        typed_lui_authority.MAIN_COLUMN_COUNT,
    );
}

pub fn ownLookupProgram(
    allocator: std.mem.Allocator,
    arena: *const symbolic.Arena,
    lookups: *const SymbolicLookupList,
    main_column_count: usize,
) !prover_component.OwnedLookupPolynomialProgram {
    try arena.checkAllocation();
    const nodes = try copyNodes(allocator, arena.nodes.items);
    errdefer allocator.free(nodes);
    const entries = try allocator.alloc(
        prover_component.LookupPolynomialEntry,
        lookups.len,
    );
    errdefer allocator.free(entries);
    for (lookups.entries[0..lookups.len], entries) |source, *destination| {
        destination.* = .{
            .numerator = source.numerator.id,
            .arity = source.arity,
        };
        for (source.values[0..source.arity], destination.values[0..source.arity]) |value, *root|
            root.* = value.id;
    }
    const result = prover_component.OwnedLookupPolynomialProgram{
        .allocator = allocator,
        .nodes = nodes,
        .entries = entries,
        .column_count = main_column_count,
        .batch_size = lookups.batch_size,
    };
    try result.validate();
    return result;
}

fn copyNodes(
    allocator: std.mem.Allocator,
    source_nodes: []const symbolic.Node,
) ![]prover_component.BasePolynomialNode {
    const nodes = try allocator.alloc(
        prover_component.BasePolynomialNode,
        source_nodes.len,
    );
    for (source_nodes, nodes) |source, *destination| {
        destination.* = .{
            .op = @enumFromInt(@intFromEnum(source.op)),
            .lhs = source.lhs,
            .rhs = source.rhs,
            .value = source.value,
        };
    }
    return nodes;
}

/// Canonicalize only the predecessor clock of an authentic x0 access. Its
/// semantic before/after values must already be zero. The old typed source
/// owns the exact predecessor column; a compound expression is rejected.
/// Used before the new root exists, never during OODS/quotient evaluation.
pub fn normalizeX0Predecessors(family: trace.OpcodeFamily, physical: []M31, old_program: *const prover_component.OwnedLookupPolynomialProgram) !void {
    const width = trace.nColumnsForFamily(family);
    if (physical.len != width or old_program.column_count != width) return error.InvalidX0HintGeometry;
    var lifted: [trace.MAX_FAMILY_COLUMNS]QM31 = undefined;
    for (physical, lifted[0..width]) |value, *out| out.* = QM31.fromBase(value);
    const list = try opcode_entries.fromMain(family, lifted[0..width]);
    const layout = try local_zero.Schedule.fromList(&list);
    for (layout.groups[0..layout.len]) |group| {
        const before = list.entries[group.consume];
        const after = list.entries[group.emit];
        if (try local_zero.baseWitness(after.numerator) == 0 or try local_zero.baseWitness(before.values[0]) != 0 or try local_zero.baseWitness(before.values[1]) != 0) continue;
        for (before.values[3..7], after.values[3..7]) |first, last| {
            if (!first.isZero() or !last.isZero()) return error.NonzeroX0SemanticWitness;
        }
        const root = old_program.entries[group.consume].values[2];
        if (root >= old_program.nodes.len) return error.InvalidX0PredecessorSource;
        const node = old_program.nodes[root];
        if (node.op != .column or node.value >= width) return error.InvalidX0PredecessorSource;
        physical[node.value] = M31.zero();
    }
}
fn declareLocalZero(arena: *symbolic.Arena, family: trace.OpcodeFamily, columns: []symbolic.Scalar) !void {
    const old_width = trace.nColumnsForFamily(family);
    try model.declareColumns(arena, family, columns[0..old_width]);
    for (columns[old_width..], 0..) |*column, index| column.* = arena.column(if (index % 2 == 0) "x0_nonzero" else "x0_address_inverse");
}
pub fn buildLocalZero(a: std.mem.Allocator, family: trace.OpcodeFamily) !prover_component.OwnedBasePolynomialProgram {
    var arena = symbolic.Arena.initRecoverable(a);
    defer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();
    const width = try local_zero.mainColumnCount(family);
    var columns: [local_zero.MAX_MAIN_COLUMNS]symbolic.Scalar = undefined;
    try declareLocalZero(&arena, family, columns[0..width]);
    const direct = try local_zero.Builder(symbolic.Scalar).direct(family, columns[0..width], arena.column("is_active"));
    try arena.checkAllocation();
    return ownDirectProgram(a, &arena, direct.values[0..direct.len], width);
}
pub fn buildLocalZeroLookups(a: std.mem.Allocator, family: trace.OpcodeFamily) !prover_component.OwnedLookupPolynomialProgram {
    var arena = symbolic.Arena.initRecoverable(a);
    defer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();
    const width = try local_zero.mainColumnCount(family);
    var columns: [local_zero.MAX_MAIN_COLUMNS]symbolic.Scalar = undefined;
    try declareLocalZero(&arena, family, columns[0..width]);
    const lookups = try local_zero.Builder(symbolic.Scalar).lookups(family, columns[0..width]);
    try arena.checkAllocation();
    return ownLookupProgram(a, &arena, &lookups, width);
}

test "runtime polynomial export replays the production active selector" {
    var prng = std.Random.DefaultPrng.init(0x5256_4d45_5441_4c31);
    const random = prng.random();

    for (0..trace.N_FAMILIES) |family_index| {
        const family: trace.OpcodeFamily = @enumFromInt(family_index);
        if (!semantic_eval.isTraceCompatible(family)) continue;

        var arena = symbolic.Arena.init(std.testing.allocator);
        defer arena.deinit();
        symbolic.begin(&arena);

        const main_column_count = Builder.mainColumnCount(family);
        var symbolic_columns: [trace.MAX_FAMILY_COLUMNS]symbolic.Scalar = undefined;
        try model.declareColumns(
            &arena,
            family,
            symbolic_columns[0..main_column_count],
        );
        const selector = arena.column("is_active");
        const direct = (try Builder.buildDirect(
            family,
            symbolic_columns[0..main_column_count],
            selector,
        )).direct_constraints;
        symbolic.end();

        const inputs = try std.testing.allocator.alloc(M31, main_column_count + 1);
        defer std.testing.allocator.free(inputs);
        const sampled = try std.testing.allocator.alloc(
            semantic_eval.BaseScalar,
            main_column_count,
        );
        defer std.testing.allocator.free(sampled);
        const replayed = try std.testing.allocator.alloc(M31, arena.nodes.items.len);
        defer std.testing.allocator.free(replayed);

        for (0..2) |active| {
            for (inputs[0..main_column_count], sampled) |*input, *value| {
                input.* = M31.fromU64(random.int(u32));
                value.* = semantic_eval.BaseScalar.fromBase(input.*);
            }
            inputs[main_column_count] = M31.fromU64(active);
            symbolic.replay(&arena, inputs, replayed);
            const expected = try semantic_eval.BaseEval.evaluate(
                family,
                sampled,
                semantic_eval.BaseScalar.fromBase(inputs[main_column_count]),
            );
            try std.testing.expectEqual(expected.len, direct.len);
            for (expected.values[0..expected.len], direct.values[0..direct.len]) |want, root|
                try std.testing.expect(want.value.eql(replayed[root.id]));
        }
    }
}

test "block-v5 x0 runtime export retains direct and lookup program geometry" {
    for (0..trace.N_FAMILIES) |family_index| {
        const family: trace.OpcodeFamily = @enumFromInt(family_index);
        const width = try local_zero.mainColumnCount(family);
        var direct_program = try buildLocalZero(std.testing.allocator, family);
        defer direct_program.deinit();
        var lookup_program = try buildLocalZeroLookups(std.testing.allocator, family);
        defer lookup_program.deinit();
        try std.testing.expectEqual(width + 1, direct_program.column_count);
        try std.testing.expectEqual(width, lookup_program.column_count);
    }
}
