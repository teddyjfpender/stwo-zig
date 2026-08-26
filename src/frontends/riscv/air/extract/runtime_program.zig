//! Runtime export of the exact production semantic polynomial DAG.
//!
//! The formal extractor normally fixes `is_active = 1` because it proves row
//! uniqueness only on active rows. A proving backend must instead read the
//! committed selector. This module instantiates the same production
//! `Builder.buildDirect` with one additional symbolic input and translates the
//! resulting DAG into the backend-neutral prover capability.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
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
    var arena = symbolic.Arena.init(allocator);
    defer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();

    const main_column_count = Builder.mainColumnCount(family);
    var columns: [trace.MAX_FAMILY_COLUMNS]symbolic.Scalar = undefined;
    try model.declareColumns(&arena, family, columns[0..main_column_count]);
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
    var arena = symbolic.Arena.init(allocator);
    defer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();

    var columns: [typed_lui_authority.MAIN_COLUMN_COUNT]symbolic.Scalar = undefined;
    try model.declareColumns(&arena, .lui, &columns);
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

fn ownDirectProgram(
    allocator: std.mem.Allocator,
    arena: *const symbolic.Arena,
    direct: []const symbolic.Scalar,
    main_column_count: usize,
) !prover_component.OwnedBasePolynomialProgram {
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
    var arena = symbolic.Arena.init(allocator);
    defer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();

    const main_column_count = Builder.mainColumnCount(family);
    var columns: [trace.MAX_FAMILY_COLUMNS]symbolic.Scalar = undefined;
    try model.declareColumns(&arena, family, columns[0..main_column_count]);
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
    var arena = symbolic.Arena.init(allocator);
    defer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();

    var columns: [typed_lui_authority.MAIN_COLUMN_COUNT]symbolic.Scalar = undefined;
    try model.declareColumns(&arena, .lui, &columns);
    var lookups: SymbolicLookupList = undefined;
    try compiled.buildLookupsInto(symbolic.Scalar, &columns, &lookups);
    return ownLookupProgram(
        allocator,
        &arena,
        &lookups,
        typed_lui_authority.MAIN_COLUMN_COUNT,
    );
}

fn ownLookupProgram(
    allocator: std.mem.Allocator,
    arena: *const symbolic.Arena,
    lookups: *const SymbolicLookupList,
    main_column_count: usize,
) !prover_component.OwnedLookupPolynomialProgram {
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
