//! Source-only parity gate for the shared emitter's legacy/direct sinks.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const graph = @import("stwo_riscv_rv32").recursion.air.composition_circuit;
const canonical_lower_797c7b = @import("stwo_riscv_air_lang").framework.proof_kind;
const canonical_lower_c35963 = @import("stwo_riscv_rv32").recursion.air.verifier_arithmetic_lowering_plan;
const canonical_lower_2e7782 = @import("stwo_riscv_rv32").recursion.air.verifier_arithmetic_lowering_reference;
const fusion = @import("stwo_riscv_rv32").recursion.air.arithmetic_fusion_rows;
const storage = @import("stwo_riscv_air_lang").framework.blake3_parent_row_storage;
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const FixedColumns = @import("stwo_riscv_recursion_air").arithmetic_fusion_fixed_columns;

fn requireFixedParity(a: std.mem.Allocator, rows: *const fusion.Rows, fixed: *const fusion.Fixed) !void {
    const cohorts = .{ rows.opening, rows.multiply, rows.inverse, rows.linear };
    try std.testing.expectEqual(rows.dot4_matches, fixed.dot4_matches);
    try std.testing.expectEqual(rows.fma_matches, fixed.fma_matches);
    inline for (FixedColumns.Airs, 0..) |Air, slot| {
        try std.testing.expectEqual(cohorts[slot].len, fixed.counts[slot]);
        try std.testing.expectEqual(cohorts[slot].len, fixed.fixed[slot].len);
        for (cohorts[slot], fixed.fixed[slot]) |row, metadata| try std.testing.expectEqualDeep(storage.compactFixed(Air, row), metadata);
        var projected: std.ArrayList(Column) = .empty;
        defer {
            for (projected.items) |column| a.free(column.values);
            projected.deinit(a);
        }
        try @import("stwo_riscv_air_lang").framework.blake3_row_columns.project(Air, a, cohorts[slot], fixed.logs[slot], 0, &projected);
        const actual = fixed.columnRange(slot);
        try std.testing.expectEqual(Air.PREPROCESSED_COLUMN_COUNT, actual.len);
        for (projected.items, actual) |old, new| {
            try std.testing.expectEqual(old.log_size, new.log_size);
            try std.testing.expectEqualSlices(M, old.values, new.values);
        }
    }
}
fn fixedAllocationFault(a: std.mem.Allocator, plan: *const canonical_lower_c35963.Plan, reference: canonical_lower_2e7782.Reference, kind: canonical_lower_797c7b.ProofKind) !void {
    var fixed = try fusion.materializeFixed(a, plan, reference, kind);
    defer fixed.deinit();
}

fn requireParity(comptime Air: type, a: std.mem.Allocator, rows: []const Air.Row, direct: anytype) !void {
    var projected: std.ArrayList(Column) = .empty;
    defer {
        for (projected.items) |column| a.free(column.values);
        projected.deinit(a);
    }
    try @import("stwo_riscv_air_lang").framework.blake3_row_columns.project(Air, a, rows, direct.log, 1, &projected);
    try std.testing.expectEqual(projected.items.len, direct.main.len);
    for (projected.items, direct.main) |old, new| try std.testing.expectEqualSlices(M, old.values, new.values);
    try std.testing.expectEqual(rows.len, direct.fixed.len);
    for (rows, direct.fixed) |row, fixed| try std.testing.expectEqualDeep(storage.compactFixed(Air, row), fixed);
}
test "direct recursive arithmetic emitter matches legacy FMA inverse linear dot4 in both modes" {
    const a = std.testing.allocator;
    const nodes = [_]graph.Node{
        .{ .op = .input },                              .{ .op = .{ .constant = .{ 3, 0, 0, 0 } } },
        .{ .op = .{ .mul = .{ .lhs = 0, .rhs = 1 } } }, .{ .op = .{ .add = .{ .lhs = 2, .rhs = 1 } } },
        .{ .op = .{ .inverse = 0 } },                   .{ .op = .{ .mul = .{ .lhs = 0, .rhs = 4 } } },
        .{ .op = .{ .constant = .{ 1, 0, 0, 0 } } },    .{ .op = .{ .sub = .{ .lhs = 5, .rhs = 6 } } },
        .{ .op = .{ .neg = 3 } },                       .{ .op = .{ .add = .{ .lhs = 8, .rhs = 3 } } },
    };
    const g = try graph.CircuitGraph.authenticate(&nodes, &.{ 7, 9 }, graph.computeGraphDigest(&nodes, &.{ 7, 9 }));
    const values = [_]Q{ Q.fromBase(M.fromCanonical(7)), Q.fromBase(M.fromCanonical(3)), Q.fromBase(M.fromCanonical(21)), Q.fromBase(M.fromCanonical(24)), try Q.fromBase(M.fromCanonical(7)).inv(), Q.one(), Q.one(), Q.zero(), Q.fromBase(M.fromCanonical(24)).neg(), Q.zero() };
    var dot_nodes: [18]graph.Node = undefined;
    var dot_values: [18]Q = undefined;
    for (dot_nodes[0..9], dot_values[0..9], 0..) |*node, *value, i| {
        node.* = .{ .op = .input };
        value.* = Q.fromBase(M.fromCanonical(@intCast(i + 1)));
    }
    for (0..4) |i| {
        const mul: u32 = @intCast(9 + 2 * i);
        const left: u32 = @intCast(1 + 2 * i);
        const right: u32 = left + 1;
        const acc: u32 = if (i == 0) 0 else mul - 1;
        dot_nodes[mul] = .{ .op = .{ .mul = .{ .lhs = left, .rhs = right } } };
        dot_nodes[mul + 1] = .{ .op = .{ .add = .{ .lhs = acc, .rhs = mul } } };
        dot_values[mul] = dot_values[left].mul(dot_values[right]);
        dot_values[mul + 1] = dot_values[acc].add(dot_values[mul]);
    }
    dot_nodes[17] = .{ .op = .{ .sub = .{ .lhs = 16, .rhs = 16 } } };
    dot_values[17] = Q.zero();
    const dot_g = try graph.CircuitGraph.authenticate(&dot_nodes, &.{17}, graph.computeGraphDigest(&dot_nodes, &.{17}));
    const lanes = [_]canonical_lower_2e7782.Lane{
        .{ .circuit_id = 1500, .active_in = .segment, .circuit_identity = @splat(1), .graph = g },
        .{ .circuit_id = 1502, .active_in = .segment, .circuit_identity = @splat(2), .graph = dot_g },
        .{ .circuit_id = 1501, .active_in = .binary, .circuit_identity = @splat(3), .graph = g },
    };
    const evaluations = [_]canonical_lower_2e7782.Evaluation{
        .{ .circuit_identity = @splat(1), .values = &values },
        .{ .circuit_identity = @splat(2), .values = &dot_values },
        .{ .circuit_identity = @splat(3), .values = &values },
    };
    const reference = try canonical_lower_2e7782.Reference.seal(&lanes);
    var plan = try canonical_lower_c35963.Plan.init(a, reference);
    defer plan.deinit();
    for ([_]canonical_lower_797c7b.ProofKind{ .segment_leaf, .binary_node }) |kind| {
        var old = try fusion.materialize(a, &plan, reference, .{ .lanes = &evaluations }, kind);
        defer old.deinit();
        var direct = try fusion.materializeColumns(a, &plan, reference, .{ .lanes = &evaluations }, kind);
        defer direct.deinit();
        var fixed = try fusion.materializeFixed(a, &plan, reference, kind);
        defer fixed.deinit();
        try requireFixedParity(a, &old, &fixed);
        try std.testing.expectEqual(old.dot4_matches, direct.dot4_matches);
        try std.testing.expectEqual(old.fma_matches, direct.fma_matches);
        try std.testing.expectEqualSlices(@import("stwo_riscv_air_lang").framework.detached_opening_accumulate4.Row, old.opening, direct.opening);
        try requireParity(@import("stwo_riscv_air_lang").framework.qm31_mul_add, a, old.multiply, &direct.multiply);
        try requireParity(@import("stwo_riscv_air_lang").framework.qm31_inv, a, old.inverse, &direct.inverse);
        try requireParity(@import("stwo_riscv_air_lang").framework.linear_ops, a, old.linear, &direct.linear);
        // Move columns into exactly the production Prepared owner, then consume
        // one cohort before releasing the rest; each wrapper remains deinit-safe.
        var owned = storage.Prepared{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = 0 };
        inline for (0..storage.Airs.len) |i| owned.fixed[i] = &.{};
        defer owned.deinit();
        inline for (.{ 3, 4, 5 }, .{ &direct.multiply, &direct.inverse, &direct.linear }) |i, cohort| {
            const taken = try cohort.take();
            owned.main[i] = taken.main;
            owned.fixed[i] = taken.fixed;
        }
        owned.releaseCohort(3);
        owned.releaseRows();
        try std.testing.expectEqual(@as(usize, 0), try owned.retainedBytes());
    }
    // Reuse the genuine graph authority while failing every fixed-only owner,
    // reservation scratch and padded-column allocation. No private evaluations
    // are passed to the constructor or rematerialized by the receiver.
    inline for (.{ canonical_lower_797c7b.ProofKind.segment_leaf, canonical_lower_797c7b.ProofKind.binary_node }) |kind|
        try std.testing.checkAllAllocationFailures(a, fixedAllocationFault, .{ &plan, reference, kind });
}

test "fixed recursive arithmetic: empty active mode retains canonical padded fixed cohorts" {
    const a = std.testing.allocator;
    const nodes = [_]graph.Node{ .{ .op = .input }, .{ .op = .{ .inverse = 0 } } };
    const g = try graph.CircuitGraph.authenticate(&nodes, &.{1}, graph.computeGraphDigest(&nodes, &.{1}));
    const empty_nodes = [_]graph.Node{.{ .op = .{ .constant = .{ 0, 0, 0, 0 } } }};
    const empty_graph = try graph.CircuitGraph.authenticate(&empty_nodes, &.{0}, graph.computeGraphDigest(&empty_nodes, &.{0}));
    const lanes = [_]canonical_lower_2e7782.Lane{
        .{ .circuit_id = 77, .active_in = .binary, .circuit_identity = @splat(4), .graph = g },
        .{ .circuit_id = 78, .active_in = .segment, .circuit_identity = @splat(5), .graph = empty_graph },
    };
    const reference = try canonical_lower_2e7782.Reference.seal(&lanes);
    var plan = try canonical_lower_c35963.Plan.init(a, reference);
    defer plan.deinit();
    var fixed = try fusion.materializeFixed(a, &plan, reference, .segment_leaf);
    defer fixed.deinit();
    try std.testing.expectEqualDeep([4]usize{ 0, 0, 0, 0 }, fixed.counts);
    try std.testing.expectEqualDeep([4]u32{ 1, 1, 1, 1 }, fixed.logs);
    for (fixed.columns) |column| {
        try std.testing.expectEqual(@as(usize, 2), column.values.len);
        for (column.values) |value| try std.testing.expect(value.isZero());
    }
    try std.testing.expectError(error.UnsupportedArithmeticFusionKind, fusion.materializeFixed(a, &plan, reference, .empty_leaf));
}

test "fixed recursive arithmetic: original fixed helpers reject routing outside canonical M31" {
    const Mul = @import("stwo_riscv_air_lang").framework.qm31_mul_add;
    const Open = @import("stwo_riscv_air_lang").framework.detached_opening_accumulate4;
    const invalid = core.fields.m31.Modulus;
    const schedule = Mul.Schedule{ .circuit = 2, .output = 3, .lhs = 0, .rhs = 1, .uses = 4 };
    var changed = schedule;
    changed.addend = 1;
    try std.testing.expectError(error.InvalidQm31MulAdd, Mul.fixedRow(changed));
    changed = schedule;
    changed.circuit = invalid;
    try std.testing.expectError(error.InvalidQm31MulAdd, Mul.fixedRow(changed));
    const opening = Open.Schedule{ .circuit = 2, .accumulator = 0, .lhs = .{ 1, 2, 3, 4 }, .rhs = .{ 5, 6, 7, 8 }, .output = 9, .uses = 1 };
    var changed_opening = opening;
    changed_opening.rhs[2] = invalid;
    try std.testing.expectError(error.InvalidDetachedOpeningAccumulate4, Open.fixedRow(changed_opening));
    var complete = try FixedColumns.Sink.init(std.testing.allocator, .{ 1, 0, 0, 0 });
    defer complete.deinit();
    try std.testing.expectError(error.DirectRecursiveRowCountMismatch, complete.take(.{ .dot4_matches = 0, .fma_matches = 0 }));
    try std.testing.expectError(error.InvalidTraceShape, FixedColumns.Sink.init(std.testing.allocator, .{ 0, (1 << 24) + 1, 0, 0 }));
}

test "fixed recursive arithmetic: actual legacy direct and witness-free constructors retained" {
    inline for (.{ &fusion.materialize, &fusion.materializeColumns, &fusion.materializeFixed }) |body| std.mem.doNotOptimizeAway(body);
}
