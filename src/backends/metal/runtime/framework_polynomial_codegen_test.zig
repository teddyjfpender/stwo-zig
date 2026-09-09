//! These device-free tests validate source admission and reference semantics.
//! Actual execution of the generated Metal kernel remains a separate gate.
const std = @import("std");
const core = @import("stwo_core");
const component = @import("stwo_prover_engine").air.component_prover;
const subject = @import("framework_polynomial_codegen.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Program = component.OwnedFrameworkPolynomialProgramV1;

pub const TREE_COUNTS = [_]usize{ 3, 5, 18 };

/// Arena-owned fixture shared by source-only and actual device parity gates.
pub fn fixture(allocator: std.mem.Allocator) !Program {
    var program = Program{
        .allocator = allocator,
        .semantic_digest = @splat(7),
        .registry_order_digest = @splat(8),
        .direct = .{
            .allocator = allocator,
            .nodes = try allocator.dupe(component.BasePolynomialNode, &.{
                .{ .op = .column, .value = 0 },
                .{ .op = .column, .value = 1 },
                .{ .op = .column, .value = 2 },
                .{ .op = .mul, .lhs = 0, .rhs = 1 },
                .{ .op = .sub, .lhs = 3, .rhs = 2 },
            }),
            .roots = try allocator.dupe(u32, &.{4}),
            .column_count = 3,
        },
        .lookup_nodes = try allocator.dupe(component.BasePolynomialNode, &.{
            .{ .op = .column, .value = 0 },
            .{ .op = .column, .value = 1 },
            .{ .op = .constant, .value = 1 },
            .{ .op = .neg, .lhs = 2 },
        }),
        .entries = try allocator.dupe(component.FrameworkLookupEntryV1, &.{
            .{ .domain = 1, .schema_version = 1, .numerator = 2, .arity = 1, .values = .{1} ++ .{0} ** 32 },
            .{ .domain = 1, .schema_version = 1, .numerator = 3, .arity = 1, .values = .{0} ** 33 },
            .{ .domain = 2, .schema_version = 1, .numerator = 2, .arity = 1, .values = .{1} ++ .{0} ** 32 },
        }),
        .batches = try allocator.dupe(component.FrameworkLookupBatchV1, &.{
            .{ .first_entry = 0, .entry_count = 2, .interaction_column_start = 0 },
            .{ .first_entry = 2, .entry_count = 1, .interaction_column_start = 4 },
        }),
        .inputs = try allocator.dupe(component.TypedPolynomialInputV1, &.{
            .{ .trace_column = .{ .tree_index = 0, .column_index = 2 } },
            .{ .trace_column = .{ .tree_index = 1, .column_index = 4 } },
            .{ .profile_parameter = 0 },
        }),
        .interaction_columns = try allocator.alloc(component.TypedPolynomialColumnV1, 8),
        .profile_parameter_count = 1,
        .identity = undefined,
    };
    for (program.interaction_columns, 0..) |*column, index|
        column.* = .{ .tree_index = 2, .column_index = @intCast(10 + index) };
    program.identity = program.identityDigest();
    return program;
}

/// Independent rational oracle for this fixture, not a second polynomial DAG
/// interpreter. Device generation clears denominators; this oracle instead
/// forms signed fractions then multiplies the residual by their denominator.
/// Inputs 0/1 are PP/main; slot 2 is loaded from authenticated profile_values.
pub fn expected(
    row_inputs: [3]M31,
    current: [2]QM31,
    previous: QM31,
    parameters: component.FrameworkPolynomialParametersV1,
    powers: [3]QM31,
    denominator_inverse: M31,
    initial: QM31,
) !QM31 {
    if (parameters.profile_values.len != 1 or parameters.relation_values.len != 6)
        return error.InvalidFrameworkPolynomialParameters;
    const p = parameters.relation_values;
    const d0 = p[1].mulM31(row_inputs[1]).sub(p[0]);
    const d1 = p[3].mulM31(row_inputs[0]).sub(p[2]);
    const d2 = p[5].mulM31(row_inputs[1]).sub(p[4]);
    const direct = row_inputs[0].mul(row_inputs[1]).sub(parameters.profile_values[0]);
    const pair = current[0].sub(try d0.inv()).add(try d1.inv()).mul(d0).mul(d1);
    const final = current[1].sub(previous).sub(current[0])
        .add(try parameters.claimedSumShift()).sub(try d2.inv()).mul(d2);
    return initial.add(powers[2].mulM31(direct).add(powers[1].mul(pair))
        .add(powers[0].mul(final)).mulM31(denominator_inverse));
}

test "framework codegen binds arbitrary columns, parameters and whole-component coefficient order" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var program = try fixture(arena.allocator());
    const source = try subject.generateLibrary(arena.allocator(), &.{.{ .program = &program, .tree_column_counts = &.{ 3, 5, 18 } }});
    for ([_][]const u8{
        "uint d0 = tree0[column_offsets[0u] + row]",
        "uint d1 = tree1[column_offsets[1u] + row]",
        "uint d2 = profile_parameters[0u]",
        "riscv_load_qm31(powers, 8u), d4",
        "riscv_load_qm31(powers, 4u), constraint0",
        "riscv_load_qm31(powers, 0u), constraint1",
        "RiscvQm31 delta0 = current0;",
        "RiscvQm31 delta1 = riscv_qm_sub(current1, current0);",
        "tree2[column_offsets[7u] + previous_row]",
        "delta1 = riscv_qm_add(riscv_qm_sub(delta1, previous1), riscv_load_qm31(relation_parameters, 24u))",
        "riscv_qm_mul(riscv_qm_mul(delta0, denominator0), denominator1)",
        "riscv_qm_mul(delta1, denominator2)",
    }) |needle| try std.testing.expect(std.mem.indexOf(u8, source, needle) != null);
    try std.testing.expect(std.mem.indexOf(u8, source, "previous0") == null);
    try std.testing.expect(std.mem.indexOf(u8, source, "selector[row]") == null);
}

test "framework codegen rejects stale identity, bad geometry and unsupported trees" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var program = try fixture(arena.allocator());
    const entry = subject.Entry{ .program = &program, .tree_column_counts = &.{ 3, 5, 18, 3 } };
    const original = try subject.codegenIdentity(arena.allocator(), entry);
    program.inputs[0].trace_column.column_index = 1;
    try std.testing.expectError(error.InvalidFrameworkPolynomialIdentity, subject.codegenIdentity(arena.allocator(), entry));
    program.identity = program.identityDigest();
    try std.testing.expectEqual(original, try subject.codegenIdentity(arena.allocator(), entry));
    program.inputs[0].trace_column.tree_index = 3;
    program.identity = program.identityDigest();
    try std.testing.expectError(error.UnsupportedFrameworkPolynomialTree, subject.codegenIdentity(arena.allocator(), entry));
    program.inputs[0].trace_column.tree_index = 0;
    program.identity = program.identityDigest();
    try std.testing.expectError(error.InvalidFrameworkPolynomialInput, subject.validate(.{ .program = &program, .tree_column_counts = &.{ 3, 5, 17 } }));
}

fn relocate(program: *Program) void {
    program.inputs[0].trace_column.column_index = 1;
    program.inputs[1].trace_column.column_index = 2;
    for (program.interaction_columns, 0..) |*column, index|
        column.column_index = @intCast(index);
    program.identity = program.identityDigest();
}

test "framework kernel relocation retains full admission identities and deduplicates declarations" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var original = try fixture(allocator);
    var moved = try fixture(allocator);
    relocate(&moved);
    const original_seal = original.identity;
    const moved_seal = moved.identity;
    try std.testing.expect(!std.mem.eql(u8, &original_seal, &moved_seal));
    const first = subject.Entry{ .program = &original, .tree_column_counts = &TREE_COUNTS };
    const second = subject.Entry{ .program = &moved, .tree_column_counts = &TREE_COUNTS };
    try std.testing.expectEqual(try subject.codegenIdentity(allocator, first), try subject.codegenIdentity(allocator, second));
    try std.testing.expectEqualStrings(try subject.kernelName(allocator, first), try subject.kernelName(allocator, second));
    const one = try subject.generateLibrary(allocator, &.{first});
    try std.testing.expectEqualStrings(one, try subject.generateLibrary(allocator, &.{second}));
    try std.testing.expectEqualStrings(one, try subject.generateLibrary(allocator, &.{ first, second, first }));
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, one, "kernel void "));
    // Kernel generation never rewrites or substitutes the full program seal.
    try std.testing.expectEqual(original_seal, original.identity);
    try std.testing.expectEqual(moved_seal, moved.identity);
    try subject.validate(first);
    try subject.validate(second);
}

test "framework duplicate kernel entries still require full valid admission" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var original = try fixture(allocator);
    var moved = try fixture(allocator);
    relocate(&moved);
    const entries = [_]subject.Entry{
        .{ .program = &original, .tree_column_counts = &TREE_COUNTS },
        .{ .program = &moved, .tree_column_counts = &TREE_COUNTS },
    };
    moved.identity[0] ^= 1;
    try std.testing.expectError(error.InvalidFrameworkPolynomialIdentity, subject.generateLibrary(allocator, &entries));
    moved.inputs[0].trace_column.column_index = 999;
    moved.identity = moved.identityDigest();
    try std.testing.expectError(error.InvalidFrameworkPolynomialInput, subject.generateLibrary(allocator, &entries));
}

test "framework kernel identity changes with executable bindings equations and constraint order" {
    const Mutation = enum { input_tree, input_slot, interaction_tree, direct_equation, root_order, batch_partition };
    inline for (std.meta.tags(Mutation)) |mutation| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        var program = try fixture(allocator);
        program.direct.roots = try allocator.dupe(u32, &.{ 4, 3 });
        program.identity = program.identityDigest();
        const entry = subject.Entry{ .program = &program, .tree_column_counts = &.{ 32, 32, 32 } };
        const original_seal = program.identity;
        const original_kernel = try subject.codegenIdentity(allocator, entry);
        switch (mutation) {
            .input_tree => program.inputs[0].trace_column.tree_index = 1,
            .input_slot => program.direct.nodes[0].value = 1,
            .interaction_tree => program.interaction_columns[0].tree_index = 1,
            .direct_equation => program.direct.nodes[4].op = .add,
            .root_order => std.mem.swap(u32, &program.direct.roots[0], &program.direct.roots[1]),
            .batch_partition => {
                program.batches[0].entry_count = 1;
                program.batches[1].first_entry = 1;
                program.batches[1].entry_count = 2;
            },
        }
        program.identity = program.identityDigest();
        try std.testing.expect(!std.mem.eql(u8, &original_seal, &program.identity));
        try std.testing.expect(!std.mem.eql(u8, &original_kernel, &try subject.codegenIdentity(allocator, entry)));
    }
}

fn generateAllocationChecked(allocator: std.mem.Allocator, entries: []const subject.Entry) !void {
    const source = try subject.generateLibrary(allocator, entries);
    defer allocator.free(source);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, source, "kernel void "));
}

test "framework kernel canonical source and deduplication release every failed allocation" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var original = try fixture(arena.allocator());
    var moved = try fixture(arena.allocator());
    relocate(&moved);
    const entries = [_]subject.Entry{
        .{ .program = &original, .tree_column_counts = &TREE_COUNTS },
        .{ .program = &moved, .tree_column_counts = &TREE_COUNTS },
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, generateAllocationChecked, .{@as([]const subject.Entry, &entries)});
}

/// Scalar translation of the reused MSL address helper, tested against the
/// core's independent circle-point shift below, including both coset halves.
fn generatedPrevious(row: usize, trace_log: u32, eval_log: u32) usize {
    const rows = @as(usize, 1) << @intCast(eval_log);
    const half = rows / 2;
    const step = (@as(usize, 1) << @intCast(eval_log - trace_log)) / 2;
    const natural = core.utils.bitReverseIndex(row, eval_log);
    const shifted = if (natural < half) (natural + half - step) % half else (natural - half + step) % half + half;
    return core.utils.bitReverseIndex(shifted, eval_log);
}

fn sample(point: core.circle.CirclePointM31) QM31 {
    return QM31.fromM31Array(.{ point.x, point.y, point.x.square(), point.y.square().add(M31.one()) });
}

test "framework off-domain final recurrence preserves circle shift and same-row subtraction" {
    const numerators = [_]M31{ M31.fromU64(3), M31.fromU64(5).neg(), M31.fromU64(7) };
    const denominators = [_]QM31{
        QM31.fromU32Unchecked(9, 2, 3, 1),
        QM31.fromU32Unchecked(4, 7, 2, 5),
        QM31.fromU32Unchecked(1, 3, 8, 2),
    };
    const fractions = [_]QM31{
        (try denominators[0].inv()).mulM31(numerators[0]),
        (try denominators[1].inv()).mulM31(numerators[1]),
        (try denominators[2].inv()).mulM31(numerators[2]),
    };
    for ([_]u32{ 2, 3, 5 }) |trace_log| for ([_]u32{ 1, 2, 3 }) |extension| {
        const eval_log = trace_log + extension;
        const domain = core.poly.circle.canonic.CanonicCoset.new(eval_log).circleDomain();
        const trace = core.poly.circle.canonic.CanonicCoset.new(trace_log);
        const parameters = component.FrameworkPolynomialParametersV1{
            .profile_values = &.{},
            .relation_values = &.{},
            .trace_log_size = trace_log,
            .claimed_sum = QM31.fromU32Unchecked(17, 5, 3, 9),
        };
        const shift = try parameters.claimedSumShift();
        for (0..domain.size()) |row| {
            const previous = generatedPrevious(row, trace_log, eval_log);
            try std.testing.expectEqual(core.utils.previousBitReversedCircleDomainIndex(row, trace_log, eval_log), previous);
            const point = domain.at(core.utils.bitReverseIndex(row, eval_log));
            const shifted = domain.at(core.utils.bitReverseIndex(previous, eval_log));
            try std.testing.expect(point.sub(trace.step()).eql(shifted));
            const current0 = sample(point).square();
            const current1 = sample(point);
            const previous1 = sample(shifted);
            const delta0 = current0;
            const delta1 = current1.sub(current0).sub(previous1).add(shift);
            const generated_pair = delta0.mul(denominators[0]).mul(denominators[1])
                .sub(denominators[1].mulM31(numerators[0])).sub(denominators[0].mulM31(numerators[1]));
            const rational_pair = delta0.sub(fractions[0]).sub(fractions[1]).mul(denominators[0]).mul(denominators[1]);
            try std.testing.expect(generated_pair.eql(rational_pair));
            const generated_final = delta1.mul(denominators[2]).sub(QM31.fromM31(numerators[2], M31.zero(), M31.zero(), M31.zero()));
            const rational_final = current1.sub(previous1).add(shift).sub(current0).sub(fractions[2]).mul(denominators[2]);
            try std.testing.expect(generated_final.eql(rational_final));
            const wrong_final = current1.sub(previous1).add(shift).sub(fractions[2]).mul(denominators[2]);
            if (!current0.eql(QM31.zero())) try std.testing.expect(!wrong_final.eql(rational_final));
        }
    };
}
