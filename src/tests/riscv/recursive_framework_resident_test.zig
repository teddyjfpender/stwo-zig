//! Real admitted-AOT dispatch over committed trees for an exported production
//! typed AIR. This checks composition evaluation, not a complete STARK proof.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const air = @import("stwo_riscv_frontend").recursion.air;
const metal = @import("stwo_metal_backend");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Air = air.qm31_mul_add_v1;
const Relation = air.universal_relation_binding.Binding(Air);
const Adapter = air.universal_typed_component.Component(Air, Relation);
const Dispatch = metal.runtime.FrameworkPolynomialDispatch;
const Output = metal.runtime.BasePolynomialOutput;

// Rejected invocations exercise the production C admission boundary directly:
// expected failures must not emit std.log.err through the friendly Zig API.
extern fn stwo_zig_metal_framework_polynomial_batch(
    *anyopaque,
    [*]const ?*anyopaque,
    u32,
    ?*anyopaque,
    ?[*]const u32,
    usize,
    [*]const ?[*]const u32,
    u32,
    [*]const Dispatch,
    u32,
    [*]const u32,
    u32,
    [*]const u32,
    u32,
    [*]const u32,
    u32,
    [*]const Output,
    u32,
    *f64,
    [*]u8,
    usize,
) u32;

fn reject(
    expected_status: u32,
    runtime: *metal.Runtime,
    trees: []const ?*anyopaque,
    columns: []const ?[*]const u32,
    dispatch: Dispatch,
    relations: []const u32,
    powers: []const u32,
    output: Output,
) !void {
    var message: [1024]u8 = @splat(0);
    var gpu_ms: f64 = 0;
    const status = stwo_zig_metal_framework_polynomial_batch(
        runtime.handle,
        trees.ptr,
        @intCast(trees.len),
        null,
        null,
        0,
        columns.ptr,
        @intCast(columns.len),
        &.{dispatch},
        1,
        &.{},
        0,
        relations.ptr,
        @intCast(relations.len),
        powers.ptr,
        @intCast(powers.len),
        &.{output},
        1,
        &gpu_ms,
        &message,
        message.len,
    );
    if (status != expected_status) std.debug.print("framework rejection expected={} actual={} detail={s}\n", .{ expected_status, status, std.mem.sliceTo(&message, 0) });
    try std.testing.expectEqual(expected_status, status);
    try std.testing.expect(message[0] != 0);
    try std.testing.expectEqual(@as(f64, 0), gpu_ms);
    for (output.columns) |column| for (column[0..output.row_count]) |word|
        try std.testing.expectEqual(@as(u32, 109), word);
}

fn secureWords(destination: []u32, value: QM31) void {
    for (destination, value.toM31Array()) |*word, coordinate| word.* = coordinate.toU32();
}

test "recursive framework AOT executes exported typed AIR on resident trees with native parity and rejection controls" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const temporary = arena.allocator();
    // Mandatory explicit bundle and trust anchor: missing inputs fail this gate.
    const bundle = try std.process.getEnvVarOwned(temporary, "STWO_RECURSIVE_FRAMEWORK_AOT_BUNDLE");
    const pin = try std.process.getEnvVarOwned(temporary, "STWO_RECURSIVE_FRAMEWORK_AOT_MANIFEST_SHA256");
    if (pin.len != 64) return error.InvalidRecursiveFrameworkAotPin;
    var digest: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&digest, pin);
    var admission = try metal.core_aot.admitForProfile(allocator, bundle, digest, .recursive_framework_v1);
    defer admission.deinit();
    var runtime = try metal.Runtime.initFromAotAdmission(&admission);
    defer runtime.deinit();

    var definition = try Air.build(allocator);
    defer definition.deinit();
    const relation_plan = try Relation.authenticate(&definition);
    const relations = air.universal_challenges.UniversalRelations.dummy();
    const trace_log: u32 = 3;
    var builder = air.universal_adapter_manifest.Builder{};
    _ = try builder.append(Adapter.manifestGeometry(.qm31_mul, trace_log));
    const manifest = try builder.seal();
    const native = try Adapter.init(&definition, relation_plan, &manifest, .qm31_mul, trace_log, .{}, &relations, QM31.fromU32Unchecked(41, 43, 47, 53));
    const component = native.asProverComponent();
    const capability = component.backend_composition_capability.?.framework_polynomial_v1;
    const counts = [_]usize{ Air.PREPROCESSED_COLUMN_COUNT, Air.PHYSICAL_MAIN_COLUMN_COUNT, Air.INTERACTION_COLUMN_COUNT };
    var program = try capability.export_program(component.ctx, allocator, &counts);
    defer program.deinit();
    var parameters = try capability.export_parameters(component.ctx, allocator);
    defer parameters.deinit();
    try parameters.values.validate(&program);
    const eval_log = component.maxConstraintLogDegreeBound();
    const rows = @as(usize, 1) << @intCast(eval_log);
    const denominator_count = @as(usize, 1) << @intCast(eval_log - trace_log);
    try std.testing.expect(denominator_count <= 8);
    const domain = core.poly.circle.canonic.CanonicCoset.new(eval_log).circleDomain();
    const trace_domain = core.poly.circle.canonic.CanonicCoset.new(trace_log).coset();
    var values: [3][][]M31 = undefined;
    var resident_trees: [3]metal.Tree = undefined;
    var initialized_trees: usize = 0;
    defer for (resident_trees[0..initialized_trees]) |*tree| tree.deinit();
    const hash = metal.hash_domain.blake2sParameters(core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher).?;
    for (counts, 0..) |count, tree| {
        values[tree] = try temporary.alloc([]M31, count);
        const input = try temporary.alloc([]const u32, count);
        const logs = try temporary.alloc(u32, count);
        @memset(logs, eval_log);
        for (values[tree], input, 0..) |*column, *words, index| {
            column.* = try temporary.alloc(M31, rows);
            for (column.*, 0..) |*word, row| {
                const point = domain.at(core.utils.bitReverseIndex(row, eval_log));
                word.* = point.x.mul(M31.fromU64(index + 2)).add(point.y)
                    .add(M31.fromU64(71 + tree * 43 + index));
            }
            words.* = @as([*]const u32, @ptrCast(column.ptr))[0..rows];
        }
        resident_trees[tree] = try runtime.commitColumns(allocator, input, logs, eval_log, hash.leaf_seed, hash.node_seed, hash.domain_prefix_bytes);
        initialized_trees += 1;
    }
    var trees: [3]?*anyopaque = undefined;
    for (&trees, resident_trees) |*handle, tree| handle.* = tree.handle;
    const columns = try temporary.alloc(?[*]const u32, program.inputs.len + program.interaction_columns.len);
    const column_trees = try temporary.alloc(u32, columns.len);
    for (program.inputs, columns[0..program.inputs.len], column_trees[0..program.inputs.len]) |input, *pointer, *tree| switch (input) {
        .trace_column => |coordinate| {
            pointer.* = @ptrCast(values[coordinate.tree_index][coordinate.column_index].ptr);
            tree.* = coordinate.tree_index;
        },
        .profile_parameter => {
            pointer.* = null;
            tree.* = std.math.maxInt(u32);
        },
    };
    for (program.interaction_columns, columns[program.inputs.len..], column_trees[program.inputs.len..]) |coordinate, *pointer, *tree| {
        pointer.* = @ptrCast(values[coordinate.tree_index][coordinate.column_index].ptr);
        tree.* = coordinate.tree_index;
    }
    const name = try metal.riscv_polynomial_codegen.framework.kernelName(temporary, .{ .program = &program, .tree_column_counts = &counts });
    const relation_words = try temporary.alloc(u32, (parameters.values.relation_values.len + 1) * 4);
    for (parameters.values.relation_values, 0..) |value, index| secureWords(relation_words[index * 4 ..][0..4], value);
    secureWords(relation_words[relation_words.len - 4 ..], try parameters.values.claimedSumShift());
    const constraint_count = native.nConstraints();
    const power_start: usize = 2;
    const powers = try prover.air.accumulation.generateSecurePowers(temporary, QM31.fromU32Unchecked(3, 5, 7, 11), constraint_count + 4);
    const power_words = try temporary.alloc(u32, powers.len * 4);
    for (powers, 0..) |power, index| secureWords(power_words[index * 4 ..][0..4], power);
    var plan = try runtime.prepareFrameworkPolynomialAot(name, column_trees, 0, @intCast(relation_words.len), @intCast(constraint_count * 4));
    defer plan.deinit();
    var output = Output{ .columns = undefined, .row_count = @intCast(rows) };
    for (&output.columns) |*column| {
        const words = try temporary.alloc(u32, rows);
        @memset(words, 109);
        column.* = words.ptr;
    }
    var dispatch = Dispatch{
        .plan = plan.handle,
        .column_offset = 0,
        .column_count = @intCast(columns.len),
        .profile_word_offset = 0,
        .profile_word_count = 0,
        .relation_word_offset = 0,
        .relation_word_count = @intCast(relation_words.len),
        .power_word_offset = power_start * 4,
        .power_word_count = @intCast(constraint_count * 4),
        .output_index = 0,
        .row_count = @intCast(rows),
        .trace_log_size = trace_log,
        .denominator_count = @intCast(denominator_count),
        .denominator_inverses = @splat(0),
    };
    for (0..denominator_count) |index| {
        const point = domain.at(core.utils.bitReverseIndex(index * (rows / denominator_count), eval_log));
        dispatch.denominator_inverses[index] = (try core.constraints.cosetVanishing(M31, trace_domain, point).inv()).toU32();
    }

    // Each rejection must leave the caller's output untouched and submit no GPU work.
    var invalid = dispatch;
    invalid.column_count -= 1;
    try reject(1, &runtime, &trees, columns, invalid, relation_words, power_words, output);
    invalid = dispatch;
    invalid.trace_log_size += 1;
    try reject(1, &runtime, &trees, columns, invalid, relation_words, power_words, output);
    const saved_relation = relation_words[0];
    relation_words[0] = core.fields.m31.Modulus;
    try reject(1, &runtime, &trees, columns, dispatch, relation_words, power_words, output);
    relation_words[0] = saved_relation;
    const saved_column = columns[0];
    const escaped = try temporary.dupe(u32, saved_column.?[0..rows]);
    columns[0] = escaped.ptr;
    try reject(2, &runtime, &trees, columns, dispatch, relation_words, power_words, output);
    columns[0] = saved_column;
    std.mem.swap(?*anyopaque, &trees[0], &trees[1]);
    try reject(2, &runtime, &trees, columns, dispatch, relation_words, power_words, output);
    std.mem.swap(?*anyopaque, &trees[0], &trees[1]);
    var foreign_runtime = try metal.Runtime.initFromAotAdmission(&admission);
    defer foreign_runtime.deinit();
    var foreign_plan = try foreign_runtime.prepareFrameworkPolynomialAot(name, column_trees, 0, @intCast(relation_words.len), @intCast(constraint_count * 4));
    defer foreign_plan.deinit();
    invalid = dispatch;
    invalid.plan = foreign_plan.handle;
    try reject(1, &runtime, &trees, columns, invalid, relation_words, power_words, output);

    const gpu_ms = try runtime.evaluateFrameworkPolynomialBatch(&trees, null, columns, &.{ dispatch, dispatch }, &.{}, relation_words, power_words, &.{output});
    var nonzero = false;
    for (0..rows) |row| {
        var native_row: Relation.Row = undefined;
        for (native_row[0..Air.PHYSICAL_MAIN_COLUMN_COUNT], values[1]) |*word, column| word.* = column[row];
        for (native_row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], values[0]) |*word, column| word.* = column[row];
        var current: [Air.INTERACTION_BATCH_COUNT]QM31 = undefined;
        for (&current, 0..) |*value, index| value.* = QM31.fromM31Array(.{
            values[2][index * 4][row], values[2][index * 4 + 1][row], values[2][index * 4 + 2][row], values[2][index * 4 + 3][row],
        });
        const previous_row = core.utils.previousBitReversedCircleDomainIndex(row, trace_log, eval_log);
        const previous_start = Air.INTERACTION_COLUMN_COUNT - 4;
        const previous = QM31.fromM31Array(.{
            values[2][previous_start][previous_row],     values[2][previous_start + 1][previous_row],
            values[2][previous_start + 2][previous_row], values[2][previous_start + 3][previous_row],
        });
        var roots: [Adapter.CONSTRAINT_COUNT_TOTAL]QM31 = undefined;
        try native.evaluateBaseRowInto(native_row, current, previous, &roots);
        var expected = QM31.zero();
        for (roots, 0..) |root, index| expected = expected.add(powers[power_start + constraint_count - 1 - index].mul(root));
        const point = domain.at(core.utils.bitReverseIndex(row, eval_log));
        expected = expected.mulM31(try core.constraints.cosetVanishing(M31, trace_domain, point).inv());
        expected = expected.add(expected); // Two additive dispatches, one output bucket.
        nonzero = nonzero or !expected.eql(QM31.zero());
        for (expected.toM31Array(), 0..) |coordinate, index| try std.testing.expectEqual(coordinate.toU32(), output.columns[index][row]);
    }
    try std.testing.expect(nonzero);
    std.debug.print("FRAMEWORK_RESIDENT_AOT air={s} manifest={s} rows={} dispatches=2 coordinates={} negative_controls=6 gpu_ms={d:.3}\n", .{
        Air.STABLE_NAME, pin, rows, rows * 4, gpu_ms,
    });
}
