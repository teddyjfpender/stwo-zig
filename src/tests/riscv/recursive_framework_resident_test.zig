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

test "recursive framework AOT executes native table interactions with exact columns claims and recovery" {
    const allocator = std.testing.allocator;
    const tables = @import("stwo_riscv_frontend").air.lookups.tables;
    const interaction = metal.runtime.framework_interaction;
    const bundle = try std.process.getEnvVarOwned(allocator, "STWO_RECURSIVE_FRAMEWORK_AOT_BUNDLE");
    defer allocator.free(bundle);
    const pin = try std.process.getEnvVarOwned(allocator, "STWO_RECURSIVE_FRAMEWORK_AOT_MANIFEST_SHA256");
    defer allocator.free(pin);
    if (pin.len != 64) return error.InvalidRecursiveFrameworkAotPin;
    var digest: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&digest, pin);
    var admission = try metal.core_aot.admitForProfile(allocator, bundle, digest, .recursive_framework_v1);
    defer admission.deinit();
    var runtime = try metal.Runtime.initFromAotAdmission(&admission);
    defer runtime.deinit();
    const relations = @import("stwo_riscv_frontend").air.relation_challenges.Relations.dummy();

    for (std.meta.tags(tables.schema.Kind)) |kind| {
        const rows = tables.schema.size(kind);
        const log = tables.schema.logSize(kind);
        const arity = tables.schema.arity(kind);
        const counts = [_]usize{ arity + 1, 1, 4 };
        const indices = [_]usize{ 1, 2, 3, 4 };
        const component = try tables.component.LookupTableComponent.initProver(kind, 0, indices[0..arity], 0, 0, &relations, QM31.zero());
        var program = try tables.framework_export.exportProgram(allocator, &component, &counts);
        defer program.deinit();
        var parameters = try tables.framework_export.exportParameters(allocator, &component);
        defer parameters.deinit();
        var plan = try interaction.Plan.init(allocator, .{ .program = &program, .tree_column_counts = &counts });
        defer plan.deinit();
        // The production loader must resolve the fraction and all three scan
        // kernels in the independently admitted metallib. No source compiler.
        try plan.prepare(&runtime);
        var preprocessed = try runtime.allocateResidentBuffer(counts[0] * rows * @sizeOf(M31));
        defer preprocessed.deinit();
        var main = try runtime.allocateResidentBuffer(rows * @sizeOf(M31));
        defer main.deinit();
        const pre: []M31 = @as([*]M31, @ptrCast(@alignCast(preprocessed.contents)))[0 .. counts[0] * rows];
        const mult: []M31 = @as([*]M31, @ptrCast(@alignCast(main.contents)))[0..rows];
        @memset(pre, M31.zero());
        var counter = try tables.counter.Counter.init(allocator, kind);
        defer counter.deinit(allocator);
        for (0..rows) |row| {
            const physical = core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(row, log), log);
            const tuple = try tables.schema.tupleAt(kind, row);
            for (tuple.slice(), 0..) |value, column| pre[(column + 1) * rows + physical] = value;
            const value = if (row % 103 == 0 or row == rows - 1) M31.fromU64(1 + row % 19) else M31.zero();
            counter.values[row] = value;
            mult[physical] = value;
        }
        pre[0] = M31.one();
        var reference = try tables.interaction.generate(allocator, &counter, &relations);
        defer reference.deinit(allocator);
        var pre_offsets: [5]u64 = undefined;
        for (pre_offsets[0..counts[0]], 0..) |*offset, index| offset.* = index * rows;
        const trees = [2]?interaction.Tree{
            .{ .buffer = &preprocessed, .column_offsets = pre_offsets[0..counts[0]] },
            .{ .buffer = &main, .column_offsets = &.{0} },
        };
        const invocation = interaction.Invocation{
            .trace_log_size = log,
            .profile_values = parameters.values.profile_values,
            .relation_values = parameters.values.relation_values,
        };
        var result = try plan.generate(trees, invocation);
        defer result.deinit();
        try std.testing.expectEqual(rows, result.rows);
        try std.testing.expectEqual(@as(usize, 1), result.batches);
        for (reference.columns, 0..) |column, index|
            try std.testing.expectEqualSlices(M31, column, result.column(index));
        try std.testing.expect(reference.claim.eql(result.claim(0)));
        try std.testing.expect(result.gpu_milliseconds > 0);

        pre[0] = M31.zero();
        try std.testing.expectError(error.FrameworkInteractionInvalidSelector, plan.generate(trees, invocation));
        pre[0] = M31.one();
        const poles = try allocator.alloc(QM31, invocation.relation_values.len);
        defer allocator.free(poles);
        @memset(poles, QM31.zero());
        var pole_invocation = invocation;
        pole_invocation.relation_values = poles;
        try std.testing.expectError(error.FrameworkInteractionZeroDenominator, plan.generate(trees, pole_invocation));
        var recovered = try plan.generate(trees, invocation);
        defer recovered.deinit();
        try std.testing.expect(reference.claim.eql(recovered.claim(0)));
        for (reference.columns, 0..) |column, index|
            try std.testing.expectEqualSlices(M31, column, recovered.column(index));
        std.debug.print("NATIVE_TABLE_AOT_INTERACTION kind={s} rows={} columns=4 native_parity=true claim_parity=true rejection_recovery=true gpu_ms={d:.3}\n", .{ @tagName(kind), rows, result.gpu_milliseconds });
    }
}

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

test "recursive framework AOT executes production table bridge with native parity" {
    const allocator = std.testing.allocator;
    const frontend = @import("stwo_riscv_frontend");
    const tables = frontend.air.lookups.tables;
    const Backend = metal.MetalCommitBackend;
    const bundle = try std.process.getEnvVarOwned(allocator, "STWO_RECURSIVE_FRAMEWORK_AOT_BUNDLE");
    defer allocator.free(bundle);
    const pin = try std.process.getEnvVarOwned(allocator, "STWO_RECURSIVE_FRAMEWORK_AOT_MANIFEST_SHA256");
    defer allocator.free(pin);
    var digest: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&digest, pin);
    try Backend.initializeRuntime(allocator, .{ .authenticated_aot = .{ .bundle_path = bundle, .manifest_sha256 = digest, .profile = .recursive_framework_v1 } });
    defer Backend.shutdown() catch unreachable;
    try std.testing.expect(try Backend.supportsFrameworkInteractions());
    const before = try Backend.telemetrySnapshot();
    const relations = frontend.air.relation_challenges.Relations.dummy();
    inline for (std.meta.tags(tables.schema.Kind)) |kind| {
        var counter = try tables.counter.Counter.init(allocator, kind);
        defer counter.deinit(allocator);
        for (counter.values, 0..) |*value, index| value.* = M31.fromCanonical(@intCast(index % 13));
        var reference = try tables.interaction.generate(allocator, &counter, &relations);
        defer reference.deinit(allocator);
        var actual = try tables.device_interaction.generate(Backend, allocator, &counter, &relations);
        defer actual.deinit(allocator);
        try std.testing.expect(reference.claim.eql(actual.claim));
        for (reference.columns, actual.columns) |expected, got| try std.testing.expectEqualSlices(M31, expected, got);
        var malformed = counter;
        malformed.values = counter.values[0 .. counter.values.len - 1];
        try std.testing.expectError(error.InvalidTraceShape, tables.device_interaction.generate(Backend, allocator, &malformed, &relations));
        var poles = relations;
        switch (kind) {
            inline else => |selected| @field(poles, @tagName(selected)).z = QM31.zero(),
        }
        try std.testing.expectError(error.DivisionByZero, tables.device_interaction.generate(Backend, allocator, &counter, &poles));
        var recovered = try tables.device_interaction.generate(Backend, allocator, &counter, &relations);
        defer recovered.deinit(allocator);
        try std.testing.expect(reference.claim.eql(recovered.claim));
        for (reference.columns, recovered.columns) |expected, got| try std.testing.expectEqualSlices(M31, expected, got);
    }
    const delta = (try Backend.telemetrySnapshot()).delta(before);
    try std.testing.expectEqual(@as(u64, 48), delta.counters.metal_framework_interaction_dispatches);
}

test "recursive framework AOT executes parent interaction catalog with CPU column and claim parity" {
    try checkTypedInteractionCatalog(air.detached_parent_catalog_v1.LOGICAL_ROWS, "PARENT");
}

test "recursive framework AOT executes leaf interaction catalog with CPU column and claim parity" {
    try checkTypedInteractionCatalog(air.segment_leaf_catalog_v2.LOGICAL_ROWS, "LEAF");
}

fn checkTypedInteractionCatalog(comptime catalog: anytype, comptime profile: []const u8) !void {
    @setEvalBranchQuota(1_000_000);
    const allocator = std.testing.allocator;
    const Backend = metal.MetalCommitBackend;
    const bundle = try std.process.getEnvVarOwned(allocator, "STWO_RECURSIVE_FRAMEWORK_AOT_BUNDLE");
    defer allocator.free(bundle);
    const pin = try std.process.getEnvVarOwned(allocator, "STWO_RECURSIVE_FRAMEWORK_AOT_MANIFEST_SHA256");
    defer allocator.free(pin);
    var digest: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&digest, pin);
    try Backend.initializeRuntime(allocator, .{ .authenticated_aot = .{ .bundle_path = bundle, .manifest_sha256 = digest, .profile = .recursive_framework_v1 } });
    defer Backend.shutdown() catch unreachable;
    const before = try Backend.telemetrySnapshot();
    const relations = air.universal_challenges.UniversalRelations.dummy();
    const recursion = @import("stwo_riscv_frontend").recursion;
    const leaf_profile = comptime std.mem.eql(u8, profile, "LEAF");
    const lane = air.query_bits_profile.LaneProfile{ .query_count = 1, .lifting_log_size = 9, .trace_tree_count = 3, .fri_layer_count = 1 };
    const admitted = recursion.detached_segment_admission_v1.AdmissionParametersV1{ .query_reference = try air.query_bits_profile.Reference.seal(lane, lane), .poseidon_active_rows = 0 };
    inline for (catalog) |entry| {
        for ([_]usize{ 512, 509 }) |live_count| {
            const Typed = entry.Air;
            const Binding = air.universal_relation_binding.Binding(Typed);
            const Framework = air.framework_interaction.Runtime(Binding.Runtime);
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();
            const temporary = arena.allocator();
            var definition = if (entry.requires_location) try Typed.build(temporary, .generated) else try Typed.build(temporary);
            defer definition.deinit();
            const direct = try air.direct_constraint_program.authenticate(&definition.arena, Typed.SEMANTIC_DIGEST, Typed.LOGICAL_INPUT_COUNT);
            const relation = try Binding.authenticate(&definition);
            var program = try air.framework_polynomial_export_v1.exportLocalPrepared(Typed, temporary, &direct, &relation);
            defer program.deinit();
            const counts = [_]usize{ Typed.PREPROCESSED_COLUMN_COUNT, Typed.PHYSICAL_MAIN_COLUMN_COUNT, Typed.INTERACTION_COLUMN_COUNT };
            const log = 9;
            const row_count = 1 << log;
            const logical = try temporary.alloc([Typed.LOGICAL_INPUT_COUNT]M31, row_count);
            const parameter_start = counts[0] + counts[1];
            for (logical, 0..) |*row, index| for (row, 0..) |*value, column| {
                // These exercise relation evaluation; direct AIR satisfaction is
                // covered by the complete proof gate, not claimed by this test.
                value.* = M31.fromU64(2 + (column * 13 + if (column < parameter_start) index * 7 else 0) % 251);
            };
            if (comptime leaf_profile) {
                const profile_values = try recursion.segment_leaf_parameters_v2.parametersFor(entry, admitted);
                for (logical) |*row| @memcpy(row[parameter_start..], &profile_values);
            }
            const live_rows = logical[0..live_count];
            for (logical[live_rows.len..]) |*row| @memset(row, M31.zero());
            var sources: [2][]const []const M31 = undefined;
            for (0..2) |tree| {
                const columns = try temporary.alloc([]const M31, counts[tree]);
                for (columns, 0..) |*column, local| {
                    const values = try temporary.alloc(M31, row_count);
                    const source = if (tree == 0) counts[1] + local else local;
                    for (logical, 0..) |row, index| values[air.framework_interaction.committedRow(index, log)] = row[source];
                    column.* = values;
                }
                sources[tree] = columns;
            }
            const destination = try temporary.alloc([]M31, counts[2]);
            for (destination) |*column| column.* = try temporary.alloc(M31, row_count);
            const relation_values = try air.framework_polynomial_export_v1.exportRelationParameters(temporary, &relation, &relations);
            var reference = try Framework.generatePrepared(temporary, &relation, live_rows, log, &relations);
            defer reference.deinit(temporary);
            const invocation = metal.runtime.framework_interaction.Invocation{ .trace_log_size = log, .profile_values = logical[0][parameter_start..], .relation_values = relation_values };
            const claim = if (comptime leaf_profile) generated: {
                var workspace = try Framework.Workspace.init(temporary, log);
                defer workspace.deinit();
                // This is a component fixture, not a cohort admission. Production
                // constructs the policy with init against the independently admitted key.
                var measured = std.testing.FailingAllocator.init(temporary, .{});
                const Generator = recursion.leaf_interaction_generator_v2.ForBackend(Backend);
                const generator = Generator{ .allocator = measured.allocator(), .parameters = admitted, .device = true };
                const typed_destination: *[Typed.INTERACTION_COLUMN_COUNT][]M31 = destination[0..Typed.INTERACTION_COLUMN_COUNT];
                const actual = try generator.generatePreparedIntoWithDomainSums(Framework, &workspace, &relation, live_rows, log, &relations, typed_destination);
                const host_generator = recursion.leaf_interaction_generator_v2.ForBackend(void){ .allocator = temporary, .parameters = admitted, .device = false };
                const expected_domains = try host_generator.generatePreparedIntoWithDomainSums(Framework, &workspace, &relation, live_rows, log, &relations, &reference.columns);
                try std.testing.expectEqualDeep(expected_domains, actual);
                if (comptime @intFromEnum(entry.row) == 0) {
                    if (live_count == 512) {
                        // The last allocation belongs to the independent audit:
                        // prove a completed GPU dispatch cannot publish early.
                        var failing = std.testing.FailingAllocator.init(temporary, .{ .fail_index = measured.alloc_index - 1 });
                        const failing_generator = Generator{ .allocator = failing.allocator(), .parameters = admitted, .device = true };
                        for (destination) |column| @memset(column, M31.one());
                        const before_failure = try Backend.telemetrySnapshot();
                        try std.testing.expectError(error.OutOfMemory, failing_generator.generatePreparedIntoWithDomainSums(Framework, &workspace, &relation, live_rows, log, &relations, typed_destination));
                        const after_failure = try Backend.telemetrySnapshot();
                        try std.testing.expectEqual(@as(u64, 4), after_failure.counters.metal_framework_interaction_dispatches - before_failure.counters.metal_framework_interaction_dispatches);
                        for (destination) |column| for (column) |word| try std.testing.expectEqual(M31.one(), word);
                        failing.fail_index = std.math.maxInt(usize);
                        const retried = try failing_generator.generatePreparedIntoWithDomainSums(Framework, &workspace, &relation, live_rows, log, &relations, typed_destination);
                        try std.testing.expectEqualDeep(expected_domains, retried);
                        for (reference.columns, destination) |expected, got| try std.testing.expectEqualSlices(M31, expected, got);
                        var aliased = typed_destination.*;
                        const flat: []M31 = @alignCast(std.mem.bytesAsSlice(M31, std.mem.sliceAsBytes(logical)));
                        aliased[0] = flat[0..row_count];
                        try std.testing.expectError(error.DestinationAlias, generator.generatePreparedInto(Framework, &workspace, &relation, live_rows, log, &relations, &aliased));
                        for (reference.columns, destination) |expected, got| try std.testing.expectEqualSlices(M31, expected, got);
                        std.debug.print("LEAF_GENERATOR_AUDIT_FAILURE gpu_completed=true destination_unchanged=true retry=true alias_rejected=true\n", .{});
                    }
                }
                break :generated actual.claimed_sum;
            } else try air.framework_device_interaction.generateInto(Backend, Typed, temporary, &direct, &relation, live_rows, invocation.profile_values, log, &relations, destination);
            try std.testing.expect(claim.eql(reference.claimed_sum));
            for (reference.columns, destination) |expected, actual| try std.testing.expectEqualSlices(M31, expected, actual);
            // Rejected output must leave every caller-owned destination untouched.
            const poles = try temporary.alloc(QM31, relation_values.len);
            @memset(poles, QM31.zero());
            var invalid = invocation;
            invalid.relation_values = poles;
            try std.testing.expectError(error.FrameworkInteractionZeroDenominator, Backend.generateFrameworkInteractionInto(temporary, &program, &counts, sources, invalid, destination));
            for (reference.columns, destination) |expected, actual| try std.testing.expectEqualSlices(M31, expected, actual);
            const recovered = try Backend.generateFrameworkInteractionInto(temporary, &program, &counts, sources, invocation, destination);
            try std.testing.expect(recovered.eql(claim));
            for (reference.columns, destination) |expected, actual| try std.testing.expectEqualSlices(M31, expected, actual);
            std.debug.print("{s}_TYPED_INTERACTION_AOT row={} rows={} trace_rows={} batches={} parity=true recovery=true\n", .{ profile, @intFromEnum(entry.row), live_count, row_count, program.batches.len });
        }
    }
    const after = try Backend.telemetrySnapshot();
    try std.testing.expectEqual(@as(u64, catalog.len * 16 + (if (leaf_profile) @as(usize, 8) else 0)), after.counters.metal_framework_interaction_dispatches - before.counters.metal_framework_interaction_dispatches);
}
