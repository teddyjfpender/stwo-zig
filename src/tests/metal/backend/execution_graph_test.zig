const std = @import("std");
const metal = @import("stwo_metal_backend").runtime;
const m31 = @import("stwo_core").fields.m31;
const blake2_merkle = @import("stwo_core").vcs_lifted.blake2_merkle;
const blake2_hash = @import("stwo_core").vcs.blake2_hash;
const merkle_prover = @import("stwo_prover_impl").vcs_lifted.prover;
const pcs_core = @import("stwo_core").pcs;
const MetalProverEngine = @import("stwo_metal_backend").prover_engine.MetalProverEngine;
const canonic = @import("stwo_core").poly.circle.canonic;
const circle_poly = @import("stwo_prover_impl").poly.circle.poly;
const twiddles = @import("stwo_prover_impl").poly.twiddles;
const core_fri = @import("stwo_core").fri;
const qm31 = @import("stwo_core").fields.qm31;
const line = @import("stwo_core").poly.line;
const prover_line = @import("stwo_prover_impl").line;
const MetalBackend = @import("stwo_metal_backend").commit_backend.MetalCommitBackend;
const metal_commit_policy = @import("stwo_metal_backend").commit_policy;
const eval_program = @import("stwo_cairo_frontend").witness.eval_program;
const eval_codegen = @import("../../../integrations/cairo_metal/eval_codegen.zig");
const circle_core = @import("stwo_core").circle;
const core_utils = @import("stwo_core").utils;
const blake2s_channel = @import("stwo_core").channel.blake2s;
const protocol_recipes = @import("stwo_metal_backend").protocol_recipes;
const arena_plan = @import("stwo_metal_backend").arena_plan;
const secure_column = @import("stwo_prover_impl").secure_column;
const secure_circle_poly = @import("stwo_prover_impl").poly.circle.secure_poly;
const cairo_arena_binding = @import("../../../integrations/cairo_metal/arena_binding.zig");
const cairo_oods = @import("../../../integrations/cairo_metal/oods.zig");
const cairo_quotient_inputs = @import("../../../integrations/cairo_metal/quotient_inputs.zig");
const cairo_quotient_reference = @import("../../../integrations/cairo_metal/quotient_reference.zig");

const M31 = m31.M31;
const Hasher = blake2_merkle.Blake2sMerkleHasher;
const PlainHasher = blake2_merkle.Blake2sPlainMerkleHasher;
const QM31 = qm31.QM31;

fn testResidentBinding(logical_id: u32, offset_words: u32, word_count: u32) arena_plan.Binding {
    return .{
        .logical_id = logical_id,
        .slot = logical_id,
        .offset_bytes = @as(u64, offset_words) * @sizeOf(u32),
        .size_bytes = @as(u64, word_count) * @sizeOf(u32),
        .materialization = .resident,
        .occupied = [_]u64{0} ** (arena_plan.max_ticks / 64),
    };
}

test "metal: FRI commitment policy shares the exact secure-column boundary" {
    const cell_threshold = metal_commit_policy.merkle_cell_threshold;
    try std.testing.expect(!metal_commit_policy.usesResidentMerkle(cell_threshold - 1));
    try std.testing.expect(metal_commit_policy.usesResidentMerkle(cell_threshold));

    const value_threshold = std.math.divCeil(
        usize,
        cell_threshold,
        qm31.SECURE_EXTENSION_DEGREE,
    ) catch unreachable;
    try std.testing.expect(!metal_commit_policy.secureColumnUsesResidentMerkle(value_threshold - 1));
    try std.testing.expect(metal_commit_policy.secureColumnUsesResidentMerkle(value_threshold));
    try std.testing.expect(
        metal_commit_policy.secureColumnUsesResidentMerkle(std.math.maxInt(usize)),
    );

    const quotient_log = metal_commit_policy.quotient_resident_merkle_log_threshold;
    try std.testing.expect(!metal_commit_policy.quotientUsesResidentMerkle(quotient_log - 1));
    try std.testing.expect(metal_commit_policy.quotientUsesResidentMerkle(quotient_log));

    const fri_log = metal_commit_policy.fri_fold_commit_log_threshold;
    const fri_value_threshold = @as(usize, 1) << @intCast(fri_log);
    try std.testing.expect(!metal_commit_policy.friFoldCommitUsesResidentMerkle(fri_value_threshold - 1, 1));
    try std.testing.expect(metal_commit_policy.friFoldCommitUsesResidentMerkle(fri_value_threshold, 1));
    try std.testing.expect(!metal_commit_policy.friFoldCommitUsesResidentMerkle(fri_value_threshold, 2));
}

test {
    _ = @import("proof_residency_test.zig");
    _ = @import("trace_generation_test.zig");
    _ = @import("transform_pipeline_test.zig");
    std.testing.refAllDecls(cairo_arena_binding);
    std.testing.refAllDecls(cairo_oods);
    std.testing.refAllDecls(cairo_quotient_inputs);
    std.testing.refAllDecls(cairo_quotient_reference);
}

test "metal: prepared state restore preserves immutable ranges and clears mutable bytes" {
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer(256);
    defer arena.deinit();
    var snapshot = try runtime.allocateResidentBuffer(32);
    defer snapshot.deinit();
    const arena_bytes: [*]u8 = @ptrCast(arena.contents);
    @memset(arena_bytes[0..arena.byte_length], 0x31);
    for (arena_bytes[32..48], 0..) |*byte, index| byte.* = @intCast(index + 1);
    for (arena_bytes[160..176], 0..) |*byte, index| byte.* = @intCast(index + 33);
    const ranges = [_]metal.PreparedStateRange{
        .{ .arena_byte_offset = 32, .snapshot_byte_offset = 0, .byte_count = 16 },
        .{ .arena_byte_offset = 160, .snapshot_byte_offset = 16, .byte_count = 16 },
    };
    _ = try runtime.preparedStateTransfer(arena, snapshot, &ranges, true, false);
    @memset(arena_bytes[0..arena.byte_length], 0xa7);
    _ = try runtime.preparedStateTransfer(arena, snapshot, &ranges, false, true);

    for (arena_bytes[0..32]) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    for (arena_bytes[32..48], 0..) |byte, index| try std.testing.expectEqual(@as(u8, @intCast(index + 1)), byte);
    for (arena_bytes[48..160]) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    for (arena_bytes[160..176], 0..) |byte, index| try std.testing.expectEqual(@as(u8, @intCast(index + 33)), byte);
    for (arena_bytes[176..256]) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
}

test "metal: arena range clear zeros exact disjoint spans" {
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer(256);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    for (words[0..64], 0..) |*word, index| word.* = @intCast(index + 1);

    try runtime.clearArenaRanges(arena, &.{ .{ 4, 3 }, .{ 16, 5 }, .{ 40, 1 } });

    for (words[0..64], 0..) |word, index| {
        const cleared = (index >= 4 and index < 7) or
            (index >= 16 and index < 21) or index == 40;
        try std.testing.expectEqual(if (cleared) @as(u32, 0) else @as(u32, @intCast(index + 1)), word);
    }
}

test "metal: component-local relation APIs fail closed on incomplete layouts" {
    var bindings: cairo_arena_binding.PreparedProofBindings = undefined;
    bindings.relation_claimed_sums = &.{};
    try std.testing.expectError(
        cairo_arena_binding.Error.InvalidClaimedSumCount,
        bindings.prepareRelationComponents(
            std.testing.allocator,
            undefined,
            undefined,
            &.{},
            undefined,
            undefined,
            undefined,
            undefined,
        ),
    );

    var native: cairo_arena_binding.NativeBaseInterpolationBatch = undefined;
    native.fixed = &.{};
    try std.testing.expectError(cairo_arena_binding.Error.MissingBinding, native.materializeFixed("range_check_6"));
}

test "metal: prepared arena gather seals one proof buffer" {
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer(16 * 1024);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    @memcpy(words[16..20], &[_]u32{ 11, 13, 17, 19 });
    @memcpy(words[32..35], &[_]u32{ 23, 29, 31 });
    const ranges = [_]metal.ArenaCopyRange{
        .{ .source_word_offset = 16, .destination_word_offset = 64, .word_count = 4 },
        .{ .source_word_offset = 32, .destination_word_offset = 68, .word_count = 3 },
    };
    var plan = try runtime.prepareArenaCopies(&ranges);
    defer plan.deinit();
    try std.testing.expect(try runtime.arenaCopyPrepared(arena, plan) > 0);
    try std.testing.expectEqualSlices(u32, &.{ 11, 13, 17, 19, 23, 29, 31 }, words[64..71]);
}

test "metal: proof assembly recipe executes prepared resident copies" {
    const allocator = std.testing.allocator;
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    var resident = arena_plan.ResidentArena{ .buffer = try runtime.allocateResidentBuffer(16 * 1024) };
    defer resident.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(resident.buffer.contents));
    const first = testResidentBinding(1, 16, 4);
    const second = testResidentBinding(2, 32, 3);
    const destination = testResidentBinding(3, 64, 7);
    @memcpy(words[16..20], &[_]u32{ 11, 13, 17, 19 });
    @memcpy(words[32..35], &[_]u32{ 23, 29, 31 });
    var recipe = try protocol_recipes.ProofAssemblyRecipe.init(
        allocator,
        &runtime,
        &resident,
        &.{
            .{ .source = first, .destination_word_offset = 0, .word_count = 4 },
            .{ .source = second, .destination_word_offset = 4, .word_count = 3 },
        },
        destination,
    );
    defer recipe.deinit();

    try recipe.execute();

    try std.testing.expect(recipe.accumulated_gpu_ms > 0);
    try std.testing.expectEqualSlices(u32, &.{ 11, 13, 17, 19, 23, 29, 31 }, try recipe.words());
}

test "metal: witness edge gather preserves producer and packed padding order" {
    var runtime = try metal.Runtime.initFull();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer(16 * 1024);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    const outputs = [_]u32{ 512, 576, 640 };
    const producer_rows: u32 = 16;
    for (0..4) |source_word| {
        for (0..producer_rows) |row|
            words[source_word * producer_rows + row] = @intCast(source_word * 100 + row);
    }
    _ = try runtime.witnessInputGather(
        arena,
        &.{0},
        &.{.{ producer_rows, 0, 2, 2, 0 }},
        2,
        32,
        64,
        &outputs,
        true,
        false,
    );
    for (0..64) |row| {
        const source_row = if (row < 32) row else row & 15;
        const instance = source_row / 16;
        const inner = source_row % 16;
        try std.testing.expectEqual(@as(u32, @intCast(instance * 200 + inner)), words[outputs[0] + row]);
        try std.testing.expectEqual(@as(u32, @intCast(instance * 200 + 100 + inner)), words[outputs[1] + row]);
        try std.testing.expectEqual(@as(u32, @intFromBool(row < 32)), words[outputs[2] + row]);
    }
}

test "metal: fused V1 evaluation program matches scalar field arithmetic" {
    const allocator = std.testing.allocator;
    var base = [_]eval_program.BaseInst{
        .{ .op = .trace_col, .interaction = 0, .dst = 0, .a = 0, .b = 0, .imm = 0 },
        .{ .op = .constant, .interaction = 0, .dst = 1, .a = 7, .b = 0, .imm = 0 },
        .{ .op = .mul, .interaction = 0, .dst = 2, .a = 0, .b = 1, .imm = 0 },
    };
    var ext = [_]eval_program.ExtInst{
        .{ .op = .secure_col, .dst = 0, .a = 2, .b = 1, .c = 0, .d = 1 },
        .{ .op = .param, .dst = 1, .a = 0, .b = 0, .c = 0, .d = 0 },
        .{ .op = .mul, .dst = 2, .a = 0, .b = 1, .c = 0, .d = 0 },
    };
    var roots = [_]u32{2};
    const program = eval_program.Program{
        .allocator = allocator,
        .header = .{ .flags = eval_program.Flag.prefinalized_logup, .semantic_hash = 0x1234, .capability_bits = eval_program.Capability.prefinalized_logup | eval_program.Capability.ext_mul, .n_interactions = 1, .n_base_params = 0, .n_ext_params = 1, .n_constraints = 1, .max_base_regs = 3, .max_ext_regs = 3, .domain_log_size = 7 },
        .base_consts = &.{},
        .ext_consts = &.{},
        .base_insts = &base,
        .ext_insts = &ext,
        .constraint_roots = &roots,
    };
    const source = try eval_codegen.generate(allocator, program);
    defer allocator.free(source);
    const name = try eval_codegen.kernelName(allocator, program.header.semantic_hash);
    defer allocator.free(name);

    const rows: u32 = 256;
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer(16 * 1024);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    var next: u32 = 0;
    const trace = next;
    for (0..rows) |row| words[next + row] = @intCast(row + 1);
    next += rows;
    const trace_offsets = next;
    words[next] = trace;
    next += 1;
    const interaction_offsets = next;
    words[next] = 0;
    next += 1;
    const ext_params = next;
    const ext_value = QM31.fromU32Unchecked(3, 5, 11, 13);
    for (ext_value.toM31Array(), 0..) |value, index| words[next + index] = value.v;
    next += 4;
    const random_coeffs = next;
    const random = QM31.fromU32Unchecked(17, 19, 23, 29);
    for (random.toM31Array(), 0..) |value, index| words[next + index] = value.v;
    next += 4;
    const denom = next;
    words[next] = 31;
    next += 1;
    var coordinates: [4]u32 = undefined;
    for (&coordinates) |*offset| {
        offset.* = next;
        @memset(words[next .. next + rows], 0);
        next += rows;
    }
    var plan = try runtime.prepareEval(source, name, .{
        .trace_offsets = trace_offsets,
        .interaction_offsets = interaction_offsets,
        .base_params = 0,
        .ext_params = ext_params,
        .random_coeffs = random_coeffs,
        .denom_inv = denom,
        .coordinates = coordinates,
        .row_count = rows,
        .trace_log_size = 8,
        .domain_log_size = 7,
        .rc_base = 0,
    });
    defer plan.deinit();
    const gpu_ms = try runtime.evalPrepared(arena, plan);
    try std.testing.expect(gpu_ms > 0);
    for (coordinates) |offset| @memset(words[offset .. offset + rows], 0);
    var batch = try runtime.prepareEvalBatch(&.{plan});
    defer batch.deinit();
    const batch_ms = try runtime.evalBatchPrepared(arena, batch);
    try std.testing.expect(batch_ms > 0);
    for (0..rows) |row| {
        const value = M31.fromCanonical(@intCast(row + 1));
        const seven = M31.fromCanonical(7);
        const root = QM31.fromM31(value.mul(seven), seven, value, seven);
        const expected = root.mul(ext_value).mul(random).mulM31(M31.fromCanonical(31)).toM31Array();
        for (expected, coordinates) |coordinate, offset| try std.testing.expectEqual(coordinate.v, words[offset + row]);
    }
}

test "metal: fused multi-part AIR preserves legacy accumulator order" {
    const allocator = std.testing.allocator;
    var first_base = [_]eval_program.BaseInst{
        .{ .op = .trace_col, .interaction = 0, .dst = 0, .a = 0, .b = 0, .imm = 0 },
        .{ .op = .constant, .interaction = 0, .dst = 1, .a = 7, .b = 0, .imm = 0 },
        .{ .op = .mul, .interaction = 0, .dst = 2, .a = 0, .b = 1, .imm = 0 },
    };
    var second_base = [_]eval_program.BaseInst{
        .{ .op = .trace_col, .interaction = 0, .dst = 0, .a = 0, .b = 0, .imm = 0 },
        .{ .op = .constant, .interaction = 0, .dst = 1, .a = 11, .b = 0, .imm = 0 },
        .{ .op = .add, .interaction = 0, .dst = 2, .a = 0, .b = 1, .imm = 0 },
    };
    var ext = [_]eval_program.ExtInst{
        .{ .op = .secure_col, .dst = 0, .a = 2, .b = 1, .c = 0, .d = 1 },
    };
    var roots = [_]u32{0};
    const first = eval_program.Program{
        .allocator = allocator,
        .header = .{ .flags = eval_program.Flag.prefinalized_logup, .semantic_hash = 0x11112222, .capability_bits = eval_program.Capability.prefinalized_logup, .n_interactions = 1, .n_base_params = 0, .n_ext_params = 0, .n_constraints = 1, .max_base_regs = 3, .max_ext_regs = 1, .domain_log_size = 7 },
        .base_consts = &.{},
        .ext_consts = &.{},
        .base_insts = &first_base,
        .ext_insts = &ext,
        .constraint_roots = &roots,
    };
    var second = first;
    second.header.semantic_hash = 0x33334444;
    second.base_insts = &second_base;
    const fused_parts = [_]eval_codegen.FusedPart{
        .{ .program = first, .rc_base = 0 },
        .{ .program = second, .rc_base = 1 },
    };
    const first_source = try eval_codegen.generate(allocator, first);
    defer allocator.free(first_source);
    const second_source = try eval_codegen.generate(allocator, second);
    defer allocator.free(second_source);
    const fused_source = try eval_codegen.generateFusedKernel(allocator, &fused_parts, true);
    defer allocator.free(fused_source);
    const first_name = try eval_codegen.kernelName(allocator, first.header.semantic_hash);
    defer allocator.free(first_name);
    const second_name = try eval_codegen.kernelName(allocator, second.header.semantic_hash);
    defer allocator.free(second_name);
    const fused_name = try eval_codegen.fusedKernelName(allocator, &fused_parts);
    defer allocator.free(fused_name);

    const rows: u32 = 256;
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer(32 * 1024);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    var next: u32 = 0;
    const trace = next;
    for (0..rows) |row| words[next + row] = @intCast(row + 1);
    next += rows;
    const trace_offsets = next;
    words[next] = trace;
    next += 1;
    const interaction_offsets = next;
    words[next] = 0;
    next += 1;
    const random_coeffs = next;
    words[next..][0..8].* = .{ 2, 3, 5, 7, 11, 13, 17, 19 };
    next += 8;
    const denom = next;
    words[next..][0..2].* = .{ 23, 29 };
    next += 2;
    var legacy_coordinates: [4]u32 = undefined;
    var fused_coordinates: [4]u32 = undefined;
    for (&legacy_coordinates, &fused_coordinates, 0..) |*legacy, *fused, coordinate| {
        legacy.* = next;
        next += rows;
        fused.* = next;
        next += rows;
        for (0..rows) |row| {
            const initial: u32 = @intCast(coordinate * 1000 + row + 29);
            words[legacy.* + row] = initial;
            words[fused.* + row] = initial;
        }
    }
    const layout = struct {
        fn make(
            trace_offsets_: u32,
            interaction_offsets_: u32,
            random_coeffs_: u32,
            denom_: u32,
            coordinates_: [4]u32,
            rc_base_: u32,
        ) metal.EvalLayout {
            return .{
                .trace_offsets = trace_offsets_,
                .interaction_offsets = interaction_offsets_,
                .base_params = 0,
                .ext_params = 0,
                .random_coeffs = random_coeffs_,
                .denom_inv = denom_,
                .coordinates = coordinates_,
                .row_count = rows,
                .trace_log_size = 7,
                .domain_log_size = 7,
                .rc_base = rc_base_,
            };
        }
    }.make;
    var first_plan = try runtime.prepareEval(
        first_source,
        first_name,
        layout(trace_offsets, interaction_offsets, random_coeffs, denom, legacy_coordinates, 0),
    );
    defer first_plan.deinit();
    var second_plan = try runtime.prepareEval(
        second_source,
        second_name,
        layout(trace_offsets, interaction_offsets, random_coeffs, denom, legacy_coordinates, 1),
    );
    defer second_plan.deinit();
    var fused_plan = try runtime.prepareEval(
        fused_source,
        fused_name,
        layout(trace_offsets, interaction_offsets, random_coeffs, denom, fused_coordinates, 0),
    );
    defer fused_plan.deinit();
    _ = try runtime.evalPrepared(arena, first_plan);
    _ = try runtime.evalPrepared(arena, second_plan);
    _ = try runtime.evalPrepared(arena, fused_plan);
    for (legacy_coordinates, fused_coordinates) |legacy, fused|
        try std.testing.expectEqualSlices(u32, words[legacy .. legacy + rows], words[fused .. fused + rows]);
}

test "metal: composition graph interleaves LDE and AIR before finalizing coefficients" {
    const allocator = std.testing.allocator;
    const base_log: u32 = 8;
    const eval_log: u32 = 10;
    const base_rows = @as(usize, 1) << base_log;
    const eval_rows = @as(usize, 1) << eval_log;
    const base_domain = canonic.CanonicCoset.new(base_log).circleDomain();
    const eval_domain = canonic.CanonicCoset.new(eval_log).circleDomain();
    var base_tree = try twiddles.precomputeM31(allocator, base_domain.half_coset);
    defer twiddles.deinitM31(allocator, &base_tree);
    var eval_tree = try twiddles.precomputeM31(allocator, eval_domain.half_coset);
    defer twiddles.deinitM31(allocator, &eval_tree);
    const base_const_tree = twiddles.TwiddleTree([]const M31).init(base_tree.root_coset, base_tree.twiddles, base_tree.itwiddles);
    const eval_const_tree = twiddles.TwiddleTree([]const M31).init(eval_tree.root_coset, eval_tree.twiddles, eval_tree.itwiddles);
    const coefficients = try allocator.alloc(M31, base_rows);
    defer allocator.free(coefficients);
    for (coefficients, 0..) |*value, row| value.* = M31.fromCanonical(@intCast((row * 65537 + 19) % m31.Modulus));
    var expected = try allocator.dupe(M31, coefficients);
    defer allocator.free(expected);
    var base_columns = [_][]M31{expected};
    try circle_poly.interpolateBuffersWithTwiddles(&base_columns, base_domain, base_const_tree);
    const source_coefficients = try allocator.dupe(M31, expected);
    defer allocator.free(source_coefficients);
    expected = try allocator.realloc(expected, eval_rows);
    @memset(expected[base_rows..], M31.zero());
    var eval_columns = [_][]M31{expected};
    try circle_poly.evaluateBuffersWithTwiddles(&eval_columns, eval_domain, eval_const_tree);

    var base_insts = [_]eval_program.BaseInst{
        .{ .op = .trace_col, .interaction = 0, .dst = 0, .a = 0, .b = 0, .imm = 0 },
        .{ .op = .constant, .interaction = 0, .dst = 1, .a = 0, .b = 0, .imm = 0 },
    };
    var ext_insts = [_]eval_program.ExtInst{
        .{ .op = .secure_col, .dst = 0, .a = 0, .b = 1, .c = 1, .d = 1 },
    };
    var roots = [_]u32{0};
    const program = eval_program.Program{
        .allocator = allocator,
        .header = .{ .flags = eval_program.Flag.prefinalized_logup, .semantic_hash = 0x5678, .capability_bits = eval_program.Capability.prefinalized_logup, .n_interactions = 1, .n_base_params = 0, .n_ext_params = 0, .n_constraints = 1, .max_base_regs = 2, .max_ext_regs = 1, .domain_log_size = base_log },
        .base_consts = &.{},
        .ext_consts = &.{},
        .base_insts = &base_insts,
        .ext_insts = &ext_insts,
        .constraint_roots = &roots,
    };
    const source = try eval_codegen.generate(allocator, program);
    defer allocator.free(source);
    const name = try eval_codegen.kernelName(allocator, program.header.semantic_hash);
    defer allocator.free(name);
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer(128 * 1024);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    const coefficient_offset: u32 = 0;
    const tile_offset: u32 = 1024;
    const twiddle_offset: u32 = 4096;
    const trace_offsets: u32 = 8192;
    const interaction_offsets: u32 = 8193;
    const random_offset: u32 = 8194;
    const denom_offset: u32 = 8198;
    const accumulator_offset: u32 = 8202;
    const previous_accumulator_offset: u32 = 6000;
    const inverse_twiddle_offset: u32 = 25_100;
    const output_start: u32 = 26_000;
    var output_offsets: [8]u32 = undefined;
    for (&output_offsets, 0..) |*offset, index| offset.* = output_start + @as(u32, @intCast(index * eval_rows / 2));
    @memcpy(words[coefficient_offset .. coefficient_offset + base_rows], std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(source_coefficients)));
    @memcpy(words[twiddle_offset .. twiddle_offset + eval_tree.twiddles.len], std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(eval_tree.twiddles)));
    @memcpy(words[inverse_twiddle_offset .. inverse_twiddle_offset + eval_tree.itwiddles.len], std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(eval_tree.itwiddles)));
    @memset(words[previous_accumulator_offset .. previous_accumulator_offset + 4 * (@as(usize, 1) << 8)], 0);
    words[trace_offsets] = tile_offset;
    words[interaction_offsets] = 0;
    words[random_offset..][0..4].* = .{ 1, 0, 0, 0 };
    words[denom_offset..][0..4].* = .{ 1, 1, 1, 1 };
    var eval_plan = try runtime.prepareEval(source, name, .{
        .trace_offsets = trace_offsets,
        .interaction_offsets = interaction_offsets,
        .base_params = 0,
        .ext_params = 0,
        .random_coeffs = random_offset,
        .denom_inv = denom_offset,
        .coordinates = .{ accumulator_offset, accumulator_offset + eval_rows, accumulator_offset + 2 * eval_rows, accumulator_offset + 3 * eval_rows },
        .row_count = eval_rows,
        .trace_log_size = base_log,
        .domain_log_size = base_log,
        .rc_base = 0,
    });
    defer eval_plan.deinit();
    var eval_batch = try runtime.prepareEvalBatch(&.{eval_plan});
    defer eval_batch.deinit();
    var lde = try runtime.prepareCompositionLde(&.{coefficient_offset}, &.{base_log}, &.{tile_offset}, eval_log, twiddle_offset);
    defer lde.deinit();
    const dynamic_source: u32 = 25_020;
    words[dynamic_source..][0..4].* = .{ 7, 11, 13, 17 };
    const ext_descriptors = [_]metal.CompositionExtParamDescriptor{
        .{ .destination = 25_000, .kind = 0, .source = 0, .scale = 2, .constant = .{ 3, 5, 19, 23 } },
        .{ .destination = 25_004, .kind = 1, .source = dynamic_source, .scale = 3, .constant = .{ 0, 0, 0, 0 } },
    };
    var inputs = try runtime.prepareCompositionInputs(&ext_descriptors, random_offset, random_offset, 1);
    defer inputs.deinit();
    var front = try runtime.prepareCompositionFront(inputs, &.{lde}, &.{eval_batch}, accumulator_offset, 4 * eval_rows);
    defer front.deinit();
    const scale = try M31.fromCanonical(@intCast(eval_rows)).inv();
    var finalize = try runtime.prepareCompositionFinalize(
        &.{ previous_accumulator_offset, accumulator_offset },
        &.{ 8, eval_log },
        inverse_twiddle_offset,
        output_offsets,
        scale.v,
    );
    defer finalize.deinit();
    var expected_coefficients = try allocator.dupe(M31, expected);
    defer allocator.free(expected_coefficients);
    var expected_columns = [_][]M31{expected_coefficients};
    try circle_poly.interpolateBuffersWithTwiddles(&expected_columns, eval_domain, eval_const_tree);
    const gpu_ms = try runtime.compositionPrepared(arena, front, finalize);
    try std.testing.expect(gpu_ms > 0);
    try std.testing.expectEqualSlices(u32, &.{ 6, 10, 38, 46, 21, 33, 39, 51 }, words[25_000..25_008]);
    for (0..8) |output| {
        const actual_words = words[output_offsets[output] .. output_offsets[output] + eval_rows / 2];
        if ((output & 3) == 0) {
            const half = output >> 2;
            try std.testing.expectEqualSlices(
                u32,
                std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(expected_coefficients[half * eval_rows / 2 ..][0 .. eval_rows / 2])),
                actual_words,
            );
        } else for (actual_words) |value| try std.testing.expectEqual(@as(u32, 0), value);
    }
}
