//! Compact policy regressions. Genuine completion/input fixtures are used for
//! local relations; the large-shape test builds the actual fixed graph only.
//! Neither test substitutes for the pending real segment0 wrapper proof.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const compact = @import("recursive_common_ethereum_initial_public_sums_v1.zig");
const support = compact.support;
const genuine = @import("recursive_common_ethereum_initial_input_lane_v1_test.zig");
const fixed = @import("ethereum_fixed_program_admission_v1.zig");
const admission_mod = support.program_admission;
const arithmetic = frontend.recursion.arithmetic_circuit;
const Value = arithmetic.Value;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const a = std.testing.allocator;
comptime {
    _ = @import("recursive_common_ethereum_initial_input_packet_v1_test.zig");
    _ = @import("recursive_common_ethereum_incremental_leaf_field_frame_plan_v4.zig");
    _ = @import("recursive_common_ethereum_initial_input_rows_v1_test.zig");
}
const layout = support.span.canonical_layout;
fn programOwner() !*fixed.OwnedV1 {
    const elf = genuine.programElf();
    var sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&elf, &sha, .{});
    return fixed.OwnedV1.createWithCompletionFromElf(a, &elf, sha);
}
fn q(value: u32) QM31 {
    return QM31.fromBase(M31.fromCanonical(value));
}
fn passes(circuit: *const arithmetic.Circuit, inputs: []const QM31) !bool {
    var evaluation = try circuit.evaluate(a, inputs);
    defer evaluation.deinit();
    return circuit.outputsAreZero(evaluation.values);
}
test "Ethereum compact initial policy builds exact large claim shape with bounded packet graph" {
    const owner = try programOwner();
    defer owner.deinit();
    const admission = try admission_mod.ProgramAdmissionV1.createWithFixedProgram(a, owner);
    defer admission.deinit();
    const shape = try frontend.recursion.vm_public_claim.Shape.init(675173, 12);
    var large = try compact.build(a, shape, admission);
    defer large.deinit(a);
    var small = try compact.build(a, try frontend.recursion.vm_public_claim.Shape.init(40, 12), admission);
    defer small.deinit(a);
    try std.testing.expectEqual(small.bindings.len, large.bindings.len);
    try std.testing.expectEqual(try compact.inputCount(admission.openingInputWordCount()), large.bindings.len);
    try std.testing.expect(large.circuit.nodes().len < 100000);
    var packets: usize = 0;
    var bits: usize = 0;
    var roots: usize = 0;
    var roles: usize = 0;
    var globals: usize = 0;
    var clocks: usize = 0;
    var openings: usize = 0;
    var claim_headers: usize = 0;
    const claims = frontend.recursion.vm_public_claim.canonical_layout;
    const expected = [_]usize{ claims.input_start_start, claims.input_start_start + 1, claims.input_word_count_start, claims.input_word_count_start + 1, claims.outputWordCountStart(shape), claims.outputWordCountStart(shape) + 1 };
    for (large.bindings, 0..) |source, input| switch (source) {
        .packet_limb => |index| {
            try std.testing.expectEqual(packets, index);
            try std.testing.expectEqual(@as(usize, large.packet_first_input) + index, input);
            packets += 1;
        },
        .existing => |legacy| switch (legacy) {
            .role_io_word => |index| {
                try std.testing.expectEqual(roles, index);
                roles += 1;
            },
            .tuple_selector => return error.QuadraticRoleSelectorRemains,
            .native_continuation_root => roots += 1,
            .global_statement_word => globals += 1,
            .clock_aux => clocks += 1,
            .completion_opening_word => openings += 1,
            .role_source => |part| switch (part) {
                .claim_word => |index| {
                    try std.testing.expectEqual(expected[claim_headers], index);
                    claim_headers += 1;
                },
                .limb_bit => |coordinate| {
                    try std.testing.expectEqual(@as(u32, 675173), coordinate.slot);
                    bits += 1;
                },
                .input_carry, .claim_byte, .terminal_reserved => return error.UnexpectedInitialRoleSource,
                else => {},
            },
            else => {},
        },
    };
    try std.testing.expectEqual(@as(usize, 52), packets);
    try std.testing.expectEqual(@as(usize, 128), bits);
    try std.testing.expectEqual(@as(usize, 2), roots);
    try std.testing.expectEqual(@as(usize, 6), roles);
    try std.testing.expectEqual(@as(usize, 6), claim_headers);
    try std.testing.expectEqual(@as(usize, 412), globals);
    try std.testing.expectEqual(support.CLOCK_AUX_INPUT_COUNT, clocks);
    try std.testing.expectEqual(admission.openingInputWordCount(), openings);
    const tail = large.bindings[large.bindings.len - 204 ..];
    for (tail[0..32]) |source| try std.testing.expect(source.existing == .relation_challenge_word);
    for (tail[32..]) |source| try std.testing.expect(source.existing == .canonical_claim_word);
    _ = try frontend.recursion.air.ethereum_initial_input_packet_v1.preprocessing(try frontend.recursion.air.ethereum_initial_input_lane_v1.Shape.init(675173), &large.circuit, 42, large.packet_first_input);
    try std.testing.expectError(error.InvalidEthereumInitialInputAdmission, compact.build(a, try frontend.recursion.vm_public_claim.Shape.init(675173, 11), admission));
    try std.testing.expectError(error.InvalidEthereumInitialInputAdmission, compact.build(a, try frontend.recursion.vm_public_claim.Shape.init(0, 12), admission));
    std.debug.print("INITIAL_COMPACT_GRAPH input_words=675173 output_capacity=12 inputs={d} nodes={d} roots={d} opening_inputs={d} packet_inputs=52 quadratic_input_terms=0\n", .{ large.bindings.len, large.circuit.nodes().len, large.circuit.outputs().len, openings });
}
test "Ethereum compact initial policy rejects count output and noninitial position mutations" {
    var builder = arithmetic.Builder.initDefault(a);
    defer builder.deinit();
    var statement = [_]Value{Value.zero()} ** 412;
    statement[layout.first_segment_start] = try builder.input(0);
    statement[layout.first_segment_start + 1] = try builder.input(1);
    var header: [6]Value = undefined;
    for (&header, 0..) |*v, i| v.* = try builder.input(@intCast(2 + i));
    const shape = try frontend.recursion.vm_public_claim.Shape.init(675173, 12);
    try compact.constrainInitialHeader(&builder, shape, &statement, header);
    var circuit = try builder.finish();
    defer circuit.deinit();
    var inputs = [_]QM31{ QM31.zero(), QM31.zero(), q(1234), q(2), q(675173 & 65535), q(675173 >> 16), QM31.zero(), QM31.zero() };
    try std.testing.expect(try passes(&circuit, &inputs));
    for ([_]usize{ 0, 1, 4, 5, 6, 7 }) |index| {
        const original = inputs[index];
        inputs[index] = original.add(QM31.one());
        try std.testing.expect(!try passes(&circuit, &inputs));
        inputs[index] = original;
    }
}
test "Ethereum compact initial policy binds genuine completion opening and canonical packet limbs" {
    const fixture = try genuine.Fixture.init();
    const owner = try programOwner();
    defer owner.deinit();
    const admission = try admission_mod.ProgramAdmissionV1.createWithFixedProgram(a, owner);
    defer admission.deinit();
    const opening_count = admission.openingInputWordCount();
    const count = 12 + compact.DECODED_BIT_COUNT + opening_count + 18;
    const inputs = try a.alloc(QM31, count);
    defer a.free(inputs);
    @memset(inputs, QM31.zero());
    var builder = arithmetic.Builder.initDefault(a);
    defer builder.deinit();
    const values = try a.alloc(Value, count);
    defer a.free(values);
    for (values, 0..) |*v, i| v.* = try builder.input(@intCast(i));
    const native = try fixture.program_tuple.values();
    var statement = [_]Value{Value.zero()} ** 412;
    statement[layout.job_segment_count_start] = Value.fromBase(M31.fromCanonical(2));
    statement[layout.executed_segment_count_start] = Value.one();
    statement[layout.program_start] = Value.fromBase(M31.fromCanonical(admission.programRoot()));
    const exit = layout.exit_state_start + layout.machine_state_pc_start_offset;
    statement[exit] = Value.fromBase(M31.fromCanonical(native[0] & 65535));
    statement[exit + 1] = Value.fromBase(M31.fromCanonical(native[0] >> 16));
    const elf = genuine.programElf();
    const raw = std.mem.readInt(u32, elf[648..652], .little);
    inputs[0] = q(native[0] & 65535);
    inputs[1] = q(native[0] >> 16);
    inputs[2] = q(raw & 65535);
    inputs[3] = q(raw >> 16);
    for (0..4) |field| {
        inputs[4 + field] = q(native[1 + field]);
        for (0..32) |bit| inputs[12 + field * 32 + bit] = q((native[1 + field] >> @as(u5, @intCast(bit))) & 1);
    }
    inputs[8] = q(3);
    inputs[11] = QM31.one();
    for (0..opening_count) |i| inputs[140 + i] = q(try admission.openingWord(native[0], i));
    const result = try compact.constrainCompletion(&builder, admission, &statement, values[0..12], values[12..140], values[140..][0..opening_count]);
    for (result, 0..) |word, i| {
        _ = try builder.markOutput(try builder.sub(word, values[140 + opening_count + i]));
        inputs[140 + opening_count + i] = q(fixture.program_words[i]);
    }
    var circuit = try builder.finish();
    defer circuit.deinit();
    try std.testing.expect(try passes(&circuit, inputs));
    // Every completion/raw/decoded/policy limb and every canonical packet
    // word is tied to the genuine next instruction and the admitted ELF.
    for (0..12) |i| try mutateReject(&circuit, inputs, i);
    for (0..18) |i| try mutateReject(&circuit, inputs, 140 + opening_count + i);
    for ([_]usize{ 12, 43, 44, 75, 76, 107, 108, 139, 140 }) |i| try mutateReject(&circuit, inputs, i);
}
fn mutateReject(circuit: *const arithmetic.Circuit, inputs: []QM31, index: usize) !void {
    const original = inputs[index];
    inputs[index] = original.add(QM31.one());
    defer inputs[index] = original;
    const accepted = passes(circuit, inputs) catch |err| switch (err) {
        error.DivisionByZero => return,
        else => return err,
    };
    try std.testing.expect(!accepted);
}
