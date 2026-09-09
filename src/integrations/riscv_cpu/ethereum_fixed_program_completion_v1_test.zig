const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const admission = @import("ethereum_fixed_program_admission_v1.zig");
const subject = admission.completion;
const fixture = @import("recursive_common_ethereum_incremental_leaf_universal_proof_v4_genuine_fixture.zig");
const arithmetic = frontend.recursion.arithmetic_circuit;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
fn sha(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}

test "Ethereum completion opening authenticates every admitted raw and decoded leaf" {
    const allocator = std.testing.allocator;
    const elf = fixture.programElf();
    const owner = try admission.OwnedV1.createWithCompletionFromElf(allocator, &elf, sha(&elf));
    defer owner.deinit();
    const depth = try owner.completionDepth();
    const input_count = 7 + @as(usize, depth) * 9;
    var builder = arithmetic.Builder.initDefault(allocator);
    defer builder.deinit();
    const inputs = try allocator.alloc(arithmetic.Value, input_count);
    defer allocator.free(inputs);
    for (inputs, 0..) |*value, i| value.* = try builder.input(@intCast(i));
    try subject.constrain(&builder, try owner.completionRoot(), depth, @intCast((try owner.completionRows()).len), inputs[0..7].*, inputs[7..]);
    var circuit = try builder.finish();
    defer circuit.deinit();
    const values = try allocator.alloc(QM31, input_count);
    defer allocator.free(values);
    const sums = @import("recursive_common_ethereum_incremental_leaf_public_sums_v4.zig");
    const routes = @import("recursive_common_ethereum_incremental_leaf_role_input_routing_v4.zig");
    const bindings = try allocator.alloc(sums.InputSourceV4, input_count);
    defer allocator.free(bindings);
    for (bindings, 0..) |*binding, index| binding.* = if (index < 7) .{ .statement_word = @intCast(index) } else .{ .completion_opening_word = @intCast(index - 7) };
    for (try owner.completionRows()) |row| {
        const opening = try owner.completionOpening(row.pc);
        for (values[0..7], row.words()) |*value, word| value.* = QM31.fromBase(M31.fromCanonical(word));
        for (values[7..], 0..) |*value, i| value.* = QM31.fromBase(M31.fromCanonical(try opening.word(i)));
        var correct = try circuit.evaluate(allocator, values);
        defer correct.deinit();
        try std.testing.expect(try circuit.outputsAreZero(correct.values));
        const view = .{ .bindings = bindings, .values = values, .use_counts = circuit.useCounts()[0..input_count] };
        var routed = try routes.Prepared.init(allocator, view);
        defer routed.deinit();
        try routed.validate(view);
        try std.testing.expectEqual(@as(usize, depth) * 9, routed.rows.len);
        if (depth != 0) {
            const original = values[7];
            values[7] = QM31.fromM31Array(.{ M31.zero(), M31.one(), M31.zero(), M31.zero() });
            try std.testing.expectError(error.InvalidEthereumRoleInputRouting, routes.Prepared.init(allocator, view));
            values[7] = original;
        }
        // Every raw/decoded lane, direction, and sibling limb is constrained.
        for (values) |*value| {
            const original = value.*;
            value.* = original.add(QM31.one());
            var changed = try circuit.evaluate(allocator, values);
            defer changed.deinit();
            try std.testing.expect(!try circuit.outputsAreZero(changed.values));
            value.* = original;
        }
    }
    try std.testing.expectError(error.CompletionPcNotInAdmittedProgram, owner.completionOpening(1));
    try std.testing.expectError(error.InvalidCompletionOpening, subject.constrain(&builder, try owner.completionRoot(), depth, @intCast((try owner.completionRows()).len), inputs[0..7].*, inputs[7 .. inputs.len - 1]));
}

test "Ethereum completion opening preserves independent whole ELF and explicit opt in" {
    const allocator = std.testing.allocator;
    const elf = fixture.programElf();
    const ordinary = try admission.OwnedV1.createFromElf(allocator, &elf, sha(&elf));
    defer ordinary.deinit();
    try std.testing.expectError(error.EthereumCompletionOpeningNotAdmitted, ordinary.completionRoot());
    const selected = try admission.OwnedV1.createWithCompletionFromElf(allocator, &elf, sha(&elf));
    defer selected.deinit();
    try std.testing.expectEqualDeep(ordinary.descriptor(), selected.descriptor());
    const extended = try allocator.alloc(u8, elf.len + 1);
    defer allocator.free(extended);
    @memcpy(extended[0..elf.len], &elf);
    extended[elf.len] = 0x5a;
    try std.testing.expectError(error.EthereumFixedProgramSourceMismatch, admission.OwnedV1.createWithCompletionFromElf(allocator, extended, sha(&elf)));
    const other = try admission.OwnedV1.createWithCompletionFromElf(allocator, extended, sha(extended));
    defer other.deinit();
    try std.testing.expectEqual(try selected.completionRoot(), try other.completionRoot());
    try std.testing.expectError(error.EthereumFixedProgramAdmissionMismatch, selected.validateDescriptor(other.descriptor()));
    const Program = @import("recursive_common_ethereum_incremental_leaf_program_admission_v1.zig").ProgramAdmissionV1;
    const selected_program = try Program.createWithFixedProgram(allocator, selected);
    defer selected_program.deinit();
    const other_program = try Program.createWithFixedProgram(allocator, other);
    defer other_program.deinit();
    try std.testing.expectEqual(@as(u16, 1), selected_program.openingVersion());
    try std.testing.expect(!std.meta.eql(selected_program.identitySha256(), other_program.identitySha256()));
    try selected_program.validateFixedProgramOwner(selected);
    try std.testing.expectError(error.EthereumCompletionProgramOwnerMismatch, selected_program.validateFixedProgramOwner(other));
    try std.testing.expectError(error.EthereumCompletionOpeningNotAdmitted, Program.createWithFixedProgram(allocator, ordinary));
    // A real ELF has declared LLVM padding committed by native ROM, while
    // such words are forbidden as completion fetches. Exercise that distinction
    // through the actual independently pinned ELF owner, not a synthetic tree.
    var padded_elf = elf;
    std.mem.writeInt(u32, padded_elf[640..][0..4], frontend.air.program.decode.llvm_unimp_padding_word, .little);
    const padded_native = try admission.OwnedV1.createFromElf(allocator, &padded_elf, sha(&padded_elf));
    defer padded_native.deinit();
    const padded = try admission.OwnedV1.createWithCompletionFromElf(allocator, &padded_elf, sha(&padded_elf));
    defer padded.deinit();
    try std.testing.expectEqualDeep(padded_native.descriptor(), padded.descriptor());
    try std.testing.expectEqual((try padded.rows()).len - 1, (try padded.completionRows()).len);
    try std.testing.expectError(error.CompletionPcNotInAdmittedProgram, padded.completionOpening((try selected.completionRows())[0].pc));
    for (try padded.completionRows()) |row| _ = try padded.completionOpening(row.pc);
}

test "Ethereum completion opening rejects padded indices independently of hash equality" {
    const allocator = std.testing.allocator;
    var rows: [3]frontend.runner.memory_state.WordState = undefined;
    for (&rows, 0..) |*row, index| row.* = .{ .addr = 4096 + @as(u32, @intCast(index)) * 4, .initial_word = 0x00100093, .final_word = 0x00100093, .final_clock = 0 };
    var tree = try subject.Tree.init(allocator, &rows);
    defer tree.deinit();
    try std.testing.expectEqual(@as(u5, 2), tree.depth);
    // Deliberately construct a root that would authenticate row0 at padding
    // index3. Even this internally consistent hash path must fail the admitted
    // executable count constraint. The real owner never builds such a tree.
    const row = tree.rows[0];
    tree.nodes[7] = subject.leafHash(row);
    tree.nodes[3] = frontend.recursion.poseidon2_channel.MerkleHasher.hashChildren(.{ .left = tree.nodes[6], .right = tree.nodes[7] });
    tree.nodes[1] = frontend.recursion.poseidon2_channel.MerkleHasher.hashChildren(.{ .left = tree.nodes[2], .right = tree.nodes[3] });
    var builder = arithmetic.Builder.initDefault(allocator);
    defer builder.deinit();
    var inputs: [25]arithmetic.Value = undefined;
    for (&inputs, 0..) |*value, index| value.* = try builder.input(@intCast(index));
    try subject.constrain(&builder, tree.root(), 2, 3, inputs[0..7].*, inputs[7..]);
    var circuit = try builder.finish();
    defer circuit.deinit();
    var values: [25]QM31 = undefined;
    for (values[0..7], row.words()) |*value, word| value.* = QM31.fromBase(M31.fromCanonical(word));
    values[7] = QM31.one();
    values[16] = QM31.one();
    for (values[8..16], tree.nodes[6]) |*value, word| value.* = QM31.fromBase(M31.fromCanonical(word));
    for (values[17..25], tree.nodes[2]) |*value, word| value.* = QM31.fromBase(M31.fromCanonical(word));
    var evaluation = try circuit.evaluate(allocator, &values);
    defer evaluation.deinit();
    try std.testing.expect(!try circuit.outputsAreZero(evaluation.values));
    // The first output is exact integer coverage; all hash roots still agree.
    try std.testing.expect(!evaluation.values[circuit.outputs()[0]].isZero());
    for (circuit.outputs()[1..]) |node| try std.testing.expect(evaluation.values[node].isZero());
}
