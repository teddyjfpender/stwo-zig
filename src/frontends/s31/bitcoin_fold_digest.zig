//! Public digest for the fixed-key Bitcoin hash-chain fold. It binds the AIR
//! root, step, checkpoint, current block-hash root and last eleven timestamps.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Var = circuit.builder.Var;
const Blake = circuit.builder.blake;
const U32 = circuit.builder.wrappers.U32Wrapper(Var);

pub const personalization: [8]u8 = "S31BFD2!".*;
pub const genesis_time: u32 = 1231006505;
pub const missing_time: u32 = 0xffffffff;

/// Newest first. Missing ancestors occupy the tail until eleven blocks are
/// available; their value is never included in the selected median.
pub fn initialTimes() [11]u32 {
    return [1]u32{genesis_time} ++ [_]u32{missing_time} ** 10;
}

pub fn advanceTimes(prior: [11]u32, current: u32) [11]u32 {
    var next: [11]u32 = undefined;
    next[0] = current;
    @memcpy(next[1..], prior[0..10]);
    return next;
}

/// Every M31 root word is encoded as an unsigned little-endian u32. Reject
/// noncanonical claims before the native verifier computes an expected top
/// statement; reduction modulo p would change the authenticated message.
pub fn statementDigest(root: [32]u8, step: u32, checkpoint: [8]u32, current: [8]u32, times: [11]u32) ![8]u32 {
    for (checkpoint) |word| if (word >= core.fields.m31.Modulus) return error.NonCanonicalCheckpoint;
    for (current) |word| if (word >= core.fields.m31.Modulus) return error.NonCanonicalState;
    var preimage: [144]u8 = undefined;
    @memcpy(preimage[0..32], &root);
    std.mem.writeInt(u32, preimage[32..36], step, .little);
    for (checkpoint, 0..) |word, i| std.mem.writeInt(u32, preimage[36 + 4 * i ..][0..4], word, .little);
    for (current, 0..) |word, i| std.mem.writeInt(u32, preimage[68 + 4 * i ..][0..4], word, .little);
    for (times, 0..) |word, i| std.mem.writeInt(u32, preimage[100 + 4 * i ..][0..4], word, .little);
    var digest: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(&preimage, &digest, .{ .context = personalization });
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    return words;
}

/// `current` must be a constrained M31 root, normally returned by the direct
/// header-step kernel. `checkpoint` is a key-pinned constant, not a witness.
pub fn digestWires(
    comptime V: type,
    ctx: *circuit.builder.Context(V),
    self_root: Blake.HashValue(Var),
    step: U32,
    checkpoint: [8]u32,
    current: [8]Var,
    times: [11]U32,
) !Blake.HashValue(Var) {
    var message: [36]U32 = undefined;
    @memcpy(message[0..8], &self_root.words);
    message[8] = step;
    for (checkpoint, 0..) |word, i| {
        if (word >= core.fields.m31.Modulus) return error.NonCanonicalCheckpoint;
        const fixed = try ctx.constant(QM31.fromBase(M31.fromCanonical(word)));
        message[9 + i] = try Blake.m31ToU32(V, ctx, fixed);
    }
    for (current, 0..) |wire, i| message[17 + i] = try Blake.m31ToU32(V, ctx, wire);
    @memcpy(message[25..], &times);
    return Blake.blake2sU32sPersonalized(V, ctx, &message, 144, personalization);
}

test "Bitcoin fold digest binds full counter, checkpoint, state and root" {
    const root = [_]u8{0x42} ** 32;
    const checkpoint = [8]u32{ 93892305, 397617766, 1762064199, 2128125525, 211345822, 958247097, 595994426, 1074837273 };
    const current = [8]u32{ 1230097977, 338045265, 582454319, 1194138423, 159136005, 2049036807, 17165835, 883545160 };
    const times = advanceTimes(initialTimes(), 1231469665);
    const prior = try statementDigest(root, 0, checkpoint, current, times);
    for ([_]u32{ 0, 1, 65535, 65536, 0x80000000, 0xffffffff }) |step_value| {
        const expected = try statementDigest(root, step_value, checkpoint, current, times);
        if (step_value != 0) try std.testing.expect(!std.meta.eql(prior, expected));
        var ctx = try circuit.builder.Context(QM31).init(std.testing.allocator, 8);
        defer ctx.deinit();
        const self_root = try Blake.guessHash(QM31, &ctx, Blake.hashValueFromDigest(QM31, root));
        const step = try circuit.builder.wrappers.guessU32(QM31, &ctx, circuit.builder.wrappers.u32Value(QM31, step_value));
        var current_wires: [8]Var = undefined;
        for (current, &current_wires) |word, *wire|
            wire.* = try ctx.guessM31(QM31.fromBase(M31.fromCanonical(word)));
        var time_wires: [11]U32 = undefined;
        for (times, &time_wires) |time, *wire| wire.* = try circuit.builder.wrappers.guessU32(QM31, &ctx, circuit.builder.wrappers.u32Value(QM31, time));
        const digest = try digestWires(QM31, &ctx, self_root, step, checkpoint, current_wires, time_wires);
        var output: [8]Var = undefined;
        for (digest.words, &output) |word, *wire| wire.* = word.get();
        try ctx.setOutputs(&output);
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
        for (output, expected) |wire, want|
            try std.testing.expectEqual(want, circuit.builder.ivalue.unpackU32(QM31, ctx.value_table.items[wire.idx]));
        if (step_value == 65536) {
            const NoValue = circuit.builder.NoValue;
            var topology = try circuit.builder.Context(NoValue).init(std.testing.allocator, 8);
            defer topology.deinit();
            const empty_root = try Blake.guessHash(NoValue, &topology, Blake.hashValue(NoValue, @splat(0)));
            const empty_step = try circuit.builder.wrappers.guessU32(NoValue, &topology, circuit.builder.wrappers.u32Value(NoValue, 0));
            var empty_current: [8]Var = undefined;
            for (&empty_current) |*wire| wire.* = try topology.guessM31(.{});
            var empty_times: [11]U32 = undefined;
            for (&empty_times) |*wire| wire.* = try circuit.builder.wrappers.guessU32(NoValue, &topology, circuit.builder.wrappers.u32Value(NoValue, 0));
            const empty_digest = try digestWires(NoValue, &topology, empty_root, empty_step, checkpoint, empty_current, empty_times);
            var empty_output: [8]Var = undefined;
            for (empty_digest.words, &empty_output) |word, *wire| wire.* = word.get();
            try topology.setOutputs(&empty_output);
            try topology.finalize(false);
            try std.testing.expectEqual(ctx.circuit.n_vars, topology.circuit.n_vars);
            try std.testing.expectEqualDeep(ctx.circuit.add.items, topology.circuit.add.items);
            try std.testing.expectEqualDeep(ctx.circuit.mul.items, topology.circuit.mul.items);
            try std.testing.expectEqualDeep(ctx.circuit.eq.items, topology.circuit.eq.items);
            try std.testing.expectEqualDeep(ctx.circuit.m31_to_u32.items, topology.circuit.m31_to_u32.items);
            try std.testing.expectEqualDeep(ctx.circuit.blake_g_gate.items, topology.circuit.blake_g_gate.items);
            try std.testing.expectEqualDeep(ctx.circuit.output.items, topology.circuit.output.items);
        }
    }
    var other_root = root;
    other_root[0] ^= 1;
    try std.testing.expect(!std.meta.eql(prior, try statementDigest(other_root, 0, checkpoint, current, times)));
    var other_checkpoint = checkpoint;
    other_checkpoint[0] ^= 1;
    try std.testing.expect(!std.meta.eql(prior, try statementDigest(root, 0, other_checkpoint, current, times)));
    var other_current = current;
    other_current[0] ^= 1;
    try std.testing.expect(!std.meta.eql(prior, try statementDigest(root, 0, checkpoint, other_current, times)));
    other_current[0] = core.fields.m31.Modulus;
    try std.testing.expectError(error.NonCanonicalState, statementDigest(root, 0, checkpoint, other_current, times));
    var other_times = times;
    other_times[7] ^= 1;
    try std.testing.expect(!std.meta.eql(prior, try statementDigest(root, 0, checkpoint, current, other_times)));
}
