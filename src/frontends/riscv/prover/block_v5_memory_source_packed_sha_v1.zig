//! Actual original packed SHA source/schedule/round/feed-forward emission for
//! canonical source-file hashing. Guest caller memory semantics are excluded;
//! source framing/chaining and all exact wire/table requests must be proved.
//! No source receipt is produced by witness emission or native hash matching.
const std = @import("std");
const core = @import("stwo_core");
const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
const Rows = @import("../air/guest_precompile/sha256_compression_rows.zig");
const Input = @import("../air/guest_precompile/sha256_packed_source.zig");
const Graph = @import("../air/guest_precompile/sha256_compression_graph.zig");
const Calls = @import("../air/guest_precompile/sha256_packed_call.zig");
const Program = @import("../air/guest_precompile/sha256_word_program.zig");
const SHA = @import("../air/guest_precompile/sha256_compression.zig");
const Crypto = @import("../recursion/air/block_v5_memory_source_crypto_v1.zig");
pub const Boundary = struct { call: u32, state: SHA.State, block: [64]u8, output: SHA.State };
/// Sink source(*Input.Row), schedule(*Rows.Schedule.Row), round(*Rows.Round.Row),
/// feedForward(*Rows.FeedForward.Row), boundary(Boundary). Every row is borrowed
/// only during its callback. No final matrix/whole file owner lives here.
pub fn emitCompression(call: u32, state: SHA.State, block: [64]u8, sink: anytype) !SHA.State {
    if (call == 0 or call >= core.fields.m31.Modulus) return error.InvalidSourceShaCall;
    const trace = SHA.witness(state, block);
    const topology = Rows.topology;
    var values: [Graph.wire_count]u32 = undefined;
    const input = Graph.sources(state, block);
    @memcpy(values[0..Graph.source_count], &input);
    for (topology.expansion, 16..) |op, ordinal| values[op.output[0]] = trace.schedule[ordinal];
    for (topology.rounds, 0..) |op, ordinal| {
        values[op.output[0]] = trace.states[ordinal + 1][0];
        values[op.output[1]] = trace.states[ordinal + 1][4];
    }
    for (topology.feed_forward, 0..) |op, ordinal| values[op.output[0]] = trace.output_state[ordinal];
    for (input, 0..) |value, wire| {
        const row = try Input.row(call, @intCast(wire), value, &topology.uses);
        try sink.source(&row);
    }
    try emitOperations(.schedule, &topology.expansion, call, &values, sink);
    try emitOperations(.round, &topology.rounds, call, &values, sink);
    try emitOperations(.feed_forward, &topology.feed_forward, call, &values, sink);
    try sink.boundary(Boundary{ .call = call, .state = state, .block = block, .output = trace.output_state });
    return trace.output_state;
}
fn emitOperations(comptime kind: Program.Kind, operations: []const Graph.Operation(kind), call: u32, values: *const [Graph.wire_count]u32, sink: anytype) !void {
    for (operations) |op| {
        var input: [Program.inputCount(kind)]u32 = undefined;
        for (op.input, &input) |wire, *word| word.* = values[wire];
        const row = try Calls.ForKind(kind).row(call, op, &Rows.topology.uses, input);
        switch (kind) {
            .schedule => try sink.schedule(&row),
            .round => try sink.round(&row),
            .feed_forward => try sink.feedForward(&row),
        }
    }
}
pub fn compressionCount(length: u64) !u64 {
    if (length > std.math.maxInt(u64) / 8) return error.InvalidSourceShaChunk;
    return std.math.add(u64, length / 64 + 1, @intFromBool(length % 64 >= 56));
}
pub fn chunkCompressionCount(admitted: *const Source.Admitted, stream: Source.Stream, block: u64) !u32 {
    try admitted.require();
    const length = admitted.byteLength(stream);
    if (block > length / 64 or length > std.math.maxInt(u64) / 8) return error.InvalidSourceShaChunk;
    return if (block == length / 64 and length % 64 >= 56) 2 else 1;
}
/// Full SHA padding exactly matches original Source equations, including a
/// separate mandatory terminal chunk for lengths divisible by64 and the
/// 56..63-byte tail's second compression. Raw unused cells are canonical0.
pub fn emitChunk(admitted: *const Source.Admitted, stream: Source.Stream, block: u64, raw: [64]u8, state: SHA.State, first_call: u32, sink: anytype) !SHA.State {
    const count = try chunkCompressionCount(admitted, stream, block);
    if (first_call == 0 or @as(u64, first_call) + count > core.fields.m31.Modulus) return error.InvalidSourceShaCall;
    const length = admitted.byteLength(stream);
    const terminal = block == length / 64;
    const used: usize = if (terminal) @intCast(length % 64) else 64;
    if (block == 0 and !std.meta.eql(state, SHA.initial_state)) return error.InvalidSourceShaInitialState;
    for (raw[used..]) |byte| if (byte != 0) return error.NonCanonicalSourceShaTail;
    var padded = raw;
    if (terminal) {
        padded[used] = 0x80;
        if (used < 56) std.mem.writeInt(u64, padded[56..64], length * 8, .big);
    }
    var out = try emitCompression(first_call, state, padded, sink);
    if (count == 2) {
        var last: [64]u8 = @splat(0);
        std.mem.writeInt(u64, last[56..64], length * 8, .big);
        out = try emitCompression(first_call + 1, out, last, sink);
    }
    if (terminal and !std.mem.eql(u8, &SHA.stateBytes(out), &admitted.digest(stream))) return error.InvalidSourceShaTerminalDigest;
    return out;
}
pub fn Algebra(comptime S: type) type {
    return struct {
        const Self = @This();
        const C = Crypto.Algebra(S);
        pub const Pair = @import("../recursion/air/block_v5_memory_source_equations_v1.zig").Algebra(S).Pair;
        pub const Sums = struct { bytes: S, input: S, sha_chain: S };
        pub const BoundaryBits = struct { state: C.State, block: [64]C.Byte, output: C.State };
        fn pack(bits: []const S) S {
            var out = S.zero();
            var factor = S.one();
            for (bits) |bit| {
                out = out.add(factor.mul(bit));
                factor = factor.add(factor);
            }
            return out;
        }
        fn wide(value: u64) [4]S {
            var out: [4]S = undefined;
            for (&out, 0..) |*value_part, i| value_part.* = C.scalar(@intCast((value >> @intCast(16 * i)) & 65535));
            return out;
        }
        fn fraction(pair: Self.Pair, values: []const S) !S {
            const denominator = pair.combine(values);
            return if (@hasDecl(S, "inverse")) denominator.inverse() else try denominator.inv();
        }
        fn stateBytes(state: C.State) [32]S {
            var bytes: [32]S = undefined;
            for (&bytes, C.shaDigest(state)) |*value, bits| value.* = pack(&bits);
            return bytes;
        }
        fn chain(pair: Self.Pair, stream: Source.Stream, block: u64, bytes: [32]S) !S {
            return fraction(pair, &([1]S{C.scalar(@intFromEnum(stream))} ++ wide(block) ++ bytes));
        }
        /// Original Source9 semantics, separate from the dedicated packed-core
        /// wire epoch. This arithmetic can be witnessed only AFTER all raw and
        /// core operand roots are sealed. Its requesting main must then be
        /// committed BEFORE wire z/alpha. It is not a source receipt.
        /// `output` must be the exact evaluate() output, not a new free input.
        pub fn semantic(admitted: *const Source.Admitted, stream: Source.Stream, block: u64, raw: [64]C.Byte, state: C.State, output: C.State, pairs: [3]Self.Pair) !Self.Sums {
            return semanticBytes(admitted, stream, block, raw, state, stateBytes(output), pairs);
        }
        /// Packed byte output variant. `output` is SHA big-endian digest order
        /// from the SAME precommitted capture cells that the connector wires
        /// consume. Its range/hash validity requires actual fresh core/table
        /// proofs; this sum constructor alone grants no authority.
        pub fn semanticBytes(admitted: *const Source.Admitted, stream: Source.Stream, block: u64, raw: [64]C.Byte, state: C.State, output: [32]S, pairs: [3]Self.Pair) !Self.Sums {
            _ = try chunkCompressionCount(admitted, stream, block);
            const length = admitted.byteLength(stream);
            const terminal = block == length / 64;
            const used: usize = if (terminal) @intCast(length % 64) else 64;
            const offset = block * 64;
            var sums = Self.Sums{ .bytes = S.zero(), .input = S.zero(), .sha_chain = S.zero() };
            if (block != 0) sums.sha_chain = sums.sha_chain.sub(try chain(pairs[2], stream, block, stateBytes(state)));
            if (!terminal) sums.sha_chain = sums.sha_chain.add(try chain(pairs[2], stream, block + 1, output));
            if (stream != .public_input) {
                for (raw[0..used], 0..) |byte, i| {
                    const tuple = [1]S{C.scalar(@intFromEnum(stream))} ++ wide(offset + i) ++ [1]S{pack(&byte)};
                    sums.bytes = sums.bytes.sub(try fraction(pairs[0], &tuple));
                }
            } else {
                for (0..(used + 3) / 4) |i| {
                    var bytes: [4]C.Byte = @splat(C.byte(0));
                    const remaining: usize = @min(@as(usize, 4), used - i * 4);
                    @memcpy(bytes[0..remaining], raw[i * 4 ..][0..remaining]);
                    const value = C.fromBytes(bytes, .little);
                    const address = C.word(@intCast(@as(u64, admitted.pins.initial.layout.input_base) + offset + i * 4));
                    const tuple = [_]S{ pack(address[0..16]), pack(address[16..32]), pack(value[0..16]), pack(value[16..32]) };
                    var is_zero = S.one();
                    for (value) |bit| is_zero = is_zero.mul(S.one().sub(bit));
                    sums.input = sums.input.add(S.one().sub(is_zero).mul(try fraction(pairs[1], &tuple)));
                }
            }
            return sums;
        }
        fn equalWord(sink: anytype, expected: C.Word, actual: C.Word) !void {
            for (expected, actual) |x, y| try sink.zero(x.sub(y));
        }
        pub fn evaluate(admitted: *const Source.Admitted, stream: Source.Stream, block: u64, raw: [64]C.Byte, state: C.State, first_call: u32, captured: []const BoundaryBits, sink: anytype) !C.State {
            const count = try chunkCompressionCount(admitted, stream, block);
            if (captured.len != count or first_call == 0 or @as(u64, first_call) + count > core.fields.m31.Modulus) return error.InvalidSourceShaCall;
            for (raw) |byte| for (byte) |bit| {
                try sink.zero(bit.mul(bit.sub(S.one())));
            };
            for (state) |word| for (word) |bit| {
                try sink.zero(bit.mul(bit.sub(S.one())));
            };
            for (captured) |boundary| {
                for (boundary.state) |word| for (word) |bit| {
                    try sink.zero(bit.mul(bit.sub(S.one())));
                };
                for (boundary.block) |byte| for (byte) |bit| {
                    try sink.zero(bit.mul(bit.sub(S.one())));
                };
                for (boundary.output) |word| for (word) |bit| {
                    try sink.zero(bit.mul(bit.sub(S.one())));
                };
            }
            const length = admitted.byteLength(stream);
            const terminal = block == length / 64;
            const used: usize = if (terminal) @intCast(length % 64) else 64;
            for (raw[used..]) |byte| for (byte) |bit| {
                try sink.zero(bit);
            };
            if (block == 0) {
                for (state, SHA.initial_state) |actual, value| try equalWord(sink, C.word(value), actual);
            }
            var padded = raw;
            if (terminal) {
                padded[used] = C.byte(0x80);
                if (used < 56) for (0..8) |i| {
                    padded[56 + i] = C.byte(@truncate((length * 8) >> @intCast(56 - 8 * i)));
                };
            }
            var out = state;
            for (captured, 0..) |boundary, ordinal| {
                const expected_block: [64]C.Byte = if (ordinal == 0) padded else blk: {
                    var last: [64]C.Byte = @splat(C.byte(0));
                    for (0..8) |i| last[56 + i] = C.byte(@truncate((length * 8) >> @intCast(56 - 8 * i)));
                    break :blk last;
                };
                for (boundary.state, out) |actual, expected| try equalWord(sink, expected, actual);
                for (boundary.block, expected_block) |actual, expected| for (actual, expected) |x, y| try sink.zero(x.sub(y));
                const call = first_call + @as(u32, @intCast(ordinal));
                for (boundary.state, 0..) |word, wire| try sink.wire(call, Graph.input_boundary_offset + @as(u32, @intCast(wire)), 1, C.toBytes(word, .little), true);
                for (0..16) |wire| try sink.wire(call, Graph.input_boundary_offset + @as(u32, @intCast(8 + wire)), 1, C.toBytes(C.fromBytes(boundary.block[4 * wire ..][0..4].*, .big), .little), true);
                for (boundary.output, Rows.topology.output) |word, wire| try sink.wire(call, wire, 1, C.toBytes(word, .little), false);
                out = boundary.output;
            }
            if (terminal) {
                const digest = C.shaDigest(out);
                const expected = C.digest(admitted.digest(stream));
                for (digest, expected) |actual, value| for (actual, value) |x, y| try sink.zero(x.sub(y));
            }
            return out;
        }
    };
}
