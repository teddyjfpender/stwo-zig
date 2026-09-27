//! Actual canonical packed BLAKE3 G/XOR row generator and frame connectors.
//! A small leaf frame needs one compression, node frame two. At most one
//! compression's rows are live; source operations need not use bit-level hash
//! circuits. Core table requests and wire closure remain proof obligations.
const std = @import("std");
const Defaults = @import("block_v5_memory_source_batch_defaults_v1.zig");
const core = @import("stwo_core");
const Tree = @import("../air/memory_commitment/blake3_state_tree.zig");
const Plan = @import("../recursion/air/blake3_compression_plan.zig");
const Rows = @import("../recursion/air/blake3_compression_witness.zig");
const G = @import("../recursion/air/blake3_g_call.zig");
const Xor = @import("../recursion/air/blake3_xor_call.zig");
const Crypto = @import("../recursion/air/block_v5_memory_source_crypto_v1.zig");
pub const Frame = union(enum) {
    leaf: u32,
    node: struct { left: [32]u8, right: [32]u8 },
    pub fn size(self: Frame) usize {
        return switch (self) {
            .leaf => 48,
            .node => 108,
        };
    }
    pub fn raw(self: Frame) [108]u8 {
        var out: [108]u8 = @splat(0);
        @memcpy(out[0..Tree.DOMAIN.len], Tree.DOMAIN);
        std.mem.writeInt(u32, out[32..36], 2, .little);
        std.mem.writeInt(u32, out[36..40], switch (self) {
            .leaf => 1,
            .node => 2,
        }, .little);
        std.mem.writeInt(u32, out[40..44], @intFromEnum(Tree.Kind.memory), .little);
        switch (self) {
            .leaf => |value| std.mem.writeInt(u32, out[44..48], value, .little),
            .node => |value| {
                @memcpy(out[44..76], &value.left);
                @memcpy(out[76..108], &value.right);
            },
        }
        return out;
    }
    pub fn nativeDigest(self: Frame) [32]u8 {
        return switch (self) {
            .leaf => |value| (Tree.Frame{ .leaf = .{ .kind = .memory, .value = value } }).hash().bytes,
            .node => |value| (Tree.Frame{ .node = .{ .kind = .memory, .left = .{ .bytes = value.left }, .right = .{ .bytes = value.right } } }).hash().bytes,
        };
    }
};
pub const Boundary = struct {
    circuit: u32,
    initial: [32]u32,
    output: [16]u32,
    input_uses: [32]u32,
    output_wire: [16]u32,
};
/// Sink contract g(*const G.Row), xor(*const Xor.Row), boundary(Boundary).
/// These are owned-for-callback, borrowed rows. A retaining sink must copy to
/// independently bounded columns; it cannot retain addresses on this stack.
pub fn emit(frame: Frame, first_circuit: u32, sink: anytype) ![32]u8 {
    const raw = frame.raw();
    const length = frame.size();
    const count = (length + 63) / 64;
    if (first_circuit == 0 or @as(u64, first_circuit) + count > core.fields.m31.Modulus) return error.InvalidSourceHashCircuit;
    var cv = core.crypto.blake3_compression.IV;
    const plan = Plan.canonical();
    var output: [16]u32 = undefined;
    for (0..count) |ordinal| {
        const offset = ordinal * 64;
        const used: usize = @min(@as(usize, 64), length - offset);
        var bytes: [64]u8 = @splat(0);
        @memcpy(bytes[0..used], raw[offset..][0..used]);
        var block: [16]u32 = undefined;
        for (&block, 0..) |*word, i| word.* = std.mem.readInt(u32, bytes[i * 4 ..][0..4], .little);
        const flags: u32 = (if (ordinal == 0) @as(u32, 1) else 0) | (if (ordinal + 1 == count) @as(u32, 2 | 8) else 0);
        const circuit = first_circuit + @as(u32, @intCast(ordinal));
        const prepared = try Rows.prepare(circuit, cv, block, 0, @intCast(used), flags);
        for (&prepared.g_rows) |*row| try sink.g(row);
        for (&prepared.xor_rows) |*row| try sink.xor(row);
        try sink.boundary(Boundary{ .circuit = circuit, .initial = prepared.initial, .output = prepared.output, .input_uses = plan.uses[0..32].*, .output_wire = plan.output });
        output = prepared.output;
        @memcpy(&cv, output[0..8]);
    }
    var digest: [32]u8 = undefined;
    for (output[0..8], 0..) |word, i| std.mem.writeInt(u32, digest[i * 4 ..][0..4], word, .little);
    if (!std.mem.eql(u8, &digest, &frame.nativeDigest())) return error.InvalidSourceHashFraming;
    return digest;
}
/// Complete frame connector equations, not a digest oracle. A real proof must
/// close each emitted initial/output request against the G/XOR wire events.
/// All requesting cells and core main cells precede the dedicated challenge.
pub fn Algebra(comptime S: type) type {
    return struct {
        const C = Crypto.Algebra(S);
        pub const FrameBits = union(enum) { leaf: C.Word, node: struct { left: C.Digest, right: C.Digest } };
        pub const BoundaryBits = struct { initial: [32]C.Word, output: [16]C.Word };
        fn equalWord(sink: anytype, a: C.Word, b: C.Word) !void {
            for (a, b) |x, y| try sink.zero(x.sub(y));
        }
        pub fn evaluate(frame: FrameBits, digest: C.Digest, first_circuit: u32, blocks: []const BoundaryBits, sink: anytype) !void {
            // Every external operand/output bit is a real committed cell.
            // Do not rely on byte reconstruction to imply Boolean values.
            switch (frame) {
                .leaf => |word| for (word) |value| {
                    try sink.zero(value.mul(value.sub(S.one())));
                },
                .node => |value| for ([_]C.Digest{ value.left, value.right }) |digest_bits| for (digest_bits) |byte| for (byte) |bit| {
                    try sink.zero(bit.mul(bit.sub(S.one())));
                },
            }
            for (digest) |byte| for (byte) |bit| {
                try sink.zero(bit.mul(bit.sub(S.one())));
            };
            for (blocks) |block| {
                for (block.initial) |word| for (word) |bit| {
                    try sink.zero(bit.mul(bit.sub(S.one())));
                };
                for (block.output) |word| for (word) |bit| {
                    try sink.zero(bit.mul(bit.sub(S.one())));
                };
            }
            var raw: [108]C.Byte = @splat(C.byte(0));
            for (Tree.DOMAIN, 0..) |byte, i| raw[i] = C.byte(byte);
            @memcpy(raw[32..36], &C.toBytes(C.word(2), .little));
            @memcpy(raw[36..40], &C.toBytes(C.word(switch (frame) {
                .leaf => 1,
                .node => 2,
            }), .little));
            @memcpy(raw[40..44], &C.toBytes(C.word(@intFromEnum(Tree.Kind.memory)), .little));
            const length: usize = switch (frame) {
                .leaf => |value| blk: {
                    @memcpy(raw[44..48], &C.toBytes(value, .little));
                    break :blk 48;
                },
                .node => |value| blk: {
                    @memcpy(raw[44..76], &value.left);
                    @memcpy(raw[76..108], &value.right);
                    break :blk 108;
                },
            };
            const count = (length + 63) / 64;
            if (blocks.len != count or first_circuit == 0 or @as(u64, first_circuit) + count > core.fields.m31.Modulus) return error.InvalidSourceHashCircuit;
            var cv: C.State = undefined;
            for (&cv, core.crypto.blake3_compression.IV) |*word, value| word.* = C.word(value);
            const plan = Plan.canonical();
            for (blocks, 0..) |block, ordinal| {
                const offset = ordinal * 64;
                const used: usize = @min(@as(usize, 64), length - offset);
                var bytes: [64]C.Byte = @splat(C.byte(0));
                @memcpy(bytes[0..used], raw[offset..][0..used]);
                var initial: [32]C.Word = undefined;
                @memcpy(initial[0..8], &cv);
                for (0..4) |i| initial[8 + i] = C.word(core.crypto.blake3_compression.IV[i]);
                initial[12] = C.word(0);
                initial[13] = C.word(0);
                initial[14] = C.word(@intCast(used));
                initial[15] = C.word((if (ordinal == 0) @as(u32, 1) else 0) | (if (ordinal + 1 == count) @as(u32, 2 | 8) else 0));
                for (0..16) |i| initial[16 + i] = C.fromBytes(bytes[i * 4 ..][0..4].*, .little);
                const circuit = first_circuit + @as(u32, @intCast(ordinal));
                for (initial, block.initial, 0..) |expected, actual, wire| {
                    try equalWord(sink, expected, actual);
                    try sink.wire(circuit, @as(u32, @intCast(wire)), plan.uses[wire], C.toBytes(actual, .little), true);
                }
                // Consume ALL 16 output words, including the eight discarded
                // full-compression words. Original plan emits each once.
                for (block.output, plan.output) |word, wire| try sink.wire(circuit, wire, 1, C.toBytes(word, .little), false);
                @memcpy(&cv, block.output[0..8]);
            }
            for (cv, 0..) |word, i| {
                const bytes = C.toBytes(word, .little);
                for (bytes, digest[i * 4 ..][0..4]) |expected, actual| for (expected, actual) |x, y| try sink.zero(x.sub(y));
            }
        }
    };
}

const Fold = @import("block_v5_memory_source_batch_fold_v1.zig");
pub const Recipe = struct {
    frame: Frame,
    /// One actual arithmetic computation may supply an exact duplicated
    /// request twice. This is fixed by the page routing recipe, not payload.
    multiplicity: u32,
    /// A known public default frame can use an independently reconstructed
    /// constant provider. It cannot skip the framed hash request/closure.
    default_height: ?u32,
};
pub const Recipes = struct {
    values: [2]Recipe = undefined,
    count: usize = 0,
    pub fn compressionCount(self: *const Recipes) u32 {
        var out: u32 = 0;
        for (self.values[0..self.count]) |recipe| if (recipe.default_height == null) {
            out += @intCast((recipe.frame.size() + 63) / 64);
        };
        return out;
    }
};
fn defaultHeight(frame: Frame, height: u32) ?u32 {
    const hasher = Defaults.get();
    return switch (frame) {
        .leaf => |value| if (value == 0 and height == 0) 0 else null,
        .node => |value| if (height != 0 and height <= Tree.DEPTH and std.mem.eql(u8, &value.left, &hasher.defaults[Tree.DEPTH - height + 1].bytes) and std.mem.eql(u8, &value.right, &hasher.defaults[Tree.DEPTH - height + 1].bytes)) height else null,
    };
}
/// This derives candidate compression routing only. A page receiver must
/// reconstruct/check the recipe inside the proof; received metadata cannot
/// authorize a skipped core or arbitrary multiplicity.
pub fn recipes(operation: Fold.Operation) !Recipes {
    try operation.coordinate.validate();
    var out = Recipes{};
    switch (operation.kind) {
        .empty, .root => return out,
        .leaf => {
            if (operation.coordinate.height != 0) return error.InvalidSourceHashFraming;
            out.values[0] = .{ .frame = .{ .leaf = operation.leaf.before }, .multiplicity = 1, .default_height = defaultHeight(.{ .leaf = operation.leaf.before }, 0) };
            out.values[1] = .{ .frame = .{ .leaf = operation.leaf.after }, .multiplicity = 1, .default_height = defaultHeight(.{ .leaf = operation.leaf.after }, 0) };
            out.count = 2;
            if (operation.leaf.before == operation.leaf.after) {
                out.count = 1;
                out.values[0].multiplicity = 2;
            }
        },
        .branch => {
            if (operation.coordinate.height == 0) return error.InvalidSourceHashFraming;
            const before = Frame{ .node = .{ .left = operation.left.before, .right = operation.right.before } };
            const after = Frame{ .node = .{ .left = operation.left.after, .right = operation.right.after } };
            out.values[0] = .{ .frame = before, .multiplicity = 1, .default_height = defaultHeight(before, operation.coordinate.height) };
            out.values[1] = .{ .frame = after, .multiplicity = 1, .default_height = defaultHeight(after, operation.coordinate.height) };
            out.count = 2;
            if (operation.left.equal() and operation.right.equal()) {
                out.count = 1;
                out.values[0].multiplicity = 2;
            }
        },
    }
    return out;
}
/// Sink additionally defaultFrame(height,frame,multiplicity,digest) and
/// frame(frame,multiplicity,digest). Both must route hash-bus supplies, even
/// for canonical defaults. Do not interpret this emitter as proof authority.
pub fn emitOperation(operation: Fold.Operation, first_circuit: u32, sink: anytype) !u32 {
    const list = try recipes(operation);
    var circuit = first_circuit;
    for (list.values[0..list.count]) |recipe| {
        if (recipe.default_height) |height| {
            const hasher = Defaults.get();
            try sink.defaultFrame(height, recipe.frame, recipe.multiplicity, hasher.defaults[Tree.DEPTH - height].bytes);
        } else {
            const digest = try emit(recipe.frame, circuit, sink);
            try sink.frame(recipe.frame, recipe.multiplicity, digest);
            circuit += @intCast((recipe.frame.size() + 63) / 64);
        }
    }
    return circuit - first_circuit;
}

const Eq = @import("../recursion/air/block_v5_memory_source_batch_equations_v1.zig");
/// Exact opposite hash request. Public recipe multiplicity is part of the
/// arithmetic provider's independently reconstructed fixed rows. An arbitrary
/// decoded multiplicity is not an admission token.
pub fn hashSupply(comptime S: type, frame: Algebra(S).FrameBits, digest: Crypto.Algebra(S).Digest, multiplicity: u32, challenge: Eq.Algebra(S).Pair) !S {
    if (multiplicity != 1 and multiplicity != 2) return error.InvalidSourceHashMultiplicity;
    const C = Crypto.Algebra(S);
    var payload: [64]C.Byte = @splat(C.byte(0));
    const tag: u32 = switch (frame) {
        .leaf => |value| blk: {
            @memcpy(payload[0..4], &C.toBytes(value, .little));
            break :blk 1;
        },
        .node => |value| blk: {
            @memcpy(payload[0..32], &value.left);
            @memcpy(payload[32..64], &value.right);
            break :blk 2;
        },
    };
    return (try Eq.Algebra(S).hashTerm(challenge, tag, payload, digest)).mul(S.fromBase(core.fields.m31.M31.fromCanonical(multiplicity))).neg();
}
/// Public canonical default provider: no private hash payload/output can be
/// substituted. The exact constant request must still close on the hash bus.
pub fn defaultSupply(comptime S: type, height: u32, multiplicity: u32, challenge: Eq.Algebra(S).Pair) !S {
    if (height > Tree.DEPTH) return error.InvalidSourceHashFraming;
    const C = Crypto.Algebra(S);
    const hasher = Defaults.get();
    const frame: Algebra(S).FrameBits = if (height == 0) .{ .leaf = C.word(0) } else .{ .node = .{ .left = C.digest(hasher.defaults[Tree.DEPTH - height + 1].bytes), .right = C.digest(hasher.defaults[Tree.DEPTH - height + 1].bytes) } };
    return hashSupply(S, frame, C.digest(hasher.defaults[Tree.DEPTH - height].bytes), multiplicity, challenge);
}
