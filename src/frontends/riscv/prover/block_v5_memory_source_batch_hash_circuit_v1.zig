//! Bounded packed-frame connector graph. Core G/XOR matrices are separate
//! actual requesting/supplying witnesses and MUST be proven on the same
//! postcommit wire epoch. This candidate graph emits no verified receipt.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Crypto = @import("../recursion/air/block_v5_memory_source_crypto_v1.zig");
const Hash = @import("block_v5_memory_source_packed_hash_v1.zig");
const Eq = @import("../recursion/air/block_v5_memory_source_batch_equations_v1.zig");
const Record = @import("../recursion/air/composition_graph_recorder.zig");
const Universal = @import("../recursion/air/universal_challenges.zig");
const G = @import("../recursion/air/blake3_g_call.zig");
const Xor = @import("../recursion/air/blake3_xor_call.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.HostBudgetAllocator;
pub const Limits = struct { max_heap_bytes: usize = 128 * 1024 * 1024, max_nodes: usize = 1_000_000 };
pub const Claims = struct { wire: Q, hash: Q };
pub const Capture = struct {
    blocks: [2]Hash.Boundary = undefined,
    count: usize = 0,
    pub fn g(_: *@This(), _: *const G.Row) !void {}
    pub fn xor(_: *@This(), _: *const Xor.Row) !void {}
    pub fn boundary(self: *@This(), value: Hash.Boundary) !void {
        if (self.count == self.blocks.len) return error.InvalidSourceHashCircuit;
        self.blocks[self.count] = value;
        self.count += 1;
    }
};
pub fn Sink(comptime S: type) type {
    return struct {
        builder: ?*Record.Builder = null,
        wire_elements: Universal.Elements,
        wire_sum: S = S.zero(),
        pub fn zero(self: *@This(), value: S) !void {
            if (S == Q) {
                if (!value.isZero()) return error.UnsatisfiedSourceHashConnector;
            } else try self.builder.?.constrainZero(value);
        }
        fn lift(value: Q) S {
            return if (S == Q) value else S.fromSecure(value);
        }
        pub fn wire(self: *@This(), circuit: u32, id: u32, weight: u32, words: [4]Crypto.Algebra(S).Byte, positive: bool) !void {
            var tuple: [6]S = .{ S.fromBase(M.fromCanonical(circuit)), S.fromBase(M.fromCanonical(id)), S.zero(), S.zero(), S.zero(), S.zero() };
            for (words, 0..) |byte, i| {
                var factor = S.one();
                for (byte) |bit| {
                    tuple[i + 2] = tuple[i + 2].add(factor.mul(bit));
                    factor = factor.add(factor);
                }
            }
            var denominator = lift(self.wire_elements.z).neg();
            for (tuple, self.wire_elements.alpha_powers[0..6]) |value, power| denominator = denominator.add(value.mul(lift(power)));
            const inverse = if (@hasDecl(S, "inverse")) denominator.inverse() else try denominator.inv();
            const fraction = inverse.mul(S.fromBase(M.fromCanonical(weight)));
            self.wire_sum = if (positive) self.wire_sum.add(fraction) else self.wire_sum.sub(fraction);
        }
    };
}
pub fn propose(frame: Hash.Frame, multiplicity: u32, circuit: u32, captured: *const Capture, wire: Universal.Elements, hash: Eq.Algebra(Q).Pair) !Claims {
    if (wire.arity != 6 or captured.count != (frame.size() + 63) / 64) return error.InvalidSourceHashCircuit;
    const C = Crypto.Algebra(Q);
    var blocks: [2]Hash.Algebra(Q).BoundaryBits = undefined;
    for (captured.blocks[0..captured.count], blocks[0..captured.count]) |value, *block| {
        for (&block.initial, value.initial) |*word, raw| word.* = C.word(raw);
        for (&block.output, value.output) |*word, raw| word.* = C.word(raw);
    }
    const bits: Hash.Algebra(Q).FrameBits = switch (frame) {
        .leaf => |value| .{ .leaf = C.word(value) },
        .node => |value| .{ .node = .{ .left = C.digest(value.left), .right = C.digest(value.right) } },
    };
    var sink = Sink(Q){ .wire_elements = wire };
    const digest = C.digest(frame.nativeDigest());
    try Hash.Algebra(Q).evaluate(bits, digest, circuit, blocks[0..captured.count], &sink);
    return .{ .wire = sink.wire_sum, .hash = try Hash.hashSupply(Q, bits, digest, multiplicity, hash) };
}
pub const Prepared = struct {
    child: std.mem.Allocator,
    budget: Budget,
    private_count: usize,
    circuit: ?Record.Circuit = null,
    inputs: ?[]Q = null,
    pub fn deinit(self: *Prepared) void {
        if (self.circuit) |*circuit| circuit.deinit();
        if (self.inputs) |inputs| self.budget.allocator().free(inputs);
        if (self.budget.live_bytes != 0) @panic("source packed connector owner leak");
        const child = self.child;
        child.destroy(self);
    }
    pub fn evaluate(self: *Prepared) !void {
        const a = self.budget.allocator();
        const values = try a.alloc(Q, self.circuit.?.nodes.len);
        defer a.free(values);
        try self.circuit.?.evaluateInto(self.inputs.?, values);
    }
};
fn putWord(values: []Q, at: *usize, word: u32) void {
    for (0..32) |i| {
        values[at.*] = Q.fromBase(M.fromCanonical((word >> @intCast(i)) & 1));
        at.* += 1;
    }
}
fn putDigest(values: []Q, at: *usize, digest: [32]u8) void {
    for (digest) |byte| for (0..8) |i| {
        values[at.*] = Q.fromBase(M.fromCanonical((byte >> @intCast(i)) & 1));
        at.* += 1;
    };
}
fn readWordBits(comptime S: type, values: []const S, at: *usize) Crypto.Algebra(S).Word {
    const out = values[at.*..][0..32].*;
    at.* += 32;
    return out;
}
fn readDigestBits(comptime S: type, values: []const S, at: *usize) Crypto.Algebra(S).Digest {
    var out: Crypto.Algebra(S).Digest = undefined;
    for (&out) |*byte| {
        byte.* = values[at.*..][0..8].*;
        at.* += 8;
    }
    return out;
}
/// This reconstructs a graph solely from actual leaf/node framing, circuit
/// scope, fixed multiplicity and postcommit challenges. Private captured
/// operands/outputs do not choose a different graph or schedule.
pub fn prepare(a: std.mem.Allocator, frame: Hash.Frame, multiplicity: u32, circuit_id: u32, captured: *const Capture, wire: Universal.Elements, hash: Eq.Algebra(Q).Pair, claims: Claims, limits: Limits) !*Prepared {
    const blocks_count = (frame.size() + 63) / 64;
    if (captured.count != blocks_count or wire.arity != 6 or (multiplicity != 1 and multiplicity != 2) or limits.max_heap_bytes == 0 or limits.max_nodes >= core.fields.m31.Modulus) return error.InvalidSourceHashCircuit;
    const private_count: usize = (switch (frame) {
        .leaf => @as(usize, 32),
        .node => 512,
    }) + 256 + blocks_count * 48 * 32;
    if (limits.max_nodes < private_count + 2) return error.InvalidSourceHashCircuit;
    const out = try a.create(Prepared);
    out.* = .{ .child = a, .budget = Budget.init(a, limits.max_heap_bytes), .private_count = private_count };
    errdefer out.deinit();
    const bounded = out.budget.allocator();
    out.inputs = try bounded.alloc(Q, private_count + 2);
    var at: usize = 0;
    switch (frame) {
        .leaf => |value| putWord(out.inputs.?, &at, value),
        .node => |value| {
            putDigest(out.inputs.?, &at, value.left);
            putDigest(out.inputs.?, &at, value.right);
        },
    }
    putDigest(out.inputs.?, &at, frame.nativeDigest());
    for (captured.blocks[0..captured.count]) |block| {
        for (block.initial) |value| putWord(out.inputs.?, &at, value);
        for (block.output) |value| putWord(out.inputs.?, &at, value);
    }
    std.debug.assert(at == private_count);
    out.inputs.?[at] = claims.wire;
    out.inputs.?[at + 1] = claims.hash;
    var builder = Record.Builder.init(bounded);
    defer builder.deinit();
    const symbols = try bounded.alloc(Record.Scalar, private_count + 2);
    defer bounded.free(symbols);
    for (symbols) |*symbol| symbol.* = (try builder.input()).value;
    try builder.activate();
    at = 0;
    const frame_bits: Hash.Algebra(Record.Scalar).FrameBits = switch (frame) {
        .leaf => .{ .leaf = readWordBits(Record.Scalar, symbols, &at) },
        .node => .{ .node = .{ .left = readDigestBits(Record.Scalar, symbols, &at), .right = readDigestBits(Record.Scalar, symbols, &at) } },
    };
    const digest_bits = readDigestBits(Record.Scalar, symbols, &at);
    var block_bits: [2]Hash.Algebra(Record.Scalar).BoundaryBits = undefined;
    for (block_bits[0..blocks_count]) |*block| {
        for (&block.initial) |*value| value.* = readWordBits(Record.Scalar, symbols, &at);
        for (&block.output) |*value| value.* = readWordBits(Record.Scalar, symbols, &at);
    }
    std.debug.assert(at == private_count);
    var sink = Sink(Record.Scalar){ .builder = &builder, .wire_elements = wire };
    try Hash.Algebra(Record.Scalar).evaluate(frame_bits, digest_bits, circuit_id, block_bits[0..blocks_count], &sink);
    const supplied = try Hash.hashSupply(Record.Scalar, frame_bits, digest_bits, multiplicity, .{ .z = Record.Scalar.fromSecure(hash.z), .alpha = Record.Scalar.fromSecure(hash.alpha) });
    try builder.constrainZero(sink.wire_sum.sub(symbols[at]));
    try builder.constrainZero(supplied.sub(symbols[at + 1]));
    builder.deactivate();
    if (builder.nodes.items.len > limits.max_nodes) return error.SourceFoldCircuitResourceLimit;
    const completed = try builder.finish();
    out.circuit = completed;
    return out;
}
