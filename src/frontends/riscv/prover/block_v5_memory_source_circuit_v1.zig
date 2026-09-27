//! Bounded owned source-chunk arithmetic circuits. Prepared is NOT a receipt.
//! No STARK or recursive verifier is implemented by this owner. Future proofs
//! must expose/bind public inputs and prove exact chunk coverage + closure.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const recorder = @import("../recursion/air/composition_graph_recorder.zig");
const equations = @import("../recursion/air/block_v5_memory_source_equations_v1.zig");
const protocol = @import("block_v5_memory_source_auth_protocol_v1.zig");
pub const CIRCUIT_INPUT_COUNT = equations.INPUT_COUNT + 32;
const Budget = @import("stwo_prover_engine").host_budget_allocator.HostBudgetAllocator;
pub const ScalarSink = struct {
    pub fn zero(_: *@This(), value: Q) !void {
        if (!value.isZero()) return error.UnsatisfiedMemorySourceEquation;
    }
};
const GraphSink = struct {
    builder: *recorder.Builder,
    pub fn zero(self: *@This(), value: recorder.Scalar) !void {
        try self.builder.constrainZero(value);
    }
};
/// This is a candidate claim constructor; only equations/proofs can grant
/// authority. Hash and structural constraints are checked by the same generic
/// algebra used by symbolic preparation, not an alternate host-only recipe.
pub fn propose(admitted: *const protocol.Admitted, kind: equations.Kind, witness: equations.Witness, challenges: protocol.Challenges) !protocol.Sums {
    var inputs: [equations.INPUT_COUNT]Q = undefined;
    try equations.writeInputs(witness, challenges, .{}, &inputs);
    var sink = ScalarSink{};
    const sums = try equations.Algebra(Q).compute(admitted, kind, &inputs, &sink);
    var result: protocol.Sums = undefined;
    inline for (std.meta.fields(protocol.Sums)) |f| @field(result, f.name) = @field(sums, f.name);
    return result;
}
pub const Prepared = struct {
    child: std.mem.Allocator,
    budget: Budget,
    admission_id: [32]u8,
    kind: ?equations.Kind,
    private_input_count: usize = equations.BIT_COUNT,
    circuit: ?recorder.Circuit = null,
    inputs: ?[]Q = null,
    /// Stable heap address: all child allocations refer to this budget owner.
    pub fn deinit(self: *Prepared) void {
        if (self.circuit) |*c| c.deinit();
        if (self.inputs) |values| self.budget.allocator().free(values);
        std.debug.assert(self.budget.live_bytes == 0);
        const child = self.child;
        child.destroy(self);
    }
    pub fn publicInputs(self: *const Prepared) []const Q {
        return self.inputs.?[self.private_input_count..];
    }
    /// Local witness verification only; this does not mint a verified source.
    pub fn evaluate(self: *Prepared) !void {
        const circuit = &self.circuit.?;
        const a = self.budget.allocator();
        const values = try a.alloc(Q, circuit.nodes.len);
        defer a.free(values);
        try circuit.evaluateInto(self.inputs.?, values);
    }
};
/// Graph construction depends only on independent admission/kind/challenges,
/// never on private witness values. Thus a verifier can reconstruct this exact
/// graph without trusting proposer-selected descriptors or routing schedules.
pub fn prepareWithChallenges(a: std.mem.Allocator, admitted: *const protocol.Admitted, kind: equations.Kind, witness: equations.Witness, claims: protocol.Sums, challenges: protocol.Challenges) !*Prepared {
    try equations.validateKind(admitted, kind);
    if (admitted.limits.max_nodes < CIRCUIT_INPUT_COUNT) return error.MemorySourceResourceLimit;
    const out = try a.create(Prepared);
    out.* = .{ .child = a, .budget = Budget.init(a, admitted.limits.max_chunk_heap_bytes), .admission_id = admitted.identity, .kind = kind };
    errdefer out.deinit();
    const bounded = out.budget.allocator();
    out.inputs = try bounded.alloc(Q, CIRCUIT_INPUT_COUNT);
    try equations.writeInputs(witness, challenges, claims, out.inputs.?[0..equations.INPUT_COUNT]);
    const chunk_id = try chunkIdentity(admitted, kind);
    for (chunk_id, out.inputs.?[equations.INPUT_COUNT..]) |byte, *value| value.* = Q.fromBase(core.fields.m31.M31.fromCanonical(byte));
    var builder = recorder.Builder.init(bounded);
    defer builder.deinit();
    var symbols: [CIRCUIT_INPUT_COUNT]recorder.Scalar = undefined;
    for (&symbols) |*s| s.* = (try builder.input()).value;
    try builder.activate();
    var sink = GraphSink{ .builder = &builder };
    _ = try equations.Algebra(recorder.Scalar).evaluate(admitted, kind, symbols[0..equations.INPUT_COUNT], &sink);
    // Challenge inputs are public, and this isolated graph additionally pins
    // their actual sealed draw values. Future reusable setup may replace these
    // constants only with a genuine admitted transcript/public-bus binding.
    for (symbols[equations.BIT_COUNT..][0 .. 2 * equations.PAIR_COUNT], out.inputs.?[equations.BIT_COUNT..][0 .. 2 * equations.PAIR_COUNT]) |s, q| try builder.constrainZero(s.sub(recorder.Scalar.fromSecure(q)));
    for (symbols[equations.INPUT_COUNT..], chunk_id) |symbol, byte| try builder.constrainZero(symbol.sub(recorder.Scalar.fromBase(core.fields.m31.M31.fromCanonical(byte))));
    builder.deactivate();
    if (builder.nodes.items.len > admitted.limits.max_nodes) return error.MemorySourceResourceLimit;
    const completed = try builder.finish();
    out.circuit = completed;
    return out;
}
pub fn prepare(a: std.mem.Allocator, admitted: *const protocol.Admitted, kind: equations.Kind, witness: equations.Witness, claims: protocol.Sums, sealed: anytype) !*Prepared {
    try admitted.require();
    if (!std.mem.eql(u8, &admitted.sealed_digest, &sealed.digest)) return error.InvalidMemorySourceAdmission;
    return prepareWithChallenges(a, admitted, kind, witness, claims, try protocol.Challenges.draw(a, sealed));
}

/// Exact independently reconstructed chunk identity. It pins admission and
/// fixed scheduling metadata, not witness contents or a host-computed sum.
pub fn chunkIdentity(admitted: *const protocol.Admitted, kind: equations.Kind) ![32]u8 {
    try equations.validateKind(admitted, kind);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-v5/memory-source-chunk/v1\x00");
    hash.update(&admitted.identity);
    const tag: u32 = switch (kind) {
        .sha => 1,
        .record => 2,
        .leaf => 3,
        .node => 4,
        .root => 5,
    };
    var words: [20]u8 = @splat(0);
    std.mem.writeInt(u32, words[0..4], tag, .little);
    switch (kind) {
        .sha => |v| {
            std.mem.writeInt(u32, words[4..8], @intFromEnum(v.stream), .little);
            std.mem.writeInt(u64, words[8..16], v.block, .little);
        },
        .record => |v| {
            std.mem.writeInt(u32, words[4..8], @intFromEnum(v.stream), .little);
            std.mem.writeInt(u64, words[8..16], v.ordinal, .little);
        },
        .leaf => |v| {
            std.mem.writeInt(u32, words[4..8], @intFromEnum(v.edit), .little);
            std.mem.writeInt(u64, words[8..16], v.ordinal, .little);
        },
        .node => |v| {
            std.mem.writeInt(u32, words[4..8], @intFromEnum(v.edit), .little);
            std.mem.writeInt(u64, words[8..16], v.ordinal, .little);
            std.mem.writeInt(u32, words[16..20], v.height, .little);
        },
        .root => |v| {
            std.mem.writeInt(u32, words[4..8], @intFromEnum(v.edit), .little);
            std.mem.writeInt(u64, words[8..16], v.ordinal, .little);
        },
    }
    hash.update(&words);
    return hash.finalResult();
}

/// Aggregate equation owner. Its inputs MUST eventually be connected to actual
/// freshly proved chunk sums and sorted-memory claims. Evaluating it locally
/// does not authenticate any input and never returns a closure receipt.
pub fn prepareClosureWithChallenges(a: std.mem.Allocator, admitted: *const protocol.Admitted, aggregate: protocol.Sums, sorted_initial: Q, sorted_endpoint: Q, challenges: protocol.Challenges) !*Prepared {
    try admitted.require();
    const count = 2 * equations.PAIR_COUNT + equations.SUM_COUNT + 2 + 32;
    if (admitted.limits.max_nodes < count) return error.MemorySourceResourceLimit;
    const out = try a.create(Prepared);
    out.* = .{ .child = a, .budget = Budget.init(a, admitted.limits.max_chunk_heap_bytes), .admission_id = admitted.identity, .kind = null, .private_input_count = 0 };
    errdefer out.deinit();
    const bounded = out.budget.allocator();
    out.inputs = try bounded.alloc(Q, count);
    var encoded: [equations.INPUT_COUNT]Q = undefined;
    try equations.writeInputs(.{}, challenges, aggregate, &encoded);
    @memcpy(out.inputs.?[0 .. 2 * equations.PAIR_COUNT + equations.SUM_COUNT], encoded[equations.BIT_COUNT..]);
    const sums_start = 2 * equations.PAIR_COUNT;
    const expected_start = sums_start + equations.SUM_COUNT;
    out.inputs.?[expected_start] = sorted_initial;
    out.inputs.?[expected_start + 1] = sorted_endpoint;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-v5/memory-source-closure-equations/v1\x00");
    hash.update(&admitted.identity);
    const identity = hash.finalResult();
    for (out.inputs.?[expected_start + 2 ..], identity) |*value, byte| value.* = Q.fromBase(core.fields.m31.M31.fromCanonical(byte));
    var builder = recorder.Builder.init(bounded);
    defer builder.deinit();
    var symbols: [count]recorder.Scalar = undefined;
    for (&symbols) |*s| s.* = (try builder.input()).value;
    try builder.activate();
    var sink = GraphSink{ .builder = &builder };
    const A = equations.Algebra(recorder.Scalar);
    var pairs: [equations.PAIR_COUNT]A.Pair = undefined;
    for (&pairs, 0..) |*p, i| p.* = .{ .z = symbols[2 * i], .alpha = symbols[2 * i + 1] };
    var sums: A.Sums = undefined;
    inline for (std.meta.fields(A.Sums), 0..) |f, i| @field(sums, f.name) = symbols[sums_start + i];
    try A.closure(admitted, pairs, sums, symbols[expected_start], symbols[expected_start + 1], &sink);
    for (symbols[0 .. 2 * equations.PAIR_COUNT], out.inputs.?[0 .. 2 * equations.PAIR_COUNT]) |s, q| try builder.constrainZero(s.sub(recorder.Scalar.fromSecure(q)));
    for (symbols[expected_start + 2 ..], identity) |s, byte| try builder.constrainZero(s.sub(recorder.Scalar.fromBase(core.fields.m31.M31.fromCanonical(byte))));
    builder.deactivate();
    if (builder.nodes.items.len > admitted.limits.max_nodes) return error.MemorySourceResourceLimit;
    const completed = try builder.finish();
    out.circuit = completed;
    return out;
}
