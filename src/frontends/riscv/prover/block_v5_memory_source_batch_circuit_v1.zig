//! Owned bounded circuit construction for the batch operation equations.
//! Construction/evaluation is a correctness witness, NOT a source receipt.
//! Descriptors select real equation templates, never source omission policy.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Record = @import("../recursion/air/composition_graph_recorder.zig");
const Eq = @import("../recursion/air/block_v5_memory_source_batch_equations_v1.zig");
const Protocol = @import("block_v5_memory_source_batch_protocol_v1.zig");
const Fold = @import("block_v5_memory_source_batch_fold_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.HostBudgetAllocator;
pub const SUM_COUNT = std.meta.fields(Eq.Algebra(Q).Sums).len;
pub const INPUT_COUNT = Eq.BIT_COUNT + SUM_COUNT;
pub const Limits = struct { max_heap_bytes: usize = 128 * 1024 * 1024, max_nodes: usize = 1_000_000 };
pub const ScalarSink = struct {
    pub fn zero(_: *@This(), value: Q) !void {
        if (!value.isZero()) return error.UnsatisfiedSourceFoldEquation;
    }
};
const GraphSink = struct {
    builder: *Record.Builder,
    pub fn zero(self: *@This(), value: Record.Scalar) !void {
        try self.builder.constrainZero(value);
    }
};
pub fn propose(comptime hash_oracle: bool, admitted: *const Protocol.Admission, operation: Fold.Operation, challenges: Protocol.Challenges) !Eq.Algebra(Q).Sums {
    try admitted.require();
    var inputs: [Eq.BIT_COUNT]Q = undefined;
    try Eq.writeInputs(operation, &inputs);
    var sink = ScalarSink{};
    return Eq.Algebra(Q).compute(hash_oracle, admitted, .{ .kind = operation.kind, .height = operation.coordinate.height }, &inputs, Eq.Algebra(Q).challenges(challenges), &sink);
}
pub const Prepared = struct {
    child: std.mem.Allocator,
    budget: Budget,
    admission: [32]u8,
    descriptor: Eq.Descriptor,
    hash_oracle: bool,
    circuit: ?Record.Circuit = null,
    inputs: ?[]Q = null,
    pub fn deinit(self: *Prepared) void {
        if (self.circuit) |*circuit| circuit.deinit();
        if (self.inputs) |inputs| self.budget.allocator().free(inputs);
        if (self.budget.live_bytes != 0) @panic("source fold circuit owner leak");
        const child = self.child;
        child.destroy(self);
    }
    pub fn evaluate(self: *Prepared) !void {
        const a = self.budget.allocator();
        const values = try a.alloc(Q, self.circuit.?.nodes.len);
        defer a.free(values);
        try self.circuit.?.evaluateInto(self.inputs.?, values);
    }
    pub fn publicClaims(self: *const Prepared) []const Q {
        return self.inputs.?[Eq.BIT_COUNT..];
    }
};
/// Graph is reconstructed from independent source admission and the exact
/// public equation-template kind/height, independent of private cell values.
/// Packed mode omits bit-hash computation and emits hash-bus requests; it
/// MUST be paired with actual packed core proofs and a fresh hash-bus join.
pub fn prepare(comptime hash_oracle: bool, a: std.mem.Allocator, admitted: *const Protocol.Admission, operation: Fold.Operation, claims: Eq.Algebra(Q).Sums, challenges: Protocol.Challenges, limits: Limits) !*Prepared {
    try admitted.require();
    const descriptor = Eq.Descriptor{ .kind = operation.kind, .height = operation.coordinate.height };
    try descriptor.validate();
    if (limits.max_heap_bytes == 0 or limits.max_nodes < INPUT_COUNT or limits.max_nodes >= core.fields.m31.Modulus) return error.InvalidSourceFoldCircuitLimits;
    const out = try a.create(Prepared);
    out.* = .{ .child = a, .budget = Budget.init(a, limits.max_heap_bytes), .admission = admitted.identity, .descriptor = descriptor, .hash_oracle = hash_oracle };
    errdefer out.deinit();
    const bounded = out.budget.allocator();
    out.inputs = try bounded.alloc(Q, INPUT_COUNT);
    try Eq.writeInputs(operation, out.inputs.?[0..Eq.BIT_COUNT]);
    inline for (std.meta.fields(Eq.Algebra(Q).Sums), 0..) |field, i| out.inputs.?[Eq.BIT_COUNT + i] = @field(claims, field.name);
    var builder = Record.Builder.init(bounded);
    defer builder.deinit();
    var symbols: [INPUT_COUNT]Record.Scalar = undefined;
    for (&symbols) |*symbol| symbol.* = (try builder.input()).value;
    try builder.activate();
    var sink = GraphSink{ .builder = &builder };
    const computed = try Eq.Algebra(Record.Scalar).compute(hash_oracle, admitted, descriptor, symbols[0..Eq.BIT_COUNT], Eq.Algebra(Record.Scalar).challenges(challenges), &sink);
    inline for (std.meta.fields(Eq.Algebra(Q).Sums), 0..) |field, i| try builder.constrainZero(@field(computed, field.name).sub(symbols[Eq.BIT_COUNT + i]));
    builder.deactivate();
    if (builder.nodes.items.len > limits.max_nodes) return error.SourceFoldCircuitResourceLimit;
    const completed = try builder.finish();
    out.circuit = completed;
    return out;
}
