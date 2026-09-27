//! Retain actual source batch construction/emission paths; never execute them.
const std = @import("std");
const Fold = @import("prover/block_v5_memory_source_batch_fold_v1.zig");
const Circuit = @import("prover/block_v5_memory_source_batch_circuit_v1.zig");
const Protocol = @import("prover/block_v5_memory_source_batch_protocol_v1.zig");
const HashCircuit = @import("prover/block_v5_memory_source_batch_hash_circuit_v1.zig");
const Hash = @import("prover/block_v5_memory_source_packed_hash_v1.zig");
const Q = @import("stwo_core").fields.qm31.QM31;
const G = @import("recursion/air/blake3_g_call.zig");
const Xor = @import("recursion/air/blake3_xor_call.zig");
const Sink = struct {
    pub fn g(_: *@This(), _: *const G.Row) !void {}
    pub fn xor(_: *@This(), _: *const Xor.Row) !void {}
    pub fn boundary(_: *@This(), _: Hash.Boundary) !void {}
    pub fn frame(_: *@This(), _: Hash.Frame, _: u32, _: [32]u8) !void {}
    pub fn defaultFrame(_: *@This(), _: u32, _: Hash.Frame, _: u32, _: [32]u8) !void {}
};
noinline fn construct(a: std.mem.Allocator, admitted: *const Protocol.Admission, operation: Fold.Operation, challenges: Protocol.Challenges) !*Circuit.Prepared {
    return Circuit.prepare(false, a, admitted, operation, try Circuit.propose(false, admitted, operation, challenges), challenges, .{});
}
noinline fn hashConstruct(a: std.mem.Allocator, frame: Hash.Frame, capture: *const HashCircuit.Capture, wire: @import("recursion/air/universal_challenges.zig").Elements, challenge: @import("recursion/air/block_v5_memory_source_batch_equations_v1.zig").Algebra(Q).Pair) !*HashCircuit.Prepared {
    return HashCircuit.prepare(a, frame, 1, 100, capture, wire, challenge, try HashCircuit.propose(frame, 1, 100, capture, wire, challenge), .{});
}
var hash_construct_body: *const @TypeOf(hashConstruct) = hashConstruct;
noinline fn generate(operation: Fold.Operation, sink: *Sink) !u32 {
    return Hash.emitOperation(operation, 10, sink);
}
var construct_body: *const fn (std.mem.Allocator, *const Protocol.Admission, Fold.Operation, Protocol.Challenges) anyerror!*Circuit.Prepared = construct;
var generate_body: *const fn (Fold.Operation, *Sink) anyerror!u32 = generate;
test "source batch actual bodies: bounded construction packed core emission and owned graph destruction retained only" {
    std.mem.doNotOptimizeAway(&construct_body);
    std.mem.doNotOptimizeAway(&hash_construct_body);
    std.mem.doNotOptimizeAway(&generate_body);
    std.mem.doNotOptimizeAway(&Fold.Cursor.init);
    std.mem.doNotOptimizeAway(&Fold.Cursor.next);
    std.mem.doNotOptimizeAway(&Circuit.Prepared.evaluate);
    std.mem.doNotOptimizeAway(&Circuit.Prepared.deinit);
    std.mem.doNotOptimizeAway(Q.zero());
}
