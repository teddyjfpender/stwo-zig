//! Backend-neutral handoff for a verified circuit proof. A device backend
//! supplies its published STARK and the wire representation used by the next
//! recursive verifier; the recursion driver never needs prover aux trees.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const air = @import("../air.zig");
const wire = @import("stwo_circuit_recursion_wire");

pub const Profile = enum { internal, root };
pub const Input = struct {
    values: []const core.fields.qm31.QM31,
    preprocessed: *const circuit.common.preprocessed.PreprocessedCircuit,
    air: *const air.Bundle,
    config: core.pcs.config_v2.PcsConfigV2,
    profile: Profile,
    /// The authenticated registry root (leaf) or independently precomputed
    /// canonical root (fold). A backend still checks the committed proof root.
    expected_preprocessed_root: ?[8]u32 = null,
};
pub const Proof = union(Profile) {
    internal: wire.circuit_serialize.Proof,
    root: wire.circuit_felt_stream.CairoCircuitProof,
};
pub const Produced = struct {
    arena: std.heap.ArenaAllocator,
    proof: Proof,
    preprocessed_root: [8]u32,
    circuit_hash: [8]u32,
    output_digest: [8]u32,

    pub fn deinit(self: *Produced) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
pub const Source = struct {
    context: *anyopaque,
    prove: *const fn (*anyopaque, std.mem.Allocator, Input) anyerror!Produced,

    pub fn run(self: Source, allocator: std.mem.Allocator, input: Input) !Produced {
        return self.prove(self.context, allocator, input);
    }
};
