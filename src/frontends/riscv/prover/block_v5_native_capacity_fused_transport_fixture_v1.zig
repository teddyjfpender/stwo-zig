//! Literal envelopes for transport only. No commitment/proof is generated and
//! these values cannot satisfy the independent AIR verifier.
const std = @import("std");
const core = @import("stwo_core");
const Codec = @import("block_v5_native_capacity_fused_codec_v1.zig");
const Fused = @import("block_v5_native_capacity_fused_proof_v1.zig");
const Source = @import("block_v5_native_capacity_fused_source_v1.zig");
const Memory = @import("block_v5_opcode_memory_sidecar_proof_v1.zig");
const suite = core.proof_suites.Blake3;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
pub const config = @import("block_v5_native_capacity_transport_fixture_v1.zig").config;
pub fn shape(rw: bool) @import("../air/statement.zig").Blake3ExecutionStatement {
    var result = @import("block_v5_native_capacity_transport_fixture_v1.zig").shape(3);
    if (rw) {
        result.component_descs[0].family = .load_store;
        result.component_descs[0].n_columns = @intCast(@import("../runner/trace.zig").nColumnsForFamily(.load_store));
    }
    return result;
}
pub fn expected(a: std.mem.Allocator, source: *const @import("../air/statement.zig").Blake3ExecutionStatement) !Codec.Expected {
    const frame = @import("../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = 11, .cycle_count = 3 };
    const projections = try Source.slotsFromShapeForMode(a, source, 0, 1);
    defer a.free(projections);
    const memory = try Source.memorySlots(a, source, 0, frame, 1);
    defer a.free(memory);
    const roots: [2][32]u8 = .{ @splat(3), @splat(5) };
    const access: [32]u8 = if (memory.len == 0) try Source.emptyWitnessRoot(1) else @splat(13);
    return .{ .shape = source, .external_retirements = 0, .template_id = @splat(7), .native_instance_id = @splat(11), .fused_instance_id = Fused.instanceId(@splat(7), @splat(11), roots, access, 0, frame, projections, memory), .native_roots = roots, .witness_root = access, .sealed_digest = @splat(17), .index = 0, .frame = frame, .register_custody_mode = 1, .config = config };
}
pub const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    proof: Fused.Proof,
    pub fn init(a: std.mem.Allocator, pin: Codec.Expected) !Fixture {
        var arena = std.heap.ArenaAllocator.init(a);
        errdefer arena.deinit();
        const scratch = arena.allocator();
        var inventory = try Codec.Inventory.init(scratch, pin, .{});
        defer inventory.deinit();
        const geometry = try Codec.geometry(pin, &inventory);
        const projections = try scratch.alloc(Fused.Claim, inventory.projections.len);
        for (projections, inventory.projections) |*claim, slot| claim.* = .{ .sum = Q.zero(), .row_count = slot.n_rows };
        const memory = try scratch.alloc(Memory.Claim, inventory.memory.len);
        @memset(memory, .{ .transition_sum = Q.zero(), .universal_sum = Q.zero(), .range_claims = @splat(Q.zero()), .active_count = 0 });
        const samples = try scratch.alloc([][]Q, geometry.tree_count);
        const queries = try scratch.alloc([][]M, geometry.tree_count);
        const Decommit = core.vcs_lifted.verifier.MerkleDecommitmentLifted(suite.Hasher);
        const decommits = try scratch.alloc(Decommit, geometry.tree_count);
        for (geometry.tree_columns[0..geometry.tree_count], 0..) |count, tree| {
            samples[tree] = try scratch.alloc([]Q, count);
            queries[tree] = try scratch.alloc([]M, count);
            for (samples[tree], queries[tree], 0..) |*sample, *query, column| {
                sample.* = try scratch.dupe(Q, &.{Q.fromBase(M.fromCanonical(@intCast(17 + tree + column)))});
                query.* = try scratch.alloc(M, 0);
            }
            decommits[tree] = .{ .hash_witness = try scratch.alloc(suite.Hasher.Hash, 0) };
        }
        const roots = try scratch.alloc(suite.Hasher.Hash, geometry.tree_count);
        @memset(roots, @splat(19));
        @memcpy(roots[0..2], &pin.native_roots);
        if (inventory.memory.len != 0) roots[2] = pin.witness_root;
        const layers = try scratch.alloc(core.fri.FriLayerProof(suite.Hasher), geometry.max_log - 1);
        const first = core.fri.FriLayerProof(suite.Hasher){ .fri_witness = try scratch.alloc(Q, 0), .decommitment = .{ .hash_witness = try scratch.alloc(suite.Hasher.Hash, 0) }, .commitment = @splat(11) };
        for (layers) |*layer| layer.* = .{ .fri_witness = try scratch.alloc(Q, 0), .decommitment = .{ .hash_witness = try scratch.alloc(suite.Hasher.Hash, 0) }, .commitment = @splat(12) };
        return .{ .arena = arena, .proof = .{ .claims = projections, .memory_claims = memory, .stark = .{ .commitment_scheme_proof = .{
            .config = pin.config,
            .commitments = .{ .items = roots },
            .sampled_values = .{ .items = samples },
            .queried_values = .{ .items = queries },
            .decommitments = .{ .items = decommits },
            .proof_of_work = 0,
            .fri_proof = .{ .first_layer = first, .inner_layers = layers, .last_layer_poly = core.poly.line.LinePoly.initOwned(try scratch.dupe(Q, &.{Q.one()})) },
        } } } };
    }
    pub fn deinit(self: *Fixture) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
