//! Consume original joint proofs once, retaining verifier rows and claims only.
//! No recursive wrappers are proved here. Independent admission owners must
//! outlive this collection and the later detached claim reconstruction.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Sources = @import("block_v6_recursive_sources_v1.zig");
const Protocol = @import("block_v6_partitioned_native_proof_v1.zig");
const Capture = @import("block_v6_partitioned_recursive_capture_v1.zig").ForBackend(Cpu);
const Native = @import("../recursion/block_v6_partitioned_public_bus_v1.zig");
const Mixed = @import("../recursion/block_v6_mixed_direct_public_v1.zig");
const Claims = @import("../recursion/block_v6_mixed_claim_types_v1.zig");
const Reconstruct = @import("../recursion/block_v6_mixed_claim_reconstruct_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub const Limits = struct {
    max_executions: usize = Mixed.MAX_CHILDREN,
    max_live_bytes: usize = 8 << 30,
    circuit_capacity: u32 = 2,
};
pub const Owner = struct {
    a: std.mem.Allocator,
    proof_allocator: std.mem.Allocator,
    budget: *Budget,
    sources: *const Sources.Owner,
    limits: Limits,
    pieces: []Native.Prepared,
    records: []Claims.Record,
    expected: []Mixed.Expected,
    inputs: []Reconstruct.Input,
    initialized: usize = 0,

    pub fn create(backing: std.mem.Allocator, proof_allocator: std.mem.Allocator, sources: *const Sources.Owner, limits: Limits) !*Owner {
        try sources.require();
        const n = sources.executions.len;
        if (n == 0 or n > limits.max_executions or limits.max_executions > Mixed.MAX_CHILDREN or limits.max_live_bytes == 0 or limits.circuit_capacity == 0)
            return error.NativeRecursiveCollectionResourceLimit;
        const budget = try Budget.createRetainingParent(backing, limits.max_live_bytes);
        errdefer budget.destroy();
        const a = budget.allocator();
        const self = try a.create(Owner);
        errdefer a.destroy(self);
        const pieces = try a.alloc(Native.Prepared, n);
        errdefer a.free(pieces);
        const records = try a.alloc(Claims.Record, n);
        errdefer a.free(records);
        const expected = try a.alloc(Mixed.Expected, n);
        errdefer a.free(expected);
        const inputs = try a.alloc(Reconstruct.Input, n);
        errdefer a.free(inputs);
        for (sources.executions, expected, inputs, 0..) |*admitted, *pin, *input, i| {
            if (admitted.native.index != i) return error.UntrustedNativeRecursiveCollectionIndex;
            pin.* = .{ .native = .{ .index = @intCast(i), .template = admitted.template_id } };
            input.* = .{ .native = admitted };
        }
        self.* = .{ .a = a, .proof_allocator = proof_allocator, .budget = budget, .sources = sources, .limits = limits, .pieces = pieces, .records = records, .expected = expected, .inputs = inputs };
        return self;
    }
    pub fn deinit(self: *Owner) void {
        const a = self.a;
        for (self.pieces[0..self.initialized], self.records[0..self.initialized]) |*piece, record| {
            piece.deinit();
            a.free(record.claim.native.projection);
            a.free(record.claim.native.memory);
        }
        a.free(self.pieces);
        a.free(self.records);
        a.free(self.expected);
        a.free(self.inputs);
        const budget = self.budget;
        a.destroy(self);
        budget.destroy();
    }
    pub fn requireFinished(self: *const Owner) !void {
        if (self.initialized != self.pieces.len) return error.IncompleteNativeRecursiveCollection;
    }
    pub fn sink(self: *Owner) @import("block_v5_native_projection_fused_stage_v2.zig").Sink {
        return .{ .context = self, .put_fused = accept };
    }
    fn accept(raw: *anyopaque, index: u32, proof: *Protocol.Proof) !void {
        const self: *Owner = @ptrCast(@alignCast(raw));
        if (index != self.initialized or index >= self.pieces.len) return error.UntrustedNativeRecursiveCollectionIndex;
        const admitted = try self.sources.execution(index);
        // This fresh verifier preserves the original proof on every failure.
        // Only successful publication transfers and destroys caller ownership.
        var capture = try Capture.verifyBorrowed(self.a, proof, admitted, admitted.template_id);
        defer capture.deinit();
        const projection = try self.a.dupe(@import("block_v5_native_projection_fused_proof_v2.zig").Claim, capture.metadata.claims);
        errdefer self.a.free(projection);
        const memory = try self.a.dupe(@import("block_v5_opcode_memory_sidecar_proof_v1.zig").Claim, capture.metadata.memory_claims);
        errdefer self.a.free(memory);
        var piece = try Native.prepare(self.a, admitted, &capture, self.limits.circuit_capacity);
        errdefer piece.deinit();
        if (!std.meta.eql(piece.values.template, self.expected[index].native.template)) return error.UntrustedNativeRecursiveCollectionTemplate;
        self.pieces[index] = piece;
        self.records[index] = .{ .index = index, .claim = .{ .native = .{ .projection = projection, .memory = memory } } };
        self.initialized += 1;
        // The producer allocated this proof using its own backing allocator,
        // not the collection's nested budget allocator.
        proof.deinit(self.proof_allocator);
    }
};
