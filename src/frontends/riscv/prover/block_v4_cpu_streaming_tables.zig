//! Table first-round commitments from pass-one counters, before SourceSeal.
//! The counter arrays and shard plan borrow the streaming first-round roster.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const table = @import("block_memory_shared_table_proof_v2.zig").ForBackend(Cpu);
const shard = @import("block_execution_range_shard_v2.zig");
const counter = @import("../air/lookups/tables/counter.zig").Counter;
const batch = @import("block_memory_batch_verify_v2.zig");
const seal = @import("block_memory_source_seal_v2.zig").SourceSeal;

pub const Tables = struct {
    a: std.mem.Allocator,
    plan: *const shard.Plan,
    counters: []counter,
    first: []table.FirstRound,
    roots: []batch.Roots,
    wires: []batch.SerializedTableProof,

    /// All table fixed/main roots are committed before the bound SourceSeal
    /// draws relation challenges. Pass two may never replace these counters.
    pub fn init(a: std.mem.Allocator, plan: *const shard.Plan, counters: []counter, config: core.pcs.PcsConfig) !Tables {
        if (plan.shards.len != counters.len) return error.InvalidStreamingTableRoster;
        const first = try a.alloc(table.FirstRound, counters.len);
        errdefer a.free(first);
        const roots = try a.alloc(batch.Roots, counters.len);
        errdefer a.free(roots);
        const wires = try a.alloc(batch.SerializedTableProof, counters.len);
        errdefer a.free(wires);
        var count: usize = 0;
        errdefer for (first[0..count]) |*value| value.deinit(a);
        for (plan.shards, counters, first, roots) |part, *multiplicities, *commitment, *root| {
            commitment.* = try table.commitFirstRound(a, multiplicities, part, config);
            count += 1;
            root.* = commitment.roots;
        }
        return .{ .a = a, .plan = plan, .counters = counters, .first = first, .roots = roots, .wires = wires };
    }

    pub fn prove(self: *Tables, bound: seal, capture: anytype) !void {
        for (self.plan.shards, self.first, self.counters, self.roots, self.wires) |part, *commitment, *multiplicities, roots, *wire| {
            var proof = try table.prove(self.a, commitment, multiplicities, part, bound, roots);
            defer proof.deinit(self.a);
            wire.* = .{ .stark_bytes = try capture.encode(proof.stark), .claim = proof.claim };
        }
    }

    pub fn deinit(self: *Tables) void {
        for (self.first) |*value| value.deinit(self.a);
        self.a.free(self.wires);
        self.a.free(self.roots);
        self.a.free(self.first);
        self.* = undefined;
    }
};
