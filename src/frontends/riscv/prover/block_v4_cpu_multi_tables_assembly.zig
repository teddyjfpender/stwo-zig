//! Field-safe execution byte-table shards shared across ordered CPU leaves.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const shard = @import("block_execution_range_shard_v2.zig");
const counter_mod = @import("../air/lookups/tables/counter.zig");
const table = @import("block_memory_shared_table_proof_v2.zig").ForBackend(Cpu);
const seal = @import("block_memory_source_seal_v2.zig").SourceSeal;
const batch = @import("block_memory_batch_verify_v2.zig");
const execution_mod = @import("block_v4_cpu_multi_execution_assembly.zig");

pub const Tables = struct {
    a: std.mem.Allocator,
    plan: shard.Plan,
    counters: []counter_mod.Counter,
    first: []table.FirstRound,
    roots: []batch.Roots,
    wires: []batch.SerializedTableProof,

    pub fn init(a: std.mem.Allocator, executions: []execution_mod.Execution, counts: []const u64, comptime extension: bool, config: core.pcs.PcsConfig) !Tables {
        if (executions.len != counts.len) return error.InvalidExecutionRangeRoster;
        var plan = try shard.plan(a, counts);
        errdefer plan.deinit(a);
        const counters = try a.alloc(counter_mod.Counter, plan.shards.len);
        errdefer a.free(counters);
        const first = try a.alloc(table.FirstRound, plan.shards.len);
        errdefer a.free(first);
        const roots = try a.alloc(batch.Roots, plan.shards.len);
        errdefer a.free(roots);
        const wires = try a.alloc(batch.SerializedTableProof, plan.shards.len);
        errdefer a.free(wires);
        var counter_count: usize = 0;
        var first_count: usize = 0;
        errdefer {
            for (first[0..first_count]) |*value| value.deinit(a);
            for (counters[0..counter_count]) |*value| value.deinit(a);
        }
        for (plan.shards, 0..) |part, i| {
            counters[i] = try counter_mod.Counter.init(a, .range_check_8_8);
            counter_count += 1;
            const begin: usize = part.first_instance;
            const end = begin + part.instance_count;
            for (executions[begin..end], begin..) |*execution, index| {
                if (extension) {
                    if (execution.externalCounter()) |source| {
                        merge(&counters[i], source);
                    } else if (counts[index] != 0) return error.MissingExecutionRangeCounter;
                } else merge(&counters[i], execution.opcodeCounter());
            }
            first[i] = try table.commitFirstRound(a, &counters[i], part, config);
            first_count += 1;
            roots[i] = first[i].roots;
        }
        return .{ .a = a, .plan = plan, .counters = counters, .first = first, .roots = roots, .wires = wires };
    }

    pub fn prove(self: *Tables, bound: seal, capture: anytype) !void {
        for (self.plan.shards, self.first, self.counters, self.roots, self.wires) |part, *first, *counter, roots, *wire| {
            var proof = try table.prove(self.a, first, counter, part, bound, roots);
            defer proof.deinit(self.a);
            wire.* = .{ .stark_bytes = try capture.encode(proof.stark), .claim = proof.claim };
        }
    }

    pub fn deinit(self: *Tables) void {
        for (self.first) |*value| value.deinit(self.a);
        for (self.counters) |*value| value.deinit(self.a);
        self.plan.deinit(self.a);
        self.a.free(self.wires);
        self.a.free(self.roots);
        self.a.free(self.first);
        self.a.free(self.counters);
        self.* = undefined;
    }
};

fn merge(destination: *counter_mod.Counter, source: *const counter_mod.Counter) void {
    std.debug.assert(destination.values.len == source.values.len);
    for (destination.values, source.values) |*value, addend| value.* = value.add(addend);
}
