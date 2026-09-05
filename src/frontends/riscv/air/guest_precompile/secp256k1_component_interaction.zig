//! Parallel cumulative LogUp columns for one compact secp256k1 row family.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const work_pool = @import("stwo_prover_engine").work_pool;
const logup = @import("../logup.zig");
const relations_mod = @import("secp256k1_relations.zig");
const trace_mod = @import("secp256k1_component_trace.zig");

pub fn Result(comptime Config: type) type {
    return struct {
        columns: [4 * Config.batch_count][]M31,
        claims: [Config.batch_count]QM31,

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            for (self.columns) |column| allocator.free(column);
            self.* = undefined;
        }
    };
}

pub fn generate(
    comptime Config: type,
    allocator: std.mem.Allocator,
    trace: *const trace_mod.Trace(Config),
    relations: *const relations_mod.Relations,
    pool: *work_pool.WorkPool,
) !Result(Config) {
    const generated = try logup.generateParallelColumns(
        Config.batch_count,
        allocator,
        Context(Config){ .trace = trace, .relations = relations },
        trace.log_size,
        pool,
    );
    return .{ .columns = generated.columns, .claims = generated.claims };
}

fn Context(comptime Config: type) type {
    return struct {
        trace: *const trace_mod.Trace(Config),
        relations: *const relations_mod.Relations,

        pub fn rowPairsAt(self: @This(), logical_row: usize) [Config.batch_count]logup.RowPair {
            const size = self.trace.domainSize();
            const main = self.trace.mainRow(logical_row);
            const previous = self.trace.mainRow((logical_row + size - 1) % size);
            const next = self.trace.mainRow((logical_row + 1) % size);
            return Config.rowPairs(M31, &main, &previous, &next, self.relations);
        }
    };
}
