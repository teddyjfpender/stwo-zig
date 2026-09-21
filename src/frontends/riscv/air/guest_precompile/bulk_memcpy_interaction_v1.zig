//! Parallel LogUp materialization for the nonproduction bulk-memcpy profile.
//!
//! Padding rows contribute zero numerators.  The generated claims therefore
//! bind exactly the active caller/word prefix while retaining the full cyclic
//! trace domain required by the boundary-aware component.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const work_pool = @import("stwo_prover_engine").work_pool;
const contract = @import("bulk_memcpy_component_v1.zig");
const relations_mod = @import("bulk_memcpy_relations_v1.zig");
const trace_mod = @import("bulk_memcpy_trace_v1.zig");
const logup = @import("../logup.zig");

pub const production_active = false;

pub fn Result(comptime Config: type) type {
    return struct {
        columns: [Config.interaction_column_count][]M31,
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
    trace: *const TraceFor(Config),
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

pub fn TraceFor(comptime Config: type) type {
    if (Config == contract.Caller) return trace_mod.CallerTrace;
    if (Config == contract.Word) return trace_mod.WordTrace;
    @compileError("unsupported bulk memcpy interaction configuration");
}

fn Context(comptime Config: type) type {
    return struct {
        trace: *const TraceFor(Config),
        relations: *const relations_mod.Relations,

        pub fn rowPairsAt(
            self: @This(),
            logical_row: usize,
        ) [Config.batch_count]logup.RowPair {
            const main = self.trace.mainRow(logical_row);
            return Config.rowPairs(M31, &main, self.relations);
        }
    };
}

comptime {
    if (production_active or contract.production_active or
        relations_mod.production_active or
        contract.Caller.interaction_column_count != 60 or
        contract.Word.interaction_column_count != 16)
    {
        @compileError("bulk memcpy interaction contract drifted");
    }
}
