//! Parallel LogUp materialization for the nonproduction SWAP proof profile.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const work_pool = @import("stwo_prover_engine").work_pool;
const contract = @import("stack_swap_component_v1.zig");
const trace_mod = @import("stack_swap_trace_v1.zig");
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
    inputs: contract.Inputs,
    pool: *work_pool.WorkPool,
) !Result(Config) {
    const generated = try logup.generateParallelColumns(
        Config.batch_count,
        allocator,
        Context(Config){ .trace = trace, .inputs = inputs },
        trace.log_size,
        pool,
    );
    return .{ .columns = generated.columns, .claims = generated.claims };
}

pub fn TraceFor(comptime Config: type) type {
    if (Config == contract.Caller) return trace_mod.CallerTrace;
    if (Config == contract.Word) return trace_mod.WordTrace;
    @compileError("unsupported stack-swap interaction configuration");
}

fn Context(comptime Config: type) type {
    return struct {
        trace: *const TraceFor(Config),
        inputs: contract.Inputs,

        pub fn rowPairsAt(
            self: @This(),
            logical_row: usize,
        ) [Config.batch_count]logup.RowPair {
            const main = self.trace.mainRow(logical_row);
            const lane_last = self.trace.preprocessedAt(
                trace_mod.lane_last_column,
                logical_row,
            );
            return Config.rowPairs(M31, &main, lane_last, self.inputs);
        }
    };
}

comptime {
    if (production_active or contract.production_active or
        contract.Caller.interaction_column_count != 36 or
        contract.Word.interaction_column_count != 16)
    {
        @compileError("stack-swap interaction geometry drifted");
    }
}
