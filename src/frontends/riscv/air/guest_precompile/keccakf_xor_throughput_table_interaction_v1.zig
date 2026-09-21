//! Table interactions for compact chi plus throughput xor5.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const work_pool = @import("stwo_prover_engine").work_pool;
const logup = @import("../logup.zig");
const compact_tables = @import("keccakf_tables.zig");
const counters_mod = @import("keccakf_xor_throughput_multiplicities_v1.zig");
const relations_mod = @import("keccakf_relations.zig");
const throughput_tables = @import("keccakf_throughput_tables_v1.zig");

pub const production_active = false;
pub const column_count: usize = 4;

pub const Result = struct {
    columns: [column_count][]M31,
    claim: QM31,

    pub fn deinit(self: *Result, allocator: std.mem.Allocator) void {
        for (self.columns) |column| allocator.free(column);
        self.* = undefined;
    }
};

pub fn generate(
    allocator: std.mem.Allocator,
    kind: counters_mod.Kind,
    counters: *const counters_mod.Counters,
    relations: *const relations_mod.Relations,
    pool: *work_pool.WorkPool,
) !Result {
    const generated = try logup.generateParallelColumns(
        1,
        allocator,
        Context{
            .kind = kind,
            .multiplicities = counters.values(kind),
            .relations = relations,
        },
        counters_mod.logSize(kind),
        pool,
    );
    return .{ .columns = generated.columns, .claim = generated.claims[0] };
}

const Context = struct {
    kind: counters_mod.Kind,
    multiplicities: []const M31,
    relations: *const relations_mod.Relations,

    pub fn rowPairsAt(self: Context, logical_row: usize) [1]logup.RowPair {
        const tuple = switch (self.kind) {
            .chi => compact_tables.tupleAt(.chi, logical_row) catch unreachable,
            .xor5 => throughput_tables.tupleAt(.xor5, logical_row) catch unreachable,
        };
        const denominator = switch (self.kind) {
            .chi => self.relations.chi.combineBase(tuple),
            .xor5 => self.relations.xor5.combineBase(tuple),
        };
        return .{logup.RowPair.single(
            QM31.fromBase(self.multiplicities[logical_row]),
            denominator,
        )};
    }
};

comptime {
    if (column_count != 4 or production_active)
        @compileError("Keccak xor-throughput table materializer drifted");
}
