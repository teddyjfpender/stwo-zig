//! Singleton LogUp columns for the two Keccak lookup multiplicity tables.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const work_pool = @import("stwo_prover_engine").work_pool;
const logup = @import("../logup.zig");
const counters_mod = @import("keccakf_multiplicities.zig");
const relations_mod = @import("keccakf_relations.zig");
const tables = @import("keccakf_tables.zig");

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
    kind: tables.Kind,
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
        tables.logSize(kind),
        pool,
    );
    return .{ .columns = generated.columns, .claim = generated.claims[0] };
}

const Context = struct {
    kind: tables.Kind,
    multiplicities: []const M31,
    relations: *const relations_mod.Relations,

    pub fn rowPairsAt(self: Context, logical_row: usize) [1]logup.RowPair {
        const tuple = tables.tupleAt(self.kind, logical_row) catch unreachable;
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
