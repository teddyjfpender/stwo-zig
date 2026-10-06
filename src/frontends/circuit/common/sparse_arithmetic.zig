//! Versioned arithmetic-only circuit preprocessing for S31 sparse-v3.
//! It commits only QM31 operations, M31-to-u32 conversions, and the 16-bit
//! range table. Circuits with Eq, XOR, or Blake-G gates are rejected.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const preprocessed = @import("preprocessed.zig");
const builder_circuit = @import("../builder/circuit.zig");

const M31 = core.fields.m31.M31;
pub const N_COLUMNS: usize = preprocessed.QM31_OPS_COLUMN_IDS.len +
    preprocessed.M31_TO_U32_COLUMN_IDS.len + 1;
pub const active_component_indices = [_]usize{ 1, 3, 10 };

pub const Layout = struct {
    entries: [N_COLUMNS]preprocessed.LayoutEntry,

    pub fn fromSizes(qm31_rows: usize, m31_rows: usize) !Layout {
        if (qm31_rows < 16 or m31_rows < 16 or
            !std.math.isPowerOfTwo(qm31_rows) or !std.math.isPowerOfTwo(m31_rows))
            return error.InvalidSparseTraceShape;
        var result: Layout = undefined;
        var at: usize = 0;
        for (preprocessed.QM31_OPS_COLUMN_IDS) |id| {
            result.entries[at] = .{ .id = id, .log_size = std.math.log2_int(usize, qm31_rows) };
            at += 1;
        }
        for (preprocessed.M31_TO_U32_COLUMN_IDS) |id| {
            result.entries[at] = .{ .id = id, .log_size = std.math.log2_int(usize, m31_rows) };
            at += 1;
        }
        result.entries[at] = .{ .id = "seq_16", .log_size = 16 };
        std.sort.insertion(preprocessed.LayoutEntry, &result.entries, {}, struct {
            fn less(_: void, a: preprocessed.LayoutEntry, b: preprocessed.LayoutEntry) bool {
                return a.log_size < b.log_size;
            }
        }.less);
        return result;
    }

    pub fn logSize(self: *const Layout, id: []const u8) ?u32 {
        for (self.entries) |entry| if (std.mem.eql(u8, entry.id, id)) return entry.log_size;
        return null;
    }

    pub fn traceLogSize(self: *const Layout) u32 {
        var log: u32 = 0;
        for (self.entries) |entry| log = @max(log, entry.log_size);
        return log;
    }
};

pub const Circuit = struct {
    columns: [N_COLUMNS]preprocessed.Column,
    first_permutation_row: usize,
    n_outputs: usize,

    pub fn deinit(self: *Circuit, allocator: std.mem.Allocator) void {
        for (self.columns) |column| allocator.free(column.values);
        self.* = undefined;
    }

    pub fn fromBuilderCircuit(allocator: std.mem.Allocator, source: *const builder_circuit.Circuit) !Circuit {
        return fromCircuit(allocator, .fromBuilder(source));
    }

    pub fn fromCircuit(allocator: std.mem.Allocator, source: preprocessed.CircuitView) !Circuit {
        try source.validate();
        if (source.output.len == 0 or source.eq.len != 0 or
            source.triple_xor.len != 0 or source.blake_g_gate.len != 0)
            return error.UnsupportedSparseCircuit;
        if (source.nQm31OpsRows() < 16 or source.m31_to_u32.len < 16 or
            !std.math.isPowerOfTwo(source.nQm31OpsRows()) or
            !std.math.isPowerOfTwo(source.m31_to_u32.len))
            return error.InvalidSparseTraceShape;
        const multiplicities = try source.computeUses(allocator);
        defer allocator.free(multiplicities);
        if (multiplicities.len == 0) return error.InvalidSparseTraceShape;
        multiplicities[0] += @intCast(source.permutationRows());

        var columns: [N_COLUMNS]preprocessed.Column = undefined;
        var count: usize = 0;
        errdefer for (columns[0..count]) |column| allocator.free(column.values);
        const Add = struct {
            fn column(a: std.mem.Allocator, out: *[N_COLUMNS]preprocessed.Column, at: *usize, id: []const u8, len: usize) ![]M31 {
                const values = try a.alloc(M31, len);
                @memset(values, M31.zero());
                out[at.*] = .{ .id = id, .values = values };
                at.* += 1;
                return values;
            }
        }.column;
        var q: [preprocessed.QM31_OPS_COLUMN_IDS.len][]M31 = undefined;
        for (preprocessed.QM31_OPS_COLUMN_IDS, &q) |id, *column|
            column.* = try Add(allocator, &columns, &count, id, source.nQm31OpsRows());
        var row: usize = 0;
        inline for (.{ source.add, source.sub, source.mul, source.pointwise_mul }, 0..) |gates, opcode| {
            for (gates) |gate| {
                inline for (0..4) |flag| q[flag][row] = M31.fromU64(@intFromBool(flag == opcode));
                try put(q[4], row, gate.in0);
                try put(q[5], row, gate.in1);
                try put(q[6], row, gate.out);
                try put(q[7], row, multiplicities[gate.out]);
                row += 1;
            }
        }
        const first_permutation_row = row;
        var permutation_address: usize = source.n_vars;
        for (0..source.nPermutations()) |gate| {
            const begin, const end = source.permutationRange(gate);
            for (source.permutation_inputs[begin..end], source.permutation_outputs[begin..end]) |input, output| {
                q[0][row] = M31.one();
                try put(q[4], row, 0);
                try put(q[5], row, input);
                try put(q[6], row, permutation_address);
                try put(q[7], row, 1);
                row += 1;
                q[0][row] = M31.one();
                try put(q[4], row, 0);
                try put(q[5], row, permutation_address);
                try put(q[6], row, output);
                try put(q[7], row, multiplicities[output]);
                row += 1;
            }
            permutation_address += 1;
        }
        if (row != q[0].len) return error.InvalidSparseTraceShape;

        var m: [preprocessed.M31_TO_U32_COLUMN_IDS.len][]M31 = undefined;
        for (preprocessed.M31_TO_U32_COLUMN_IDS, &m) |id, *column|
            column.* = try Add(allocator, &columns, &count, id, source.m31_to_u32.len);
        for (source.m31_to_u32, 0..) |gate, i| {
            try put(m[0], i, gate.input);
            try put(m[1], i, gate.out);
            try put(m[2], i, multiplicities[gate.out]);
        }

        const seq = try Add(allocator, &columns, &count, "seq_16", 1 << 16);
        for (seq, 0..) |*value, i| value.* = M31.fromU64(i);
        std.debug.assert(count == N_COLUMNS);
        std.sort.insertion(preprocessed.Column, &columns, {}, struct {
            fn less(_: void, a: preprocessed.Column, b: preprocessed.Column) bool {
                return a.values.len < b.values.len;
            }
        }.less);
        return .{
            .columns = columns,
            .first_permutation_row = first_permutation_row,
            .n_outputs = source.output.len - 1,
        };
    }

    pub fn layout(self: *const Circuit) Layout {
        var result: Layout = undefined;
        for (self.columns, &result.entries) |column, *entry|
            entry.* = .{ .id = column.id, .log_size = column.logSize() };
        return result;
    }

    pub fn traceLogSize(self: *const Circuit) u32 {
        const shape = self.layout();
        return shape.traceLogSize();
    }

    pub fn columnValues(self: *const Circuit, id: []const u8) ?[]const M31 {
        for (self.columns) |column| if (std.mem.eql(u8, column.id, id)) return column.values;
        return null;
    }

    pub fn preprocessedRoot(self: *const Circuit, allocator: std.mem.Allocator, blowup: u32) ![32]u8 {
        var evaluations: [N_COLUMNS]prover.pcs.ColumnEvaluation = undefined;
        for (self.columns, &evaluations) |column, *evaluation|
            evaluation.* = .{ .log_size = column.logSize(), .values = column.values };
        var twiddles = prover.poly.twiddle_source.TwiddleSource.initOwned(allocator);
        defer twiddles.deinit(allocator);
        var prepared = try prover.pcs.column_preparation.prepareColumnsForCommitBorrowedForBackend(
            prover.pcs.HostMerkleBackend,
            allocator,
            &evaluations,
            blowup,
            .never,
            &twiddles,
        );
        var tree = prover.pcs.CommitmentTreeProver(core.vcs_lifted.channel_profile.proving_5a7c5ed.Blake2sM31MerkleChannel.MerkleHasher).initPrepared(
            allocator,
            &prepared,
            null,
        ) catch |err| {
            prepared.deinit(allocator);
            return err;
        };
        defer tree.deinit(allocator);
        return tree.root();
    }
};

fn put(column: []M31, row: usize, value: usize) !void {
    if (value >= core.fields.m31.Modulus) return error.AddressOutOfField;
    column[row] = M31.fromCanonical(@intCast(value));
}

test "sparse arithmetic layout has only needed fixed table" {
    const allocator = std.testing.allocator;
    const builder = @import("../builder/mod.zig");
    var ctx = try builder.Context(builder.NoValue).init(allocator, 0);
    defer ctx.deinit();
    try ctx.finalize(false);
    const raw = @import("finalize.zig").rawComponentSizes(.fromBuilder(&ctx.circuit));
    try @import("finalize.zig").padToTargets(builder.NoValue, &ctx, .{
        .eq = 0,
        .qm31_ops = @import("finalize.zig").paddedSize(raw.qm31_ops),
        .m31_to_u32 = @import("finalize.zig").paddedSize(raw.m31_to_u32),
        .triple_xor = 0,
        .blake_g_gate = 0,
    });
    var sparse = try Circuit.fromBuilderCircuit(allocator, &ctx.circuit);
    defer sparse.deinit(allocator);
    try std.testing.expectEqual(@as(usize, N_COLUMNS), sparse.columns.len);
    try std.testing.expectEqual(@as(u32, 16), sparse.traceLogSize());
}
