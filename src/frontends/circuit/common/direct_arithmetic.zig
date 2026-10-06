//! S31 direct-M31 arithmetic profile: QM31 operation AIR only.
//! Public M31 values are bound as base-field values, so this profile has no
//! M31-to-u32 component and no 16-bit range table.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const preprocessed = @import("preprocessed.zig");
const builder_circuit = @import("../builder/circuit.zig");

const M31 = core.fields.m31.M31;
pub const N_COLUMNS: usize = preprocessed.QM31_OPS_COLUMN_IDS.len;
pub const active_component_indices = [_]usize{1};

pub const Layout = struct {
    entries: [N_COLUMNS]preprocessed.LayoutEntry,

    pub fn fromSize(qm31_rows: usize) !Layout {
        if (qm31_rows < 16 or !std.math.isPowerOfTwo(qm31_rows))
            return error.InvalidDirectTraceShape;
        var result: Layout = undefined;
        for (preprocessed.QM31_OPS_COLUMN_IDS, &result.entries) |id, *entry|
            entry.* = .{ .id = id, .log_size = std.math.log2_int(usize, qm31_rows) };
        return result;
    }

    pub fn logSize(self: *const Layout, id: []const u8) ?u32 {
        for (self.entries) |entry| if (std.mem.eql(u8, entry.id, id)) return entry.log_size;
        return null;
    }

    pub fn traceLogSize(self: *const Layout) u32 {
        return self.entries[0].log_size;
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
        if (source.output.len == 0 or source.eq.len != 0 or source.triple_xor.len != 0 or
            source.m31_to_u32.len != 0 or source.blake_g_gate.len != 0)
            return error.UnsupportedDirectCircuit;
        const n_rows = source.nQm31OpsRows();
        if (n_rows < 16 or !std.math.isPowerOfTwo(n_rows)) return error.InvalidDirectTraceShape;
        const multiplicities = try source.computeUses(allocator);
        defer allocator.free(multiplicities);
        if (multiplicities.len == 0) return error.InvalidDirectTraceShape;
        multiplicities[0] += @intCast(source.permutationRows());

        var columns: [N_COLUMNS]preprocessed.Column = undefined;
        var count: usize = 0;
        errdefer for (columns[0..count]) |column| allocator.free(column.values);
        var q: [N_COLUMNS][]M31 = undefined;
        for (preprocessed.QM31_OPS_COLUMN_IDS, &q) |id, *slot| {
            const values = try allocator.alloc(M31, n_rows);
            @memset(values, M31.zero());
            columns[count] = .{ .id = id, .values = values };
            count += 1;
            slot.* = values;
        }
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
        if (row != n_rows) return error.InvalidDirectTraceShape;
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
        return self.columns[0].logSize();
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
