//! Arithmetic, equality, and u16 range preprocessing for S31 wide values.
//! This is a distinct profile from sparse-v3: Eq gates remain active, while
//! XOR and Blake-G components and their fixed tables are absent.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const pp = @import("preprocessed.zig");
const sparse = @import("sparse_arithmetic.zig");
const builder = @import("../builder/circuit.zig");

const M31 = core.fields.m31.M31;
pub const N_COLUMNS: usize = pp.EQ_COLUMN_IDS.len + sparse.N_COLUMNS;
pub const active_component_indices = [_]usize{ 0, 1, 3, 10 };
/// Transcript domain shared by the native prover and recursive statement.
pub const profile_tag: u64 = 0x5333315350573501;
pub const profile_zero_words = [_]u32{ 0, 0, 0 };

pub const Layout = struct {
    entries: [N_COLUMNS]pp.LayoutEntry,

    pub fn fromSizes(eq_rows: usize, qm_rows: usize, conversion_rows: usize) !Layout {
        if (eq_rows < 16 or qm_rows < 16 or conversion_rows < 16 or
            !std.math.isPowerOfTwo(eq_rows) or !std.math.isPowerOfTwo(qm_rows) or
            !std.math.isPowerOfTwo(conversion_rows)) return error.InvalidSparseWideShape;
        var result: Layout = undefined;
        var at: usize = 0;
        inline for (.{ .{ &pp.EQ_COLUMN_IDS, eq_rows }, .{ &pp.QM31_OPS_COLUMN_IDS, qm_rows }, .{ &pp.M31_TO_U32_COLUMN_IDS, conversion_rows } }) |block| {
            for (block[0]) |id| {
                result.entries[at] = .{ .id = id, .log_size = std.math.log2_int(usize, block[1]) };
                at += 1;
            }
        }
        result.entries[at] = .{ .id = "seq_16", .log_size = 16 };
        std.sort.insertion(pp.LayoutEntry, &result.entries, {}, lessLayout);
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

fn lessLayout(_: void, a: pp.LayoutEntry, b: pp.LayoutEntry) bool {
    return a.log_size < b.log_size;
}

pub const Circuit = struct {
    columns: [N_COLUMNS]pp.Column,
    first_permutation_row: usize,
    n_outputs: usize,
    sha_boundary: ?sparse.ShaBoundary = null,
    sha_boundary_pair: ?sparse.ShaBoundaryPair = null,

    pub fn deinit(self: *Circuit, allocator: std.mem.Allocator) void {
        for (self.columns) |column| allocator.free(column.values);
        self.* = undefined;
    }

    pub fn fromBuilderCircuit(allocator: std.mem.Allocator, source: *const builder.Circuit) !Circuit {
        return fromCircuit(allocator, .fromBuilder(source));
    }

    pub fn fromBuilderCircuitWithShaBoundary(allocator: std.mem.Allocator, source: *const builder.Circuit, boundary: sparse.ShaBoundary) !Circuit {
        return fromCircuitWithShaBoundary(allocator, .fromBuilder(source), boundary);
    }

    pub fn fromBuilderCircuitWithShaBoundaryPair(allocator: std.mem.Allocator, source: *const builder.Circuit, boundaries: sparse.ShaBoundaryPair) !Circuit {
        return fromCircuitWithShaBoundaryPair(allocator, .fromBuilder(source), boundaries);
    }

    pub fn fromCircuit(allocator: std.mem.Allocator, source: pp.CircuitView) !Circuit {
        return fromCircuitOptionalBoundaries(allocator, source, null, null);
    }

    pub fn fromCircuitWithShaBoundary(allocator: std.mem.Allocator, source: pp.CircuitView, boundary: sparse.ShaBoundary) !Circuit {
        return fromCircuitOptionalBoundaries(allocator, source, boundary, null);
    }

    pub fn fromCircuitWithShaBoundaryPair(allocator: std.mem.Allocator, source: pp.CircuitView, boundaries: sparse.ShaBoundaryPair) !Circuit {
        return fromCircuitOptionalBoundaries(allocator, source, null, boundaries);
    }

    fn fromCircuitOptionalBoundaries(allocator: std.mem.Allocator, source: pp.CircuitView, boundary: ?sparse.ShaBoundary, boundary_pair: ?sparse.ShaBoundaryPair) !Circuit {
        try source.validate();
        if (source.output.len == 0 or source.triple_xor.len != 0 or source.blake_g_gate.len != 0 or
            source.eq.len < 16 or !std.math.isPowerOfTwo(source.eq.len)) return error.UnsupportedSparseWideCircuit;
        var without_eq = source;
        without_eq.eq = &.{};
        var old = try sparse.Circuit.fromCircuit(allocator, without_eq);
        defer old.deinit(allocator);
        const uses = try source.computeUses(allocator);
        defer allocator.free(uses);
        uses[0] += @intCast(source.permutationRows());
        if (boundary) |sha| {
            try sha.validate(source);
            for (sha.addresses) |address| uses[address] += 1;
        }
        if (boundary_pair) |pair| {
            try pair.validate(source);
            for (pair.first.addresses) |address| uses[address] += 1;
            for (pair.second.addresses) |address| uses[address] += 1;
        }

        const eq_in0 = try allocator.alloc(M31, source.eq.len);
        errdefer allocator.free(eq_in0);
        const eq_in1 = try allocator.alloc(M31, source.eq.len);
        errdefer allocator.free(eq_in1);
        for (source.eq, 0..) |gate, row| {
            eq_in0[row] = M31.fromCanonical(gate.in0);
            eq_in1[row] = M31.fromCanonical(gate.in1);
        }
        var columns: [N_COLUMNS]pp.Column = undefined;
        var ready: usize = 0;
        errdefer for (columns[2..ready]) |column| allocator.free(column.values);
        columns[ready] = .{ .id = pp.EQ_COLUMN_IDS[0], .values = eq_in0 };
        ready += 1;
        columns[ready] = .{ .id = pp.EQ_COLUMN_IDS[1], .values = eq_in1 };
        ready += 1;
        // These two buffers have moved to `columns`; the errdefer above owns
        // them from here onward. The old sparse columns are copied below.
        for (old.columns) |column| {
            columns[ready] = .{ .id = column.id, .values = try allocator.dupe(M31, column.values) };
            ready += 1;
        }
        var result: Circuit = .{
            .columns = columns,
            .first_permutation_row = old.first_permutation_row,
            .n_outputs = old.n_outputs,
            .sha_boundary = boundary,
            .sha_boundary_pair = boundary_pair,
        };
        const q_out = result.mutableColumn("qm31_ops_out_address") orelse unreachable;
        const q_mults = result.mutableColumn("qm31_ops_mults") orelse unreachable;
        for (q_out, q_mults) |address, *multiplicity| {
            const index = address.toU32();
            if (index < uses.len) multiplicity.* = M31.fromU64(uses[index]);
        }
        const m_out = result.mutableColumn("m31_to_u32_output_addr") orelse unreachable;
        const m_mults = result.mutableColumn("m31_to_u32_multiplicity") orelse unreachable;
        for (m_out, m_mults) |address, *multiplicity| multiplicity.* = M31.fromU64(uses[address.toU32()]);
        std.sort.insertion(pp.Column, &result.columns, {}, struct {
            fn less(_: void, a: pp.Column, b: pp.Column) bool {
                return a.values.len < b.values.len;
            }
        }.less);
        return result;
    }

    fn mutableColumn(self: *Circuit, id: []const u8) ?[]M31 {
        for (&self.columns) |*column| if (std.mem.eql(u8, column.id, id)) return column.values;
        return null;
    }

    pub fn columnValues(self: *const Circuit, id: []const u8) ?[]const M31 {
        for (self.columns) |column| if (std.mem.eql(u8, column.id, id)) return column.values;
        return null;
    }

    pub fn layout(self: *const Circuit) Layout {
        var result: Layout = undefined;
        for (self.columns, &result.entries) |column, *entry| entry.* = .{ .id = column.id, .log_size = column.logSize() };
        return result;
    }

    pub fn traceLogSize(self: *const Circuit) u32 {
        const shape = self.layout();
        return shape.traceLogSize();
    }

    pub fn sparseView(self: *const Circuit) sparse.Circuit {
        var out: sparse.Circuit = undefined;
        var at: usize = 0;
        for (self.columns) |column| {
            if (std.mem.eql(u8, column.id, pp.EQ_COLUMN_IDS[0]) or
                std.mem.eql(u8, column.id, pp.EQ_COLUMN_IDS[1])) continue;
            out.columns[at] = column;
            at += 1;
        }
        std.debug.assert(at == sparse.N_COLUMNS);
        out.first_permutation_row = self.first_permutation_row;
        out.n_outputs = self.n_outputs;
        out.sha_boundary = self.sha_boundary;
        return out; // Borrowed columns: never call `deinit` on this view.
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

test "sparse-wide layout retains Eq and range but excludes bitwise tables" {
    const allocator = std.testing.allocator;
    const context = @import("../builder/mod.zig");
    const finalize = @import("finalize.zig");
    var ctx = try context.Context(context.NoValue).init(allocator, 0);
    defer ctx.deinit();
    try ctx.eq(ctx.zero(), ctx.zero());
    try ctx.finalize(false);
    const raw = finalize.rawComponentSizes(.fromBuilder(&ctx.circuit));
    try finalize.padToTargets(context.NoValue, &ctx, .{
        .eq = finalize.paddedSize(raw.eq),
        .qm31_ops = finalize.paddedSize(raw.qm31_ops),
        .m31_to_u32 = finalize.paddedSize(raw.m31_to_u32),
        .triple_xor = 0,
        .blake_g_gate = 0,
    });
    var selected = try Circuit.fromBuilderCircuit(allocator, &ctx.circuit);
    defer selected.deinit(allocator);
    try std.testing.expectEqual(@as(usize, N_COLUMNS), selected.columns.len);
    try std.testing.expectEqual(@as(u32, 16), selected.traceLogSize());
    try std.testing.expect(selected.columnValues("eq_in0_address") != null);
    try std.testing.expect(selected.columnValues("triple_xor_input_addr_0") == null);
}
