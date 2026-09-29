//! The circuit AIR's preprocessed trace: per-gate address and multiplicity
//! columns, the fixed lookup tables, and the preprocessed Merkle root.
//!
//! Ports `crates/circuit_common/src/preprocessed.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230) in its original order:
//!
//! - the component column blocks are appended eq, qm31_ops, triple_xor,
//!   m31_to_u32, blake_g_gate, then the fixed tables (`seq_16`, then the
//!   three `bitwise_xor_{n}_{0,1,2}` columns for n in 4, 7, 8, 9, 10);
//! - the columns are stable-sorted by length, so ties keep insertion order;
//! - multiplicities count gate uses, with `multiplicities[0]` raised by the
//!   permutation rows' uses of the constant 0 and the blake_g multiplicity
//!   read from `out_a` and asserted equal for `out_b..out_d`;
//! - permutations lower to Add rows through fresh wires starting at `n_vars`.
//!
//! The fixed tables come from `stwo_core.preprocessed_tables`; the root is
//! committed with the prover's interpolation, evaluation and
//! `MerkleProverLifted.commitLifted` under the plain Blake2s hasher of
//! `Blake2sM31MerkleChannel`, exactly as `CommitmentTreeProver::new` does.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const finalize = @import("finalize.zig");

const M31 = core.fields.m31.M31;
const tables = core.preprocessed_tables;
const CanonicCoset = core.poly.circle.canonic.CanonicCoset;
const ChannelProfile = core.vcs_lifted.channel_profile.proving_5a7c5ed.Blake2sM31MerkleChannel;
const MerkleProver = prover.vcs_lifted.prover.MerkleProverLifted(ChannelProfile.MerkleHasher);
const prover_poly = prover.poly.circle.poly;
const twiddles = prover.poly.twiddles;

pub const Blake2sHash = ChannelProfile.MerkleHasher.Hash;
pub const ComponentSizes = finalize.ComponentSizes;

// Component column ids, in commitment order (`define_preprocessed_columns!`).
pub const EQ_COLUMN_IDS = [_][]const u8{ "eq_in0_address", "eq_in1_address" };
pub const QM31_OPS_COLUMN_IDS = [_][]const u8{
    "qm31_ops_add_flag",
    "qm31_ops_sub_flag",
    "qm31_ops_mul_flag",
    "qm31_ops_pointwise_mul_flag",
    "qm31_ops_in0_address",
    "qm31_ops_in1_address",
    "qm31_ops_out_address",
    "qm31_ops_mults",
};
pub const TRIPLE_XOR_COLUMN_IDS = [_][]const u8{
    "triple_xor_input_addr_0",
    "triple_xor_input_addr_1",
    "triple_xor_input_addr_2",
    "triple_xor_output_addr",
    "triple_xor_multiplicity",
};
pub const M31_TO_U32_COLUMN_IDS = [_][]const u8{
    "m31_to_u32_input_addr",
    "m31_to_u32_output_addr",
    "m31_to_u32_multiplicity",
};
pub const BLAKE_G_GATE_COLUMN_IDS = [_][]const u8{
    "blake_g_gate_input_addr_a",
    "blake_g_gate_input_addr_b",
    "blake_g_gate_input_addr_c",
    "blake_g_gate_input_addr_d",
    "blake_g_gate_input_addr_f0",
    "blake_g_gate_input_addr_f1",
    "blake_g_gate_output_addr_a",
    "blake_g_gate_output_addr_b",
    "blake_g_gate_output_addr_c",
    "blake_g_gate_output_addr_d",
    "blake_g_gate_multiplicity",
};

/// Bit widths of the bitwise-XOR lookup tables (`XOR_TABLE_N_BITS`).
pub const XOR_TABLE_N_BITS = [_]u5{ 4, 7, 8, 9, 10 };
/// Log size of the sequence column used by `range_check_16`.
pub const SEQ_LOG_SIZE: u5 = 16;
pub const N_XOR_TABLE_COLUMNS: usize = 3;

pub const FixedColumn = struct {
    id: []const u8,
    log_size: u32,
    table: union(enum) {
        seq: u5,
        bitwise_xor: struct { n_bits: u5, col_index: u2 },
    },
};

/// `fixed_column_layout`: the fixed lookup-table columns in commitment order.
/// The sole source of their ids.
pub const FIXED_COLUMNS: [1 + XOR_TABLE_N_BITS.len * N_XOR_TABLE_COLUMNS]FixedColumn = blk: {
    var out: [1 + XOR_TABLE_N_BITS.len * N_XOR_TABLE_COLUMNS]FixedColumn = undefined;
    out[0] = .{
        .id = std.fmt.comptimePrint("seq_{d}", .{SEQ_LOG_SIZE}),
        .log_size = SEQ_LOG_SIZE,
        .table = .{ .seq = SEQ_LOG_SIZE },
    };
    var at: usize = 1;
    for (XOR_TABLE_N_BITS) |n_bits| {
        for (0..N_XOR_TABLE_COLUMNS) |col| {
            out[at] = .{
                .id = std.fmt.comptimePrint("bitwise_xor_{d}_{d}", .{ n_bits, col }),
                .log_size = 2 * @as(u32, n_bits),
                .table = .{ .bitwise_xor = .{ .n_bits = n_bits, .col_index = col } },
            };
            at += 1;
        }
    }
    break :blk out;
};

/// Number of preprocessed columns of every circuit
/// (`CIRCUIT_N_PREPROCESSED_COLUMNS`).
pub const N_PREPROCESSED_COLUMNS: usize = EQ_COLUMN_IDS.len + QM31_OPS_COLUMN_IDS.len +
    TRIPLE_XOR_COLUMN_IDS.len + M31_TO_U32_COLUMN_IDS.len + BLAKE_G_GATE_COLUMN_IDS.len +
    FIXED_COLUMNS.len;

comptime {
    std.debug.assert(N_PREPROCESSED_COLUMNS == 45);
}

pub const Error = error{
    ColumnLengthNotPowerOfTwo,
    DuplicateColumnId,
    MultiplicityMismatch,
    VariableOutOfRange,
    AddressOutOfField,
    MissingOutputGate,
} || tables.Error || tables.RowError;

/// One `(id, log_size)` entry of a preprocessed-trace layout.
pub const LayoutEntry = struct {
    id: []const u8,
    log_size: u32,
};

/// The ordered `OrderedHashMap<PreProcessedColumnId, u32>` of column log
/// sizes. Ids borrow static strings.
pub const ColumnLayout = struct {
    entries: [N_PREPROCESSED_COLUMNS]LayoutEntry,

    /// `layout_from_component_sizes`: the layout of a circuit whose
    /// components are padded to `sizes` (powers of two), without building
    /// it.
    pub fn fromComponentSizes(sizes: ComponentSizes) Error!ColumnLayout {
        var layout: ColumnLayout = undefined;
        var at: usize = 0;
        // Order of components must match `fromCircuit`.
        inline for (.{
            .{ &EQ_COLUMN_IDS, sizes.eq },
            .{ &QM31_OPS_COLUMN_IDS, sizes.qm31_ops },
            .{ &TRIPLE_XOR_COLUMN_IDS, sizes.triple_xor },
            .{ &M31_TO_U32_COLUMN_IDS, sizes.m31_to_u32 },
            .{ &BLAKE_G_GATE_COLUMN_IDS, sizes.blake_g_gate },
        }) |block| {
            const size: usize = block[1];
            if (size == 0 or !std.math.isPowerOfTwo(size)) return error.ColumnLengthNotPowerOfTwo;
            for (block[0]) |id| {
                layout.entries[at] = .{ .id = id, .log_size = std.math.log2_int(usize, size) };
                at += 1;
            }
        }
        for (FIXED_COLUMNS) |fixed| {
            layout.entries[at] = .{ .id = fixed.id, .log_size = fixed.log_size };
            at += 1;
        }
        std.debug.assert(at == N_PREPROCESSED_COLUMNS);
        // `PreProcessedTrace::sort_by_size`: stable, ties keep insertion order.
        std.sort.insertion(LayoutEntry, &layout.entries, {}, lessByLogSize);
        return layout;
    }

    /// Log size of column `id`, or null if the layout has no such column.
    pub fn logSize(self: *const ColumnLayout, id: []const u8) ?u32 {
        for (self.entries) |entry| {
            if (std.mem.eql(u8, entry.id, id)) return entry.log_size;
        }
        return null;
    }

    /// Log2 of the trace size: the largest column's log size.
    pub fn traceLogSize(self: *const ColumnLayout) u32 {
        var max: u32 = 0;
        for (self.entries) |entry| max = @max(max, entry.log_size);
        return max;
    }

    pub fn eql(self: *const ColumnLayout, other: *const ColumnLayout) bool {
        for (self.entries, other.entries) |a, b| {
            if (a.log_size != b.log_size or !std.mem.eql(u8, a.id, b.id)) return false;
        }
        return true;
    }
};

fn lessByLogSize(_: void, a: LayoutEntry, b: LayoutEntry) bool {
    return a.log_size < b.log_size;
}

/// Gate records of a finalized circuit, as the preprocessing reads them.
/// Variable indices are `u32` (the builder asserts `n_vars < 2^31`).
pub const BinaryGate = struct { in0: u32, in1: u32, out: u32 };
pub const EqGate = struct { in0: u32, in1: u32 };
pub const TripleXorGate = struct { input_a: u32, input_b: u32, input_c: u32, out: u32 };
pub const M31ToU32Gate = struct { input: u32, out: u32 };
pub const BlakeGGate = struct {
    input_a: u32,
    input_b: u32,
    input_c: u32,
    input_d: u32,
    input_f0: u32,
    input_f1: u32,
    out_a: u32,
    out_b: u32,
    out_c: u32,
    out_d: u32,
};

/// Read-only view of a finalized `Circuit` (`crates/circuits/src/circuit.rs`
/// field for field). Permutations are in CSR form: gate `g` maps
/// `permutation_inputs[offsets[g]..offsets[g + 1]]` to the same range of
/// `permutation_outputs`.
pub const CircuitView = struct {
    n_vars: usize,
    add: []const BinaryGate = &.{},
    sub: []const BinaryGate = &.{},
    mul: []const BinaryGate = &.{},
    pointwise_mul: []const BinaryGate = &.{},
    eq: []const EqGate = &.{},
    triple_xor: []const TripleXorGate = &.{},
    m31_to_u32: []const M31ToU32Gate = &.{},
    blake_g_gate: []const BlakeGGate = &.{},
    permutation_offsets: []const u32 = &.{0},
    permutation_inputs: []const u32 = &.{},
    permutation_outputs: []const u32 = &.{},
    /// `in0` of every output gate.
    output: []const u32 = &.{},

    pub fn nPermutations(self: CircuitView) usize {
        return self.permutation_offsets.len - 1;
    }

    /// Rows the permutations occupy in qm31_ops: one per input and output.
    pub fn permutationRows(self: CircuitView) usize {
        return self.permutation_inputs.len + self.permutation_outputs.len;
    }

    /// `Circuit::compute_multiplicities().0`: uses of every variable.
    pub fn computeUses(self: CircuitView, allocator: std.mem.Allocator) (Error || std.mem.Allocator.Error)![]u32 {
        const uses = try allocator.alloc(u32, self.n_vars);
        errdefer allocator.free(uses);
        @memset(uses, 0);
        const bump = struct {
            fn at(counts: []u32, variable: u32) Error!void {
                if (variable >= counts.len) return error.VariableOutOfRange;
                counts[variable] += 1;
            }
        }.at;
        inline for (.{ self.add, self.sub, self.mul, self.pointwise_mul }) |gates| {
            for (gates) |gate| {
                try bump(uses, gate.in0);
                try bump(uses, gate.in1);
            }
        }
        for (self.eq) |gate| {
            try bump(uses, gate.in0);
            try bump(uses, gate.in1);
        }
        for (self.triple_xor) |gate| {
            try bump(uses, gate.input_a);
            try bump(uses, gate.input_b);
            try bump(uses, gate.input_c);
        }
        for (self.m31_to_u32) |gate| try bump(uses, gate.input);
        for (self.blake_g_gate) |gate| {
            inline for (.{ "input_a", "input_b", "input_c", "input_d", "input_f0", "input_f1" }) |field|
                try bump(uses, @field(gate, field));
        }
        for (self.permutation_inputs) |variable| try bump(uses, variable);
        for (self.output) |variable| try bump(uses, variable);
        return uses;
    }
};

/// One owned preprocessed column.
pub const Column = struct {
    id: []const u8,
    values: []M31,

    pub fn logSize(self: Column) u32 {
        return std.math.log2_int(usize, self.values.len);
    }
};

/// `PreprocessedCircuit`: the ordered preprocessed columns plus the
/// parameters derived from the circuit's structure.
pub const PreprocessedCircuit = struct {
    columns: [N_PREPROCESSED_COLUMNS]Column,
    /// First permutation row of the qm31_ops component.
    first_permutation_row: usize,
    /// Public outputs, excluding the output gate of the `u` wire.
    n_outputs: usize,

    pub fn deinit(self: *PreprocessedCircuit, allocator: std.mem.Allocator) void {
        for (self.columns) |column| allocator.free(column.values);
        self.* = undefined;
    }

    /// `PreprocessedCircuit::from_finalized_circuit`.
    pub fn fromCircuit(allocator: std.mem.Allocator, circuit: CircuitView) (Error || std.mem.Allocator.Error)!PreprocessedCircuit {
        if (circuit.output.len == 0) return error.MissingOutputGate;
        const multiplicities = try circuit.computeUses(allocator);
        defer allocator.free(multiplicities);
        // The permutation rows read the constant 0 once per input and output.
        if (multiplicities.len == 0) return error.VariableOutOfRange;
        multiplicities[0] += @intCast(circuit.permutationRows());

        var builder = TraceBuilder{ .allocator = allocator };
        errdefer builder.deinit();

        // Eq.
        {
            const cols = try builder.block(&EQ_COLUMN_IDS, circuit.eq.len);
            for (circuit.eq, 0..) |gate, row| {
                try put(cols[0], row, gate.in0);
                try put(cols[1], row, gate.in1);
            }
        }
        // QM31 operations: binary ops by kind, then the lowered permutations.
        var first_permutation_row: usize = 0;
        {
            const binary_rows = circuit.add.len + circuit.sub.len + circuit.mul.len + circuit.pointwise_mul.len;
            const cols = try builder.block(&QM31_OPS_COLUMN_IDS, binary_rows + circuit.permutationRows());
            var row: usize = 0;
            inline for (.{ circuit.add, circuit.sub, circuit.mul, circuit.pointwise_mul }, 0..) |gates, op_code| {
                for (gates) |gate| {
                    try putFlags(cols, row, op_code);
                    try put(cols[4], row, gate.in0);
                    try put(cols[5], row, gate.in1);
                    try put(cols[6], row, gate.out);
                    try put(cols[7], row, multiplicities[gate.out]);
                    row += 1;
                }
            }
            first_permutation_row = row;
            // `fill_permutation_columns`: each pair writes the input to the
            // gate's fresh wire and reads the output back from it.
            var permutation_address: usize = circuit.n_vars;
            for (0..circuit.nPermutations()) |gate| {
                const begin = circuit.permutation_offsets[gate];
                const end = circuit.permutation_offsets[gate + 1];
                for (circuit.permutation_inputs[begin..end], circuit.permutation_outputs[begin..end]) |input, output| {
                    try putFlags(cols, row, 0);
                    try put(cols[4], row, 0);
                    try put(cols[5], row, input);
                    try put(cols[6], row, permutation_address);
                    try put(cols[7], row, 1);
                    row += 1;
                    try putFlags(cols, row, 0);
                    try put(cols[4], row, 0);
                    try put(cols[5], row, permutation_address);
                    try put(cols[6], row, output);
                    try put(cols[7], row, multiplicities[output]);
                    row += 1;
                }
                permutation_address += 1;
            }
        }
        // TripleXor.
        {
            const cols = try builder.block(&TRIPLE_XOR_COLUMN_IDS, circuit.triple_xor.len);
            for (circuit.triple_xor, 0..) |gate, row| {
                try put(cols[0], row, gate.input_a);
                try put(cols[1], row, gate.input_b);
                try put(cols[2], row, gate.input_c);
                try put(cols[3], row, gate.out);
                try put(cols[4], row, multiplicities[gate.out]);
            }
        }
        // M31ToU32.
        {
            const cols = try builder.block(&M31_TO_U32_COLUMN_IDS, circuit.m31_to_u32.len);
            for (circuit.m31_to_u32, 0..) |gate, row| {
                try put(cols[0], row, gate.input);
                try put(cols[1], row, gate.out);
                try put(cols[2], row, multiplicities[gate.out]);
            }
        }
        // BlakeGGate: the four outputs share one multiplicity column.
        {
            const cols = try builder.block(&BLAKE_G_GATE_COLUMN_IDS, circuit.blake_g_gate.len);
            for (circuit.blake_g_gate, 0..) |gate, row| {
                inline for (.{
                    "input_a", "input_b", "input_c", "input_d", "input_f0",
                    "input_f1", "out_a",  "out_b",  "out_c",   "out_d",
                }, 0..) |field, col| try put(cols[col], row, @field(gate, field));
                const mult = multiplicities[gate.out_a];
                for ([_]u32{ gate.out_b, gate.out_c, gate.out_d }) |out| {
                    if (multiplicities[out] != mult) return error.MultiplicityMismatch;
                }
                try put(cols[10], row, mult);
            }
        }
        // Fixed lookup tables.
        for (FIXED_COLUMNS) |fixed| {
            const len = @as(usize, 1) << @intCast(fixed.log_size);
            const values = try builder.push(fixed.id, len);
            switch (fixed.table) {
                .seq => |log_size| {
                    const seq = try tables.Seq.init(log_size);
                    for (values, 0..) |*value, row| value.* = M31.fromCanonical(try seq.value(@intCast(row)));
                },
                .bitwise_xor => |xor| {
                    const table = try tables.BitwiseXor.init(xor.n_bits, xor.col_index);
                    for (values, 0..) |*value, row| value.* = M31.fromCanonical(try table.value(@intCast(row)));
                },
            }
        }
        std.debug.assert(builder.len == N_PREPROCESSED_COLUMNS);
        // `sort_by_size`: stable by length.
        std.sort.insertion(Column, &builder.columns, {}, lessByLength);
        for (builder.columns) |column| {
            if (column.values.len == 0 or !std.math.isPowerOfTwo(column.values.len))
                return error.ColumnLengthNotPowerOfTwo;
        }
        const columns = builder.columns;
        builder.len = 0;
        return .{
            .columns = columns,
            .first_permutation_row = first_permutation_row,
            .n_outputs = circuit.output.len - 1,
        };
    }

    /// `PreProcessedTrace::log_sizes`.
    pub fn layout(self: *const PreprocessedCircuit) ColumnLayout {
        var out: ColumnLayout = undefined;
        for (self.columns, &out.entries) |column, *entry| entry.* = .{ .id = column.id, .log_size = column.logSize() };
        return out;
    }

    pub fn traceLogSize(self: *const PreprocessedCircuit) u32 {
        return self.layout().traceLogSize();
    }

    pub fn columnValues(self: *const PreprocessedCircuit, id: []const u8) ?[]const M31 {
        for (self.columns) |entry| {
            if (std.mem.eql(u8, entry.id, id)) return entry.values;
        }
        return null;
    }

    /// `PreprocessedCircuit::preprocessed_root`: the Merkle root of the
    /// preprocessed trace committed as tree 0 of a proof of this circuit, at
    /// lifting height `trace_log_size + log_blowup_factor`.
    ///
    /// Each column is interpolated on its canonic coset, evaluated on the
    /// blown-up canonic coset (bit-reversed, as `CommitmentTreeProver::new`
    /// does) and committed with `commitLifted`. Peak memory is the extended
    /// columns plus one Merkle leaf layer at the lifting height.
    pub fn preprocessedRoot(
        self: *const PreprocessedCircuit,
        allocator: std.mem.Allocator,
        log_blowup_factor: u32,
    ) !Blake2sHash {
        const lifting_log_size = self.traceLogSize() + log_blowup_factor;
        var trees = TwiddleCache{ .allocator = allocator };
        defer trees.deinit();

        const extended = try allocator.alloc([]M31, self.columns.len);
        defer allocator.free(extended);
        var n_extended: usize = 0;
        defer for (extended[0..n_extended]) |values| allocator.free(values);

        for (self.columns) |entry| {
            const log_size = entry.logSize();
            const domain = CanonicCoset.new(log_size).circleDomain();
            const extended_domain = CanonicCoset.new(log_size + log_blowup_factor).circleDomain();
            const coeffs_buffer = try allocator.dupe(M31, entry.values);
            var coeffs = prover_poly.interpolateOwnedValuesWithTwiddles(
                domain,
                coeffs_buffer,
                try trees.get(log_size),
            ) catch |err| {
                allocator.free(coeffs_buffer);
                return err;
            };
            defer coeffs.deinit(allocator);
            const evaluation = try coeffs.evaluateWithTwiddles(
                allocator,
                extended_domain,
                try trees.get(log_size + log_blowup_factor),
            );
            extended[n_extended] = @constCast(evaluation.values);
            n_extended += 1;
        }

        const views = try allocator.alloc([]const M31, n_extended);
        defer allocator.free(views);
        for (views, extended[0..n_extended]) |*view, values| view.* = values;
        var merkle = try MerkleProver.commitLifted(allocator, views, lifting_log_size);
        defer merkle.deinit(allocator);
        return merkle.root();
    }
};

/// Twiddle trees keyed by circle-domain log size, each rooted at that
/// domain's own half coset. Upstream precomputes one tree at the lifting
/// size and borrows its doublings; the values are identical, but core's
/// `Coset.isDoublingOf` rejects a size-1 half coset reached by doubling, so
/// each domain gets an exact root here.
const TwiddleCache = struct {
    allocator: std.mem.Allocator,
    trees: [32]?twiddles.TwiddleTree([]M31) = .{null} ** 32,

    fn get(self: *TwiddleCache, log_size: u32) !twiddles.TwiddleTree([]const M31) {
        if (self.trees[log_size] == null) {
            self.trees[log_size] = try twiddles.precomputeM31(
                self.allocator,
                CanonicCoset.new(log_size).circleDomain().half_coset,
            );
        }
        const tree = self.trees[log_size].?;
        return .{ .root_coset = tree.root_coset, .twiddles = tree.twiddles, .itwiddles = tree.itwiddles };
    }

    fn deinit(self: *TwiddleCache) void {
        for (&self.trees) |*slot| {
            if (slot.*) |*tree| twiddles.deinitM31(self.allocator, tree);
            slot.* = null;
        }
    }
};

fn lessByLength(_: void, a: Column, b: Column) bool {
    return a.values.len < b.values.len;
}

/// Accumulates owned columns in commitment order.
const TraceBuilder = struct {
    allocator: std.mem.Allocator,
    columns: [N_PREPROCESSED_COLUMNS]Column = undefined,
    len: usize = 0,

    fn push(self: *TraceBuilder, id: []const u8, n_rows: usize) (Error || std.mem.Allocator.Error)![]M31 {
        for (self.columns[0..self.len]) |existing| {
            if (std.mem.eql(u8, existing.id, id)) return error.DuplicateColumnId;
        }
        const values = try self.allocator.alloc(M31, n_rows);
        self.columns[self.len] = .{ .id = id, .values = values };
        self.len += 1;
        return values;
    }

    fn block(self: *TraceBuilder, comptime ids: anytype, n_rows: usize) (Error || std.mem.Allocator.Error)![ids.len][]M31 {
        var out: [ids.len][]M31 = undefined;
        for (ids, &out) |id, *slot| slot.* = try self.push(id, n_rows);
        return out;
    }

    fn deinit(self: *TraceBuilder) void {
        for (self.columns[0..self.len]) |column| self.allocator.free(column.values);
        self.len = 0;
    }
};

inline fn put(column: []M31, row: usize, value: usize) Error!void {
    if (value >= core.fields.m31.Modulus) return error.AddressOutOfField;
    column[row] = M31.fromCanonical(@intCast(value));
}

/// The one-hot op-code flags of `push_op_code_flags` (Add, Sub, Mul,
/// PointwiseMul), in columns 0..4 of the qm31_ops block.
inline fn putFlags(cols: [QM31_OPS_COLUMN_IDS.len][]M31, row: usize, op_code: usize) Error!void {
    inline for (0..4) |flag| try put(cols[flag], row, @intFromBool(flag == op_code));
}

test {
    _ = @import("preprocessed_test.zig");
}
