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
//!   read from the first output (`out_base`) and asserted equal for the other three;
//! - permutations lower to Add rows through fresh wires starting at `n_vars`.
//!
//! The fixed tables come from `stwo_core.preprocessed_tables`; the root is
//! committed through the prover's PCS column preparation and
//! `CommitmentTreeProver` under the plain Blake2s hasher of
//! `Blake2sM31MerkleChannel`, as upstream's `CommitmentTreeProver::new` does.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const finalize = @import("finalize.zig");
const builder_circuit = @import("../builder/circuit.zig");
const builder_context = @import("../builder/context.zig");

const M31 = core.fields.m31.M31;
const tables = core.preprocessed_tables;
const ChannelProfile = core.vcs_lifted.channel_profile.proving_5a7c5ed.Blake2sM31MerkleChannel;

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
    MultiplicityOutOfField,
    VariableOutOfRange,
    DuplicateProducerAddress,
    AddressOutOfField,
    MissingOutputGate,
    InvalidShaPrivateBoundary,
    PublicShaPrivateBoundary,
    DuplicateShaPrivateBoundary,
    InvalidShaBoundaryProducer,
} || tables.Error || tables.RowError;

/// Gate lookup multiplicities are M31 values. Reject a count that would
/// become zero or alias a smaller count after field conversion.
fn addCanonicalMultiplicity(counter: *u32, increment: usize) Error!void {
    const modulus: u32 = core.fields.m31.Modulus;
    if (increment >= @as(usize, modulus)) return error.MultiplicityOutOfField;
    const addend: u32 = @intCast(increment);
    if (counter.* >= modulus - addend) return error.MultiplicityOutOfField;
    counter.* += addend;
}

test "Gate multiplicities reject characteristic wrap" {
    const modulus: u32 = core.fields.m31.Modulus;
    var count: u32 = modulus - 2;
    try addCanonicalMultiplicity(&count, 1);
    try std.testing.expectEqual(modulus - 1, count);
    try std.testing.expectError(error.MultiplicityOutOfField, addCanonicalMultiplicity(&count, 1));
    try std.testing.expectEqual(modulus - 1, count);

    var empty: u32 = 0;
    try std.testing.expectError(error.MultiplicityOutOfField, addCanonicalMultiplicity(&empty, modulus));
    try std.testing.expectEqual(@as(u32, 0), empty);
    var invalid: u32 = std.math.maxInt(u32);
    try std.testing.expectError(error.MultiplicityOutOfField, addCanonicalMultiplicity(&invalid, 0));
}

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

/// Gate records of a finalized circuit: the builder's own (`builder/circuit.zig`).
/// Variable indices are `u32` (the builder asserts `n_vars < 2^31`).
pub const BinaryGate = builder_circuit.BinaryGate;
pub const EqGate = builder_circuit.EqGate;
pub const TripleXorGate = builder_circuit.TripleXorGate;
pub const M31ToU32Gate = builder_circuit.M31ToU32Gate;
/// Outputs `out_base .. out_base + 3` (`outputs()`).
pub const BlakeGGate = builder_circuit.BlakeGGate;

/// Read-only view of a finalized `Circuit` (`crates/circuits/src/circuit.rs`
/// field for field), borrowing the gate lists. Permutations are in the
/// builder's CSR form: gate `g` maps `permutation_inputs[start..end]` to the
/// same range of `permutation_outputs`, with `end = permutation_ends[g]` and
/// `start` the previous gate's end (0 for the first).
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
    permutation_ends: []const u32 = &.{},
    permutation_inputs: []const u32 = &.{},
    permutation_outputs: []const u32 = &.{},
    /// `in0` of every output gate.
    output: []const u32 = &.{},

    /// A view of a builder circuit; borrows its lists.
    pub fn fromBuilder(circuit: *const builder_circuit.Circuit) CircuitView {
        return .{
            .n_vars = circuit.n_vars,
            .add = circuit.add.items,
            .sub = circuit.sub.items,
            .mul = circuit.mul.items,
            .pointwise_mul = circuit.pointwise_mul.items,
            .eq = circuit.eq.items,
            .triple_xor = circuit.triple_xor.items,
            .m31_to_u32 = circuit.m31_to_u32.items,
            .blake_g_gate = circuit.blake_g_gate.items,
            .permutation_ends = circuit.permutation.ends.items,
            .permutation_inputs = circuit.permutation.inputs.items,
            .permutation_outputs = circuit.permutation.outputs.items,
            .output = circuit.output.items,
        };
    }

    pub fn nPermutations(self: CircuitView) usize {
        return self.permutation_ends.len;
    }

    /// The input and output range of permutation gate `gate`.
    pub fn permutationRange(self: CircuitView, gate: usize) struct { usize, usize } {
        const begin = if (gate == 0) 0 else self.permutation_ends[gate - 1];
        return .{ begin, self.permutation_ends[gate] };
    }

    /// Rows the permutations occupy in qm31_ops: one per input and output.
    pub fn permutationRows(self: CircuitView) usize {
        return self.permutation_inputs.len + self.permutation_outputs.len;
    }

    /// `qm31_ops_n_rows`: binary-op gates plus one row per permutation input
    /// and output.
    pub fn nQm31OpsRows(self: CircuitView) usize {
        return self.add.len + self.sub.len + self.mul.len + self.pointwise_mul.len + self.permutationRows();
    }

    /// Checks every index `fromCircuit` dereferences: gate outputs below
    /// `n_vars` and a CSR permutation layout (ends never decrease, the last
    /// is the input count, and outputs pair one-to-one with inputs). Upstream indexes with bounds-checked `Vec`s and panics; this
    /// port fails closed with `VariableOutOfRange` instead. Use indices are
    /// checked by `computeUses`.
    pub fn validate(self: CircuitView) Error!void {
        const check = struct {
            fn at(n_vars: usize, variable: u32) Error!void {
                if (variable >= n_vars) return error.VariableOutOfRange;
            }
        }.at;
        inline for (.{ self.add, self.sub, self.mul, self.pointwise_mul }) |gates| {
            for (gates) |gate| try check(self.n_vars, gate.out);
        }
        for (self.triple_xor) |gate| try check(self.n_vars, gate.out);
        for (self.m31_to_u32) |gate| try check(self.n_vars, gate.out);
        for (self.blake_g_gate) |gate| {
            // `out_base + 3 < n_vars` bounds all four outputs.
            if (gate.out_base >= self.n_vars or self.n_vars - gate.out_base < 4) return error.VariableOutOfRange;
        }
        for (self.permutation_outputs) |variable| try check(self.n_vars, variable);
        var previous: u32 = 0;
        for (self.permutation_ends) |end| {
            if (end < previous) return error.VariableOutOfRange;
            previous = end;
        }
        if (previous != self.permutation_inputs.len or
            self.permutation_outputs.len != self.permutation_inputs.len)
            return error.VariableOutOfRange;
    }

    /// A Gate address must have at most one producing row. This validates
    /// caller-supplied views as well as builder-owned circuits, so the Gate
    /// lookup's address join cannot mix two producer values at one address.
    pub fn validateUniqueProducers(self: CircuitView, allocator: std.mem.Allocator) (Error || std.mem.Allocator.Error)!void {
        const seen = try allocator.alloc(bool, self.n_vars);
        defer allocator.free(seen);
        @memset(seen, false);
        const mark = struct {
            fn at(flags: []bool, address: u32) Error!void {
                if (address >= flags.len) return error.VariableOutOfRange;
                if (flags[address]) return error.DuplicateProducerAddress;
                flags[address] = true;
            }
        }.at;
        inline for (.{ self.add, self.sub, self.mul, self.pointwise_mul }) |gates|
            for (gates) |gate| try mark(seen, gate.out);
        for (self.triple_xor) |gate| try mark(seen, gate.out);
        for (self.m31_to_u32) |gate| try mark(seen, gate.out);
        for (self.blake_g_gate) |gate|
            for (gate.outputs()) |address| try mark(seen, address);
        for (self.permutation_outputs) |address| try mark(seen, address);
    }

    /// `Circuit::compute_multiplicities().0`: uses of every variable.
    pub fn computeUses(self: CircuitView, allocator: std.mem.Allocator) (Error || std.mem.Allocator.Error)![]u32 {
        const uses = try allocator.alloc(u32, self.n_vars);
        errdefer allocator.free(uses);
        @memset(uses, 0);
        const bump = struct {
            fn at(counts: []u32, variable: u32) Error!void {
                if (variable >= counts.len) return error.VariableOutOfRange;
                try addCanonicalMultiplicity(&counts[variable], 1);
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

/// Fixed Gate addresses for one private 80-byte Bitcoin header and its
/// 32-byte SHA256d digest. The caller AIR consumes one extra Gate yield at
/// each address. The verifier derives these addresses from value-free
/// topology; they are never chosen by the proof witness.
pub const ShaBoundary = struct {
    addresses: [56]u32,

    pub fn validate(self: ShaBoundary, source: CircuitView) !void {
        for (self.addresses, 0..) |address, index| {
            if (address <= 2 or address >= source.n_vars or address >= core.fields.m31.Modulus)
                return error.InvalidShaPrivateBoundary;
            if (std.mem.indexOfScalar(u32, source.output, address) != null)
                return error.PublicShaPrivateBoundary;
            for (self.addresses[0..index]) |earlier|
                if (earlier == address) return error.DuplicateShaPrivateBoundary;
            var producers: u32 = 0;
            inline for (.{ source.add, source.sub, source.mul, source.pointwise_mul }) |gates|
                for (gates) |gate| {
                    producers += @intFromBool(gate.out == address);
                };
            for (source.m31_to_u32) |gate| producers += @intFromBool(gate.out == address);
            for (source.permutation_outputs) |out| producers += @intFromBool(out == address);
            if (producers != 1) return error.InvalidShaBoundaryProducer;
        }
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
    sha_boundary: ?ShaBoundary = null,

    pub fn deinit(self: *PreprocessedCircuit, allocator: std.mem.Allocator) void {
        for (self.columns) |column| allocator.free(column.values);
        self.* = undefined;
    }

    /// `PreprocessedCircuit::from_finalized_circuit`.
    pub fn fromCircuit(allocator: std.mem.Allocator, circuit: CircuitView) (Error || std.mem.Allocator.Error)!PreprocessedCircuit {
        return fromCircuitOptionalBoundary(allocator, circuit, null);
    }

    pub fn fromCircuitWithShaBoundary(allocator: std.mem.Allocator, circuit: CircuitView, boundary: ShaBoundary) !PreprocessedCircuit {
        return fromCircuitOptionalBoundary(allocator, circuit, boundary);
    }

    fn fromCircuitOptionalBoundary(allocator: std.mem.Allocator, circuit: CircuitView, boundary: ?ShaBoundary) !PreprocessedCircuit {
        if (circuit.output.len == 0) return error.MissingOutputGate;
        try circuit.validate();
        try circuit.validateUniqueProducers(allocator);
        const multiplicities = try circuit.computeUses(allocator);
        defer allocator.free(multiplicities);
        // The permutation rows read the constant 0 once per input and output.
        if (multiplicities.len == 0) return error.VariableOutOfRange;
        try addCanonicalMultiplicity(&multiplicities[0], circuit.permutationRows());
        if (boundary) |sha| {
            try sha.validate(circuit);
            for (sha.addresses) |address| try addCanonicalMultiplicity(&multiplicities[address], 1);
        }

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
                const begin, const end = circuit.permutationRange(gate);
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
                const outputs = gate.outputs();
                for (gate.inputs() ++ outputs, 0..) |variable, col| try put(cols[col], row, variable);
                const mult = multiplicities[outputs[0]];
                for (outputs[1..]) |out| {
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
            .sha_boundary = boundary,
        };
    }

    /// `PreprocessedCircuit::preprocess_circuit`: pads the finalized
    /// context's components (`pad_context`), then preprocesses its circuit.
    pub fn preprocessContext(
        comptime V: type,
        allocator: std.mem.Allocator,
        ctx: *builder_context.Context(V),
    ) (Error || finalize.PadError || std.mem.Allocator.Error)!PreprocessedCircuit {
        try finalize.padContext(V, ctx);
        return fromBuilderCircuit(allocator, &ctx.circuit);
    }

    /// `PreprocessedCircuit::from_finalized_circuit` of a finalized builder
    /// circuit, read in place (`CircuitView.fromBuilder`).
    pub fn fromBuilderCircuit(allocator: std.mem.Allocator, circuit: *const builder_circuit.Circuit) (Error || std.mem.Allocator.Error)!PreprocessedCircuit {
        return fromCircuit(allocator, .fromBuilder(circuit));
    }

    pub fn fromBuilderCircuitWithShaBoundary(allocator: std.mem.Allocator, circuit: *const builder_circuit.Circuit, boundary: ShaBoundary) !PreprocessedCircuit {
        return fromCircuitWithShaBoundary(allocator, .fromBuilder(circuit), boundary);
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
    /// The columns go through the prover's own commit path, as
    /// `CommitmentTreeProver::new` does upstream: the shared PCS column
    /// preparation (interpolate on the canonic coset, extend to the blown-up
    /// coset, bit-reversed) followed by the host lifted Merkle tree. The
    /// values are borrowed; only the extended columns are allocated.
    pub fn preprocessedRoot(
        self: *const PreprocessedCircuit,
        allocator: std.mem.Allocator,
        log_blowup_factor: u32,
    ) !Blake2sHash {
        var evaluations: [N_PREPROCESSED_COLUMNS]prover.pcs.ColumnEvaluation = undefined;
        for (self.columns, &evaluations) |column, *evaluation| {
            evaluation.* = .{ .log_size = column.logSize(), .values = column.values };
        }
        var twiddle_source = prover.poly.twiddle_source.TwiddleSource.initOwned(allocator);
        defer twiddle_source.deinit(allocator);
        var prepared = try prover.pcs.column_preparation.prepareColumnsForCommitBorrowedForBackend(
            prover.pcs.HostMerkleBackend,
            allocator,
            &evaluations,
            log_blowup_factor,
            .never,
            &twiddle_source,
        );
        var tree = prover.pcs.CommitmentTreeProver(ChannelProfile.MerkleHasher).initPrepared(allocator, &prepared, null) catch |err| {
            prepared.deinit(allocator);
            return err;
        };
        defer tree.deinit(allocator);
        return tree.root();
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

/// Writes an address or multiplicity. Deliberate fail-closed deviation:
/// upstream's `BaseField::from` reduces a value `>= P` modulo P, which would
/// alias two addresses; here it is rejected with `AddressOutOfField`. The
/// builder bounds `n_vars` below 2^31, so no valid circuit reaches it.
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
