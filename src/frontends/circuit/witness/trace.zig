//! The circuit prover's base and interaction traces.
//!
//! Ports `write_trace` and `write_interaction_trace` of
//! `crates/circuit_prover/src/witness/trace.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230). Column order in each tree is
//! `ComponentList` order, whatever order the work finishes in. Rows are the
//! committed evaluations' indices (bit-reversed circle-domain order), exactly
//! as the preprocessed columns are indexed.
//!
//! The gather components (eq, qm31_ops, triple_xor, m_31_to_u_32 and
//! blake_g_gate) read the context values at the preprocessed address
//! columns; their table uses accumulate into `TableMultiplicities`, which
//! become the table components' multiplicity columns. The interaction pass
//! re-derives every lookup from the committed base columns
//! (`components.zig`) and builds the LogUp columns with the prover engine's
//! `logup_columns`, the port of Stwo's `LogupTraceGenerator`.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const component_list = @import("../common/component_list.zig");
const preprocessed = @import("../common/preprocessed.zig");
const components = @import("components.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const ColumnEvaluation = prover.pcs.ColumnEvaluation;
const PerComponent = component_list.PerComponent;
const N_COMPONENTS = component_list.N_COMPONENTS;
const logup_columns = prover.air.logup_columns;
const Lookup = components.Lookup;

/// `circuits::context::U_VAR_IDX`: the outputs follow the `u` wire.
pub const U_VAR_IDX: usize = 2;

pub const Error = error{
    InvalidPreprocessedCircuit,
    VariableOutOfRange,
    InvalidTraceShape,
} || components.Error;

/// The base trace of one proof: every component's columns, `ComponentList`
/// order, ready for `commit`.
pub const BaseTrace = struct {
    allocator: std.mem.Allocator,
    log_sizes: PerComponent(u32),
    /// Owned flat column list; `takeColumns` hands it to the commitment.
    columns: []ColumnEvaluation,
    /// `CircuitClaim::output_values`: the values after the `u` wire.
    output_values: []QM31,

    pub fn deinit(self: *BaseTrace) void {
        freeColumns(self.allocator, self.columns);
        self.allocator.free(self.output_values);
        self.* = undefined;
    }

    /// Transfers the columns to the caller (the commitment scheme).
    pub fn takeColumns(self: *BaseTrace) []ColumnEvaluation {
        const columns = self.columns;
        self.columns = &.{};
        return columns;
    }
};

pub fn freeColumns(allocator: std.mem.Allocator, columns: []ColumnEvaluation) void {
    for (columns) |column| allocator.free(column.values);
    allocator.free(columns);
}

/// The column widths of each component, `ComponentList` order.
pub fn traceWidths() [N_COMPONENTS]usize {
    var out: [N_COMPONENTS]usize = undefined;
    for (component_list.component_facts.toArray(), &out) |facts, *width| width.* = facts.trace_columns;
    return out;
}

pub fn interactionWidths() [N_COMPONENTS]usize {
    var out: [N_COMPONENTS]usize = undefined;
    for (component_list.component_facts.toArray(), &out) |facts, *width| width.* = facts.interaction_columns;
    return out;
}

/// Accumulates owned columns in `ComponentList` order.
const ColumnSink = struct {
    allocator: std.mem.Allocator,
    columns: std.ArrayListUnmanaged(ColumnEvaluation) = .empty,

    fn block(self: *ColumnSink, comptime n: usize, log_size: u32) ![n][]M31 {
        var out: [n][]M31 = undefined;
        for (&out) |*values| values.* = try self.push(log_size);
        return out;
    }

    fn push(self: *ColumnSink, log_size: u32) ![]M31 {
        const values = try self.allocator.alloc(M31, @as(usize, 1) << @intCast(log_size));
        errdefer self.allocator.free(values);
        try self.columns.append(self.allocator, .{ .log_size = log_size, .values = values });
        return values;
    }

    fn deinit(self: *ColumnSink) void {
        for (self.columns.items) |column| self.allocator.free(column.values);
        self.columns.deinit(self.allocator);
    }
};

const Pp = struct {
    circuit: *const preprocessed.PreprocessedCircuit,

    fn column(self: Pp, id: []const u8) Error![]const M31 {
        return self.circuit.columnValues(id) orelse error.InvalidPreprocessedCircuit;
    }

    fn columns(self: Pp, comptime ids: anytype) Error![ids.len][]const M31 {
        var out: [ids.len][]const M31 = undefined;
        inline for (ids, &out) |id, *values| values.* = try self.column(id);
        const n_rows = out[0].len;
        for (out) |values| if (values.len != n_rows) return error.InvalidPreprocessedCircuit;
        return out;
    }
};

/// A gather component's row count: a power of two of at least `N_LANES`
/// (`ComponentTrace` packs 16-row vectors).
fn gatherLogSize(n_rows: usize) Error!u32 {
    if (n_rows < component_list.N_LANES or !std.math.isPowerOfTwo(n_rows)) return error.InvalidTraceShape;
    return std.math.log2_int(usize, n_rows);
}

fn value(values: []const QM31, address: M31) Error!QM31 {
    const index = address.toU32();
    if (index >= values.len) return error.VariableOutOfRange;
    return values[index];
}

inline fn u32Of(v: QM31) u32 {
    const limbs = v.toM31Array();
    return limbs[0].toU32() | (limbs[1].toU32() << 16);
}

/// `write_trace`: the base trace of `values` (the finalized context's value
/// table) under `circuit`.
pub fn writeTrace(
    allocator: std.mem.Allocator,
    values: []const QM31,
    circuit: *const preprocessed.PreprocessedCircuit,
) (Error || std.mem.Allocator.Error)!BaseTrace {
    const pp = Pp{ .circuit = circuit };
    var sink = ColumnSink{ .allocator = allocator };
    errdefer sink.deinit();
    var tables = try components.TableMultiplicities.init(allocator);
    defer tables.deinit(allocator);
    var log_sizes: [N_COMPONENTS]u32 = undefined;

    // eq.
    {
        const K = components.eq;
        const addr = try pp.columns(preprocessed.EQ_COLUMN_IDS);
        const log_size = try gatherLogSize(addr[0].len);
        log_sizes[0] = log_size;
        const cols = try sink.block(K.n_columns, log_size);
        for (0..addr[0].len) |r| {
            var row: [K.n_columns]M31 = undefined;
            K.row(try value(values, addr[0][r]), &row);
            scatter(K.n_columns, &cols, r, &row);
        }
    }
    // qm31_ops: binary rows, then permutation rows in pairs whose in0 is the
    // zero wire (`extract_component_inputs`).
    {
        const K = components.qm31_ops;
        const pc = try pp.columns(preprocessed.QM31_OPS_COLUMN_IDS);
        const in0 = pc[4];
        const in1 = pc[5];
        const out_address = pc[6];
        const n_rows = in0.len;
        const log_size = try gatherLogSize(n_rows);
        log_sizes[1] = log_size;
        const first_permutation_row = circuit.first_permutation_row;
        if (first_permutation_row > n_rows or (n_rows - first_permutation_row) % 2 != 0)
            return error.InvalidPreprocessedCircuit;
        const cols = try sink.block(K.n_columns, log_size);
        for (0..n_rows) |r| {
            var row: [K.n_columns]M31 = undefined;
            if (r < first_permutation_row) {
                K.row(try value(values, in0[r]), try value(values, in1[r]), try value(values, out_address[r]), &row);
            } else {
                const pair = r - (r - first_permutation_row) % 2;
                const through = if (r == pair)
                    try value(values, in1[pair])
                else
                    try value(values, out_address[pair + 1]);
                K.row(QM31.zero(), through, through, &row);
            }
            scatter(K.n_columns, &cols, r, &row);
        }
    }
    // triple_xor.
    {
        const K = components.triple_xor;
        const pc = try pp.columns(preprocessed.TRIPLE_XOR_COLUMN_IDS);
        const log_size = try gatherLogSize(pc[0].len);
        log_sizes[2] = log_size;
        const cols = try sink.block(K.n_columns, log_size);
        for (0..pc[0].len) |r| {
            var row: [K.n_columns]M31 = undefined;
            K.row(
                u32Of(try value(values, pc[0][r])),
                u32Of(try value(values, pc[1][r])),
                u32Of(try value(values, pc[2][r])),
                u32Of(try value(values, pc[3][r])),
                &row,
            );
            scatter(K.n_columns, &cols, r, &row);
            const lookups = K.lookups(&row, .{ .in0 = pc[0][r], .in1 = pc[1][r], .in2 = pc[2][r], .out = pc[3][r], .mults = pc[4][r] });
            try tables.addUses(&lookups);
        }
    }
    // m_31_to_u_32.
    {
        const K = components.m31_to_u32;
        const pc = try pp.columns(preprocessed.M31_TO_U32_COLUMN_IDS);
        const log_size = try gatherLogSize(pc[0].len);
        log_sizes[3] = log_size;
        const cols = try sink.block(K.n_columns, log_size);
        for (0..pc[0].len) |r| {
            var row: [K.n_columns]M31 = undefined;
            K.row((try value(values, pc[0][r])).toM31Array()[0], &row);
            scatter(K.n_columns, &cols, r, &row);
            const lookups = K.lookups(&row, .{ .input = pc[0][r], .output = pc[1][r], .mults = pc[2][r] });
            try tables.addUses(&lookups);
        }
    }
    // blake_g_gate.
    {
        const K = components.blake_g_gate;
        const pc = try pp.columns(preprocessed.BLAKE_G_GATE_COLUMN_IDS);
        const log_size = try gatherLogSize(pc[0].len);
        log_sizes[4] = log_size;
        const cols = try sink.block(K.n_columns, log_size);
        for (0..pc[0].len) |r| {
            var words: [10]u32 = undefined;
            for (&words, 0..) |*word, index| word.* = u32Of(try value(values, pc[index][r]));
            var row: [K.n_columns]M31 = undefined;
            K.row(words, &row);
            scatter(K.n_columns, &cols, r, &row);
            const lookups = K.lookups(&row, blakePp(&pc, r));
            try tables.addUses(&lookups);
        }
    }
    // The tables: their multiplicity columns.
    const table_columns = .{
        .{ &tables.xor8, components.xor_8.logSize() },
        .{ &tables.xor12, components.xor_12.log_size },
        .{ &[_][]u32{tables.xor4}, components.xor_4.logSize() },
        .{ &[_][]u32{tables.xor7}, components.xor_7.logSize() },
        .{ &[_][]u32{tables.xor9}, components.xor_9.logSize() },
        .{ &[_][]u32{tables.rc16}, components.range_check_16.log_size },
    };
    inline for (table_columns, 5..) |entry, index| {
        log_sizes[index] = entry[1];
        for (entry[0]) |counts| {
            const column = try sink.push(entry[1]);
            for (counts, column) |count, *out| out.* = M31.fromU64(count);
        }
    }

    const n_outputs = circuit.n_outputs;
    if (U_VAR_IDX + 1 + n_outputs > values.len) return error.VariableOutOfRange;
    const output_values = try allocator.dupe(QM31, values[U_VAR_IDX + 1 ..][0..n_outputs]);
    errdefer allocator.free(output_values);
    const columns = try sink.columns.toOwnedSlice(allocator);
    return .{
        .allocator = allocator,
        .log_sizes = PerComponent(u32).fromArray(log_sizes),
        .columns = columns,
        .output_values = output_values,
    };
}

inline fn scatter(comptime n: usize, cols: *const [n][]M31, r: usize, row: *const [n]M31) void {
    for (cols, row) |column, entry| column[r] = entry;
}

fn blakePp(pc: *const [preprocessed.BLAKE_G_GATE_COLUMN_IDS.len][]const M31, r: usize) components.blake_g_gate.Pp {
    return .{
        .inputs = .{ pc[0][r], pc[1][r], pc[2][r], pc[3][r], pc[4][r], pc[5][r] },
        .outputs = .{ pc[6][r], pc[7][r], pc[8][r], pc[9][r] },
        .mults = pc[10][r],
    };
}

/// The interaction trace: every component's LogUp columns and claimed sum.
pub const InteractionTrace = struct {
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
    claimed_sums: PerComponent(QM31),

    pub fn deinit(self: *InteractionTrace) void {
        freeColumns(self.allocator, self.columns);
        self.* = undefined;
    }

    pub fn takeColumns(self: *InteractionTrace) []ColumnEvaluation {
        const columns = self.columns;
        self.columns = &.{};
        return columns;
    }
};

/// `CommonLookupElements`: `combine(values) = sum_i alpha^i values[i] - z`.
pub const LookupElements = struct {
    z: QM31,
    alpha_powers: [components.MAX_TUPLE]QM31,

    pub fn init(z: QM31, alpha: QM31) LookupElements {
        var powers: [components.MAX_TUPLE]QM31 = undefined;
        var power = QM31.one();
        for (&powers) |*slot| {
            slot.* = power;
            power = power.mul(alpha);
        }
        return .{ .z = z, .alpha_powers = powers };
    }

    pub fn combine(self: *const LookupElements, tuple: []const M31) QM31 {
        var sum = QM31.zero();
        for (tuple, self.alpha_powers[0..tuple.len]) |entry, power| sum = sum.add(power.mulM31(entry));
        return sum.sub(self.z);
    }
};

/// Reads committed base columns row by row, per component.
const BaseView = struct {
    columns: []const ColumnEvaluation,
    offsets: [N_COMPONENTS]usize,

    fn init(columns: []const ColumnEvaluation) Error!BaseView {
        var offsets: [N_COMPONENTS]usize = undefined;
        var cursor: usize = 0;
        for (traceWidths(), &offsets) |width, *offset| {
            offset.* = cursor;
            cursor += width;
        }
        if (cursor != columns.len) return error.InvalidTraceShape;
        return .{ .columns = columns, .offsets = offsets };
    }

    fn row(self: BaseView, comptime n: usize, index: usize, r: usize) [n]M31 {
        var out: [n]M31 = undefined;
        for (&out, self.columns[self.offsets[index]..][0..n]) |*entry, column| entry.* = column.values[r];
        return out;
    }

    fn component(self: BaseView, index: usize, width: usize) []const ColumnEvaluation {
        return self.columns[self.offsets[index]..][0..width];
    }
};

/// Frees base component `index`'s columns when releasing.
fn releaseComponent(allocator: std.mem.Allocator, release: ?[]ColumnEvaluation, base: BaseView, index: usize) void {
    const columns = release orelse return;
    const widths = traceWidths();
    for (columns[base.offsets[index]..][0..widths[index]]) |*column| {
        allocator.free(column.values);
        column.values = &.{};
    }
}

/// Pairs consecutive lookups into secure-column fractions.
fn pairFractions(elements: *const LookupElements, lookups: []const Lookup, out: []logup_columns.Fraction) void {
    for (out, 0..) |*fraction, column| {
        const first = &lookups[2 * column];
        const d0 = elements.combine(first.values());
        if (2 * column + 1 == lookups.len) {
            fraction.* = .{ .numerator = QM31.fromBase(first.numerator), .denominator = d0 };
            continue;
        }
        const second = &lookups[2 * column + 1];
        const d1 = elements.combine(second.values());
        fraction.* = .{
            .numerator = d1.mulM31(first.numerator).add(d0.mulM31(second.numerator)),
            .denominator = d0.mul(d1),
        };
    }
}

fn GatherRows(comptime K: type, comptime component: usize) type {
    return struct {
        base: BaseView,
        pp: []const []const M31,
        elements: *const LookupElements,

        fn fill(self: @This(), r: usize, out: []logup_columns.Fraction) anyerror!void {
            const row = self.base.row(K.n_columns, component, r);
            const lookups = K.lookups(&row, ppRow(K, self.pp, r));
            pairFractions(self.elements, &lookups, out);
        }
    };
}

fn ppRow(comptime K: type, pp: []const []const M31, r: usize) K.Pp {
    return switch (K) {
        components.eq => .{ .in0 = pp[0][r], .in1 = pp[1][r] },
        components.qm31_ops => .{ .in0 = pp[4][r], .in1 = pp[5][r], .out = pp[6][r], .mults = pp[7][r] },
        components.triple_xor => .{ .in0 = pp[0][r], .in1 = pp[1][r], .in2 = pp[2][r], .out = pp[3][r], .mults = pp[4][r] },
        components.m31_to_u32 => .{ .input = pp[0][r], .output = pp[1][r], .mults = pp[2][r] },
        components.blake_g_gate => .{
            .inputs = .{ pp[0][r], pp[1][r], pp[2][r], pp[3][r], pp[4][r], pp[5][r] },
            .outputs = .{ pp[6][r], pp[7][r], pp[8][r], pp[9][r] },
            .mults = pp[10][r],
        },
        else => @compileError("not a gather component"),
    };
}

const XorTableRows = struct {
    table: components.XorTable,
    mults: []const ColumnEvaluation,
    pp: [3][]const M31,
    elements: *const LookupElements,

    fn fill(self: @This(), r: usize, out: []logup_columns.Fraction) anyerror!void {
        var multiplicities: [2]M31 = undefined;
        for (self.mults, 0..) |column, index| multiplicities[index] = column.values[r];
        var lookups: [2]Lookup = undefined;
        const n = self.table.relations.len;
        components.xorTableLookups(self.table, .{ self.pp[0][r], self.pp[1][r], self.pp[2][r] }, multiplicities[0..n], lookups[0..n]);
        pairFractions(self.elements, lookups[0..n], out);
    }
};

const Xor12Rows = struct {
    mults: []const ColumnEvaluation,
    elements: *const LookupElements,

    fn fill(self: @This(), r: usize, out: []logup_columns.Fraction) anyerror!void {
        var lookups: [components.xor_12.n_mult_columns]Lookup = undefined;
        for (&lookups, self.mults, 0..) |*lookup, column, index| {
            const tuple = components.xor_12.tupleAt(index, r);
            lookup.* = .{ .numerator = column.values[r].neg(), .len = 4 };
            lookup.tuple[0..4].* = tuple;
        }
        pairFractions(self.elements, &lookups, out);
    }
};

const RangeCheckRows = struct {
    mults: []const ColumnEvaluation,
    seq: []const M31,
    elements: *const LookupElements,

    fn fill(self: @This(), r: usize, out: []logup_columns.Fraction) anyerror!void {
        var lookup = Lookup{ .numerator = self.mults[0].values[r].neg(), .len = 2 };
        lookup.tuple[0] = components.range_check_16.relation;
        lookup.tuple[1] = self.seq[r];
        pairFractions(self.elements, (&lookup)[0..1], out);
    }
};

/// `write_interaction_trace`: the LogUp columns of every component, from
/// the committed base columns (`base_columns`, `ComponentList` order).
pub fn writeInteractionTrace(
    allocator: std.mem.Allocator,
    base_columns: []const ColumnEvaluation,
    log_sizes: PerComponent(u32),
    circuit: *const preprocessed.PreprocessedCircuit,
    z: QM31,
    alpha: QM31,
) !InteractionTrace {
    return writeInteractionTraceImpl(allocator, base_columns, null, log_sizes, circuit, z, alpha);
}

/// `writeInteractionTrace` that frees each component's base columns (leaving
/// them empty in `base`) as soon as that component's LogUp columns are
/// built: component `i`'s interaction reads only base component `i`, so the
/// base and interaction traces are never both whole. `base` is left with
/// every column empty on success.
pub fn writeInteractionTraceReleasing(
    allocator: std.mem.Allocator,
    base: *BaseTrace,
    circuit: *const preprocessed.PreprocessedCircuit,
    z: QM31,
    alpha: QM31,
) !InteractionTrace {
    return writeInteractionTraceImpl(allocator, base.columns, base.columns, base.log_sizes, circuit, z, alpha);
}

fn writeInteractionTraceImpl(
    allocator: std.mem.Allocator,
    base_columns: []const ColumnEvaluation,
    release: ?[]ColumnEvaluation,
    log_sizes: PerComponent(u32),
    circuit: *const preprocessed.PreprocessedCircuit,
    z: QM31,
    alpha: QM31,
) !InteractionTrace {
    const pp = Pp{ .circuit = circuit };
    const base = try BaseView.init(base_columns);
    const elements = LookupElements.init(z, alpha);
    const logs = log_sizes.toArray();
    const widths = interactionWidths();

    var outputs: [N_COMPONENTS]?logup_columns.Output = .{null} ** N_COMPONENTS;
    defer for (outputs) |maybe| if (maybe) |output| freeColumns(allocator, output.columns);

    const gather = .{
        .{ components.eq, 0, preprocessed.EQ_COLUMN_IDS },
        .{ components.qm31_ops, 1, preprocessed.QM31_OPS_COLUMN_IDS },
        .{ components.triple_xor, 2, preprocessed.TRIPLE_XOR_COLUMN_IDS },
        .{ components.m31_to_u32, 3, preprocessed.M31_TO_U32_COLUMN_IDS },
        .{ components.blake_g_gate, 4, preprocessed.BLAKE_G_GATE_COLUMN_IDS },
    };
    inline for (gather) |entry| {
        const K = entry[0];
        const index = entry[1];
        const pc = try pp.columns(entry[2]);
        if (pc[0].len != @as(usize, 1) << @intCast(logs[index])) return error.InvalidTraceShape;
        const Rows = GatherRows(K, index);
        outputs[index] = try logup_columns.build(allocator, logs[index], widths[index] / 4, Rows{
            .base = base,
            .pp = &pc,
            .elements = &elements,
        }, Rows.fill);
        releaseComponent(allocator, release, base, index);
    }
    const tables = .{
        .{ components.xor_8, 5, "bitwise_xor_8" },
        .{ components.xor_4, 7, "bitwise_xor_4" },
        .{ components.xor_7, 8, "bitwise_xor_7" },
        .{ components.xor_9, 9, "bitwise_xor_9" },
    };
    inline for (tables) |entry| {
        const table = entry[0];
        const index = entry[1];
        const pc = try pp.columns(.{ entry[2] ++ "_0", entry[2] ++ "_1", entry[2] ++ "_2" });
        const mults = base.component(index, table.relations.len);
        outputs[index] = try logup_columns.build(allocator, logs[index], widths[index] / 4, XorTableRows{
            .table = table,
            .mults = mults,
            .pp = pc,
            .elements = &elements,
        }, XorTableRows.fill);
        releaseComponent(allocator, release, base, index);
    }
    outputs[6] = try logup_columns.build(allocator, logs[6], widths[6] / 4, Xor12Rows{
        .mults = base.component(6, components.xor_12.n_mult_columns),
        .elements = &elements,
    }, Xor12Rows.fill);
    releaseComponent(allocator, release, base, 6);
    outputs[10] = try logup_columns.build(allocator, logs[10], widths[10] / 4, RangeCheckRows{
        .mults = base.component(10, 1),
        .seq = try pp.column("seq_16"),
        .elements = &elements,
    }, RangeCheckRows.fill);
    releaseComponent(allocator, release, base, 10);

    var total: usize = 0;
    for (outputs) |maybe| total += maybe.?.columns.len;
    const columns = try allocator.alloc(ColumnEvaluation, total);
    var claimed_sums: [N_COMPONENTS]QM31 = undefined;
    var cursor: usize = 0;
    for (&outputs, &claimed_sums) |*maybe, *sum| {
        const output = maybe.*.?;
        @memcpy(columns[cursor..][0..output.columns.len], output.columns);
        cursor += output.columns.len;
        sum.* = output.claimed_sum;
        allocator.free(output.columns);
        maybe.* = null;
    }
    return .{
        .allocator = allocator,
        .columns = columns,
        .claimed_sums = PerComponent(QM31).fromArray(claimed_sums),
    };
}

/// `lookup_sum`: the claimed sums plus the public sum of the output gates,
/// `sum_i 1 / combine(GATE, U_VAR_IDX + 1 + i, output_i)` and the `u` wire's
/// `1 / combine(GATE, U_VAR_IDX, U_VALUE)`. Zero for a valid proof.
pub fn lookupSum(
    output_values: []const QM31,
    claimed_sums: PerComponent(QM31),
    z: QM31,
    alpha: QM31,
) !QM31 {
    const elements = LookupElements.init(z, alpha);
    var sum = QM31.zero();
    for (claimed_sums.toArray()) |claimed| sum = sum.add(claimed);
    for (output_values, 0..) |output, index|
        sum = sum.add(try outputTerm(&elements, U_VAR_IDX + 1 + index, output));
    // The `u` wire's output gate, checked by the sum rather than hashed.
    return sum.add(try outputTerm(&elements, U_VAR_IDX, U_VALUE));
}

/// `circuits::context::U_VALUE`.
pub const U_VALUE = QM31.fromU32Unchecked(0, 0, 1, 0);

fn outputTerm(elements: *const LookupElements, address: usize, output: QM31) !QM31 {
    const limbs = output.toM31Array();
    const tuple = [_]M31{
        M31.fromCanonical(component_list.GATE_RELATION_ID),
        M31.fromU64(address),
        limbs[0],
        limbs[1],
        limbs[2],
        limbs[3],
    };
    return elements.combine(&tuple).inv();
}
