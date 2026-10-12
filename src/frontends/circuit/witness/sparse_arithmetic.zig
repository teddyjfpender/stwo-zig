//! Witness and LogUp columns for the sparse-v3 arithmetic circuit profile.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const pp_mod = @import("../common/preprocessed.zig");
const sparse_pp = @import("../common/sparse_arithmetic.zig");
const components = @import("components.zig");
const circuit_trace = @import("trace.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const ColumnEvaluation = prover.pcs.ColumnEvaluation;
const Fraction = prover.air.logup_columns.Fraction;

pub const main_width: usize = components.qm31_ops.n_columns +
    components.m31_to_u32.n_columns + 1;
pub const interaction_width: usize = 8 + 12 + 4;

pub const Base = struct {
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
    log_sizes: [3]u32,
    output_values: []QM31,

    pub fn deinit(self: *Base) void {
        freeColumns(self.allocator, self.columns);
        self.allocator.free(self.output_values);
        self.* = undefined;
    }
};

pub const Interaction = struct {
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
    claimed_sums: [3]QM31,

    pub fn deinit(self: *Interaction) void {
        freeColumns(self.allocator, self.columns);
        self.* = undefined;
    }
};

fn freeColumns(allocator: std.mem.Allocator, columns: []ColumnEvaluation) void {
    for (columns) |entry| allocator.free(entry.values);
    allocator.free(columns);
}

fn column(allocator: std.mem.Allocator, log_size: u32) !ColumnEvaluation {
    return .{
        .log_size = log_size,
        .values = try allocator.alloc(M31, @as(usize, 1) << @intCast(log_size)),
    };
}

fn ppColumns(pp: *const sparse_pp.Circuit, comptime ids: anytype) ![ids.len][]const M31 {
    var out: [ids.len][]const M31 = undefined;
    inline for (ids, &out) |id, *slot|
        slot.* = pp.columnValues(id) orelse return error.MissingSparseColumn;
    return out;
}

fn value(values: []const QM31, address: M31) !QM31 {
    const index = address.toU32();
    if (index >= values.len) return error.VariableOutOfRange;
    return values[index];
}

pub fn writeBase(
    allocator: std.mem.Allocator,
    values: []const QM31,
    pp: *const sparse_pp.Circuit,
) !Base {
    const q = try ppColumns(pp, pp_mod.QM31_OPS_COLUMN_IDS);
    const m = try ppColumns(pp, pp_mod.M31_TO_U32_COLUMN_IDS);
    const q_log = std.math.log2_int(usize, q[0].len);
    const m_log = std.math.log2_int(usize, m[0].len);
    for (q) |entry| if (entry.len != q[0].len) return error.InvalidSparseTraceShape;
    for (m) |entry| if (entry.len != m[0].len) return error.InvalidSparseTraceShape;
    const result = try allocator.alloc(ColumnEvaluation, main_width);
    var ready: usize = 0;
    errdefer {
        for (result[0..ready]) |entry| allocator.free(entry.values);
        allocator.free(result);
    }
    for (result[0..12]) |*entry| {
        entry.* = try column(allocator, q_log);
        ready += 1;
    }
    for (result[12..16]) |*entry| {
        entry.* = try column(allocator, m_log);
        ready += 1;
    }
    result[16] = try column(allocator, 16);
    ready += 1;
    const range_counts = try allocator.alloc(u32, 1 << 16);
    defer allocator.free(range_counts);
    @memset(range_counts, 0);

    for (0..q[0].len) |row| {
        var limbs: [12]M31 = undefined;
        if (row < pp.first_permutation_row) {
            components.qm31_ops.row(
                try value(values, q[4][row]),
                try value(values, q[5][row]),
                try value(values, q[6][row]),
                &limbs,
            );
        } else {
            const pair = row - (row - pp.first_permutation_row) % 2;
            const through = if (row == pair)
                try value(values, q[5][pair])
            else
                try value(values, q[6][pair + 1]);
            components.qm31_ops.row(QM31.zero(), through, through, &limbs);
        }
        for (limbs, result[0..12]) |limb, *entry| @constCast(entry.values)[row] = limb;
    }
    for (0..m[0].len) |row| {
        var limbs: [4]M31 = undefined;
        components.m31_to_u32.row((try value(values, m[0][row])).toM31Array()[0], &limbs);
        for (limbs, result[12..16]) |limb, *entry| @constCast(entry.values)[row] = limb;
        const low = limbs[1].toU32();
        const high = limbs[2].toU32();
        if (low >= 1 << 16 or high > 32767) return error.InvalidSparseRange;
        range_counts[low] += 1;
        range_counts[high] += 1;
        range_counts[32767 - high] += 1;
    }
    for (range_counts, 0..) |count, row| @constCast(result[16].values)[row] = M31.fromU64(count);
    if (circuit_trace.U_VAR_IDX + 1 + pp.n_outputs > values.len)
        return error.VariableOutOfRange;
    const output_values = try allocator.dupe(QM31, values[circuit_trace.U_VAR_IDX + 1 ..][0..pp.n_outputs]);
    return .{
        .allocator = allocator,
        .columns = result,
        .log_sizes = .{ q_log, m_log, 16 },
        .output_values = output_values,
    };
}

const LookupElements = circuit_trace.LookupElements;
const Lookup = components.Lookup;

fn fractions(elements: *const LookupElements, lookups: []const Lookup, out: []Fraction) void {
    for (out, 0..) |*fraction, index| {
        const first = &lookups[2 * index];
        const d0 = elements.combine(first.values());
        if (2 * index + 1 == lookups.len) {
            fraction.* = .{ .numerator = QM31.fromBase(first.numerator), .denominator = d0 };
        } else {
            const second = &lookups[2 * index + 1];
            const d1 = elements.combine(second.values());
            fraction.* = .{
                .numerator = d1.mulM31(first.numerator).add(d0.mulM31(second.numerator)),
                .denominator = d0.mul(d1),
            };
        }
    }
}

const QRows = struct {
    base: []const ColumnEvaluation,
    pp: [pp_mod.QM31_OPS_COLUMN_IDS.len][]const M31,
    elements: *const LookupElements,

    fn fill(self: @This(), row: usize, out: []Fraction) !void {
        var values: [12]M31 = undefined;
        for (&values, self.base[0..12]) |*slot, source| slot.* = source.values[row];
        const lookups = components.qm31_ops.lookups(&values, .{
            .in0 = self.pp[4][row],
            .in1 = self.pp[5][row],
            .out = self.pp[6][row],
            .mults = self.pp[7][row],
        });
        fractions(self.elements, &lookups, out);
    }
};

const MRows = struct {
    base: []const ColumnEvaluation,
    pp: [pp_mod.M31_TO_U32_COLUMN_IDS.len][]const M31,
    elements: *const LookupElements,

    fn fill(self: @This(), row: usize, out: []Fraction) !void {
        var values: [4]M31 = undefined;
        for (&values, self.base[12..16]) |*slot, source| slot.* = source.values[row];
        const lookups = components.m31_to_u32.lookups(&values, .{
            .input = self.pp[0][row],
            .output = self.pp[1][row],
            .mults = self.pp[2][row],
        });
        fractions(self.elements, &lookups, out);
    }
};

const RangeRows = struct {
    base: []const ColumnEvaluation,
    seq: []const M31,
    elements: *const LookupElements,

    fn fill(self: @This(), row: usize, out: []Fraction) !void {
        var lookup = Lookup{
            .numerator = self.base[16].values[row].neg(),
            .len = 2,
        };
        lookup.tuple[0] = components.range_check_16.relation;
        lookup.tuple[1] = self.seq[row];
        fractions(self.elements, (&lookup)[0..1], out);
    }
};

pub fn writeInteraction(
    allocator: std.mem.Allocator,
    base: *const Base,
    pp: *const sparse_pp.Circuit,
    z: QM31,
    alpha: QM31,
) !Interaction {
    const elements = LookupElements.init(z, alpha);
    const q = try ppColumns(pp, pp_mod.QM31_OPS_COLUMN_IDS);
    const m = try ppColumns(pp, pp_mod.M31_TO_U32_COLUMN_IDS);
    const seq = pp.columnValues("seq_16") orelse return error.MissingSparseColumn;
    const q_output = try prover.air.logup_columns.build(
        allocator,
        base.log_sizes[0],
        2,
        QRows{ .base = base.columns, .pp = q, .elements = &elements },
        QRows.fill,
    );
    errdefer freeColumns(allocator, q_output.columns);
    const m_output = try prover.air.logup_columns.build(
        allocator,
        base.log_sizes[1],
        3,
        MRows{ .base = base.columns, .pp = m, .elements = &elements },
        MRows.fill,
    );
    errdefer freeColumns(allocator, m_output.columns);
    const range_output = try prover.air.logup_columns.build(
        allocator,
        16,
        1,
        RangeRows{ .base = base.columns, .seq = seq, .elements = &elements },
        RangeRows.fill,
    );
    errdefer freeColumns(allocator, range_output.columns);
    const output = try allocator.alloc(ColumnEvaluation, interaction_width);
    @memcpy(output[0..8], q_output.columns);
    @memcpy(output[8..20], m_output.columns);
    @memcpy(output[20..24], range_output.columns);
    allocator.free(q_output.columns);
    allocator.free(m_output.columns);
    allocator.free(range_output.columns);
    return .{
        .allocator = allocator,
        .columns = output,
        .claimed_sums = .{ q_output.claimed_sum, m_output.claimed_sum, range_output.claimed_sum },
    };
}

pub fn lookupSum(outputs: []const QM31, sums: [3]QM31, z: QM31, alpha: QM31) !QM31 {
    var all = [_]QM31{QM31.zero()} ** @import("../common/component_list.zig").N_COMPONENTS;
    for (sparse_pp.active_component_indices, sums) |index, sum| all[index] = sum;
    return circuit_trace.lookupSum(
        outputs,
        @import("../common/component_list.zig").PerComponent(QM31).fromArray(all),
        z,
        alpha,
    );
}
