//! QM31-only witness and LogUp trace for S31's direct-M31 profile.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const pp_mod = @import("../common/preprocessed.zig");
const direct_pp = @import("../common/direct_arithmetic.zig");
const components = @import("components.zig");
const circuit_trace = @import("trace.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const ColumnEvaluation = prover.pcs.ColumnEvaluation;
const Fraction = prover.air.logup_columns.Fraction;

pub const main_width: usize = components.qm31_ops.n_columns;
pub const interaction_width: usize = 8;

pub const Base = struct {
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
    log_size: u32,
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
    claimed_sum: QM31,

    pub fn deinit(self: *Interaction) void {
        freeColumns(self.allocator, self.columns);
        self.* = undefined;
    }
};

fn freeColumns(allocator: std.mem.Allocator, columns: []ColumnEvaluation) void {
    for (columns) |entry| allocator.free(entry.values);
    allocator.free(columns);
}

fn ppColumns(pp: *const direct_pp.Circuit) ![direct_pp.N_COLUMNS][]const M31 {
    var result: [direct_pp.N_COLUMNS][]const M31 = undefined;
    for (pp_mod.QM31_OPS_COLUMN_IDS, &result) |id, *entry|
        entry.* = pp.columnValues(id) orelse return error.MissingDirectColumn;
    return result;
}

fn value(values: []const QM31, address: M31) !QM31 {
    const index = address.toU32();
    if (index >= values.len) return error.VariableOutOfRange;
    return values[index];
}

pub fn writeBase(allocator: std.mem.Allocator, values: []const QM31, pp: *const direct_pp.Circuit) !Base {
    const q = try ppColumns(pp);
    const log_size = std.math.log2_int(usize, q[0].len);
    for (q) |entry| if (entry.len != q[0].len) return error.InvalidDirectTraceShape;
    const columns = try allocator.alloc(ColumnEvaluation, main_width);
    var ready: usize = 0;
    errdefer {
        for (columns[0..ready]) |entry| allocator.free(entry.values);
        allocator.free(columns);
    }
    for (columns) |*entry| {
        entry.* = .{ .log_size = log_size, .values = try allocator.alloc(M31, q[0].len) };
        ready += 1;
    }
    for (0..q[0].len) |row| {
        var limbs: [main_width]M31 = undefined;
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
        for (limbs, columns) |limb, *entry| @constCast(entry.values)[row] = limb;
    }
    if (circuit_trace.U_VAR_IDX + 1 + pp.n_outputs > values.len)
        return error.VariableOutOfRange;
    const outputs = try allocator.dupe(QM31, values[circuit_trace.U_VAR_IDX + 1 ..][0..pp.n_outputs]);
    return .{ .allocator = allocator, .columns = columns, .log_size = log_size, .output_values = outputs };
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

const Rows = struct {
    base: []const ColumnEvaluation,
    pp: [direct_pp.N_COLUMNS][]const M31,
    elements: *const LookupElements,

    fn fill(self: @This(), row: usize, out: []Fraction) !void {
        var values: [main_width]M31 = undefined;
        for (&values, self.base) |*slot, source| slot.* = source.values[row];
        const lookups = components.qm31_ops.lookups(&values, .{
            .in0 = self.pp[4][row],
            .in1 = self.pp[5][row],
            .out = self.pp[6][row],
            .mults = self.pp[7][row],
        });
        fractions(self.elements, &lookups, out);
    }
};

pub fn writeInteraction(
    allocator: std.mem.Allocator,
    base: *const Base,
    pp: *const direct_pp.Circuit,
    z: QM31,
    alpha: QM31,
) !Interaction {
    const elements = LookupElements.init(z, alpha);
    const q = try ppColumns(pp);
    const output = try prover.air.logup_columns.build(
        allocator,
        base.log_size,
        2,
        Rows{ .base = base.columns, .pp = q, .elements = &elements },
        Rows.fill,
    );
    return .{ .allocator = allocator, .columns = output.columns, .claimed_sum = output.claimed_sum };
}

pub fn lookupSum(outputs: []const QM31, claimed: QM31, z: QM31, alpha: QM31) !QM31 {
    var all = [_]QM31{QM31.zero()} ** @import("../common/component_list.zig").N_COMPONENTS;
    all[1] = claimed;
    return circuit_trace.lookupSum(
        outputs,
        @import("../common/component_list.zig").PerComponent(QM31).fromArray(all),
        z,
        alpha,
    );
}
