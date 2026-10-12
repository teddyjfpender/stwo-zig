//! Eq plus sparse-v3 arithmetic/range witness, in selected component order.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const pp_mod = @import("../common/preprocessed.zig");
const wide_pp = @import("../common/sparse_wide.zig");
const sparse = @import("sparse_arithmetic.zig");
const components = @import("components.zig");
const circuit_trace = @import("trace.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const ColumnEvaluation = prover.pcs.ColumnEvaluation;
const Fraction = prover.air.logup_columns.Fraction;

pub const main_width: usize = components.eq.n_columns + sparse.main_width;
pub const interaction_width: usize = 4 + sparse.interaction_width;

pub const Base = struct {
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
    log_sizes: [4]u32,
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
    claimed_sums: [4]QM31,

    pub fn deinit(self: *Interaction) void {
        freeColumns(self.allocator, self.columns);
        self.* = undefined;
    }
};

fn freeColumns(allocator: std.mem.Allocator, columns: []ColumnEvaluation) void {
    for (columns) |column| allocator.free(column.values);
    allocator.free(columns);
}

fn value(values: []const QM31, address: M31) !QM31 {
    const index = address.toU32();
    if (index >= values.len) return error.VariableOutOfRange;
    return values[index];
}

pub fn writeBase(allocator: std.mem.Allocator, values: []const QM31, pp: *const wide_pp.Circuit) !Base {
    var sparse_view = pp.sparseView();
    var old = try sparse.writeBase(allocator, values, &sparse_view);
    errdefer old.deinit();
    const addresses = pp.columnValues(pp_mod.EQ_COLUMN_IDS[0]) orelse return error.MissingSparseWideColumn;
    const log_size = std.math.log2_int(usize, addresses.len);
    const columns = try allocator.alloc(ColumnEvaluation, main_width);
    var ready: usize = 0;
    errdefer {
        for (columns[0..ready]) |column| allocator.free(column.values);
        allocator.free(columns);
    }
    for (columns[0..components.eq.n_columns]) |*column| {
        column.* = .{ .log_size = log_size, .values = try allocator.alloc(M31, addresses.len) };
        ready += 1;
    }
    for (addresses, 0..) |address, row| {
        var limbs: [components.eq.n_columns]M31 = undefined;
        components.eq.row(try value(values, address), &limbs);
        for (limbs, columns[0..components.eq.n_columns]) |limb, *column| @constCast(column.values)[row] = limb;
    }
    @memcpy(columns[components.eq.n_columns..], old.columns);
    allocator.free(old.columns);
    old.columns = &.{};
    const output_values = old.output_values;
    old.output_values = &.{};
    return .{
        .allocator = allocator,
        .columns = columns,
        .log_sizes = .{ log_size, old.log_sizes[0], old.log_sizes[1], old.log_sizes[2] },
        .output_values = output_values,
    };
}

const EqRows = struct {
    base: []const ColumnEvaluation,
    in0: []const M31,
    in1: []const M31,
    elements: *const circuit_trace.LookupElements,

    fn fill(self: @This(), row: usize, out: []Fraction) !void {
        var limbs: [components.eq.n_columns]M31 = undefined;
        for (&limbs, self.base[0..components.eq.n_columns]) |*limb, column| limb.* = column.values[row];
        const lookups = components.eq.lookups(&limbs, .{ .in0 = self.in0[row], .in1 = self.in1[row] });
        const first = self.elements.combine(lookups[0].values());
        const second = self.elements.combine(lookups[1].values());
        out[0] = .{ .numerator = first.add(second), .denominator = first.mul(second) };
    }
};

pub fn writeInteraction(allocator: std.mem.Allocator, base: *const Base, pp: *const wide_pp.Circuit, z: QM31, alpha: QM31) !Interaction {
    var sparse_view = pp.sparseView();
    const old_base = sparse.Base{
        .allocator = allocator,
        .columns = base.columns[components.eq.n_columns..],
        .log_sizes = .{ base.log_sizes[1], base.log_sizes[2], base.log_sizes[3] },
        .output_values = base.output_values,
    };
    var old = try sparse.writeInteraction(allocator, &old_base, &sparse_view, z, alpha);
    errdefer old.deinit();
    const in0 = pp.columnValues(pp_mod.EQ_COLUMN_IDS[0]) orelse return error.MissingSparseWideColumn;
    const in1 = pp.columnValues(pp_mod.EQ_COLUMN_IDS[1]) orelse return error.MissingSparseWideColumn;
    if (in0.len != in1.len) return error.InvalidSparseWideShape;
    const elements = circuit_trace.LookupElements.init(z, alpha);
    const eq = try prover.air.logup_columns.build(allocator, base.log_sizes[0], 1, EqRows{ .base = base.columns, .in0 = in0, .in1 = in1, .elements = &elements }, EqRows.fill);
    errdefer freeColumns(allocator, eq.columns);
    const columns = try allocator.alloc(ColumnEvaluation, interaction_width);
    @memcpy(columns[0..4], eq.columns);
    @memcpy(columns[4..], old.columns);
    allocator.free(eq.columns);
    allocator.free(old.columns);
    old.columns = &.{};
    return .{
        .allocator = allocator,
        .columns = columns,
        .claimed_sums = .{ eq.claimed_sum, old.claimed_sums[0], old.claimed_sums[1], old.claimed_sums[2] },
    };
}

pub fn lookupSum(outputs: []const QM31, sums: [4]QM31, z: QM31, alpha: QM31) !QM31 {
    const list = @import("../common/component_list.zig");
    var all = [_]QM31{QM31.zero()} ** list.N_COMPONENTS;
    for (wide_pp.active_component_indices, sums) |index, sum| all[index] = sum;
    return circuit_trace.lookupSum(outputs, list.PerComponent(QM31).fromArray(all), z, alpha);
}
