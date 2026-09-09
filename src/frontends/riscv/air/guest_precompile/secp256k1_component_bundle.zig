//! Complete typed trace bundle for compact secp256k1 ECDSA verification.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const affine = @import("secp256k1_affine.zig");
const config = @import("secp256k1_component_config.zig");
const ecdsa_direct = @import("secp256k1_ecdsa_direct.zig");
const linear_direct = @import("secp256k1_linear_direct.zig");
const mul_direct = @import("secp256k1_mul_direct.zig");
const point_direct = @import("secp256k1_point_direct.zig");
const recovery_direct = @import("secp256k1_recovery_direct.zig");
const recovery_caller = @import("secp256k1_recovery_caller.zig");
const recovery_call_buffer = @import("../../runner/guest_precompile/secp256k1_recover_call_buffer.zig");
const scalar_direct = @import("secp256k1_scalar_direct.zig");
const split_direct = @import("secp256k1_split_direct.zig");
const table_direct = @import("secp256k1_table_direct.zig");
const trace_mod = @import("secp256k1_component_trace.zig");

pub const ProductBase = config.Product(.base);
pub const ProductScalar = config.Product(.scalar);
pub const LinearBase = config.Linear(.base);
pub const LinearScalar = config.Linear(.scalar);

pub const ProductBaseTrace = trace_mod.Trace(ProductBase);
pub const ProductScalarTrace = trace_mod.Trace(ProductScalar);
pub const LinearBaseTrace = trace_mod.Trace(LinearBase);
pub const LinearScalarTrace = trace_mod.Trace(LinearScalar);
pub const PointTrace = trace_mod.Trace(config.Point);
pub const SplitTrace = trace_mod.Trace(config.Split);
pub const ScalarTrace = trace_mod.Trace(config.ScalarProgram);
pub const TableTrace = trace_mod.Trace(config.Table);
pub const EcdsaTrace = trace_mod.Trace(config.Ecdsa);
pub const RecoveryTrace = trace_mod.Trace(config.Recovery);
pub const RecoveryCallerTrace = trace_mod.Trace(config.RecoveryCaller);
pub const ByteTrace = trace_mod.Trace(config.ByteTable);

pub const Bundle = struct {
    product_base: ProductBaseTrace,
    product_scalar: ProductScalarTrace,
    linear_base: LinearBaseTrace,
    linear_scalar: LinearScalarTrace,
    point: PointTrace,
    split: SplitTrace,
    scalar: ScalarTrace,
    table: TableTrace,
    ecdsa: EcdsaTrace,
    recovery: RecoveryTrace,
    byte: ByteTrace,

    pub fn deinit(self: *Bundle) void {
        self.byte.deinit();
        self.recovery.deinit();
        self.ecdsa.deinit();
        self.table.deinit();
        self.scalar.deinit();
        self.split.deinit();
        self.point.deinit();
        self.linear_scalar.deinit();
        self.linear_base.deinit();
        self.product_scalar.deinit();
        self.product_base.deinit();
        self.* = undefined;
    }
};

pub fn generate(allocator: std.mem.Allocator, tape: *const affine.Tape) !Bundle {
    var byte_counts: [256]u64 = @splat(0);
    var product_base_rows: std.ArrayList(ProductBaseTrace.Row) = .empty;
    defer product_base_rows.deinit(allocator);
    var product_scalar_rows: std.ArrayList(ProductScalarTrace.Row) = .empty;
    defer product_scalar_rows.deinit(allocator);
    for (tape.products.items) |*record| {
        const row = mul_direct.rowFromWitness(&record.witness);
        switch (record.modulus) {
            .base => {
                try product_base_rows.append(allocator, row);
                try countBytes(ProductBase, &row, &byte_counts);
            },
            .scalar => {
                try product_scalar_rows.append(allocator, row);
                try countBytes(ProductScalar, &row, &byte_counts);
            },
        }
    }

    var linear_base_rows: std.ArrayList(LinearBaseTrace.Row) = .empty;
    defer linear_base_rows.deinit(allocator);
    var linear_scalar_rows: std.ArrayList(LinearScalarTrace.Row) = .empty;
    defer linear_scalar_rows.deinit(allocator);
    for (tape.linears.items) |*record| {
        const row = try linear_direct.rowFromRecord(record);
        switch (record.modulus) {
            .base => {
                try linear_base_rows.append(allocator, row);
                try countBytes(LinearBase, &row, &byte_counts);
            },
            .scalar => {
                try linear_scalar_rows.append(allocator, row);
                try countBytes(LinearScalar, &row, &byte_counts);
            },
        }
    }

    var point_rows: std.ArrayList(PointTrace.Row) = .empty;
    defer point_rows.deinit(allocator);
    for (tape.points.items) |*record| {
        const row = try point_direct.rowFromRecord(tape, record);
        try point_rows.append(allocator, row);
        try countBytes(config.Point, &row, &byte_counts);
    }

    var split_rows: std.ArrayList(SplitTrace.Row) = .empty;
    defer split_rows.deinit(allocator);
    for (tape.scalar_splits.items) |*record| {
        const row = try split_direct.rowFromRecord(tape, record);
        try split_rows.append(allocator, row);
        try countBytes(config.Split, &row, &byte_counts);
    }

    var scalar_rows: std.ArrayList(ScalarTrace.Row) = .empty;
    defer scalar_rows.deinit(allocator);
    for (tape.scalar_programs.items) |*program| {
        for (0..program.step_count) |ordinal| {
            const row = try scalar_direct.rowFromStep(tape, program, ordinal);
            try scalar_rows.append(allocator, row);
            try countBytes(config.ScalarProgram, &row, &byte_counts);
        }
    }

    const table_counts = try allocator.alloc(
        [affine.signed_table_size]u32,
        tape.tables.items.len,
    );
    defer allocator.free(table_counts);
    @memset(table_counts, @splat(0));
    for (tape.scalar_programs.items) |program| {
        for (tape.scalar_steps.items[program.step_start..][0..program.step_count]) |step| {
            for (step.digits, 0..) |digit, local_table| {
                if (digit != 0) table_counts[program.table_start + local_table][
                    affine.signedTableIndex(digit)
                ] += 1;
            }
        }
    }
    var table_rows: std.ArrayList(TableTrace.Row) = .empty;
    defer table_rows.deinit(allocator);
    for (tape.tables.items, 0..) |*table, table_index| {
        for (0..affine.signed_table_size) |code| {
            const row = try table_direct.rowFromEntry(
                tape,
                table,
                code,
                table_counts[table_index][code],
            );
            try table_rows.append(allocator, row);
            try countBytes(config.Table, &row, &byte_counts);
        }
    }

    var ecdsa_rows: std.ArrayList(EcdsaTrace.Row) = .empty;
    defer ecdsa_rows.deinit(allocator);
    for (tape.ecdsa.items) |*record| {
        const row = try ecdsa_direct.rowFromRecord(tape, record);
        try ecdsa_rows.append(allocator, row);
        try countBytes(config.Ecdsa, &row, &byte_counts);
    }

    var recovery_rows: std.ArrayList(RecoveryTrace.Row) = .empty;
    defer recovery_rows.deinit(allocator);
    for (tape.recoveries.items) |*record| {
        const row = try recovery_direct.rowFromRecord(tape, record);
        try recovery_rows.append(allocator, row);
        try countBytes(config.Recovery, &row, &byte_counts);
    }

    var byte_rows: [256]ByteTrace.Row = undefined;
    for (&byte_rows, 0..) |*row, value| {
        row.* = config.ByteTable.row(@intCast(value), M31.fromU64(byte_counts[value]));
    }

    var result: Bundle = undefined;
    result.product_base = try initPossiblyEmpty(
        ProductBase,
        allocator,
        product_base_rows.items,
    );
    errdefer result.product_base.deinit();
    result.product_scalar = try initPossiblyEmpty(
        ProductScalar,
        allocator,
        product_scalar_rows.items,
    );
    errdefer result.product_scalar.deinit();
    result.linear_base = try initPossiblyEmpty(
        LinearBase,
        allocator,
        linear_base_rows.items,
    );
    errdefer result.linear_base.deinit();
    result.linear_scalar = try initPossiblyEmpty(
        LinearScalar,
        allocator,
        linear_scalar_rows.items,
    );
    errdefer result.linear_scalar.deinit();
    result.point = try initPossiblyEmpty(config.Point, allocator, point_rows.items);
    errdefer result.point.deinit();
    result.split = try initPossiblyEmpty(config.Split, allocator, split_rows.items);
    errdefer result.split.deinit();
    result.scalar = try initPossiblyEmpty(
        config.ScalarProgram,
        allocator,
        scalar_rows.items,
    );
    errdefer result.scalar.deinit();
    result.table = try initPossiblyEmpty(config.Table, allocator, table_rows.items);
    errdefer result.table.deinit();
    result.ecdsa = try initPossiblyEmpty(
        config.Ecdsa,
        allocator,
        ecdsa_rows.items,
    );
    errdefer result.ecdsa.deinit();
    result.recovery = try initPossiblyEmpty(
        config.Recovery,
        allocator,
        recovery_rows.items,
    );
    errdefer result.recovery.deinit();
    result.byte = try ByteTrace.init(allocator, &byte_rows, &.{}, &.{});
    return result;
}

pub fn generateRecoveryCaller(
    allocator: std.mem.Allocator,
    records: []const recovery_call_buffer.Record,
) !RecoveryCallerTrace {
    var rows: std.ArrayList(RecoveryCallerTrace.Row) = .empty;
    defer rows.deinit(allocator);
    var active_prefix: std.ArrayList(usize) = .empty;
    defer active_prefix.deinit(allocator);
    try rows.ensureTotalCapacity(allocator, records.len);
    try active_prefix.ensureTotalCapacity(allocator, records.len);
    for (records, 0..) |record, index| {
        rows.appendAssumeCapacity(recovery_caller.rowFromRecord(record));
        active_prefix.appendAssumeCapacity(index);
    }
    if (rows.items.len != 0) return RecoveryCallerTrace.init(
        allocator,
        rows.items,
        active_prefix.items,
        &.{},
    );
    const padding = [1]RecoveryCallerTrace.Row{@splat(M31.zero())};
    return RecoveryCallerTrace.init(allocator, &padding, &.{}, &.{});
}

fn countBytes(
    comptime Config: type,
    row: *const [Config.main_column_count]M31,
    counts: *[256]u64,
) !void {
    if (Config == ProductBase or Config == ProductScalar)
        return countPairs(mul_direct.rangePairs(M31, row), counts);
    if (Config == LinearBase or Config == LinearScalar)
        return countPairs(linear_direct.rangePairs(M31, row), counts);
    if (Config == config.Point)
        return countPairs(point_direct.rangePairs(M31, row), counts);
    if (Config == config.Split)
        return countPairs(split_direct.rangePairs(M31, row), counts);
    if (Config == config.ScalarProgram)
        return countPairs(scalar_direct.rangePairs(M31, row), counts);
    if (Config == config.Table)
        return countPairs(table_direct.rangePairs(M31, row), counts);
    if (Config == config.Ecdsa)
        return countPairs(ecdsa_direct.rangePairs(M31, row), counts);
    if (Config == config.Recovery)
        return countPairs(recovery_direct.rangePairs(M31, row), counts);
    @compileError("unsupported secp256k1 byte source");
}

fn initPossiblyEmpty(
    comptime Config: type,
    allocator: std.mem.Allocator,
    rows: []const trace_mod.Trace(Config).Row,
) !trace_mod.Trace(Config) {
    if (rows.len != 0) return trace_mod.Trace(Config).init(
        allocator,
        rows,
        &.{},
        &.{},
    );
    const padding = [1]trace_mod.Trace(Config).Row{
        @splat(M31.zero()),
    };
    return trace_mod.Trace(Config).init(allocator, &padding, &.{}, &.{});
}

fn countPairs(pairs: anytype, counts: *[256]u64) !void {
    for (pairs) |pair| for (pair) |value| {
        const byte = value.toU32();
        if (byte > 255) return error.OutOfRangeByte;
        counts[byte] = std.math.add(u64, counts[byte], 1) catch
            return error.ByteMultiplicityOverflow;
    };
}
