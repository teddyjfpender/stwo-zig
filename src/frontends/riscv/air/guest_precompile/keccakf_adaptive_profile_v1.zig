//! Non-production adaptive Keccak-f verifier-program profile.
//!
//! Selection is based only on the public call count and exact committed-cell
//! geometry.  Zero calls omit the entire family.  Small shards preserve the
//! compact profile; medium shards batch parity lookups; large shards use both
//! the five-output chi and three-position parity tables.  Every mode has a
//! distinct verifier-program identity and therefore cannot be relabelled as
//! the production compact AIR.

const std = @import("std");
const compact_plan = @import("keccakf_interaction_plan.zig");
const compact_tables = @import("keccakf_tables.zig");
const throughput_plan = @import("keccakf_throughput_interaction_plan_v1.zig");
const throughput_tables = @import("keccakf_throughput_tables_v1.zig");
const trace = @import("keccakf_trace.zig");
const witness = @import("keccakf_witness.zig");
const xor_throughput_plan = @import("keccakf_xor_throughput_interaction_plan_v1.zig");

pub const production_active = false;
pub const schema_version: u16 = 1;
pub const Digest = [32]u8;

pub const Mode = enum(u8) {
    inactive_zero_count = 0,
    compact_v2 = 1,
    throughput_xor_v1 = 2,
    throughput_chi_xor_v1 = 3,
};

pub const Costs = struct {
    preprocessed_cells: u64,
    main_cells: u64,
    interaction_cells: u64,
    total_cells: u64,

    fn init(preprocessed: u64, main: u64, interaction: u64) Costs {
        return .{
            .preprocessed_cells = preprocessed,
            .main_cells = main,
            .interaction_cells = interaction,
            .total_cells = preprocessed + main + interaction,
        };
    }
};

pub const Plan = struct {
    version: u16,
    mode: Mode,
    call_count: u32,
    n_rows: u32,
    log_size: u32,
    shard_interaction_columns: u32,
    chi_table_log_size: u32,
    chi_table_rows: u32,
    xor5_table_log_size: u32,
    xor5_table_rows: u32,
    costs: Costs,
    verifier_program_identity: Digest,
    instance_identity: Digest,

    pub fn validate(self: Plan) Error!void {
        const expected = switch (self.mode) {
            .inactive_zero_count => try compile(self.call_count),
            .compact_v2 => try compileCompactBaseline(self.call_count),
            .throughput_xor_v1, .throughput_chi_xor_v1 => try compileMode(self.call_count, self.mode),
        };
        if (!std.meta.eql(self, expected)) return error.PlanMismatch;
    }
};

pub const Error = error{
    ArithmeticOverflow,
    CallRangeTooLarge,
    PlanMismatch,
    UnsupportedMode,
};

pub fn compile(call_count: u32) Error!Plan {
    if (call_count == 0) return finish(.{
        .version = schema_version,
        .mode = .inactive_zero_count,
        .call_count = 0,
        .n_rows = 0,
        .log_size = 0,
        .shard_interaction_columns = 0,
        .chi_table_log_size = 0,
        .chi_table_rows = 0,
        .xor5_table_log_size = 0,
        .xor5_table_rows = 0,
        .costs = Costs.init(0, 0, 0),
        .verifier_program_identity = undefined,
        .instance_identity = undefined,
    });
    if (call_count > trace.maximum_calls_per_shard)
        return error.CallRangeTooLarge;

    const shape = try activeShape(call_count);
    const compact = geometry(.compact_v2, call_count, shape.n_rows, shape.log_size);
    const xor = geometry(
        .throughput_xor_v1,
        call_count,
        shape.n_rows,
        shape.log_size,
    );
    const full = geometry(
        .throughput_chi_xor_v1,
        call_count,
        shape.n_rows,
        shape.log_size,
    );
    const selected = if (full.costs.total_cells < xor.costs.total_cells and
        full.costs.total_cells < compact.costs.total_cells)
        full
    else if (xor.costs.total_cells < compact.costs.total_cells)
        xor
    else
        compact;
    return finish(selected);
}

/// Compiles one explicit active candidate mode.  This is used by corpus
/// projections to compare the deterministic adaptive choice against each
/// executable alternative without copying the cost formula outside Zig.
pub fn compileMode(call_count: u32, mode: Mode) Error!Plan {
    if (call_count == 0 or mode == .inactive_zero_count)
        return error.UnsupportedMode;
    const shape = try activeShape(call_count);
    return finish(geometry(mode, call_count, shape.n_rows, shape.log_size));
}

/// Existing compact-profile baseline, including its canonical log-5 empty
/// shard and both fixed lookup tables.  This deliberately differs from the
/// adaptive zero-count omission plan.
pub fn compileCompactBaseline(call_count: u32) Error!Plan {
    if (call_count > trace.maximum_calls_per_shard)
        return error.CallRangeTooLarge;
    if (call_count == 0) return finish(geometry(
        .compact_v2,
        0,
        0,
        trace.minimum_log_size,
    ));
    return compileMode(call_count, .compact_v2);
}

const ActiveShape = struct { n_rows: u32, log_size: u32 };

fn activeShape(call_count: u32) Error!ActiveShape {
    if (call_count == 0) return error.UnsupportedMode;
    if (call_count > trace.maximum_calls_per_shard)
        return error.CallRangeTooLarge;
    const slots = std.math.divCeil(u32, call_count, 2) catch unreachable;
    const n_rows = std.math.mul(u32, slots, witness.row_count) catch
        return error.ArithmeticOverflow;
    const log_size = @max(
        trace.minimum_log_size,
        std.math.log2_int_ceil(u32, n_rows),
    );
    if (log_size > trace.maximum_log_size) return error.CallRangeTooLarge;
    return .{ .n_rows = n_rows, .log_size = log_size };
}

fn geometry(mode: Mode, calls: u32, n_rows: u32, log_size: u32) Plan {
    const domain = @as(u64, 1) << @intCast(log_size);
    const chi_throughput = mode == .throughput_chi_xor_v1;
    const xor_throughput = mode == .throughput_xor_v1 or
        mode == .throughput_chi_xor_v1;
    const chi_log = if (chi_throughput)
        throughput_tables.logSize(.chi)
    else
        compact_tables.logSize(.chi);
    const xor_log = if (xor_throughput)
        throughput_tables.logSize(.xor5)
    else
        compact_tables.logSize(.xor5);
    const chi_rows: u32 = @intCast(if (chi_throughput)
        throughput_tables.semanticRows(.chi)
    else
        compact_tables.semanticRows(.chi));
    const xor_rows: u32 = @intCast(if (xor_throughput)
        throughput_tables.semanticRows(.xor5)
    else
        compact_tables.semanticRows(.xor5));
    const chi_domain = @as(u64, 1) << @intCast(chi_log);
    const xor_domain = @as(u64, 1) << @intCast(xor_log);
    const interaction_columns: u32 = switch (mode) {
        .compact_v2 => compact_plan.interaction_column_count,
        .throughput_xor_v1 => xor_throughput_plan.interaction_column_count,
        .throughput_chi_xor_v1 => throughput_plan.interaction_column_count,
        .inactive_zero_count => unreachable,
    };
    const table_domain = chi_domain + xor_domain;
    return .{
        .version = schema_version,
        .mode = mode,
        .call_count = calls,
        .n_rows = n_rows,
        .log_size = log_size,
        .shard_interaction_columns = interaction_columns,
        .chi_table_log_size = chi_log,
        .chi_table_rows = chi_rows,
        .xor5_table_log_size = xor_log,
        .xor5_table_rows = xor_rows,
        .costs = Costs.init(
            trace.Layout.preprocessed_columns * domain + 7 * table_domain,
            trace.Layout.main_columns * domain + table_domain,
            interaction_columns * domain + 4 * table_domain,
        ),
        .verifier_program_identity = undefined,
        .instance_identity = undefined,
    };
}

fn finish(partial: Plan) Plan {
    var result = partial;
    result.verifier_program_identity = programIdentity(result);
    result.instance_identity = instanceIdentity(result);
    return result;
}

fn programIdentity(plan: Plan) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.keccakf.adaptive-verifier-program.v1\x00");
    hashInt(&hash, schema_version);
    hashInt(&hash, @intFromEnum(plan.mode));
    hashInt(&hash, trace.Layout.preprocessed_columns);
    hashInt(&hash, trace.Layout.main_columns);
    hashInt(&hash, plan.log_size);
    hashInt(&hash, plan.shard_interaction_columns);
    hashInt(&hash, plan.chi_table_log_size);
    hashInt(&hash, plan.chi_table_rows);
    hashInt(&hash, plan.xor5_table_log_size);
    hashInt(&hash, plan.xor5_table_rows);
    var result: Digest = undefined;
    hash.final(&result);
    return result;
}

fn instanceIdentity(plan: Plan) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.keccakf.adaptive-instance.v1\x00");
    hash.update(&plan.verifier_program_identity);
    hashInt(&hash, plan.call_count);
    hashInt(&hash, plan.n_rows);
    hashInt(&hash, plan.log_size);
    hashInt(&hash, plan.costs.preprocessed_cells);
    hashInt(&hash, plan.costs.main_cells);
    hashInt(&hash, plan.costs.interaction_cells);
    hashInt(&hash, plan.costs.total_cells);
    var result: Digest = undefined;
    hash.final(&result);
    return result;
}

fn hashInt(hash: anytype, value: anytype) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (xor_throughput_plan.interaction_column_count != 3_740 or production_active)
        @compileError("adaptive Keccak candidate profile drifted");
}
