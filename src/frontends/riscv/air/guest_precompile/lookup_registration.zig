//! Transactional fixed-table registration for the Poseidon2 caller.
//!
//! The base prover owns one dense counter set and populates it from ordinary
//! components before lookup multiplicity columns are committed. This boundary
//! validates the profile authority and every guest tuple first, then adds the
//! exact caller requests to that same set. No guest call can partially mutate
//! the counters: the mutation pass is reached only after an identical
//! read-only pass proves every table index representable.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const components = @import("component_registry.zig");
const interaction_plan = @import("interaction_plan.zig");
const main_trace = @import("main_trace.zig");
const statement_mod = @import("statement.zig");
const riscv_statement = @import("../statement.zig");
const table_counter = @import("../lookups/tables/counter.zig");
const table_schema = @import("../lookups/tables/schema.zig");

const M31 = m31.M31;
const RiscVStatement = riscv_statement.RiscVStatement;
const ExtensionStatement = statement_mod.ExtensionStatement;

pub const fixed_table_count: usize = table_schema.KIND_COUNT;
pub const caller_source_column_count: usize =
    interaction_plan.caller_relation_source_columns;
pub const CallerMainColumns =
    [main_trace.caller_main_column_count][]const M31;
pub const DemandCounts = [fixed_table_count]u64;

pub const Error = statement_mod.Error || components.Error || table_schema.Error || error{
    FixedTableDemandMismatch,
    InvalidCounterSet,
    InvalidMainTraceShape,
    CallerSelectorMismatch,
    CallerActivityMismatch,
};

pub const Summary = struct {
    n_calls: u32,
    demand: DemandCounts,
};

const Authority = struct {
    n_calls: u32,
    demand: DemandCounts,
    layout: *const components.CallerLayout,
};

const CallerSource = struct {
    columns: [caller_source_column_count][]const M31,
    log_size: u32,
    n_rows: u32,
    domain_size: usize,
};

/// Add the exact guest fixed-table requests to an already populated base set.
///
/// `main` must remain immutable for the duration of this call. The function
/// accepts no allocator and retains no memory; registration cost is linear in
/// the authenticated caller rows and independent of padded trace length except
/// for the selector/activity shape check.
pub fn register(
    core: *const RiscVStatement,
    extension: *const ExtensionStatement,
    main: *const main_trace.Result,
    counters: *table_counter.Set,
) Error!Summary {
    const authority = try authenticate(core, extension);
    try validateCounterSet(counters);
    const source = try sourceFromResult(main, extension, authority);
    return registerSource(&source, authority, counters);
}

/// Production boundary for main columns generated directly into final Tree-1
/// storage. It neither constructs the legacy combined arena nor depends on the
/// compact post-commit relation projection. Call this only after
/// `main_trace.generateMainInto` has completed and keep the destinations
/// immutable until registration returns.
pub fn registerGenerated(
    core: *const RiscVStatement,
    extension: *const ExtensionStatement,
    destinations: *const main_trace.MainDestinations,
    counters: *table_counter.Set,
) Error!Summary {
    const authority = try authenticate(core, extension);
    try validateCounterSet(counters);
    const source = try sourceFromDestinations(
        destinations,
        extension.components[0].log_size,
        authority.n_calls,
        authority.layout,
    );
    return registerSource(&source, authority, counters);
}

/// Split Tree-1 boundary: register the same caller demand from independently
/// owned caller columns, without requiring or even accepting provider storage.
pub fn registerCallerColumns(
    core: *const RiscVStatement,
    extension: *const ExtensionStatement,
    columns: *const CallerMainColumns,
    log_size: u32,
    n_rows: u32,
    counters: *table_counter.Set,
) Error!Summary {
    const authority = try authenticate(core, extension);
    try validateCounterSet(counters);
    if (log_size != extension.components[0].log_size)
        return error.InvalidMainTraceShape;
    const source = try sourceFromCallerColumns(
        columns,
        log_size,
        n_rows,
        authority,
    );
    return registerSource(&source, authority, counters);
}

fn registerSource(
    source: *const CallerSource,
    authority: Authority,
    counters: *table_counter.Set,
) Error!Summary {
    var observed = [_]u64{0} ** fixed_table_count;
    try visitRows(
        false,
        source,
        authority.layout,
        null,
        &observed,
    );
    if (!std.meta.eql(observed, authority.demand))
        return error.FixedTableDemandMismatch;

    // Every index and every coefficient was validated above. With immutable
    // input the second pass has no failure edge, so mutation is transactional
    // without allocating a second ~11 MiB dense counter set.
    visitRows(
        true,
        source,
        authority.layout,
        counters,
        null,
    ) catch unreachable;
    return .{ .n_calls = authority.n_calls, .demand = authority.demand };
}

/// Checked guest contribution before any base coefficient is added.
pub fn checkedDemandCounts(n_calls: u64) Error!DemandCounts {
    var result: DemandCounts = undefined;
    for (&result, components.caller_fixed_table_demand) |*count, per_call| {
        count.* = std.math.mul(u64, n_calls, per_call) catch
            return error.CoefficientBoundExceeded;
        if (count.* >= statement_mod.field_modulus)
            return error.CoefficientBoundExceeded;
    }
    return result;
}

fn authenticate(
    core: *const RiscVStatement,
    extension: *const ExtensionStatement,
) Error!Authority {
    // Check the fields needed for safe arithmetic before the broader canonical
    // validation. This keeps hostile counts from reaching multiplication or
    // descriptor-derived slicing.
    if (extension.profile != .rv32im_zkvm_poseidon2_v1)
        return error.ProfileMismatch;
    if (extension.counts.n_guest != extension.counts.custom_retirements or
        extension.counts.n_guest != extension.counts.frozen_call_count)
    {
        return error.CallCountMismatch;
    }
    const demand = try checkedDemandCounts(extension.counts.n_guest);

    try extension.validate(core);
    const registry = components.Registry.forProfile(extension.profile);
    const construction = try registry.verifierConstruction(extension.components[0]);
    const caller = switch (construction) {
        .caller => |value| value,
        else => return error.ConstructionAuthorityMismatch,
    };
    try caller.validate();
    if (!std.meta.eql(caller.fixed_table_demand.*, components.caller_fixed_table_demand))
        return error.FixedTableDemandMismatch;

    // Pin this mutation boundary directly to the statement's independently
    // checked coefficient certificate instead of merely trusting `n_guest`.
    for (
        extension.admission.base_fixed_table_bounds,
        extension.admission.extended_fixed_table_bounds,
        demand,
    ) |base, extended, guest| {
        const expected = std.math.add(u64, base, guest) catch
            return error.CoefficientBoundExceeded;
        if (expected >= statement_mod.field_modulus)
            return error.CoefficientBoundExceeded;
        if (extended != expected) return error.FixedTableDemandMismatch;
    }
    return .{
        .n_calls = extension.counts.n_guest,
        .demand = demand,
        .layout = caller.layout,
    };
}

fn validateCounterSet(counters: *const table_counter.Set) Error!void {
    for (&counters.counters, 0..) |*counter, index| {
        const expected: table_schema.Kind = @enumFromInt(index);
        if (counter.kind != expected or counter.values.len != table_schema.size(expected))
            return error.InvalidCounterSet;
    }
}

fn sourceFromResult(
    main: *const main_trace.Result,
    extension: *const ExtensionStatement,
    authority: Authority,
) Error!CallerSource {
    if (main.log_size != extension.components[0].log_size or
        main.n_rows != authority.n_calls or
        main.log_size >= @bitSizeOf(usize))
    {
        return error.InvalidMainTraceShape;
    }
    const domain_size = @as(usize, 1) << @intCast(main.log_size);
    const expected_cells = std.math.mul(
        usize,
        main_trace.total_column_count,
        domain_size,
    ) catch return error.InvalidMainTraceShape;
    if (main.domain_size != domain_size or main.storage.len != expected_cells or
        @as(usize, authority.n_calls) > domain_size)
    {
        return error.InvalidMainTraceShape;
    }

    var source = CallerSource{
        .columns = undefined,
        .log_size = main.log_size,
        .n_rows = main.n_rows,
        .domain_size = domain_size,
    };
    for (&source.columns, 0..) |*column, index| column.* = main.callerMain(index);

    const first_selector = main.callerPreprocessed(0);
    const active_selector = main.callerPreprocessed(1);
    for (0..domain_size) |logical_row| {
        const physical_row = main_trace.committedRow(logical_row, main.log_size);
        const expected_first = M31.fromCanonical(@intFromBool(logical_row == 0));
        const expected_active = M31.fromCanonical(
            @intFromBool(logical_row < authority.n_calls),
        );
        if (!first_selector[physical_row].eql(expected_first))
            return error.CallerSelectorMismatch;
        if (!active_selector[physical_row].eql(expected_active))
            return error.CallerSelectorMismatch;
    }
    try validateActivity(&source, authority.layout);
    return source;
}

fn sourceFromDestinations(
    destinations: *const main_trace.MainDestinations,
    log_size: u32,
    n_rows: u32,
    layout: *const components.CallerLayout,
) Error!CallerSource {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidMainTraceShape;
    const domain_size = @as(usize, 1) << @intCast(log_size);
    if (@as(usize, n_rows) > domain_size) return error.InvalidMainTraceShape;
    for (destinations.caller) |column| {
        if (column.len != domain_size) return error.InvalidMainTraceShape;
    }
    for (destinations.provider) |column| {
        if (column.len != domain_size) return error.InvalidMainTraceShape;
    }

    var source = CallerSource{
        .columns = undefined,
        .log_size = log_size,
        .n_rows = n_rows,
        .domain_size = domain_size,
    };
    for (&source.columns, destinations.caller[0..caller_source_column_count]) |*destination, column| {
        destination.* = column;
    }
    try validateActivity(&source, layout);
    return source;
}

fn sourceFromCallerColumns(
    columns: *const CallerMainColumns,
    log_size: u32,
    n_rows: u32,
    authority: Authority,
) Error!CallerSource {
    if (n_rows != authority.n_calls or
        log_size >= @bitSizeOf(usize))
    {
        return error.InvalidMainTraceShape;
    }
    const domain_size = @as(usize, 1) << @intCast(log_size);
    if (@as(usize, n_rows) > domain_size)
        return error.InvalidMainTraceShape;
    for (columns) |column| {
        if (column.len != domain_size) return error.InvalidMainTraceShape;
    }
    var source = CallerSource{
        .columns = undefined,
        .log_size = log_size,
        .n_rows = n_rows,
        .domain_size = domain_size,
    };
    for (&source.columns, columns[0..caller_source_column_count]) |*destination, column| {
        destination.* = column;
    }
    try validateActivity(&source, authority.layout);
    return source;
}

fn validateActivity(
    source: *const CallerSource,
    layout: *const components.CallerLayout,
) Error!void {
    const enabler = source.columns[layout.enabler];
    for (0..source.domain_size) |logical_row| {
        const physical_row = main_trace.committedRow(logical_row, source.log_size);
        const expected = M31.fromCanonical(@intFromBool(logical_row < source.n_rows));
        if (!enabler[physical_row].eql(expected))
            return error.CallerActivityMismatch;
    }
}

fn visitRows(
    comptime apply: bool,
    source: *const CallerSource,
    layout: *const components.CallerLayout,
    counters: ?*table_counter.Set,
    observed: ?*DemandCounts,
) Error!void {
    if (comptime apply) {
        std.debug.assert(counters != null and observed == null);
    } else {
        std.debug.assert(counters == null and observed != null);
    }
    for (0..source.n_rows) |logical_row| {
        const physical_row = main_trace.committedRow(logical_row, source.log_size);
        try visitRow(
            apply,
            &source.columns,
            layout,
            physical_row,
            counters,
            observed,
        );
    }
}

fn visitRow(
    comptime apply: bool,
    columns: *const [caller_source_column_count][]const M31,
    layout: *const components.CallerLayout,
    row: usize,
    counters: ?*table_counter.Set,
    observed: ?*DemandCounts,
) Error!void {
    const clock = cell(columns, layout.execution_clock, row);
    const pointer_clock_gap = accessClock(clock, 1)
        .sub(cell(columns, layout.pointer_previous_clock, row)).sub(M31.one());
    try request(apply, .range_check_20, &.{pointer_clock_gap}, counters, observed);

    for (0..16) |lane_index| {
        const lane: u8 = @intCast(lane_index);
        const gap = accessClock(clock, 2)
            .sub(cell(columns, layout.previousClock(lane), row)).sub(M31.one());
        try request(apply, .range_check_20, &.{gap}, counters, observed);
    }

    for (0..2) |output| for (0..16) |lane_index| {
        const lane: u8 = @intCast(lane_index);
        const start = if (output == 0)
            layout.inputByte(lane, 0)
        else
            layout.outputByte(lane, 0);
        try request(apply, .range_check_8_8, &.{
            cell(columns, start, row),
            cell(columns, start + 1, row),
        }, counters, observed);
        try request(apply, .range_check_8_8, &.{
            cell(columns, start + 2, row),
            cell(columns, start + 3, row),
        }, counters, observed);
        try request(apply, .range_check_m31, &.{
            M31.zero(),
            cell(columns, start + 3, row),
        }, counters, observed);
    };

    try request(apply, .range_check_8_8, &.{
        cell(columns, layout.span_end_limbs, row),
        cell(columns, layout.span_end_limbs + 1, row),
    }, counters, observed);
    try request(apply, .range_check_8_8_4, &.{
        cell(columns, layout.span_end_limbs + 2, row),
        cell(columns, layout.pointer_bytes + 3, row).mul(M31.fromCanonical(4)),
        cell(columns, layout.span_end_limbs + 3, row),
    }, counters, observed);
}

fn request(
    comptime apply: bool,
    kind: table_schema.Kind,
    tuple: []const M31,
    counters: ?*table_counter.Set,
    observed: ?*DemandCounts,
) Error!void {
    const table_row = if (comptime apply)
        table_schema.indexBase(kind, tuple) catch unreachable
    else
        try table_schema.indexBase(kind, tuple);

    if (comptime apply) {
        const value = &counters.?.get(kind).values[table_row];
        value.* = value.sub(M31.one());
    } else {
        const count = &observed.?[@intFromEnum(kind)];
        count.* = std.math.add(u64, count.*, 1) catch
            return error.CoefficientBoundExceeded;
    }
}

inline fn cell(
    columns: *const [caller_source_column_count][]const M31,
    column: usize,
    row: usize,
) M31 {
    return columns[column][row];
}

inline fn accessClock(clock: M31, ordinal: u32) M31 {
    return clock.sub(M31.one()).mul(M31.fromCanonical(4))
        .add(M31.fromCanonical(ordinal));
}

comptime {
    if (fixed_table_count != components.caller_fixed_table_demand.len or
        fixed_table_count != 6 or caller_source_column_count != 158)
    {
        @compileError("guest fixed-table registration geometry drifted");
    }
    if (!std.meta.eql(
        components.caller_fixed_table_demand,
        components.FixedTableDemand{ 0, 17, 0, 1, 65, 32 },
    )) {
        @compileError("guest fixed-table demand drifted from the reviewed plan");
    }
}
