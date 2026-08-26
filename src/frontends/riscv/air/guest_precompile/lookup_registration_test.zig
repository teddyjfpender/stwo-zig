//! Differential and rollback evidence for guest fixed-table registration.

const std = @import("std");
const fields = @import("stwo_core").fields;
const M31 = fields.m31.M31;
const QM31 = fields.qm31.QM31;
const subject = @import("lookup_registration.zig");
const components = @import("component_registry.zig");
const interaction_plan = @import("interaction_plan.zig");
const main_trace = @import("main_trace.zig");
const support = @import("main_trace_test_support.zig");
const statement_mod = @import("statement.zig");
const relation_types = @import("../lang/types.zig");
const table_counter = @import("../lookups/tables/counter.zig");
const table_schema = @import("../lookups/tables/schema.zig");

const Fixture = struct {
    core: support.RiscVStatement,
    extension: statement_mod.ExtensionStatement,
    logs: support.OwnedLogs,
    main: main_trace.Result,

    fn init(allocator: std.mem.Allocator, n_calls: u32) !Fixture {
        var core = support.coreFixture(n_calls);
        const extension = try statement_mod.ExtensionStatement.canonical(&core, n_calls);
        var logs = try support.logsFixture(allocator, n_calls);
        errdefer logs.deinit();
        const main = try main_trace.generate(
            allocator,
            &core,
            &extension,
            &logs.calls,
            &logs.rows,
        );
        return .{
            .core = core,
            .extension = extension,
            .logs = logs,
            .main = main,
        };
    }

    fn deinit(self: *Fixture) void {
        self.main.deinit();
        self.logs.deinit();
        self.* = undefined;
    }
};

test "lookup registration exactly matches authenticated interaction events and columns" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator, 3);
    defer fixture.deinit();
    var expected = try table_counter.Set.init(allocator);
    defer expected.deinit(allocator);
    var actual = try table_counter.Set.init(allocator);
    defer actual.deinit(allocator);
    var generated = try table_counter.Set.init(allocator);
    defer generated.deinit(allocator);
    var split = try table_counter.Set.init(allocator);
    defer split.deinit(allocator);
    seedBaseCounters(&expected);
    seedBaseCounters(&actual);
    seedBaseCounters(&generated);
    seedBaseCounters(&split);

    const projected_demand = try registerExpectedFromInteractionPlan(&fixture.main, &expected);
    const summary = try subject.register(
        &fixture.core,
        &fixture.extension,
        &fixture.main,
        &actual,
    );
    var destinations = fixture.main.mutableMainDestinations();
    const generated_summary = try subject.registerGenerated(
        &fixture.core,
        &fixture.extension,
        &destinations,
        &generated,
    );
    var caller_columns: subject.CallerMainColumns = undefined;
    for (&caller_columns, 0..) |*column, index| {
        column.* = fixture.main.callerMain(index);
    }
    const split_summary = try subject.registerCallerColumns(
        &fixture.core,
        &fixture.extension,
        &caller_columns,
        fixture.main.log_size,
        fixture.main.n_rows,
        &split,
    );

    try std.testing.expectEqual(@as(u32, 3), summary.n_calls);
    try std.testing.expectEqual(
        subject.DemandCounts{ 0, 51, 0, 3, 195, 96 },
        summary.demand,
    );
    try std.testing.expectEqual(summary.demand, projected_demand);
    try std.testing.expectEqualDeep(summary, generated_summary);
    try std.testing.expectEqualDeep(summary, split_summary);
    try expectCounterSetsEqual(&expected, &actual);
    try expectCounterSetsEqual(&expected, &generated);
    try expectCounterSetsEqual(&expected, &split);
    try expectCommittedColumnsEqual(allocator, &expected, &actual);
    try expectCommittedColumnsEqual(allocator, &expected, &generated);
    try expectCommittedColumnsEqual(allocator, &expected, &split);
}

test "zero-call registration is the exact base-only identity" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator, 0);
    defer fixture.deinit();
    var base_only = try table_counter.Set.init(allocator);
    defer base_only.deinit(allocator);
    var extended = try table_counter.Set.init(allocator);
    defer extended.deinit(allocator);
    seedBaseCounters(&base_only);
    seedBaseCounters(&extended);

    var destinations = fixture.main.mutableMainDestinations();
    const summary = try subject.registerGenerated(
        &fixture.core,
        &fixture.extension,
        &destinations,
        &extended,
    );
    try std.testing.expectEqual(@as(u32, 0), summary.n_calls);
    try std.testing.expectEqual(
        [_]u64{0} ** table_schema.KIND_COUNT,
        summary.demand,
    );
    try expectCounterSetsEqual(&base_only, &extended);
    try expectCommittedColumnsEqual(allocator, &base_only, &extended);
}

test "profile count manifest and component authority reject before counter mutation" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator, 1);
    defer fixture.deinit();

    var changed = fixture.extension;
    changed.profile = .rv32im_zkvm_v1;
    try expectRejectedWithoutMutation(
        error.ProfileMismatch,
        &fixture.core,
        &changed,
        &fixture.main,
    );

    changed = fixture.extension;
    changed.counts.custom_retirements += 1;
    try expectRejectedWithoutMutation(
        error.CallCountMismatch,
        &fixture.core,
        &changed,
        &fixture.main,
    );

    changed = fixture.extension;
    changed.manifest_digest[0] ^= 1;
    try expectRejectedWithoutMutation(
        error.ManifestDigestMismatch,
        &fixture.core,
        &changed,
        &fixture.main,
    );

    changed = fixture.extension;
    changed.components[0].slot = .provider;
    try expectRejectedWithoutMutation(
        error.ComponentOrderMismatch,
        &fixture.core,
        &changed,
        &fixture.main,
    );
}

test "count geometry selector and counter-shape mismatches are atomic" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator, 1);
    defer fixture.deinit();

    var changed_main = fixture.main;
    changed_main.n_rows = 0;
    try expectRejectedWithoutMutation(
        error.InvalidMainTraceShape,
        &fixture.core,
        &fixture.extension,
        &changed_main,
    );

    const active_row = main_trace.committedRow(0, fixture.main.log_size);
    fixture.main.storage[fixture.main.domain_size + active_row] = M31.zero();
    try expectRejectedWithoutMutation(
        error.CallerSelectorMismatch,
        &fixture.core,
        &fixture.extension,
        &fixture.main,
    );
    fixture.main.storage[fixture.main.domain_size + active_row] = M31.one();

    var malformed_destinations = fixture.main.mutableMainDestinations();
    malformed_destinations.caller[0] =
        malformed_destinations.caller[0][0 .. fixture.main.domain_size - 1];
    try expectGeneratedRejectedWithoutMutation(
        error.InvalidMainTraceShape,
        &fixture.core,
        &fixture.extension,
        &malformed_destinations,
    );

    var destinations = fixture.main.mutableMainDestinations();
    const enabler = components.caller_layout.enabler;
    destinations.caller[enabler][active_row] = M31.zero();
    try expectGeneratedRejectedWithoutMutation(
        error.CallerActivityMismatch,
        &fixture.core,
        &fixture.extension,
        &destinations,
    );
    destinations.caller[enabler][active_row] = M31.one();

    var counters = try table_counter.Set.init(allocator);
    defer counters.deinit(allocator);
    counters.counters[0].kind = .range_check_20;
    try std.testing.expectError(
        error.InvalidCounterSet,
        subject.register(
            &fixture.core,
            &fixture.extension,
            &fixture.main,
            &counters,
        ),
    );
    try expectAllCountersZero(&counters);
}

test "coefficient bound rejects repeated-call wrap before mutation" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator, 0);
    defer fixture.deinit();
    const excessive: u32 = @intCast(
        (statement_mod.field_modulus - 1) / components.caller_fixed_table_demand[4] + 1,
    );
    var changed = fixture.extension;
    changed.counts = .{
        .n_guest = excessive,
        .custom_retirements = excessive,
        .frozen_call_count = excessive,
    };

    try std.testing.expectError(
        error.CoefficientBoundExceeded,
        subject.checkedDemandCounts(excessive),
    );
    try expectRejectedWithoutMutation(
        error.CoefficientBoundExceeded,
        &fixture.core,
        &changed,
        &fixture.main,
    );
}

test "late unrepresentable caller tuple cannot partially register earlier rows" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator, 2);
    defer fixture.deinit();
    const physical_row = main_trace.committedRow(1, fixture.main.log_size);
    const high_byte = components.caller_layout.inputByte(15, 3);
    const global_column = main_trace.preprocessed_column_count + high_byte;
    fixture.main.storage[global_column * fixture.main.domain_size + physical_row] =
        M31.fromCanonical(255);

    try expectRejectedWithoutMutation(
        error.ValueOutOfRange,
        &fixture.core,
        &fixture.extension,
        &fixture.main,
    );
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var fixture = try Fixture.init(allocator, 2);
    defer fixture.deinit();
    var counters = try table_counter.Set.init(allocator);
    defer counters.deinit(allocator);
    var destinations = fixture.main.mutableMainDestinations();
    _ = try subject.registerGenerated(
        &fixture.core,
        &fixture.extension,
        &destinations,
        &counters,
    );
}

test "integrated lookup registration releases every surrounding partial allocation" {
    // Registration itself accepts no allocator and cannot allocate. This
    // sweep proves that every owner needed to reach it still rolls back cleanly.
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

fn registerExpectedFromInteractionPlan(
    main: *const main_trace.Result,
    counters: *table_counter.Set,
) !subject.DemandCounts {
    var demand = [_]u64{0} ** table_schema.KIND_COUNT;
    var secure_row: [main_trace.caller_main_column_count]QM31 = undefined;
    for (0..main.n_rows) |logical_row| {
        const physical_row = main_trace.committedRow(logical_row, main.log_size);
        for (&secure_row, 0..) |*value, column| {
            value.* = QM31.fromBase(main.callerMain(column)[physical_row]);
        }
        for (components.caller_events, 0..) |event, event_index| {
            const schema_index = relation_types.idIndex(event.schema);
            if (schema_index < 6 or schema_index >= 6 + table_schema.KIND_COUNT) {
                continue;
            }
            const kind_index = schema_index - 6;
            const kind: table_schema.Kind = @enumFromInt(kind_index);
            const projected = try interaction_plan.callerEntry(&secure_row, event_index);
            try counters.get(kind).registerRaw(
                projected.numerator,
                projected.values[0..projected.arity],
            );
            if (!projected.numerator.isZero()) demand[kind_index] += 1;
        }
    }
    return demand;
}

fn seedBaseCounters(counters: *table_counter.Set) void {
    for (&counters.counters, 0..) |*counter, index| {
        const row = index + 1;
        counter.values[row] = M31.fromCanonical(@intCast(index + 2)).neg();
    }
}

fn expectRejectedWithoutMutation(
    expected: subject.Error,
    core: *const support.RiscVStatement,
    extension: *const statement_mod.ExtensionStatement,
    main: *const main_trace.Result,
) !void {
    var counters = try table_counter.Set.init(std.testing.allocator);
    defer counters.deinit(std.testing.allocator);
    try std.testing.expectError(
        expected,
        subject.register(core, extension, main, &counters),
    );
    try expectAllCountersZero(&counters);
}

fn expectGeneratedRejectedWithoutMutation(
    expected: subject.Error,
    core: *const support.RiscVStatement,
    extension: *const statement_mod.ExtensionStatement,
    destinations: *const main_trace.MainDestinations,
) !void {
    var counters = try table_counter.Set.init(std.testing.allocator);
    defer counters.deinit(std.testing.allocator);
    try std.testing.expectError(
        expected,
        subject.registerGenerated(core, extension, destinations, &counters),
    );
    try expectAllCountersZero(&counters);
}

fn expectAllCountersZero(counters: *const table_counter.Set) !void {
    for (&counters.counters) |*counter| {
        for (counter.values) |value| try std.testing.expect(value.isZero());
    }
}

fn expectCounterSetsEqual(
    expected: *const table_counter.Set,
    actual: *const table_counter.Set,
) !void {
    for (&expected.counters, &actual.counters) |*want, *got| {
        try std.testing.expectEqual(want.kind, got.kind);
        try std.testing.expectEqual(want.values.len, got.values.len);
        for (want.values, got.values) |want_value, got_value| {
            try std.testing.expect(want_value.eql(got_value));
        }
    }
}

fn expectCommittedColumnsEqual(
    allocator: std.mem.Allocator,
    expected: *const table_counter.Set,
    actual: *const table_counter.Set,
) !void {
    for (&expected.counters, &actual.counters) |*want, *got| {
        const expected_column = try want.committedColumn(allocator);
        defer allocator.free(expected_column);
        const actual_column = try got.committedColumn(allocator);
        defer allocator.free(actual_column);
        for (expected_column, actual_column) |want_value, got_value| {
            try std.testing.expect(want_value.eql(got_value));
        }
    }
}
