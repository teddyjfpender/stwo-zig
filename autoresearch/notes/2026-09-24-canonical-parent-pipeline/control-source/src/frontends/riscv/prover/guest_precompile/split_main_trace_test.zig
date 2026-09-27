//! Differential, failure-atomic, and performance evidence for R-008 traces.

const std = @import("std");
const builtin = @import("builtin");
const M31 = @import("stwo_core").fields.m31.M31;
const combined = @import("../../air/guest_precompile/main_trace.zig");
const statement_mod = @import("../../air/guest_precompile/statement.zig");
const support = @import("../../air/guest_precompile/main_trace_test_support.zig");
const aggregation_hash = @import("../../aggregation/hash.zig");
const subject = @import("split_main_trace.zig");

fn canonicalCallerColumns(
    result: *const combined.Result,
) subject.CallerCommittedColumns {
    var columns: subject.CallerCommittedColumns = undefined;
    for (&columns, 0..) |*column, index| column.* = result.callerMain(index);
    return columns;
}

fn canonicalProviderColumns(
    result: *const combined.Result,
) subject.ProviderCommittedColumns {
    var columns: subject.ProviderCommittedColumns = undefined;
    for (&columns, 0..) |*column, index| column.* = result.providerMain(index);
    return columns;
}

fn expectPairEqualsOracle(
    oracle: *const combined.Result,
    pair: *const subject.OwnedPairV1,
) !void {
    try std.testing.expectEqual(oracle.log_size, pair.caller.log_size);
    try std.testing.expectEqual(oracle.log_size, pair.provider.log_size);
    try std.testing.expectEqual(oracle.n_rows, pair.caller.n_rows);
    try std.testing.expectEqual(oracle.n_rows, pair.provider.n_rows);
    try std.testing.expectEqual(oracle.domain_size, pair.caller.domain_size);
    try std.testing.expectEqual(oracle.domain_size, pair.provider.domain_size);
    for (0..subject.caller_column_count) |column| {
        try std.testing.expectEqualSlices(
            M31,
            oracle.callerMain(column),
            pair.caller.column(column),
        );
    }
    for (0..subject.provider_column_count) |column| {
        try std.testing.expectEqualSlices(
            M31,
            oracle.providerMain(column),
            pair.provider.column(column),
        );
    }

    const oracle_caller = canonicalCallerColumns(oracle);
    const oracle_provider = canonicalProviderColumns(oracle);
    const split_caller = pair.caller.committedColumns();
    const split_provider = pair.provider.committedColumns();
    try std.testing.expectEqualSlices(
        u8,
        &(try subject.callerTraceDigest(
            oracle.log_size,
            oracle.n_rows,
            &oracle_caller,
        )),
        &(try subject.callerTraceDigest(
            pair.caller.log_size,
            pair.caller.n_rows,
            &split_caller,
        )),
    );
    try std.testing.expectEqualSlices(
        u8,
        &(try subject.providerTraceDigest(
            oracle.log_size,
            oracle.n_rows,
            &oracle_provider,
        )),
        &(try subject.providerTraceDigest(
            pair.provider.log_size,
            pair.provider.n_rows,
            &split_provider,
        )),
    );
}

test "split owned caller and provider are row-exact against combined oracle" {
    const cases = [_]u32{ 0, 1, 2, 17, 31 };
    for (cases) |call_count| {
        var core = support.coreFixture(call_count);
        const extension = try statement_mod.ExtensionStatement.canonical(
            &core,
            call_count,
        );
        var logs = try support.logsFixture(std.testing.allocator, call_count);
        defer logs.deinit();
        var oracle = try combined.generate(
            std.testing.allocator,
            &core,
            &extension,
            &logs.calls,
            &logs.rows,
        );
        defer oracle.deinit();
        var pair = try subject.generateOwned(
            std.testing.allocator,
            &core,
            &extension,
            &logs.calls,
            &logs.rows,
        );
        defer pair.deinit();

        try expectPairEqualsOracle(&oracle, &pair);
        try std.testing.expectEqual(call_count, pair.caller.n_rows);
        try std.testing.expectEqual(call_count, extension.counts.n_guest);
        try std.testing.expectEqual(@as(usize, call_count), logs.calls.len());
        const profile = pair.workProfile();
        try std.testing.expectEqual(
            subject.caller_column_count * oracle.domain_size,
            profile.caller_cells,
        );
        try std.testing.expectEqual(
            subject.provider_column_count * oracle.domain_size,
            profile.provider_cells,
        );
        try std.testing.expectEqual(@as(usize, 2), profile.construction_allocations);
        try std.testing.expectEqual(@as(usize, 0), profile.hot_path_allocations);
        try std.testing.expectEqual(
            @as(usize, 0),
            profile.hot_path_dynamic_dispatches,
        );
    }
    try std.testing.expect(subject.RESEARCH_ONLY);
    try std.testing.expect(!subject.ACTIVATES_PRODUCTION_PROOF);
    try std.testing.expect(subject.ALLOWS_PARALLEL_ROLE_FILL);
    try std.testing.expect(!subject.VERIFIES_SPLIT_STARKS);
}

const caller_trace_digest_17 = [_]u8{
    0x93, 0xa6, 0xcb, 0x82, 0x9e, 0x1f, 0xca, 0xf0,
    0x26, 0xe8, 0x3e, 0x92, 0x63, 0x0e, 0x55, 0x1e,
    0xdc, 0xd2, 0xf0, 0xf3, 0x02, 0x96, 0xa6, 0x14,
    0x35, 0xf6, 0x10, 0x88, 0x20, 0xce, 0xc7, 0xae,
};
const provider_trace_digest_17 = [_]u8{
    0x62, 0x29, 0x1f, 0x51, 0x81, 0xb0, 0xbb, 0xd9,
    0xbb, 0x8d, 0x49, 0x6b, 0xf3, 0x08, 0x1b, 0x6b,
    0x78, 0xb3, 0xd6, 0x9d, 0xe1, 0xf7, 0x5d, 0x6f,
    0x61, 0x9a, 0x00, 0x19, 0x30, 0xf6, 0x57, 0x7b,
};

test "split role trace digests are golden and explicitly non-PCS" {
    var core = support.coreFixture(17);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, 17);
    var logs = try support.logsFixture(std.testing.allocator, 17);
    defer logs.deinit();
    var pair = try subject.generateOwned(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    defer pair.deinit();
    const caller_columns = pair.caller.committedColumns();
    const provider_columns = pair.provider.committedColumns();
    const caller_digest = try subject.callerTraceDigest(
        pair.caller.log_size,
        pair.caller.n_rows,
        &caller_columns,
    );
    const provider_digest = try subject.providerTraceDigest(
        pair.provider.log_size,
        pair.provider.n_rows,
        &provider_columns,
    );
    try expectGolden("caller split trace", caller_trace_digest_17, caller_digest);
    try expectGolden(
        "provider split trace",
        provider_trace_digest_17,
        provider_digest,
    );
    try std.testing.expect(!aggregation_hash.eql(caller_digest, provider_digest));
}

fn expectGolden(label: []const u8, expected: [32]u8, actual: [32]u8) !void {
    if (!std.mem.eql(u8, &expected, &actual)) {
        const hex = std.fmt.bytesToHex(actual, .lower);
        std.debug.print("{s}={s}\n", .{ label, &hex });
    }
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

const DestinationStorage = struct {
    allocator: std.mem.Allocator,
    storage: []M31,
    caller: subject.CallerDestinations,
    provider: subject.ProviderDestinations,
    domain_size: usize,

    fn init(
        allocator: std.mem.Allocator,
        domain_size: usize,
        initial: M31,
    ) !DestinationStorage {
        const storage = try allocator.alloc(
            M31,
            subject.total_column_count * domain_size,
        );
        @memset(storage, initial);
        var result = DestinationStorage{
            .allocator = allocator,
            .storage = storage,
            .caller = undefined,
            .provider = undefined,
            .domain_size = domain_size,
        };
        var column: usize = 0;
        for (&result.caller) |*destination| {
            destination.* = storage[column * domain_size ..][0..domain_size];
            column += 1;
        }
        for (&result.provider) |*destination| {
            destination.* = storage[column * domain_size ..][0..domain_size];
            column += 1;
        }
        std.debug.assert(column == subject.total_column_count);
        return result;
    }

    fn deinit(self: *DestinationStorage) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }

    fn expectAll(self: *const DestinationStorage, expected: M31) !void {
        for (self.storage) |value| try std.testing.expect(value.eql(expected));
    }
};

fn expectDestinationsEqualOracle(
    oracle: *const combined.Result,
    destinations: *const DestinationStorage,
) !void {
    for (destinations.caller, 0..) |column, index| {
        try std.testing.expectEqualSlices(M31, oracle.callerMain(index), column);
    }
    for (destinations.provider, 0..) |column, index| {
        try std.testing.expectEqualSlices(M31, oracle.providerMain(index), column);
    }
}

const FinishThread = struct {
    prepared: *const subject.PreparedDestinationsV1,

    fn caller(self: *const FinishThread) void {
        self.prepared.finishCaller();
    }

    fn provider(self: *const FinishThread) void {
        self.prepared.finishProvider();
    }
};

test "pair admission is mutation-free and role finishes are independent and parallel" {
    const guard = M31.fromCanonical(0x123456);
    var core = support.coreFixture(17);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, 17);
    var logs = try support.logsFixture(std.testing.allocator, 17);
    defer logs.deinit();
    var oracle = try combined.generate(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    defer oracle.deinit();

    var serial = try DestinationStorage.init(
        std.testing.allocator,
        oracle.domain_size,
        guard,
    );
    defer serial.deinit();
    const prepared = try subject.prepareInto(
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
        &serial.caller,
        &serial.provider,
    );
    try serial.expectAll(guard);
    prepared.finishCaller();
    for (serial.caller, 0..) |column, index| {
        try std.testing.expectEqualSlices(M31, oracle.callerMain(index), column);
    }
    for (serial.provider) |column| {
        for (column) |value| try std.testing.expect(value.eql(guard));
    }
    prepared.finishProvider();
    try expectDestinationsEqualOracle(&oracle, &serial);

    var parallel = try DestinationStorage.init(
        std.testing.allocator,
        oracle.domain_size,
        guard,
    );
    defer parallel.deinit();
    const parallel_prepared = try subject.prepareInto(
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
        &parallel.caller,
        &parallel.provider,
    );
    const invocation = FinishThread{ .prepared = &parallel_prepared };
    const caller_thread = try std.Thread.spawn(
        .{},
        FinishThread.caller,
        .{&invocation},
    );
    const provider_thread = try std.Thread.spawn(
        .{},
        FinishThread.provider,
        .{&invocation},
    );
    caller_thread.join();
    provider_thread.join();
    try expectDestinationsEqualOracle(&oracle, &parallel);
}

test "shape alias cross-role and semantic failures reject before mutation" {
    const guard = M31.fromCanonical(0x654321);
    var core = support.coreFixture(1);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, 1);
    var logs = try support.logsFixture(std.testing.allocator, 1);
    defer logs.deinit();
    var destinations = try DestinationStorage.init(
        std.testing.allocator,
        16,
        guard,
    );
    defer destinations.deinit();

    const saved_caller = destinations.caller[1];
    destinations.caller[1] = destinations.caller[0];
    try std.testing.expectError(
        error.OverlappingDestinations,
        subject.prepareInto(
            &core,
            &extension,
            &logs.calls,
            &logs.rows,
            &destinations.caller,
            &destinations.provider,
        ),
    );
    try destinations.expectAll(guard);
    destinations.caller[1] = saved_caller;

    const saved_provider = destinations.provider[0];
    destinations.provider[0] = destinations.caller[0];
    try std.testing.expectError(
        error.OverlappingDestinations,
        subject.prepareInto(
            &core,
            &extension,
            &logs.calls,
            &logs.rows,
            &destinations.caller,
            &destinations.provider,
        ),
    );
    try destinations.expectAll(guard);
    destinations.provider[0] = saved_provider[0 .. saved_provider.len - 1];
    try std.testing.expectError(
        error.InvalidDestinationShape,
        subject.prepareInto(
            &core,
            &extension,
            &logs.calls,
            &logs.rows,
            &destinations.caller,
            &destinations.provider,
        ),
    );
    try destinations.expectAll(guard);
    destinations.provider[0] = saved_provider;

    logs.calls.storage.items[0].output[0] +%= 1;
    try std.testing.expectError(
        error.ProviderOutputMismatch,
        subject.prepareInto(
            &core,
            &extension,
            &logs.calls,
            &logs.rows,
            &destinations.caller,
            &destinations.provider,
        ),
    );
    try destinations.expectAll(guard);
}

fn allocationCase(
    allocator: std.mem.Allocator,
    core: *const support.RiscVStatement,
    extension: *const statement_mod.ExtensionStatement,
    logs: *const support.OwnedLogs,
) !void {
    var pair = try subject.generateOwned(
        allocator,
        core,
        extension,
        &logs.calls,
        &logs.rows,
    );
    defer pair.deinit();
}

test "owned split uses exactly two allocations and rolls back every failure" {
    var core = support.coreFixture(17);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, 17);
    var logs = try support.logsFixture(std.testing.allocator, 17);
    defer logs.deinit();

    var exactly_two = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 2 },
    );
    var pair = try subject.generateOwned(
        exactly_two.allocator(),
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    try std.testing.expect(!exactly_two.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 2), exactly_two.alloc_index);
    pair.deinit();
    try std.testing.expectEqual(
        exactly_two.allocated_bytes,
        exactly_two.freed_bytes,
    );

    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationCase,
        .{ &core, &extension, &logs },
    );

    logs.calls.storage.items[0].output[0] +%= 1;
    var no_allocation = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.ProviderOutputMismatch,
        subject.generateOwned(
            no_allocation.allocator(),
            &core,
            &extension,
            &logs.calls,
            &logs.rows,
        ),
    );
    try std.testing.expect(!no_allocation.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 0), no_allocation.alloc_index);
}

fn combinedDestinations(
    storage: *DestinationStorage,
) combined.MainDestinations {
    return .{ .caller = storage.caller, .provider = storage.provider };
}

fn consume(values: []const M31) void {
    var checksum: u64 = 0;
    for (values) |value| checksum +%= value.v;
    std.mem.doNotOptimizeAway(&checksum);
}

fn measureCombined(
    core: *const support.RiscVStatement,
    extension: *const statement_mod.ExtensionStatement,
    logs: *const support.OwnedLogs,
    destinations: *DestinationStorage,
) !u64 {
    const views = combinedDestinations(destinations);
    var timer = try std.time.Timer.start();
    try combined.generateMainInto(
        core,
        extension,
        &logs.calls,
        &logs.rows,
        &views,
    );
    const elapsed = timer.read();
    consume(destinations.storage);
    return elapsed;
}

fn measureSplit(
    core: *const support.RiscVStatement,
    extension: *const statement_mod.ExtensionStatement,
    logs: *const support.OwnedLogs,
    destinations: *DestinationStorage,
) !u64 {
    var timer = try std.time.Timer.start();
    const prepared = try subject.prepareInto(
        core,
        extension,
        &logs.calls,
        &logs.rows,
        &destinations.caller,
        &destinations.provider,
    );
    prepared.finishCaller();
    prepared.finishProvider();
    const elapsed = timer.read();
    consume(destinations.storage);
    return elapsed;
}

test "split sequential shadow path retains paired combined throughput" {
    if (builtin.mode != .ReleaseFast) return;
    const samples = 9;
    const call_count: u32 = 64;
    var core = support.coreFixture(call_count);
    const extension = try statement_mod.ExtensionStatement.canonical(
        &core,
        call_count,
    );
    var logs = try support.logsFixture(std.testing.allocator, call_count);
    defer logs.deinit();
    const domain_size: usize = 64;
    var oracle_storage = try DestinationStorage.init(
        std.testing.allocator,
        domain_size,
        M31.zero(),
    );
    defer oracle_storage.deinit();
    var split_storage = try DestinationStorage.init(
        std.testing.allocator,
        domain_size,
        M31.zero(),
    );
    defer split_storage.deinit();

    _ = try measureCombined(&core, &extension, &logs, &oracle_storage);
    _ = try measureSplit(&core, &extension, &logs, &split_storage);
    var combined_ns: [samples]u64 = undefined;
    var split_ns: [samples]u64 = undefined;
    for (0..samples) |sample| {
        if ((sample & 1) == 0) {
            combined_ns[sample] = try measureCombined(
                &core,
                &extension,
                &logs,
                &oracle_storage,
            );
            split_ns[sample] = try measureSplit(
                &core,
                &extension,
                &logs,
                &split_storage,
            );
        } else {
            split_ns[sample] = try measureSplit(
                &core,
                &extension,
                &logs,
                &split_storage,
            );
            combined_ns[sample] = try measureCombined(
                &core,
                &extension,
                &logs,
                &oracle_storage,
            );
        }
    }
    std.mem.sort(u64, &combined_ns, {}, std.sort.asc(u64));
    std.mem.sort(u64, &split_ns, {}, std.sort.asc(u64));
    const combined_median = combined_ns[samples / 2];
    const split_median = split_ns[samples / 2];
    try std.testing.expect(split_median <= combined_median + combined_median / 2);
    try std.testing.expectEqualSlices(
        M31,
        oracle_storage.storage,
        split_storage.storage,
    );
    std.debug.print(
        "R-008 split main trace ReleaseFast: rows={d} combined={d}ns " ++
            "split={d}ns ratio={d:.3}\n",
        .{
            call_count,
            combined_median,
            split_median,
            @as(f64, @floatFromInt(split_median)) /
                @as(f64, @floatFromInt(combined_median)),
        },
    );
}

comptime {
    if (subject.caller_column_count != 286 or
        subject.provider_column_count != 445 or
        subject.total_column_count != 731)
    {
        @compileError("R-008 split main-trace test geometry drifted");
    }
}
