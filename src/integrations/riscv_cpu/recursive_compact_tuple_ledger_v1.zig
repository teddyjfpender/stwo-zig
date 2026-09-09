//! Exact tuple aggregation for integrations with the row35 range provider:
//! Ethereum cohorts and detached recursive parents. CSP diagnostic storage stays
//! unchanged. Range tuples use their exact table index; other domains retain the
//! shared canonical SHA-256 grouping. Initial38 histogram admission is optional.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const relation = frontend.recursion.air.relation_interaction;
const universal = frontend.recursion.air.universal_challenges;
const tables = frontend.air.lookups.tables;
const initial_rows = @import("recursive_common_ethereum_initial_input_rows_v1.zig");
const Domain = @FieldType(relation.TupleContribution, "domain");
const Role = @FieldType(relation.TupleContribution, "role");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Map = std.AutoHashMapUnmanaged([32]u8, QM31);
const TABLE_SIZE = tables.schema.size(.range_check_8_8);
const PROVIDER_COMPONENT = 35;

pub const Owner = struct {
    allocator: std.mem.Allocator,
    maps: [universal.RELATION_COUNT]Map = @splat(.empty),
    source_counter: tables.counter.Counter,
    range_residual: []M31,
    initial_histogram: ?[]u32,
    initial_count: usize = 0,
    source_finished: bool = false,
    first_error: ?anyerror = null,
    contribution_count: usize = 0,
    source_range_contribution_count: usize = 0,
    live_entries: usize = 0,
    peak_entries: usize = 0,

    pub fn init(allocator: std.mem.Allocator, initial: bool) !Owner {
        var counter = try tables.counter.Counter.init(allocator, .range_check_8_8);
        errdefer counter.deinit(allocator);
        const residual = try allocator.alloc(M31, TABLE_SIZE);
        errdefer allocator.free(residual);
        @memset(residual, M31.zero());
        const histogram = if (initial) try allocator.alloc(u32, TABLE_SIZE) else null;
        if (histogram) |bins| @memset(bins, 0);
        return .{ .allocator = allocator, .source_counter = counter, .range_residual = residual, .initial_histogram = histogram };
    }

    pub fn deinit(self: *Owner) void {
        for (&self.maps) |*map| map.deinit(self.allocator);
        self.source_counter.deinit(self.allocator);
        self.allocator.free(self.range_residual);
        if (self.initial_histogram) |bins| self.allocator.free(bins);
        self.* = undefined;
    }

    /// The returned adapter borrows this owner's stable address. Destroy it
    /// before the owner and never reserve or inspect its empty record array.
    pub fn ledger(self: *Owner) relation.TupleLedger {
        return .{ .allocator = self.allocator, .sink = .{ .context = self, .append_fn = appendErased, .classify_fn = classifyErased, .print_unmatched_fn = printUnmatchedErased } };
    }

    pub fn validate(self: *const Owner) !void {
        if (self.first_error) |err| return err;
    }

    /// Freeze the source histogram before adding row35. The range owner checks
    /// Initial38 requests against the independently constructed lane histogram.
    pub fn sealSources(self: *Owner, initial: ?*const initial_rows.OwnedV1) !void {
        return self.sealSourceHistogram(if (initial) |rows| rows.rangeHistogram() else null, if (initial) |rows| rows.rangeContributionCount() else 0);
    }

    pub fn sealSourceHistogram(self: *Owner, expected: ?[]const u32, expected_count: usize) !void {
        try self.validate();
        if (self.source_finished or (expected != null) != (self.initial_histogram != null)) return error.EthereumCompactTupleSourceMismatch;
        if (expected) |bins| {
            if (self.initial_count != expected_count or !std.mem.eql(u32, self.initial_histogram.?, bins)) return error.EthereumCompactTupleSourceMismatch;
        }
        self.source_finished = true;
    }

    pub fn classify(self: *const Owner) !relation.TupleClosureReport {
        try self.validate();
        return self.report();
    }

    pub const Metrics = struct {
        contribution_count: usize,
        source_range_contribution_count: usize,
        live_entries: usize,
        peak_entries: usize,
        capacity_entries: usize,
        // Capacity accounting includes one metadata byte per hash slot, but
        // excludes allocator headers/alignment. Dense table storage is exact.
        retained_bytes: usize,
        retained_bytes_is_estimate: bool = true,
    };

    pub fn metrics(self: *const Owner) Metrics {
        var capacity: usize = 0;
        for (self.maps) |map| capacity += map.capacity();
        return .{ .contribution_count = self.contribution_count, .source_range_contribution_count = self.source_range_contribution_count, .live_entries = self.live_entries, .peak_entries = self.peak_entries, .capacity_entries = capacity, .retained_bytes = capacity * (@sizeOf([32]u8) + @sizeOf(QM31) + 1) + TABLE_SIZE * (@sizeOf(M31) * 2 + if (self.initial_histogram != null) @as(usize, @sizeOf(u32)) else 0) };
    }

    fn appendErased(context: *anyopaque, domain: Domain, component: u8, event: u8, role: Role, weight: QM31, values: []const QM31) std.mem.Allocator.Error!void {
        const self: *Owner = @ptrCast(@alignCast(context));
        _ = event;
        if (weight.isZero()) return;
        self.contribution_count = std.math.add(usize, self.contribution_count, 1) catch {
            self.first_error = error.ArithmeticOverflow;
            return;
        };
        if (self.first_error != null) return;
        if (domain == .range_check_8_8) {
            self.appendRange(component, role, weight, values) catch |err| {
                self.first_error = err;
            };
            return;
        }
        const key = relation.TupleLedger.canonicalHash(domain, values);
        const map = &self.maps[@intFromEnum(domain)];
        if (map.getEntry(key)) |retained| {
            const next = retained.value_ptr.add(weight);
            if (next.isZero()) {
                // The matching entry is already located; do not hash/probe it
                // a second time just to remove a closed tuple.
                map.removeByPtr(retained.key_ptr);
                self.live_entries -= 1;
            } else retained.value_ptr.* = next;
        } else {
            map.put(self.allocator, key, weight) catch |err| {
                self.first_error = err;
                return err;
            };
            self.live_entries += 1;
            self.peak_entries = @max(self.peak_entries, self.live_entries);
        }
    }

    fn appendRange(self: *Owner, component: u8, role: Role, weight: QM31, values: []const QM31) !void {
        // Validate every original tuple before aggregation: malformed requests
        // must not vanish when later weights cancel them.
        if (values.len != 2) return error.EthereumCompactTupleSourceMismatch;
        const numerator = weight.tryIntoM31() catch return error.NonBaseFieldValue;
        const index = try tables.schema.indexSecure(.range_check_8_8, values);
        if (!self.source_finished) {
            if (component == PROVIDER_COMPONENT) return error.EthereumCompactTupleSourceMismatch;
            if (self.initial_histogram) |histogram| {
                if (component == initial_rows.PACKET_COMPONENT) return error.EthereumCompactTupleSourceMismatch;
                if (component == initial_rows.LANE_COMPONENT) {
                    if (role != .request or !weight.eql(QM31.one().neg())) return error.EthereumCompactTupleSourceMismatch;
                    histogram[index] = try std.math.add(u32, histogram[index], 1);
                    self.initial_count = try std.math.add(usize, self.initial_count, 1);
                }
            }
            self.source_counter.values[index] = self.source_counter.values[index].add(numerator);
            self.source_range_contribution_count = try std.math.add(usize, self.source_range_contribution_count, 1);
        } else if (component != PROVIDER_COMPONENT) return error.EthereumCompactTupleSourceMismatch;
        self.range_residual[index] = self.range_residual[index].add(numerator);
    }

    fn report(self: *const Owner) relation.TupleClosureReport {
        var result = relation.TupleClosureReport{ .contribution_count = self.contribution_count, .unmatched_tuple_count = 0, .unmatched_by_domain = @splat(0) };
        for (self.maps, 0..) |map, domain| {
            // Zero balances are removed immediately.
            result.unmatched_by_domain[domain] = map.count();
            result.unmatched_tuple_count += map.count();
        }
        for (self.range_residual) |value| if (!value.isZero()) {
            result.unmatched_by_domain[@intFromEnum(Domain.range_check_8_8)] += 1;
            result.unmatched_tuple_count += 1;
        };
        return result;
    }

    fn classifyErased(context: *anyopaque) relation.TupleClosureReport {
        const self: *Owner = @ptrCast(@alignCast(context));
        var result = self.report();
        // Legacy classify cannot return an error. Never report closure after a
        // failed ingestion; the explicit validate/classify APIs return its cause.
        if (self.first_error != null) {
            result.unmatched_tuple_count += 1;
            result.unmatched_by_domain[@intFromEnum(Domain.range_check_8_8)] += 1;
        }
        return result;
    }

    fn printUnmatchedErased(context: *anyopaque, limit: usize) void {
        const self: *Owner = @ptrCast(@alignCast(context));
        if (self.first_error) |err| std.debug.print("ETHEREUM_COMPACT_TUPLE_ERROR error={s}\n", .{@errorName(err)});
        for (&self.maps, 0..) |*map, domain| {
            var iterator = map.iterator();
            var printed: usize = 0;
            while (iterator.next()) |entry| {
                if (printed == limit) break;
                std.debug.print("TUPLE_UNMATCHED domain={s} hash={s} residual={any} compact=true\n", .{ @tagName(@as(Domain, @enumFromInt(domain))), std.fmt.bytesToHex(entry.key_ptr.*, .lower), entry.value_ptr.toM31Array() });
                printed += 1;
            }
        }
        var printed: usize = 0;
        for (self.range_residual, 0..) |value, index| if (!value.isZero()) {
            if (printed == limit) break;
            std.debug.print("TUPLE_UNMATCHED domain=range_check_8_8 table_index={d} residual={d} compact=true\n", .{ index, value.toU32() });
            printed += 1;
        };
    }
};

fn q(value: u32) QM31 {
    return QM31.fromBase(M31.fromU64(value));
}

fn appendBoth(old: *relation.TupleLedger, compact: *relation.TupleLedger, domain: Domain, component: u8, weight: QM31, values: []const QM31) !void {
    try old.append(domain, component, 0, .request, weight, values);
    try compact.append(domain, component, 0, .request, weight, values);
}

test "Ethereum compact tuple ledger matches canonical records and range provider exactly" {
    const allocator = std.testing.allocator;
    const Range = @import("recursive_common_ethereum_incremental_leaf_range_provider_v4.zig").OwnerV4;
    var ordinary = relation.TupleLedger.init(allocator);
    defer ordinary.deinit();
    var compact = try Owner.init(allocator, false);
    defer compact.deinit();
    var sink = compact.ledger();
    defer sink.deinit();
    try appendBoth(&ordinary, &sink, .recursion_wire, 2, q(2), &.{q(19)});
    try appendBoth(&ordinary, &sink, .recursion_wire, 3, q(2).neg(), &.{q(19)});
    // Distinct domain, arity and extension-field coordinates cannot cancel.
    try appendBoth(&ordinary, &sink, .recursion_wire, 2, q(1), &.{ q(1), q(2) });
    try appendBoth(&ordinary, &sink, .recursion_wire, 3, q(1).neg(), &.{q(1)});
    try appendBoth(&ordinary, &sink, .poseidon2, 4, q(1).neg(), &.{ q(1), q(2) });
    const extension = QM31.fromU32Unchecked(1, 2, 3, 4);
    try appendBoth(&ordinary, &sink, .recursion_wire, 2, extension, &.{ extension, q(2) });
    try appendBoth(&ordinary, &sink, .recursion_wire, 3, extension.neg(), &.{ extension, q(2) });
    for (0..7) |_| try appendBoth(&ordinary, &sink, .range_check_8_8, 4, q(1).neg(), &.{ q(3), q(5) });
    try appendBoth(&ordinary, &sink, .range_check_8_8, 7, q(2), &.{ q(3), q(5) });
    try appendBoth(&ordinary, &sink, .range_check_8_8, 8, q(1).neg(), &.{ q(255), q(255) });
    try appendBoth(&ordinary, &sink, .range_check_8_8, 35, QM31.zero(), &.{}); // Both omit zero events.
    try std.testing.expectEqualDeep(ordinary.classify(), try compact.classify());
    try std.testing.expectEqual(@as(usize, 0), sink.contributions.items.len);
    var old_provider = try Range.init(allocator, &ordinary);
    defer old_provider.deinit();
    var new_provider = try Range.initFromCompact(allocator, &compact, null);
    defer new_provider.deinit();
    try std.testing.expectEqualDeep(old_provider.batch.counter.values, new_provider.batch.counter.values);
    try std.testing.expectEqualDeep(old_provider.relation_rows, new_provider.relation_rows);
    try std.testing.expectEqualDeep(old_provider.identity_sha256, new_provider.identity_sha256);
    try std.testing.expectEqual(old_provider.source_contribution_count, new_provider.source_contribution_count);
    try old_provider.appendTupleContributions(&ordinary);
    try new_provider.appendTupleContributions(&sink);
    try std.testing.expectEqualDeep(ordinary.classify(), try compact.classify());
    try std.testing.expectEqualDeep(ordinary.classify(), sink.classify());
    try std.testing.expectEqual(@as(usize, 3), compact.metrics().live_entries);
    try std.testing.expect(compact.metrics().peak_entries >= compact.metrics().live_entries);
    try std.testing.expectEqual(@as(usize, 9), compact.metrics().source_range_contribution_count);
}

test "Ethereum compact tuple ledger preserves cancellation counts without retained records" {
    const allocator = std.testing.allocator;
    var ordinary = relation.TupleLedger.init(allocator);
    defer ordinary.deinit();
    var compact = try Owner.init(allocator, false);
    defer compact.deinit();
    var sink = compact.ledger();
    defer sink.deinit();
    for (0..64) |i| {
        try appendBoth(&ordinary, &sink, .recursion_wire, 0, q(1), &.{q(@intCast(i))});
        try appendBoth(&ordinary, &sink, .recursion_wire, 1, q(1).neg(), &.{q(@intCast(i))});
    }
    try compact.sealSourceHistogram(null, 0);
    const report = try compact.classify();
    try std.testing.expect(report.isClosed());
    try std.testing.expectEqualDeep(ordinary.classify(), report);
    try std.testing.expectEqual(@as(usize, 128), report.contribution_count);
    try std.testing.expectEqual(@as(usize, 0), compact.metrics().live_entries);
    try std.testing.expectEqual(@as(usize, 1), compact.metrics().peak_entries);
    try std.testing.expect(compact.metrics().capacity_entries > 0);
}

test "Ethereum compact tuple ledger rejects malformed range requests before cancellation" {
    inline for (.{ "arity", "value", "weight", "provider", "packet", "lane_role", "lane_weight" }) |kind| {
        var compact = try Owner.init(std.testing.allocator, true);
        defer compact.deinit();
        var sink = compact.ledger();
        defer sink.deinit();
        const tuple = if (comptime std.mem.eql(u8, kind, "arity")) &[_]QM31{q(1)} else if (comptime std.mem.eql(u8, kind, "value")) &[_]QM31{ q(256), q(2) } else &[_]QM31{ q(1), q(2) };
        const component: u8 = if (comptime std.mem.eql(u8, kind, "provider")) 35 else if (comptime std.mem.eql(u8, kind, "packet")) initial_rows.PACKET_COMPONENT else if (comptime std.mem.startsWith(u8, kind, "lane_")) initial_rows.LANE_COMPONENT else 4;
        const role: Role = if (comptime std.mem.eql(u8, kind, "lane_role")) .emit else .request;
        const weight = if (comptime std.mem.eql(u8, kind, "weight")) QM31.fromU32Unchecked(1, 1, 0, 0) else if (comptime std.mem.eql(u8, kind, "lane_weight")) q(2).neg() else q(1).neg();
        try sink.append(.range_check_8_8, component, 0, role, weight, tuple);
        try sink.append(.range_check_8_8, component, 0, role, weight.neg(), tuple);
        if (compact.validate()) |_| return error.TestExpectedError else |_| {}
        if (compact.classify()) |_| return error.TestExpectedError else |_| {}
        try std.testing.expect(!sink.classify().isClosed());
    }
}

test "Ethereum compact tuple ledger checks initial histogram and source phase exactly" {
    var compact = try Owner.init(std.testing.allocator, true);
    defer compact.deinit();
    var sink = compact.ledger();
    defer sink.deinit();
    const bins = try std.testing.allocator.alloc(u32, TABLE_SIZE);
    defer std.testing.allocator.free(bins);
    @memset(bins, 0);
    const tuple = [_]QM31{ q(7), q(9) };
    const index = try tables.schema.indexSecure(.range_check_8_8, &tuple);
    try sink.append(.range_check_8_8, initial_rows.LANE_COMPONENT, 0, .request, q(1).neg(), &tuple);
    bins[index] = 1;
    try std.testing.expectError(error.EthereumCompactTupleSourceMismatch, compact.sealSourceHistogram(bins, 2));
    bins[index] = 0;
    try std.testing.expectError(error.EthereumCompactTupleSourceMismatch, compact.sealSourceHistogram(bins, 1));
    bins[index] = 1;
    try compact.sealSourceHistogram(bins, 1);
    try sink.append(.range_check_8_8, 35, 0, .emit, q(1), &tuple);
    try std.testing.expect((try compact.classify()).isClosed());
    try std.testing.expectEqual(@as(usize, 1), compact.source_range_contribution_count);
    try sink.append(.range_check_8_8, 2, 0, .request, q(1).neg(), &tuple);
    try std.testing.expectError(error.EthereumCompactTupleSourceMismatch, compact.validate());
}

fn exerciseAllocationFailures(allocator: std.mem.Allocator) !void {
    var compact = try Owner.init(allocator, true);
    defer compact.deinit();
    var sink = compact.ledger();
    defer sink.deinit();
    for (0..32) |i| try sink.append(.recursion_wire, 2, 0, .request, q(1), &.{q(@intCast(i))});
    for (0..32) |i| try sink.append(.recursion_wire, 3, 0, .emit, q(1).neg(), &.{q(@intCast(i))});
    try compact.validate();
    try std.testing.expect((try compact.classify()).isClosed());
}

test "Ethereum compact tuple ledger cleans up every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, exerciseAllocationFailures, .{});
}

fn exerciseProviderAllocationFailures(allocator: std.mem.Allocator) !void {
    const Range = @import("recursive_common_ethereum_incremental_leaf_range_provider_v4.zig").OwnerV4;
    var compact = try Owner.init(allocator, false);
    defer compact.deinit();
    var sink = compact.ledger();
    defer sink.deinit();
    try sink.append(.range_check_8_8, 4, 0, .request, q(1).neg(), &.{ q(13), q(17) });
    var provider = Range.initFromCompact(allocator, &compact, null) catch |err| {
        // The range constructor consumes the source phase before allocating
        // its owned batch/definition/rows. Failed publication must leave no
        // balancing provider contribution or retryable source phase behind.
        try std.testing.expect(compact.source_finished);
        try std.testing.expect(!sink.classify().isClosed());
        try std.testing.expectError(error.EthereumCompactTupleSourceMismatch, compact.sealSourceHistogram(null, 0));
        return err;
    };
    defer provider.deinit();
    try std.testing.expect(compact.source_finished);
    try provider.appendTupleContributions(&sink);
    try std.testing.expect((try compact.classify()).isClosed());
}

test "Ethereum compact tuple ledger cleans up provider failures after source sealing" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, exerciseProviderAllocationFailures, .{});
}

test "Ethereum compact tuple ledger keeps map allocation failure sticky through cancellation" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    {
        var compact = try Owner.init(failing.allocator(), false);
        defer compact.deinit();
        var sink = compact.ledger();
        defer sink.deinit();
        failing.fail_index = failing.alloc_index;
        try std.testing.expectError(error.OutOfMemory, sink.append(.recursion_wire, 2, 0, .request, q(1), &.{q(19)}));
        try std.testing.expect(failing.has_induced_failure);
        const allocations_at_failure = failing.allocations;
        failing.fail_index = std.math.maxInt(usize);
        // Restoring memory and supplying an opposite event cannot undo the
        // missing original tuple or turn the poisoned adapter into closure.
        try sink.append(.recursion_wire, 3, 0, .emit, q(1).neg(), &.{q(19)});
        try std.testing.expectEqual(allocations_at_failure, failing.allocations);
        try std.testing.expectError(error.OutOfMemory, compact.validate());
        try std.testing.expectError(error.OutOfMemory, compact.classify());
        try std.testing.expect(!sink.classify().isClosed());
        try std.testing.expectEqual(@as(usize, 0), compact.metrics().live_entries);
    }
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}
