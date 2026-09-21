//! Backend-neutral exact tuple preparation for the row35 range provider:
//! Ethereum cohorts and detached recursive parents. CSP diagnostic storage stays
//! unchanged. Range tuples use their exact table index; other domains retain the
//! shared canonical SHA-256 grouping. Initial38 histogram admission is optional.
const std = @import("std");
const core = @import("stwo_core");
const relation = @import("air/relation_interaction.zig");
const universal = @import("air/universal_challenges.zig");
const table_schema = @import("../air/lookups/tables/schema.zig");
const table_counter = @import("../air/lookups/tables/counter.zig");

// Initial38 protocol component assignments, shared with its row materializer.
pub const INITIAL_LANE_COMPONENT: u8 = 36;
pub const INITIAL_PACKET_COMPONENT: u8 = 37;
const Domain = @FieldType(relation.TupleContribution, "domain");
const Role = @FieldType(relation.TupleContribution, "role");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Map = std.AutoHashMapUnmanaged([32]u8, QM31);
const TABLE_SIZE = table_schema.size(.range_check_8_8);
const PROVIDER_COMPONENT = 35;

pub const Owner = struct {
    allocator: std.mem.Allocator,
    maps: [universal.RELATION_COUNT]Map = @splat(.empty),
    source_counter: table_counter.Counter,
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
        var counter = try table_counter.Counter.init(allocator, .range_check_8_8);
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
        const index = try table_schema.indexSecure(.range_check_8_8, values);
        if (!self.source_finished) {
            if (component == PROVIDER_COMPONENT) return error.EthereumCompactTupleSourceMismatch;
            if (self.initial_histogram) |histogram| {
                if (component == INITIAL_PACKET_COMPONENT) return error.EthereumCompactTupleSourceMismatch;
                if (component == INITIAL_LANE_COMPONENT) {
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
