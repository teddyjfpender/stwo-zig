//! Bounded column-major trace custody for one sorted-memory instance.
//! Selectors and wide ordinals are deterministic fixed columns; predecessor masks are
//! derived from committed current-row columns by the AIR adapter.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const component = @import("memory_component.zig");
const transition = @import("memory_transition.zig");
const bit_reversal = core.utils;

pub const fixed_column_count = 22;
pub const main_column_count = component.Layout.linked_previous + 17;
pub const fixed = struct {
    pub const active = 0;
    pub const first = 1;
    pub const last = 2;
    pub const global_first = 3;
    pub const global_last = 4;
    pub const domain_last = 5;
    pub const ordinal = 6;
    pub const previous_ordinal = 14;
};

pub const FixedTrace = struct {
    allocator: std.mem.Allocator,
    claim: component.Claim,
    storage: []M,

    pub fn init(allocator: std.mem.Allocator, claim: component.Claim) !FixedTrace {
        return .{ .allocator = allocator, .claim = claim, .storage = try makeFixedStorage(allocator, claim) };
    }
    pub fn deinit(self: *FixedTrace) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }
    pub fn domainSize(self: *const FixedTrace) usize {
        return @as(usize, 1) << @intCast(self.claim.log_size);
    }
    pub fn column(self: *const FixedTrace, index: usize) []const M {
        std.debug.assert(index < fixed_column_count);
        const size = self.domainSize();
        return self.storage[index * size ..][0..size];
    }
};

pub const Trace = TraceFor(false);
pub const CompactTrace = TraceFor(true);

fn TraceFor(comptime compact: bool) type {
    return struct {
        const Self = @This();
        pub const stored_main_columns = if (compact) component.Layout.linked_previous else main_column_count;
        allocator: std.mem.Allocator,
        claim: component.Claim,
        fixed_storage: []M,
        main_storage: []M,
        written: u32 = 0,
        preceding: ?transition.Transition,
        claimed_boundaries: bool = true,
        sealed: bool = false,
        poisoned: bool = false,

        pub fn init(allocator: std.mem.Allocator, claim: component.Claim) !Self {
            try claim.validate();
            const size: usize = @as(usize, 1) << @intCast(claim.log_size);
            const main_len = try std.math.mul(usize, size, stored_main_columns);
            const fixed_storage = try makeFixedStorage(allocator, claim);
            errdefer allocator.free(fixed_storage);
            const main_storage = try allocator.alloc(M, main_len);
            errdefer allocator.free(main_storage);
            @memset(main_storage, M.zero());
            return .{ .allocator = allocator, .claim = claim, .fixed_storage = fixed_storage, .main_storage = main_storage, .preceding = claim.preceding };
        }

        /// One-pass builder for `memory_instance.Partitioner`: the exact count and
        /// public predecessor are known before reading, while first/last values
        /// are learned from the sorted stream and bound when `seal` succeeds.
        pub fn initPlanned(allocator: std.mem.Allocator, first_row: u64, total_rows: u64, rows: u32, log_size: u32, preceding: ?transition.Transition) !Self {
            const blank: transition.Transition = .{ .space = 0, .address = 0, .clock = 0, .before = 0, .after = 0 };
            var result = try Self.init(allocator, .{ .first_row = first_row, .total_rows = total_rows, .rows = rows, .log_size = log_size, .first = blank, .last = blank, .preceding = preceding });
            result.claimed_boundaries = false;
            return result;
        }

        /// Consume exactly one independently sized instance from the sorted
        /// partitioner. The source's exact census and predecessor are carried
        /// into the public claim before any commitment is made.
        pub fn nextFromPartitioner(allocator: std.mem.Allocator, partitioner: *@import("memory_instance.zig").Partitioner, minimum_log_size: u32) !?Self {
            if (partitioner.poisoned) return error.InvalidMemoryInstancePhase;
            if (minimum_log_size < 1 or minimum_log_size > 30) return error.InvalidMemoryInstancePlan;
            if (partitioner.finished) return null;
            if (partitioner.emitted >= partitioner.expected_rows) return error.InvalidMemoryInstancePhase;
            const capacity = try partitioner.currentCapacity();
            const rows: u32 = @intCast(@min(partitioner.expected_rows - partitioner.emitted, capacity));
            const log_size: u32 = @max(minimum_log_size, @as(u32, @intCast(std.math.log2_int(u32, capacity))));
            var result = try Self.initPlanned(allocator, partitioner.emitted, partitioner.expected_rows, rows, log_size, partitioner.previous);
            errdefer result.deinit();
            const summary = (try partitioner.next(result.partitionSink())) orelse return error.InvalidMemoryInstancePhase;
            if (summary.first_row != result.claim.first_row or summary.rows != rows) return error.MemoryInstanceSummaryMismatch;
            try result.seal();
            if (!std.meta.eql(summary.first, result.claim.first) or !std.meta.eql(summary.last, result.claim.last))
                return error.MemoryInstanceSummaryMismatch;
            return result;
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.main_storage);
            self.allocator.free(self.fixed_storage);
            self.* = undefined;
        }

        pub fn append(self: *Self, item: transition.Transition) !void {
            if (self.poisoned or self.sealed or self.written >= self.claim.rows) return error.InvalidMemoryComponentPhase;
            errdefer self.poisoned = true;
            const first = self.written == 0;
            const last = self.written + 1 == self.claim.rows;
            if (first) {
                if (self.claimed_boundaries and !std.meta.eql(item, self.claim.first)) return error.MemoryFirstBoundaryMismatch;
                if (!self.claimed_boundaries) self.claim.first = item;
            }
            if (last) {
                if (self.claimed_boundaries and !std.meta.eql(item, self.claim.last)) return error.MemoryLastBoundaryMismatch;
                if (!self.claimed_boundaries) self.claim.last = item;
            }
            const row = try component.witness(self.preceding, item, first, last);
            const size = self.domainSize();
            const physical = committedRow(self.written, self.claim.log_size);
            for (row[0..stored_main_columns], 0..) |value, column| self.main_storage[column * size + physical] = value;
            self.preceding = item;
            self.written += 1;
        }

        pub fn partitionSink(self: *Self) @import("memory_instance.zig").Sink {
            return .{ .context = self, .append = appendFromPartition };
        }

        fn appendFromPartition(context: *anyopaque, item: transition.Transition, link: ?@import("memory_order.zig").Row) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(context));
            const expected = if (self.preceding) |prior| try transition.adjacency(prior, item) else null;
            if (!std.meta.eql(expected, link)) return error.MemoryPartitionLinkMismatch;
            try self.append(item);
        }

        pub fn seal(self: *Self) !void {
            if (self.poisoned or self.sealed) return error.InvalidMemoryComponentPhase;
            if (self.written != self.claim.rows) {
                self.poisoned = true;
                return error.MemoryInstanceCensusUnderflow;
            }
            try self.claim.validate();
            self.claimed_boundaries = true;
            self.sealed = true;
        }

        pub fn domainSize(self: *const Self) usize {
            return @as(usize, 1) << @intCast(self.claim.log_size);
        }
        pub fn fixedColumn(self: *const Self, index: usize) []const M {
            std.debug.assert(index < fixed_column_count);
            const size = self.domainSize();
            return self.fixed_storage[index * size ..][0..size];
        }
        pub fn mainColumn(self: *const Self, index: usize) []const M {
            std.debug.assert(index < stored_main_columns);
            const size = self.domainSize();
            return self.main_storage[index * size ..][0..size];
        }
        pub fn inputRow(self: *const Self, logical: usize) component.Row {
            std.debug.assert(logical < self.domainSize());
            var row: component.Row = @splat(M.zero());
            const physical = committedRow(logical, self.claim.log_size);
            for (0..stored_main_columns) |column| row[column] = self.mainColumn(column)[physical];
            if (compact) fillCompactPrevious(&row);
            if (logical > 0) {
                const prior = committedRow(logical - 1, self.claim.log_size);
                const order = @import("memory_order.zig");
                for (0..5) |i| row[component.Layout.shifted_previous + i] = self.mainColumn(order.Layout.current_key + i)[prior];
                for (0..8) |i| row[component.Layout.shifted_previous + 5 + i] = self.mainColumn(order.Layout.current_clock + i)[prior];
                for (0..4) |i| row[component.Layout.shifted_previous + 13 + i] = self.mainColumn(component.Layout.after + i)[prior];
            }
            row[component.Layout.active] = self.fixedColumn(fixed.active)[physical];
            row[component.Layout.first] = self.fixedColumn(fixed.first)[physical];
            row[component.Layout.last] = self.fixedColumn(fixed.last)[physical];
            row[component.Layout.global_first] = self.fixedColumn(fixed.global_first)[physical];
            row[component.Layout.global_last] = self.fixedColumn(fixed.global_last)[physical];
            return row;
        }

        /// Canonical v2 interaction source. Each field is read from committed
        /// main/fixed columns; the AIR adapter must evaluate the same expressions
        /// at verifier challenge points before these become proof authority.
        pub fn eventRow(self: *const Self, logical: usize) @import("../../prover/block_memory_relation_v2.zig").EventRow {
            const bus = @import("../../prover/block_memory_relation_v2.zig");
            const ordering = @import("memory_order.zig");
            const row = self.inputRow(logical);
            const physical = committedRow(logical, self.claim.log_size);
            const active = !row[component.Layout.active].isZero();
            var result = bus.EventRow{ .active = active, .transition = @splat(M.zero()) };
            if (!active) return result;
            result.transition[0] = row[ordering.Layout.current_key + 4];
            @memcpy(result.transition[1..5], row[ordering.Layout.current_key..][0..4]);
            @memcpy(result.transition[5..13], row[ordering.Layout.current_clock..][0..8]);
            @memcpy(result.transition[13..17], row[ordering.Layout.current_value..][0..4]);
            @memcpy(result.transition[17..21], row[component.Layout.after..][0..4]);
            result.initial_request = !row[component.Layout.global_first].isZero() or
                (!row[ordering.Layout.active].isZero() and row[ordering.Layout.same].isZero());
            if (result.initial_request) {
                result.initial[0] = result.transition[0];
                @memcpy(result.initial[1..5], result.transition[1..5]);
                @memcpy(result.initial[5..9], result.transition[13..17]);
            }
            result.link_emit = row[component.Layout.global_last].isZero();
            result.link_consume = row[component.Layout.global_first].isZero();
            if (result.link_emit) {
                for (0..8) |i| result.emitted[i] = self.fixedColumn(fixed.ordinal + i)[physical];
                result.emitted[8] = result.transition[0];
                @memcpy(result.emitted[9..13], result.transition[1..5]);
                @memcpy(result.emitted[13..21], result.transition[5..13]);
                @memcpy(result.emitted[21..25], result.transition[17..21]);
            }
            if (result.link_consume) {
                for (0..8) |i| result.consumed[i] = self.fixedColumn(fixed.previous_ordinal + i)[physical];
                result.consumed[8] = row[component.Layout.linked_previous + 4];
                @memcpy(result.consumed[9..13], row[component.Layout.linked_previous..][0..4]);
                @memcpy(result.consumed[13..21], row[component.Layout.linked_previous + 5 ..][0..8]);
                @memcpy(result.consumed[21..25], row[component.Layout.linked_previous + 13 ..][0..4]);
            }
            return result;
        }

        pub fn eventRows(self: *const Self, allocator: std.mem.Allocator) ![]@import("../../prover/block_memory_relation_v2.zig").EventRow {
            if (!self.sealed) return error.InvalidMemoryComponentPhase;
            const rows = try allocator.alloc(@import("../../prover/block_memory_relation_v2.zig").EventRow, self.domainSize());
            for (rows, 0..) |*row, logical| row.* = self.eventRow(logical);
            return rows;
        }
    };
}

fn makeFixedStorage(allocator: std.mem.Allocator, claim: component.Claim) ![]M {
    try claim.validate();
    const size: usize = @as(usize, 1) << @intCast(claim.log_size);
    const fixed_len = try std.math.mul(usize, size, fixed_column_count);
    const storage = try allocator.alloc(M, fixed_len);
    @memset(storage, M.zero());
    for (0..claim.rows) |logical| {
        const physical = committedRow(logical, claim.log_size);
        storage[fixed.active * size + physical] = M.one();
        if (logical == 0) {
            storage[fixed.first * size + physical] = M.one();
            if (claim.first_row == 0) storage[fixed.global_first * size + physical] = M.one();
        }
        if (logical + 1 == claim.rows) storage[fixed.last * size + physical] = M.one();
        const ordinal = try std.math.add(u64, claim.first_row, logical);
        if (ordinal + 1 == claim.total_rows) storage[fixed.global_last * size + physical] = M.one();
        for (0..8) |byte| {
            storage[(fixed.ordinal + byte) * size + physical] = M.fromCanonical(@as(u8, @truncate(ordinal >> @intCast(8 * byte))));
            if (ordinal != 0) storage[(fixed.previous_ordinal + byte) * size + physical] = M.fromCanonical(@as(u8, @truncate((ordinal - 1) >> @intCast(8 * byte))));
        }
    }
    storage[fixed.domain_last * size + committedRow(size - 1, claim.log_size)] = M.one();
    return storage;
}

pub inline fn committedRow(logical_row: usize, log_size: u32) usize {
    return bit_reversal.bitReverseIndex(bit_reversal.cosetIndexToCircleDomainIndex(logical_row, log_size), log_size);
}

/// Alias the already authenticated ordering predecessor into the logical
/// link inputs; compact v5 never commits the redundant seventeen cells.
pub fn fillCompactPrevious(row: *component.Row) void {
    const order = @import("memory_order.zig");
    @memcpy(row[component.Layout.linked_previous..][0..5], row[order.Layout.previous_key..][0..5]);
    @memcpy(row[component.Layout.linked_previous + 5 ..][0..8], row[order.Layout.previous_clock..][0..8]);
    @memcpy(row[component.Layout.linked_previous + 13 ..][0..4], row[order.Layout.previous_value..][0..4]);
}
