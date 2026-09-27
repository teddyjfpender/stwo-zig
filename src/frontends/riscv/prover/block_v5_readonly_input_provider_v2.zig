//! Group-keyed public interval provider. Columns are witness proposals; neither
//! their host census nor fixed roots grant source or provider proof authority.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Plan = @import("block_v5_readonly_input_plan_v1.zig");
const Original = @import("block_v5_readonly_input_protocol_v1.zig");
const Framework = @import("../recursion/air/framework_interaction.zig");
pub const MAX_FRAGMENTS: u32 = 32768;
pub const RANGE_PLANES: usize = 9;
pub const Fragment = struct { interval_index: u32, count: u16 };
pub const Counts = struct { events: u64, readonly: u64, range_requests: u64 };
pub const Layout = struct {
    pub const count = 0;
    pub const total = 1;
    pub const readonly = 5;
    pub const total_carry = 9;
    pub const readonly_carry = 13;
    pub const inverse_count = 17;
    pub const main = 18;
    pub const fixed = 10; // active/first/last, interval tuple5, byte addressLE16x2
    pub const interactions = 44;
};
pub const Shard = struct {
    index: u32,
    group_id: u32,
    first_fragment: u64,
    fragment_count: u32,
    row_log: u32,
    counts: Counts,
    pub fn require(self: Shard) !void {
        if (self.group_id >= core.fields.m31.Modulus or self.fragment_count == 0 or self.fragment_count > MAX_FRAGMENTS or
            self.row_log < 1 or self.row_log > 15 or self.fragment_count > (@as(u32, 1) << @intCast(self.row_log)) or
            self.counts.events < self.fragment_count or self.counts.events > @as(u64, self.fragment_count) * 65535 or
            self.counts.events >= core.fields.m31.Modulus or self.counts.readonly > self.counts.events or
            self.counts.range_requests != RANGE_PLANES * (@as(u64, 1) << @intCast(self.row_log))) return error.InvalidReadonlyProviderShard;
        _ = try std.math.add(u64, self.first_fragment, self.fragment_count);
    }
};
pub const Limits = struct { max_matrix_bytes: usize = 64 * 1024 * 1024 };
/// Shape is derived from the actual canonical fragment stream, not a field
/// reduction of u64 counts. Duplicate ordinals fragment a large multiplicity.
pub fn shard(index: u32, group_id: u32, first: u64, intervals: []const Plan.Interval, fragments: []const Fragment) !Shard {
    if (fragments.len == 0 or fragments.len > MAX_FRAGMENTS) return error.InvalidReadonlyProviderShard;
    var total: u64 = 0;
    var readonly: u64 = 0;
    for (fragments, 0..) |fragment, i| {
        if (fragment.count == 0 or fragment.interval_index >= intervals.len or
            (i != 0 and fragment.interval_index < fragments[i - 1].interval_index)) return error.InvalidReadonlyProviderFragments;
        total = try std.math.add(u64, total, fragment.count);
        if (intervals[fragment.interval_index].readonly) readonly = try std.math.add(u64, readonly, fragment.count);
    }
    const log: u32 = @max(1, std.math.log2_int_ceil(usize, fragments.len));
    const result = Shard{ .index = index, .group_id = group_id, .first_fragment = first, .fragment_count = @intCast(fragments.len), .row_log = log, .counts = .{ .events = total, .readonly = readonly, .range_requests = RANGE_PLANES * (@as(u64, 1) << @intCast(log)) } };
    try result.require();
    return result;
}
pub const Fixed = struct {
    a: std.mem.Allocator,
    storage: []M,
    columns: [Layout.fixed]engine.pcs.ColumnEvaluation,
    pub fn deinit(self: *Fixed) void {
        self.a.free(self.storage);
        self.* = undefined;
    }
    pub fn init(a: std.mem.Allocator, intervals: []const Plan.Interval, ordinals: []const u32, shape: Shard, limits: Limits) !Fixed {
        try shape.require();
        if (ordinals.len != shape.fragment_count) return error.InvalidReadonlyProviderFragments;
        const rows: usize = @as(usize, 1) << @intCast(shape.row_log);
        const cells = try std.math.mul(usize, rows, Layout.fixed);
        if (try std.math.mul(usize, cells, @sizeOf(M)) > limits.max_matrix_bytes) return error.ReadonlyProviderResourceLimit;
        for (ordinals, 0..) |ordinal, i| if (ordinal >= intervals.len or (i != 0 and ordinal < ordinals[i - 1])) return error.InvalidReadonlyProviderFragments;
        const storage = try a.alloc(M, cells);
        @memset(storage, M.zero());
        var result = Fixed{ .a = a, .storage = storage, .columns = undefined };
        for (&result.columns, 0..) |*column, i| column.* = .{ .log_size = shape.row_log, .values = storage[i * rows ..][0..rows] };
        storage[rows + Framework.committedRow(0, shape.row_log)] = M.one();
        storage[2 * rows + Framework.committedRow(rows - 1, shape.row_log)] = M.one();
        for (ordinals, 0..) |ordinal, logical| {
            const physical = Framework.committedRow(logical, shape.row_log);
            storage[physical] = M.one();
            for (Original.intervalTuple(intervals[ordinal]), 0..) |value, i| storage[(i + 3) * rows + physical] = value;
            const address = intervals[ordinal].lower * 4;
            storage[8 * rows + physical] = M.fromCanonical(address & 65535);
            storage[9 * rows + physical] = M.fromCanonical(address >> 16);
        }
        return result;
    }
};
pub const Columns = struct {
    fixed: Fixed,
    storage: []M,
    main: [Layout.main]engine.pcs.ColumnEvaluation,
    shape: Shard,
    pub fn deinit(self: *Columns) void {
        self.fixed.a.free(self.storage);
        self.fixed.deinit();
        self.* = undefined;
    }
    pub fn init(a: std.mem.Allocator, intervals: []const Plan.Interval, fragments: []const Fragment, shape: Shard, limits: Limits) !Columns {
        const derived = try shard(shape.index, shape.group_id, shape.first_fragment, intervals, fragments);
        if (!std.meta.eql(derived, shape)) return error.UntrustedReadonlyProviderCensus;
        const rows: usize = @as(usize, 1) << @intCast(shape.row_log);
        const cells = try std.math.mul(usize, rows, Layout.main + Layout.fixed);
        if (try std.math.mul(usize, cells, @sizeOf(M)) > limits.max_matrix_bytes) return error.ReadonlyProviderResourceLimit;
        const ordinals = try a.alloc(u32, fragments.len);
        defer a.free(ordinals);
        for (ordinals, fragments) |*ordinal, fragment| ordinal.* = fragment.interval_index;
        var fixed = try Fixed.init(a, intervals, ordinals, shape, limits);
        errdefer fixed.deinit();
        const storage = try a.alloc(M, rows * Layout.main);
        errdefer a.free(storage);
        @memset(storage, M.zero());
        var result = Columns{ .fixed = fixed, .storage = storage, .main = undefined, .shape = shape };
        for (&result.main, 0..) |*column, i| column.* = .{ .log_size = shape.row_log, .values = storage[i * rows ..][0..rows] };
        var total: u64 = 0;
        var readonly: u64 = 0;
        for (0..rows) |logical| {
            const physical = Framework.committedRow(logical, shape.row_log);
            const count: u16 = if (logical < fragments.len) fragments[logical].count else 0;
            const ro = logical < fragments.len and intervals[fragments[logical].interval_index].readonly;
            storage[physical] = M.fromCanonical(count);
            if (count != 0) storage[Layout.inverse_count * rows + physical] = try M.fromCanonical(count).inv();
            const before = [_]u64{ total, readonly };
            total = try std.math.add(u64, total, count);
            if (ro) readonly = try std.math.add(u64, readonly, count);
            for ([_]u64{ total, readonly }, before, [_]usize{ Layout.total, Layout.readonly }, [_]usize{ Layout.total_carry, Layout.readonly_carry }, 0..) |value, prior, prefix_offset, carry_offset, which| {
                var carry: u32 = if (which == 0 or ro) count else 0;
                for (0..4) |limb| {
                    const shift: u6 = @intCast(16 * limb);
                    const sum = @as(u32, @intCast((prior >> shift) & 65535)) + carry;
                    carry = sum >> 16;
                    storage[(prefix_offset + limb) * rows + physical] = M.fromCanonical(@intCast((value >> shift) & 65535));
                    storage[(carry_offset + limb) * rows + physical] = M.fromCanonical(carry);
                }
                if (carry != 0) return error.ReadonlyProviderIntegerOverflow;
            }
        }
        return result;
    }
    /// Counter requests include padded rows' retained prefix limbs, not just
    /// logical fragments. This is the exact separately proved range census.
    pub fn addRangeCounters(self: *const Columns, counter: anytype) !void {
        for (self.main[0..RANGE_PLANES]) |column| for (column.values) |value| try counter.add(@intCast(value.toU32()));
    }
};

/// Borrowed streaming fragmentation of one exact group counter vector. The
/// collector owns its stable vector through exhaustion. No root/proof authority
/// is created by this iterator; actual provider AIR must prove the fragments.
pub const FragmentCursor = struct {
    counts: []const u64,
    interval_index: usize = 0,
    remaining: u64 = 0,
    loaded: bool = false,
    emitted: u64 = 0,
    mass: u64 = 0,
    expected_events: u64,
    pub fn init(counts: []const u64, expected_events: u64) !FragmentCursor {
        if (counts.len > std.math.maxInt(u32) or expected_events == 0 or expected_events >= core.fields.m31.Modulus) return error.InvalidReadonlyProviderGroup;
        return .{ .counts = counts, .expected_events = expected_events };
    }
    pub fn next(self: *FragmentCursor) !?Fragment {
        while (self.interval_index < self.counts.len) {
            if (!self.loaded) {
                self.remaining = self.counts[self.interval_index];
                self.loaded = true;
                self.mass = try std.math.add(u64, self.mass, self.remaining);
                if (self.mass > self.expected_events) return error.UntrustedReadonlyProviderCensus;
            }
            if (self.remaining == 0) {
                self.interval_index += 1;
                self.loaded = false;
                continue;
            }
            const count: u16 = @intCast(@min(self.remaining, 65535));
            self.remaining -= count;
            self.emitted = try std.math.add(u64, self.emitted, 1);
            return .{ .interval_index = @intCast(self.interval_index), .count = count };
        }
        if (self.mass != self.expected_events) return error.UntrustedReadonlyProviderCensus;
        return null;
    }
};
/// Pins the exact fixed mapping inventory. It is only an operand transport pin;
/// a fresh provider verifier reconstructs every tuple from admitted Plan bytes.
pub fn ordinalDigest(shape: Shard, plan_digest: [32]u8, ordinals: []const u32) ![32]u8 {
    try shape.require();
    if (ordinals.len != shape.fragment_count) return error.InvalidReadonlyProviderFragments;
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ 0x42354950, 2, shape.index, shape.group_id, shape.fragment_count, shape.row_log });
    channel.mixU64(shape.first_fragment);
    channel.mixRoot(plan_digest);
    for (ordinals, 0..) |ordinal, i| {
        if (i != 0 and ordinal < ordinals[i - 1]) return error.InvalidReadonlyProviderFragments;
        channel.mixU32s(&.{ordinal});
    }
    return channel.digestBytes();
}
