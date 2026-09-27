//! First-pass proposals for shared readonly providers. One interval vector is
//! reused across field-safe source groups. Sink views expire on return; no
//! counter, census, staging hash or source record grants verification authority.
const std = @import("std");
const core = @import("stwo_core");
const Plan = @import("block_v5_readonly_input_plan_v1.zig");
const Proposal = @import("block_v5_readonly_input_proposal_v1.zig");
const Digest = [32]u8;
const Hash = std.crypto.hash.sha2.Sha256;
var next_owner_identity = std.atomic.Value(u64).init(1);
fn ownerIdentity() !u64 {
    var value = next_owner_identity.load(.monotonic);
    while (true) {
        if (value == std.math.maxInt(u64)) return error.ReadonlyCounterOwnerIdentityExhausted;
        if (next_owner_identity.cmpxchgWeak(value, value + 1, .monotonic, .monotonic)) |actual| value = actual else return value;
    }
}
pub const Census = Proposal.Census;
pub const CounterSchema = enum(u32) { histogram_v1 = 1, interval_stream_v2 = 2 };
pub const Token = struct { owner_id: u64, generation: u64, kind: Proposal.Kind, index: u32, group_id: u32, expected_events: u64 };
const Pending = struct { token: Token, census: Census, hash: Hash };
pub const Limits = struct {
    max_metadata_bytes: usize = 64 * 1024 * 1024,
    /// Whole source proofs are assigned greedily, without proof-count rounding.
    max_group_events: u64 = core.fields.m31.Modulus - 1,
};
pub const SourceRecord = struct {
    kind: Proposal.Kind,
    index: u32,
    group_id: u32,
    /// Native fixed/main/access, or genuine caller fixed/main/membership roots.
    roots: [3]Digest,
    classifier_roots: ?[2]Digest,
    /// Native classifier geometry; caller geometry remains in its original schedule.
    row_log: u32,
    counter_digest: Digest,
    counter_schema: CounterSchema = .histogram_v1,
    census: Census,
};
pub const Group = struct { index: u32, first_source: u32, source_count: u32, census: Census };
pub const GroupView = struct { group: Group, counts: []const u64 };
pub const Sink = struct {
    context: *anyopaque,
    /// Must finish copying/staging before returning. Failure poisons collection.
    put_group: *const fn (*anyopaque, GroupView) anyerror!void,
};
pub const Options = struct { limits: Limits = .{}, sink: Sink };
pub fn metadataBytes(intervals: usize, natives: usize, limits: Limits) !usize {
    if (intervals == 0 or intervals > std.math.maxInt(u32) or natives == 0 or natives > (core.fields.m31.Modulus - 1) / 2 or
        limits.max_group_events == 0 or limits.max_group_events >= core.fields.m31.Modulus) return error.InvalidReadonlyCounterCollectionLimits;
    const source_capacity = try std.math.mul(usize, natives, 2);
    const bytes = try std.math.add(usize, @sizeOf(Owned), try std.math.add(usize, try std.math.mul(usize, intervals, @sizeOf(u64)), try std.math.add(usize, try std.math.mul(usize, source_capacity, @sizeOf(SourceRecord)), try std.math.mul(usize, source_capacity, @sizeOf(Group)))));
    if (bytes > limits.max_metadata_bytes) return error.ReadonlyCounterCollectionResourceLimit;
    return bytes;
}
pub const Owned = struct {
    a: std.mem.Allocator,
    /// Borrowed original independently admitted selection intervals.
    intervals: []const Plan.Interval,
    selection_digest: Digest,
    limits: Limits,
    sink: Sink,
    counts: []u64,
    sources: []SourceRecord,
    groups: []Group,
    source_count: usize = 0,
    group_count: usize = 0,
    expected_natives: u32,
    next_native: u32 = 0,
    current: Group = .{ .index = 0, .first_source = 0, .source_count = 0, .census = .{ .all_rw = 0, .mutable = 0, .readonly = 0 } },
    census: Census = .{ .all_rw = 0, .mutable = 0, .readonly = 0 },
    finished: bool = false,
    poisoned: bool = false,
    owner_id: u64,
    token_generation: u64 = 0,
    pending: ?Pending = null,
    pub fn init(a: std.mem.Allocator, selection: Digest, intervals: []const Plan.Interval, natives: usize, options: Options) !Owned {
        _ = try metadataBytes(intervals.len, natives, options.limits);
        if (std.mem.allEqual(u8, &selection, 0)) return error.InvalidReadonlyCounterSelection;
        var upper: u32 = 0;
        for (intervals) |interval| {
            if (interval.lower != upper or interval.upper <= upper or interval.upper > Plan.WORD_LIMIT or
                (interval.readonly and interval.upper != interval.lower + 1) or (!interval.readonly and interval.value != 0)) return error.InvalidReadonlyInputPartition;
            upper = interval.upper;
        }
        if (upper != Plan.WORD_LIMIT) return error.InvalidReadonlyInputPartition;
        const counts = try a.alloc(u64, intervals.len);
        errdefer a.free(counts);
        @memset(counts, 0);
        const sources = try a.alloc(SourceRecord, natives * 2);
        errdefer a.free(sources);
        const groups = try a.alloc(Group, sources.len);
        errdefer a.free(groups);
        return .{ .a = a, .selection_digest = selection, .intervals = intervals, .limits = options.limits, .sink = options.sink, .counts = counts, .sources = sources, .groups = groups, .expected_natives = @intCast(natives), .owner_id = try ownerIdentity() };
    }
    pub fn deinit(self: *Owned) void {
        self.a.free(self.groups);
        self.a.free(self.sources);
        self.a.free(self.counts);
        self.* = undefined;
    }
    fn requireAppend(self: *const Owned, kind: Proposal.Kind, index: u32, census: Census) !void {
        if (self.poisoned or self.finished or self.pending != null or self.source_count == self.sources.len) return error.ReadonlyCounterCollectionClosed;
        try census.require(census.all_rw);
        if (census.all_rw > self.limits.max_group_events) return error.ReadonlyCounterSourceMassLimit;
        if (kind == .native) {
            if (index != self.next_native or index >= self.expected_natives) return error.InvalidReadonlyCounterSourceOrder;
        } else if (self.source_count == 0 or self.sources[self.source_count - 1].kind != .native or
            self.sources[self.source_count - 1].index != index) return error.InvalidReadonlyCounterSourceOrder;
        _ = try addCensus(self.census, census);
    }
    fn prepare(self: *Owned, kind: Proposal.Kind, index: u32, census: Census) !void {
        try self.requireAppend(kind, index, census);
        if (try std.math.add(u64, self.current.census.all_rw, census.all_rw) > self.limits.max_group_events) try self.flush();
    }
    fn complete(self: *Owned, record: SourceRecord) void {
        var value = record;
        value.group_id = self.current.index;
        self.sources[self.source_count] = value;
        self.source_count += 1;
        self.current.source_count += 1;
        self.current.census = addCensus(self.current.census, record.census) catch unreachable;
        self.census = addCensus(self.census, record.census) catch unreachable;
        if (record.kind == .native) self.next_native += 1;
    }
    /// The actual job selection was independently admitted before constructing
    /// this owner. Sources borrow that exact slice; the late canonical Plan is
    /// independently rebuilt once after collection, before root admission.
    pub fn requireSelectionBorrow(self: *const Owned, selection: Digest, borrowed: []const Plan.Interval) !void {
        if (self.finished or self.poisoned or !std.meta.eql(selection, self.selection_digest) or borrowed.ptr != self.intervals.ptr or borrowed.len != self.intervals.len) return error.StaleReadonlyCounterSelectionBorrow;
    }
    /// Reserve the complete source mass before walking its live rows, so group
    /// boundaries never split a source or require a second guest pass.
    pub fn beginSource(self: *Owned, kind: Proposal.Kind, index: u32, expected_events: u64) !Token {
        try self.requireAppend(kind, index, .{ .all_rw = expected_events, .mutable = expected_events, .readonly = 0 });
        if (self.token_generation == std.math.maxInt(u64)) return error.ReadonlyCounterGenerationExhausted;
        if (try std.math.add(u64, self.current.census.all_rw, expected_events) > self.limits.max_group_events) try self.flush();
        const token = Token{ .owner_id = self.owner_id, .generation = self.token_generation + 1, .kind = kind, .index = index, .group_id = self.current.index, .expected_events = expected_events };
        var hash = Hash.init(.{});
        hash.update("stwo-zig/block-v5/readonly-input-interval-stream/v2\x00");
        hash.update(&self.selection_digest);
        put(&hash, @intFromEnum(kind));
        put(&hash, index);
        put(&hash, token.group_id);
        put(&hash, expected_events);
        self.pending = .{ .token = token, .hash = hash, .census = .{ .all_rw = 0, .mutable = 0, .readonly = 0 } };
        self.token_generation = token.generation;
        return token;
    }
    fn requireToken(self: *const Owned, token: Token) !void {
        if (self.finished or self.poisoned or self.pending == null or !std.meta.eql(self.pending.?.token, token)) return error.StaleReadonlyCounterSourceToken;
    }
    /// Canonical original source order, with count=1 for each actual active
    /// event. Batched observers must keep the same deterministic count grammar.
    pub fn observe(self: *Owned, token: Token, interval_index: u32, count: u64) !void {
        try self.requireToken(token);
        if (count == 0 or interval_index >= self.intervals.len) return error.InvalidReadonlyCounterObservation;
        const pending = &self.pending.?;
        const next = try std.math.add(u64, pending.census.all_rw, count);
        if (next > token.expected_events) return error.StaleReadonlyCounterCensus;
        const interval = self.intervals[interval_index];
        try addInterval(&pending.census, interval, count);
        self.counts[interval_index] += count; // reserved group mass proves no overflow
        put(&pending.hash, interval_index);
        put(&pending.hash, count);
    }
    /// The physical record comes from the real first-round owner after its
    /// roots are committed. Counter digest/census/group are minted here rather
    /// than supplied by that record. This remains a proposal, not a receipt.
    pub fn endSource(self: *Owned, token: Token, physical: SourceRecord) !SourceRecord {
        try self.requireToken(token);
        var pending = self.pending.?;
        if (physical.kind != token.kind or physical.index != token.index or physical.group_id != token.group_id or
            pending.census.all_rw != token.expected_events or !std.meta.eql(physical.census, pending.census)) return error.StaleReadonlyCounterCensus;
        for (physical.roots) |root| if (std.mem.allEqual(u8, &root, 0)) return error.InvalidReadonlyCounterSourceRoots;
        if (physical.kind == .native) {
            if ((pending.census.all_rw == 0) != (physical.classifier_roots == null) or (pending.census.all_rw == 0 and physical.row_log != 0)) return error.InvalidReadonlyCounterSourceRoots;
            if (physical.classifier_roots) |roots| {
                for (roots) |root| if (std.mem.allEqual(u8, &root, 0)) return error.InvalidReadonlyCounterSourceRoots;
                if (physical.row_log < 1 or physical.row_log > 24 or pending.census.all_rw > (@as(u64, 1) << @intCast(physical.row_log))) return error.InvalidReadonlyCounterSourceRoots;
            }
        } else if (physical.classifier_roots != null or physical.row_log != 0) return error.InvalidReadonlyCounterSourceRoots;
        var record = physical;
        record.census = pending.census;
        record.counter_schema = .interval_stream_v2;
        record.counter_digest = pending.hash.finalResult();
        self.pending = null;
        self.complete(record);
        return record;
    }
    /// Partial observations are never rolled back by subtracting unauthenticated
    /// deltas. Failed physical construction poisons the job before admission.
    pub fn abortSource(self: *Owned, token: Token) !void {
        try self.requireToken(token);
        self.poisoned = true;
        self.pending = null;
    }
    pub fn appendNative(self: *Owned, proposal: Proposal.Proposal, counters: []const u64) !void {
        try proposal.require(proposal.expected);
        const expected = proposal.expected;
        if (expected.source.kind != .native or !std.meta.eql(expected.selection_digest, self.selection_digest)) return error.InvalidReadonlyCounterSelection;
        try self.requireAppend(.native, expected.source.index, expected.census);
        if (counters.len != self.intervals.len and !(counters.len == 0 and expected.census.all_rw == 0)) return error.InvalidReadonlyCounterLength;
        var hash = Hash.init(.{});
        hash.update("stwo-zig/block-v5/readonly-input-interval-census/v1\x00");
        hash.update(&self.selection_digest);
        var census = Census{ .all_rw = 0, .mutable = 0, .readonly = 0 };
        for (self.intervals, 0..) |interval, i| {
            const count = if (counters.len == 0) 0 else counters[i];
            put(&hash, count);
            try addInterval(&census, interval, count);
        }
        if (!std.meta.eql(census, expected.census) or !std.meta.eql(hash.finalResult(), expected.counter_digest)) return error.StaleReadonlyCounterCensus;
        try self.prepare(.native, expected.source.index, census);
        for (counters, 0..) |count, i| self.counts[i] += count; // mass bound proves no overflow
        self.complete(.{ .kind = .native, .index = expected.source.index, .group_id = undefined, .roots = .{ expected.source.roots[0], expected.source.roots[1], expected.source.access_root }, .classifier_roots = expected.classifier_roots, .row_log = expected.source.row_log, .counter_digest = expected.counter_digest, .census = census });
    }
    /// Original physical metadata and each live caller slot's counter vector.
    /// Uses structural inputs to avoid owning/copying witness slot arrays.
    pub fn appendCaller(self: *Owned, index: u32, physical: anytype, metadata: anytype) !void {
        const census = Census{ .all_rw = physical.all_rw_events, .mutable = try std.math.sub(u64, physical.all_rw_events, physical.readonly_events), .readonly = physical.readonly_events };
        if (!std.meta.eql(physical.selection_digest, self.selection_digest)) return error.InvalidReadonlyCounterSelection;
        for (physical.roots) |root| if (std.mem.allEqual(u8, &root, 0)) return error.InvalidReadonlyCounterSourceRoots;
        try self.requireAppend(.caller, index, census);
        var hash = Hash.init(.{});
        hash.update("stwo-zig/block-v5/caller-readonly-physical-counters/v1\x00");
        hash.update(&self.selection_digest);
        var actual = Census{ .all_rw = 0, .mutable = 0, .readonly = 0 };
        for (metadata) |slot| {
            if (slot.counters.len != self.intervals.len) return error.InvalidReadonlyCounterLength;
            var slot_mass: u64 = 0;
            for (slot.counters, self.intervals) |count, interval| {
                put(&hash, count);
                try addInterval(&actual, interval, count);
                slot_mass = try std.math.add(u64, slot_mass, count);
            }
            if (slot_mass != slot.events) return error.StaleReadonlyCounterCensus;
        }
        if (!std.meta.eql(actual, census) or !std.meta.eql(hash.finalResult(), physical.counter_digest)) return error.StaleReadonlyCounterCensus;
        try self.prepare(.caller, index, census);
        for (metadata) |slot| for (slot.counters, self.counts) |count, *target| {
            target.* += count;
        };
        self.complete(.{ .kind = .caller, .index = index, .group_id = undefined, .roots = physical.roots, .classifier_roots = null, .row_log = 0, .counter_digest = physical.counter_digest, .census = census });
    }
    fn flush(self: *Owned) !void {
        if (self.current.source_count == 0 or self.current.index >= core.fields.m31.Modulus or self.group_count >= self.groups.len) return error.InvalidReadonlyCounterGroup;
        self.sink.put_group(self.sink.context, .{ .group = self.current, .counts = self.counts }) catch |err| {
            self.poisoned = true;
            return err;
        };
        self.groups[self.group_count] = self.current;
        self.group_count += 1;
        @memset(self.counts, 0);
        self.current = .{ .index = @intCast(self.group_count), .first_source = @intCast(self.source_count), .source_count = 0, .census = .{ .all_rw = 0, .mutable = 0, .readonly = 0 } };
    }
    pub fn finish(self: *Owned) !void {
        if (self.poisoned or self.finished or self.pending != null) return error.ReadonlyCounterCollectionClosed;
        if (self.next_native != self.expected_natives) return error.IncompleteReadonlyCounterSources;
        try self.flush();
        self.finished = true;
    }
    pub fn requirePlan(self: *const Owned, selection: Digest, plan: *const Plan.Owned) !void {
        if (!self.finished or self.poisoned or !std.meta.eql(selection, self.selection_digest) or std.mem.allEqual(u8, &plan.digest, 0) or plan.intervals.len != self.intervals.len) return error.UnboundReadonlyCounterPlan;
        for (plan.intervals, self.intervals) |late, early| if (!std.meta.eql(late, early)) return error.UnboundReadonlyCounterPlan;
    }
    pub fn sourceRecords(self: *const Owned) ![]const SourceRecord {
        if (!self.finished or self.poisoned) return error.ReadonlyCounterCollectionClosed;
        return self.sources[0..self.source_count];
    }
    pub fn groupRecords(self: *const Owned) ![]const Group {
        if (!self.finished or self.poisoned) return error.ReadonlyCounterCollectionClosed;
        return self.groups[0..self.group_count];
    }
};
fn addCensus(left: Census, right: Census) !Census {
    return .{ .all_rw = try std.math.add(u64, left.all_rw, right.all_rw), .mutable = try std.math.add(u64, left.mutable, right.mutable), .readonly = try std.math.add(u64, left.readonly, right.readonly) };
}
fn addInterval(census: *Census, interval: Plan.Interval, count: u64) !void {
    census.all_rw = try std.math.add(u64, census.all_rw, count);
    if (interval.readonly) census.readonly = try std.math.add(u64, census.readonly, count) else census.mutable = try std.math.add(u64, census.mutable, count);
}
fn put(hash: *Hash, value: u64) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .little);
    hash.update(&bytes);
}
