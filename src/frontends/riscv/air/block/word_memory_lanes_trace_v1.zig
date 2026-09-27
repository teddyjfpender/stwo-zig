//! Bounded streaming witness builder. Input events are appended once; no
//! event-sized side buffer, duplicate predecessor witness or adaptive clocks.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Air = @import("word_memory_lanes_v1.zig");
const Word = @import("word_memory_v5.zig");
const Protocol = @import("../../prover/block_v5_ram_lanes_protocol_v1.zig");
const Transition = @import("memory_transition.zig").Transition;
const Placement = @import("memory_component_trace.zig");
pub const FixedLayout = struct {
    pub const active = 0;
    pub const first = 1;
    pub const last = 2;
    pub const domain_last = 3;
    pub const ordinal = 4;
    pub const previous_ordinal = 8;
    pub const len = 12;
};
pub const Limits = struct { max_row_log: u32, max_events: u32, max_owned_bytes: usize };
pub const Trace = struct {
    a: std.mem.Allocator,
    claim: Protocol.Claim,
    main: []M,
    fixed: []M,
    previous: ?Transition,
    written: u32 = 0,
    sealed: bool = false,
    pub fn ownedBytes(claim: Protocol.Claim) !usize {
        try claim.validate();
        return ownedBytesForRowLog(claim.row_log);
    }
    pub fn ownedBytesForRowLog(row_log: u32) !usize {
        if (row_log < 1 or row_log > 24) return error.InvalidV5RamLanesGeometry;
        const rows: usize = @as(usize, 1) << @intCast(row_log);
        return std.math.mul(usize, try std.math.mul(usize, rows, Air.MAIN_COLUMNS + Air.FIXED_COLUMNS), @sizeOf(M));
    }
    pub fn init(a: std.mem.Allocator, claim: Protocol.Claim, limits: Limits) !Trace {
        try claim.validate();
        if (claim.row_log > limits.max_row_log or claim.events > limits.max_events or try ownedBytes(claim) > limits.max_owned_bytes) return error.V5RamLanesResourceLimit;
        const size: usize = claim.rowCapacity();
        const main = try a.alloc(M, try std.math.mul(usize, size, Air.MAIN_COLUMNS));
        errdefer a.free(main);
        @memset(main, M.zero());
        const fixed = try a.alloc(M, try std.math.mul(usize, size, Air.FIXED_COLUMNS));
        errdefer a.free(fixed);
        fillFixed(fixed, claim);
        return .{ .a = a, .claim = claim, .main = main, .fixed = fixed, .previous = claim.preceding };
    }
    pub fn append(self: *Trace, event: Transition) !void {
        if (self.sealed or self.written >= self.claim.events) return error.InvalidV5RamLanesPhase;
        if (event.space != 1) return error.InvalidV5RamLanesSpace;
        if (self.written == 0 and !std.meta.eql(event, self.claim.first)) return error.MemoryFirstBoundaryMismatch;
        if (self.written + 1 == self.claim.events and !std.meta.eql(event, self.claim.last)) return error.MemoryLastBoundaryMismatch;
        const row = try Word.witness(self.previous, event);
        const logical = self.written / 2;
        const lane = self.written % 2;
        const physical = Placement.committedRow(logical, self.claim.row_log);
        const size = self.domainSize();
        for (row, 0..) |value, column| self.main[(lane * Word.Layout.len + column) * size + physical] = value;
        self.previous = event;
        self.written += 1;
    }
    pub fn seal(self: *Trace) !void {
        if (self.sealed or self.written != self.claim.events) return error.InvalidV5RamLanesCensus;
        try self.claim.validate();
        self.sealed = true;
    }
    pub fn deinit(self: *Trace) void {
        self.a.free(self.main);
        self.a.free(self.fixed);
        self.* = undefined;
    }
    pub fn domainSize(self: *const Trace) usize {
        return self.claim.rowCapacity();
    }
    pub fn mainColumn(self: *const Trace, column: usize) []const M {
        std.debug.assert(column < Air.MAIN_COLUMNS);
        return self.main[column * self.domainSize() ..][0..self.domainSize()];
    }
    pub fn fixedColumn(self: *const Trace, column: usize) []const M {
        std.debug.assert(column < Air.FIXED_COLUMNS);
        return self.fixed[column * self.domainSize() ..][0..self.domainSize()];
    }
    pub fn rowAt(self: *const Trace, logical: usize) [2][Word.Layout.len]Q {
        const physical = Placement.committedRow(logical, self.claim.row_log);
        var row: [2][Word.Layout.len]Q = undefined;
        for (&row, 0..) |*lane, which| {
            for (lane, 0..) |*out, column| out.* = Q.fromBase(self.mainColumn(which * Word.Layout.len + column)[physical]);
        }
        return row;
    }
    pub fn fixedAt(self: *const Trace, logical: usize) Air.Fixed {
        const physical = Placement.committedRow(logical, self.claim.row_log);
        var values: [Air.FIXED_COLUMNS]Q = undefined;
        for (&values, 0..) |*out, column| out.* = Q.fromBase(self.fixedColumn(column)[physical]);
        return fixedPoint(Q, values, self.claim);
    }
};
/// Receiver reconstruction allocates fixed rows only, never a main witness.
/// The producer and receiver share one canonical selector construction.
pub const FixedTrace = struct {
    a: std.mem.Allocator,
    claim: Protocol.Claim,
    storage: []M,
    pub fn init(a: std.mem.Allocator, claim: Protocol.Claim, max_bytes: usize) !FixedTrace {
        try claim.validate();
        const cells = try std.math.mul(usize, claim.rowCapacity(), Air.FIXED_COLUMNS);
        if (try std.math.mul(usize, cells, @sizeOf(M)) > max_bytes) return error.V5RamLanesResourceLimit;
        const storage = try a.alloc(M, cells);
        fillFixed(storage, claim);
        return .{ .a = a, .claim = claim, .storage = storage };
    }
    pub fn deinit(self: *FixedTrace) void {
        self.a.free(self.storage);
        self.* = undefined;
    }
    pub fn column(self: *const FixedTrace, index: usize) []const M {
        std.debug.assert(index < Air.FIXED_COLUMNS);
        const size: usize = self.claim.rowCapacity();
        return self.storage[index * size ..][0..size];
    }
};
fn fillFixed(storage: []M, claim: Protocol.Claim) void {
    const size: usize = claim.rowCapacity();
    std.debug.assert(storage.len == size * Air.FIXED_COLUMNS);
    @memset(storage, M.zero());
    for (0..size) |logical| {
        const physical = Placement.committedRow(logical, claim.row_log);
        for (0..2) |lane| {
            const offset = 2 * logical + lane;
            const active = offset < claim.events;
            const ordinal: u64 = if (active) claim.first_event + offset else 0;
            var cells: [FixedLayout.len]M = @splat(M.zero());
            cells[FixedLayout.active] = M.fromCanonical(@intFromBool(active));
            cells[FixedLayout.first] = M.fromCanonical(@intFromBool(offset == 0));
            cells[FixedLayout.last] = M.fromCanonical(@intFromBool(active and offset + 1 == claim.events));
            cells[FixedLayout.domain_last] = M.fromCanonical(@intFromBool(logical + 1 == size and lane == 1));
            put(cells[FixedLayout.ordinal..][0..4], ordinal);
            put(cells[FixedLayout.previous_ordinal..][0..4], if (ordinal == 0) 0 else ordinal - 1);
            for (cells, 0..) |value, column| storage[(lane * FixedLayout.len + column) * size + physical] = value;
        }
    }
}
pub fn fixedPoint(comptime S: type, values: [Air.FIXED_COLUMNS]S, claim: Protocol.Claim) Air.Algebra(S).Fixed {
    var result: Air.Algebra(S).Fixed = undefined;
    for (&result, 0..) |*out, lane| {
        const cells = values[lane * FixedLayout.len ..][0..FixedLayout.len];
        out.* = .{ .active = cells[FixedLayout.active], .first = cells[FixedLayout.first], .last = cells[FixedLayout.last], .global_first = publicGate(S, cells[FixedLayout.first], claim.first_event == 0), .global_last = publicGate(S, cells[FixedLayout.last], claim.first_event + claim.events == claim.total_events), .domain_last = cells[FixedLayout.domain_last], .ordinal = cells[FixedLayout.ordinal..][0..4].*, .previous_ordinal = cells[FixedLayout.previous_ordinal..][0..4].* };
    }
    return result;
}
fn publicGate(comptime S: type, selector: S, enabled: bool) S {
    // Reusable device IR binds the public flag without changing the DAG.
    // Scalar/packed evaluators retain their existing branch and arithmetic.
    if (@hasDecl(S, "publicFlag")) return selector.mul(S.publicFlag(enabled));
    return if (enabled) selector else S.zero();
}
fn put(out: []M, value: u64) void {
    for (out, 0..) |*cell, i| cell.* = M.fromCanonical(@intCast((value >> @intCast(16 * i)) & 65535));
}
