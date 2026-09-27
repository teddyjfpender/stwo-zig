//! Owned27-column word-memory trace; all old memory claim endpoints retain
//! their full byte-address/u64-clock/u32-value host representation.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const row_mod = @import("word_memory_v5.zig");
const source = @import("memory_component_trace.zig");
const packed_fixed = @import("word_memory_fixed_v5.zig");
const component = @import("memory_component.zig");
const transition = @import("memory_transition.zig");
const partition = @import("memory_instance.zig");
pub const Trace = struct {
    a: std.mem.Allocator,
    claim: component.Claim,
    fixed: packed_fixed.Trace,
    storage: []M,
    preceding: ?transition.Transition,
    written: u32 = 0,
    sealed: bool = false,
    claimed: bool = true,
    pub fn init(a: std.mem.Allocator, claim: component.Claim) !Trace {
        try row_mod.validatePublicClaim(claim);
        var fixed = try packed_fixed.Trace.init(a, claim);
        errdefer fixed.deinit();
        const storage = try a.alloc(M, try std.math.mul(usize, row_mod.Layout.len, @as(usize, 1) << @intCast(claim.log_size)));
        @memset(storage, M.zero());
        return .{ .a = a, .claim = claim, .fixed = fixed, .storage = storage, .preceding = claim.preceding };
    }
    pub fn nextFromPartitioner(a: std.mem.Allocator, p: *partition.Partitioner, minimum_log: u32) !?Trace {
        if (p.finished) return null;
        if (minimum_log < 1 or minimum_log > 24) return error.InvalidWordMemoryGeometry;
        const capacity = try p.currentCapacity();
        const count: u32 = @intCast(@min(p.expected_rows - p.emitted, capacity));
        const blank: transition.Transition = .{ .space = 0, .address = 0, .clock = 0, .before = 0, .after = 0 };
        var trace = try init(a, .{ .first_row = p.emitted, .total_rows = p.expected_rows, .rows = count, .log_size = @max(minimum_log, std.math.log2_int(u32, capacity)), .first = blank, .last = blank, .preceding = p.previous });
        errdefer trace.deinit();
        trace.claimed = false;
        const summary = (try p.next(.{ .context = &trace, .append = appendSink })) orelse return error.InvalidWordMemoryCensus;
        try trace.seal();
        if (!std.meta.eql(summary.first, trace.claim.first) or !std.meta.eql(summary.last, trace.claim.last) or summary.rows != count) return error.InvalidWordMemoryCensus;
        return trace;
    }
    pub fn append(self: *Trace, value: transition.Transition) !void {
        if (self.sealed or self.written >= self.claim.rows) return error.InvalidWordMemoryPhase;
        const first = self.written == 0;
        const last = self.written + 1 == self.claim.rows;
        if (first) {
            if (self.claimed and !std.meta.eql(value, self.claim.first)) return error.MemoryFirstBoundaryMismatch;
            self.claim.first = value;
        }
        if (last) {
            if (self.claimed and !std.meta.eql(value, self.claim.last)) return error.MemoryLastBoundaryMismatch;
            self.claim.last = value;
        }
        const row = try row_mod.witness(self.preceding, value);
        const physical = source.committedRow(self.written, self.claim.log_size);
        const size = self.domainSize();
        for (row, 0..) |cell, column| self.storage[column * size + physical] = cell;
        self.preceding = value;
        self.written += 1;
    }
    pub fn seal(self: *Trace) !void {
        if (self.sealed or self.written != self.claim.rows) return error.InvalidWordMemoryCensus;
        try row_mod.validatePublicClaim(self.claim);
        self.fixed.claim = self.claim;
        self.sealed = true;
    }
    pub fn deinit(self: *Trace) void {
        self.a.free(self.storage);
        self.fixed.deinit();
        self.* = undefined;
    }
    pub fn domainSize(self: *const Trace) usize {
        return @as(usize, 1) << @intCast(self.claim.log_size);
    }
    pub fn mainColumn(self: *const Trace, index: usize) []const M {
        std.debug.assert(index < row_mod.Layout.len);
        return self.storage[index * self.domainSize() ..][0..self.domainSize()];
    }
    pub fn fixedColumn(self: *const Trace, index: usize) []const M {
        return self.fixed.column(index);
    }
    pub fn rowAt(self: *const Trace, logical: usize) [row_mod.Layout.len]Q {
        const physical = source.committedRow(logical, self.claim.log_size);
        var row: [row_mod.Layout.len]Q = undefined;
        for (&row, 0..) |*cell, i| cell.* = Q.fromBase(self.mainColumn(i)[physical]);
        return row;
    }
    pub fn fixedAt(self: *const Trace, logical: usize) row_mod.Fixed {
        const physical = source.committedRow(logical, self.claim.log_size);
        var cells: [packed_fixed.COLUMN_COUNT]Q = undefined;
        for (&cells, 0..) |*cell, i| cell.* = Q.fromBase(self.fixedColumn(i)[physical]);
        return fixedPoint(cells, self.claim);
    }
    fn appendSink(context: *anyopaque, value: transition.Transition, link: ?@import("memory_order.zig").Row) anyerror!void {
        const self: *Trace = @ptrCast(@alignCast(context));
        const expected = if (self.preceding) |prior| try transition.adjacency(prior, value) else null;
        if (!std.meta.eql(expected, link)) return error.MemoryPartitionLinkMismatch;
        try self.append(value);
    }
};
pub fn fixedPoint(cells: [packed_fixed.COLUMN_COUNT]Q, claim: component.Claim) row_mod.Fixed {
    return fixedPointGeneric(Q, cells, claim);
}
pub fn fixedPointGeneric(comptime S: type, cells: [packed_fixed.COLUMN_COUNT]S, claim: component.Claim) row_mod.Algebra(S).Fixed {
    const L = packed_fixed.Layout;
    return .{ .active = cells[L.active], .first = cells[L.first], .last = cells[L.last], .global_first = publicGate(S, cells[L.first], claim.first_row == 0), .global_last = publicGate(S, cells[L.last], claim.first_row + claim.rows == claim.total_rows), .domain_last = cells[L.domain_last], .ordinal = cells[L.ordinal..][0..4].*, .previous_ordinal = cells[L.previous_ordinal..][0..4].* };
}

fn publicGate(comptime S: type, selector: S, enabled: bool) S {
    // Device exporters bind this public value without changing the DAG. Host
    // scalar/packed evaluators retain the branch and incur no extra multiply.
    if (@hasDecl(S, "publicFlag")) return selector.mul(S.publicFlag(enabled));
    return if (enabled) selector else S.zero();
}
