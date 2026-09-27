//! Row AIR for independently sized sorted-memory instances. The fixed active,
//! first and last selectors and the shifted predecessor columns are part of
//! the committed trace placement, not prover-controlled hints. The block-v2
//! transition and initial-state buses still require their interaction backend.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../lang/definition.zig");
const effects = @import("../../recursion/air/relation_effect.zig");
const order = @import("memory_order.zig");
const transition = @import("memory_transition.zig");
const instance = @import("memory_instance.zig");
const M = core.fields.m31.M31;
const Id = lang.types.ValueId;
const span = lang.source.SourceSpan.generated();

pub const STABLE_NAME = "block.sorted_memory_instance.v1";
pub const Layout = struct {
    pub const ordering = 0;
    pub const after = order.Layout.len;
    pub const linked_previous = after + 4;
    /// Mask values from the preceding logical row of the same instance.
    /// These are read-only shifted cells, not independently committed columns.
    pub const shifted_previous = linked_previous + 17;
    pub const active = shifted_previous + 17;
    pub const first = active + 1;
    pub const last = first + 1;
    pub const global_first = last + 1;
    pub const global_last = global_first + 1;
    pub const len = global_last + 1;
};
pub const Row = [Layout.len]M;

/// These fields are public instance claims. The verifier must recompute the
/// selectors from `rows` and `log_size`, verify the fixed commitment, and
/// check adjacent summaries (including their preceding transition).
pub const Claim = struct {
    first_row: u64,
    total_rows: u64,
    rows: u32,
    log_size: u32,
    first: transition.Transition,
    last: transition.Transition,
    preceding: ?transition.Transition,

    pub fn fromSummary(summary: instance.Summary, total_rows: u64, log_size: u32, preceding: ?transition.Transition) !Claim {
        const result: Claim = .{
            .first_row = summary.first_row,
            .total_rows = total_rows,
            .rows = summary.rows,
            .log_size = log_size,
            .first = summary.first,
            .last = summary.last,
            .preceding = preceding,
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: Claim) !void {
        if (self.log_size < 1 or self.log_size > 30 or self.rows == 0 or
            self.rows > @as(u32, 1) << @intCast(self.log_size)) return error.InvalidMemoryComponentClaim;
        if ((self.first_row == 0) != (self.preceding == null)) return error.InvalidMemoryComponentClaim;
        const end = try std.math.add(u64, self.first_row, self.rows);
        if (self.total_rows == 0 or end > self.total_rows) return error.InvalidMemoryComponentClaim;
        if (self.rows == 1 and !std.meta.eql(self.first, self.last)) return error.InvalidMemoryComponentClaim;
    }
};

/// Public roster admission before verifying any instance proof. `total_rows`
/// must itself come from the execution event census in the sealed manifest.
pub fn admitSequence(claims: []const Claim, total_rows: u64) !void {
    if (claims.len == 0 or total_rows == 0) return error.InvalidMemoryInstanceCensus;
    var next_row: u64 = 0;
    var prior: ?transition.Transition = null;
    for (claims) |claim| {
        try claim.validate();
        if (claim.total_rows != total_rows or claim.first_row != next_row or
            !std.meta.eql(claim.preceding, prior)) return error.InvalidMemoryInstanceCensus;
        next_row = try std.math.add(u64, next_row, claim.rows);
        prior = claim.last;
    }
    if (next_row != total_rows) return error.InvalidMemoryInstanceCensus;
}

pub const Definition = struct {
    arena: lang.ir.Arena,
    inputs: [Layout.len]Id,
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
    }
};

pub fn build(a: std.mem.Allocator, claim: Claim) !Definition {
    try claim.validate();
    var base = try order.build(a);
    errdefer base.deinit();
    const arena = &base.arena;
    var ids: [Layout.len]Id = undefined;
    @memcpy(ids[0..order.Layout.len], &base.inputs);
    for (order.Layout.len..Layout.len) |i| {
        var name: [48]u8 = undefined;
        const ty: lang.types.Type = if (i >= Layout.active) .selector else .byte;
        ids[i] = try arena.input(try std.fmt.bufPrint(&name, "sorted_memory.input_{d}", .{i}), ty, span);
    }
    const one = try arena.constantField(1, span);
    const zero = try arena.constantField(0, span);
    const active = ids[Layout.active];
    const first = ids[Layout.first];
    const last = ids[Layout.last];
    const global_first = ids[Layout.global_first];
    const global_last = ids[Layout.global_last];
    var serial: usize = 0;
    try bit(arena, &serial, active);
    try bit(arena, &serial, first);
    try bit(arena, &serial, last);
    try bit(arena, &serial, global_first);
    try bit(arena, &serial, global_last);
    try equal(arena, &serial, ids[order.Layout.active], try arena.mul(active, try arena.sub(one, global_first, span), span));
    try zeroWhen(arena, &serial, first, try arena.sub(one, active, span));
    try zeroWhen(arena, &serial, last, try arena.sub(one, active, span));
    try zeroWhen(arena, &serial, global_first, try arena.sub(one, first, span));
    if (claim.first_row == 0) {
        try equal(arena, &serial, global_first, first);
    } else try equal(arena, &serial, global_first, zero);
    if (claim.first_row + claim.rows == claim.total_rows) {
        try equal(arena, &serial, global_last, last);
    } else try equal(arena, &serial, global_last, zero);

    // The 17 predecessor bytes must be the previous committed row's key,
    // clock and post-value. Physical placement supplies those shifted cells.
    // The first row uses the public preceding boundary instead of a cyclic
    // previous-row mask. The AIR pins both routes to the same logical cells.
    for (0..17) |i| {
        const previous_id = previousOrderId(ids, i);
        try zeroWhen(arena, &serial, ids[order.Layout.active], try arena.sub(previous_id, ids[Layout.linked_previous + i], span));
        try zeroWhen(arena, &serial, try arena.mul(active, try arena.sub(one, first, span), span), try arena.sub(ids[Layout.linked_previous + i], ids[Layout.shifted_previous + i], span));
    }
    if (claim.preceding) |prior| {
        const bytes = predecessorBytes(prior);
        for (bytes, 0..) |byte, i| {
            try zeroWhen(arena, &serial, first, try arena.sub(ids[Layout.linked_previous + i], try arena.constantField(byte, span), span));
        }
    }

    const first_bytes = transitionBytes(claim.first);
    const last_bytes = transitionBytes(claim.last);
    for (0..21) |i| {
        const cell = transitionId(ids, i);
        try zeroWhen(arena, &serial, first, try arena.sub(cell, try arena.constantField(first_bytes[i], span), span));
        try zeroWhen(arena, &serial, last, try arena.sub(cell, try arena.constantField(last_bytes[i], span), span));
    }

    // The order gadget ranges all current bytes except the first block row;
    // after-values are new fields and need their own byte-table requests.
    var byte_ids: [22]Id = undefined;
    for (0..17) |i| byte_ids[i] = transitionId(ids, i);
    byte_ids[17] = try arena.constantUnsigned(.byte, 0, span);
    for (0..4) |i| byte_ids[18 + i] = ids[Layout.after + i];
    for (0..11) |i| {
        const gate = if (i < 9) global_first else active;
        _ = try effects.appendGroup(1, arena, .{.{ .domain = .range_check_8_8, .role = .request, .values = byte_ids[i * 2 ..][0..2], .weight = gate }}, span);
    }
    // On the first block row the order gadget is disabled. The high key
    // byte is still a Boolean address-space value.
    try zeroWhen(arena, &serial, global_first, try arena.mul(ids[order.Layout.current_key + 4], try arena.sub(ids[order.Layout.current_key + 4], one, span), span));
    try lang.validate.validate(arena);
    const result: Definition = .{ .arena = base.arena, .inputs = ids };
    base.arena = undefined;
    return result;
}

pub fn witness(previous: ?transition.Transition, current: transition.Transition, first: bool, last: bool) !Row {
    if (previous == null and !first) return error.InvalidMemoryComponentBoundary;
    var row: Row = @splat(M.zero());
    if (previous) |prior| {
        const order_row = try transition.adjacency(prior, current);
        @memcpy(row[0..order.Layout.len], &order_row);
        const before = predecessorBytes(prior);
        for (before, 0..) |byte, i| row[Layout.linked_previous + i] = M.fromCanonical(byte);
        if (!first) for (before, 0..) |byte, i| {
            row[Layout.shifted_previous + i] = M.fromCanonical(byte);
        };
    } else {
        const current_bytes = transitionBytes(current);
        for (0..5) |i| row[order.Layout.current_key + i] = M.fromCanonical(current_bytes[i]);
        for (0..8) |i| row[order.Layout.current_clock + i] = M.fromCanonical(current_bytes[5 + i]);
        for (0..4) |i| row[order.Layout.current_value + i] = M.fromCanonical(current_bytes[13 + i]);
        row[Layout.global_first] = M.one();
    }
    for (0..4) |i| row[Layout.after + i] = M.fromCanonical(@as(u8, @truncate(current.after >> @intCast(i * 8))));
    row[Layout.active] = M.one();
    if (first) row[Layout.first] = M.one();
    if (last) row[Layout.last] = M.one();
    return row;
}

fn previousOrderId(ids: [Layout.len]Id, index: usize) Id {
    if (index < 5) return ids[order.Layout.previous_key + index];
    if (index < 13) return ids[order.Layout.previous_clock + index - 5];
    return ids[order.Layout.previous_value + index - 13];
}
fn transitionId(ids: [Layout.len]Id, index: usize) Id {
    if (index < 5) return ids[order.Layout.current_key + index];
    if (index < 13) return ids[order.Layout.current_clock + index - 5];
    if (index < 17) return ids[order.Layout.current_value + index - 13];
    return ids[Layout.after + index - 17];
}
fn predecessorBytes(item: transition.Transition) [17]u8 {
    var bytes: [17]u8 = undefined;
    std.mem.writeInt(u32, bytes[0..4], item.address, .little);
    bytes[4] = item.space;
    std.mem.writeInt(u64, bytes[5..13], item.clock, .little);
    std.mem.writeInt(u32, bytes[13..17], item.after, .little);
    return bytes;
}
fn transitionBytes(item: transition.Transition) [21]u8 {
    var bytes: [21]u8 = undefined;
    std.mem.writeInt(u32, bytes[0..4], item.address, .little);
    bytes[4] = item.space;
    std.mem.writeInt(u64, bytes[5..13], item.clock, .little);
    std.mem.writeInt(u32, bytes[13..17], item.before, .little);
    std.mem.writeInt(u32, bytes[17..21], item.after, .little);
    return bytes;
}
fn zeroWhen(arena: *lang.ir.Arena, serial: *usize, gate: Id, value: Id) !void {
    var name: [56]u8 = undefined;
    _ = try arena.assertZero(try std.fmt.bufPrint(&name, "sorted_memory.constraint_{d}", .{serial.*}), try arena.mul(gate, value, span), null, .semantic, span);
    serial.* += 1;
}
fn equal(arena: *lang.ir.Arena, serial: *usize, lhs: Id, rhs: Id) !void {
    try zeroWhen(arena, serial, try arena.constantField(1, span), try arena.sub(lhs, rhs, span));
}
fn bit(arena: *lang.ir.Arena, serial: *usize, value: Id) !void {
    try zeroWhen(arena, serial, try arena.constantField(1, span), try arena.mul(value, try arena.sub(value, try arena.constantField(1, span), span), span));
}
