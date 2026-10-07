//! Word-bus tuples and event expressions for the table-free SHA256d AIR.
//! Host multiset audits and local LogUp components use the same tuple layout.
//! The full joined proof must constrain every event and close all word claims
//! under one transcript challenge to authenticate private caller custody.
const std = @import("std");
const core = @import("stwo_core");
const sha = @import("s31_sha_provider").compression;
const plan_mod = @import("../config/sha_chip_plan.zig");
const caller = @import("sha_caller_stream_equations.zig");
const schedule = @import("sha_schedule_direct_equations.zig");
const feed = @import("sha_feed_direct_equations.zig");
const feed_air = @import("sha_feed_direct_air.zig");
const round = @import("sha_round_direct_air.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;

pub const relation_id: u32 = 0x5333_3103;
pub const schedule_base: u32 = 1024;
pub const terminal_base: u32 = 2048;
pub const boundary_word_count: usize = 32;
pub const events_per_call: usize = 32 + 80 + 80 + 24;
pub const Source = enum(u2) { caller, schedule, round, feed };

fn field(comptime F: type, n: u32) F {
    const base = M31.fromCanonical(n);
    return if (F == M31) base else QM31.fromBase(base);
}

pub fn Expr(comptime F: type) type {
    return struct { values: [6]F, weight: F };
}

fn halfBits(comptime F: type, bits: [32]F, start: usize) F {
    var value = field(F, 0);
    for (0..16) |i| value = value.add(bits[start + i].mul(field(F, @as(u32, 1) << @intCast(i))));
    return value;
}

/// Nine fixed slots per direct-round row. Slot zero consumes W[t] on active
/// rows; slots 1..8 consume the initial state on the first row and emit the
/// terminal state on row 64. The round index and all three selectors are
/// verifier-fixed columns. Inactive slots have zero numerator in LogUp.
pub fn roundEventExpr(comptime F: type, row: round.Row(F), fixed: round.Fixed(F), call_id: F, slot: usize) Expr(F) {
    std.debug.assert(slot < 9);
    if (slot == 0) return .{
        .values = tuple(F, call_id, field(F, schedule_base).add(fixed.round_index), row.w_lo, row.w_hi),
        .weight = field(F, 0).sub(fixed.active),
    };
    const i = slot - 1;
    return .{
        .values = tuple(F, call_id, fixed.first.mul(field(F, @intCast(i))).add(fixed.terminal.mul(field(F, terminal_base + @as(u32, @intCast(i))))), halfBits(F, row.state[i], 0), halfBits(F, row.state[i], 16)),
        .weight = fixed.terminal.sub(fixed.first),
    };
}

/// Three fixed events per feed row: incoming and terminal state are consumed,
/// then the carried output is emitted. The logical word index is verifier-
/// fixed in column six; output halves come from Boolean-constrained bits.
pub fn feedEventExpr(comptime F: type, fixed: [feed_air.fixed_width]F, main: [feed_air.main_width]F, call_id: F, slot: usize) Expr(F) {
    std.debug.assert(slot < 3);
    const words = feed_air.busWords(F, fixed, main);
    const pair = switch (slot) {
        0 => words.incoming,
        1 => words.terminal,
        2 => words.output,
        else => unreachable,
    };
    const address = switch (slot) {
        0 => fixed[6],
        1 => field(F, terminal_base).add(fixed[6]),
        2 => field(F, 24).add(fixed[6]),
        else => unreachable,
    };
    return .{ .values = tuple(F, call_id, address, pair[0], pair[1]), .weight = if (slot == 2) field(F, 1) else field(F, 0).sub(field(F, 1)) };
}

/// The same six-field encoding will be used by every committed component.
/// The final zero separates this relation from six-field uses with a payload
/// in that position; the relation ID separates it from Gate and VM buses.
pub fn tuple(comptime F: type, call_id: F, address: F, lo: F, hi: F) [6]F {
    const id = M31.fromCanonical(relation_id);
    return .{ if (F == M31) id else QM31.fromBase(id), call_id, address, lo, hi, if (F == M31) M31.zero() else QM31.zero() };
}

pub const Elements = struct {
    z: QM31,
    powers: [6]QM31,

    pub fn init(z: QM31, alpha: QM31) Elements {
        var powers: [6]QM31 = undefined;
        var power = QM31.one();
        for (&powers) |*slot| {
            slot.* = power;
            power = power.mul(alpha);
        }
        return .{ .z = z, .powers = powers };
    }

    pub fn denominator(self: Elements, comptime F: type, values: [6]F) QM31 {
        var result = QM31.zero();
        for (values, self.powers) |value, power| {
            result = result.add(power.mul(if (F == M31) QM31.fromBase(value) else value));
        }
        return result.sub(self.z);
    }
};

pub const Event = struct {
    source: Source,
    call_id: u32,
    address: u32,
    lo: u16,
    hi: u16,
    weight: i8,

    pub fn key(self: Event) Key {
        return .{ .call_id = self.call_id, .address = self.address, .lo = self.lo, .hi = self.hi };
    }
};
pub const Key = struct { call_id: u32, address: u32, lo: u16, hi: u16 };

fn event(source: Source, call_id: u32, address: u32, word: u32, weight: i8) Event {
    return .{ .source = source, .call_id = call_id, .address = address, .lo = @truncate(word), .hi = @truncate(word >> 16), .weight = weight };
}

fn blockWords(block: [64]u8) [16]u32 {
    var words: [16]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, block[4 * i ..][0..4], .big);
    return words;
}

fn outputWord(row: feed.Row(M31)) u32 {
    var result: u32 = 0;
    for (row.output_bits, 0..) |bit, i| result |= bit.toU32() << @intCast(i);
    return result;
}

/// The caller emits each state input with multiplicity two: the round AIR
/// consumes it once and feed-forward consumes it once. A block input is
/// consumed once by schedule. Outputs are consumed by the caller, then
/// produced by feed-forward. Internal schedule and terminal addresses cannot
/// collide with boundary addresses or with one another.
pub fn build(allocator: std.mem.Allocator, headers: []const [80]u8, first_call_id: u32) ![]Event {
    const count = std.math.mul(usize, headers.len, 3) catch return error.TooManyShaCalls;
    if (headers.len == 0 or first_call_id == 0 or count > core.fields.m31.Modulus - first_call_id)
        return error.InvalidShaCallId;
    var events: std.ArrayList(Event) = .empty;
    errdefer events.deinit(allocator);
    try events.ensureTotalCapacity(allocator, headers.len * 3 * events_per_call);

    for (headers, 0..) |header, header_index| {
        const plan = plan_mod.prepare(header);
        const caller_rows = caller.witness(header);
        const base_id = first_call_id + @as(u32, @intCast(header_index * 3));
        for (caller_rows, 0..) |row, row_index| {
            for (caller.wordEvents(M31, row, row_index, base_id)) |maybe_word| if (maybe_word) |word| {
                try events.append(allocator, .{
                    .source = .caller,
                    .call_id = word.call_id,
                    .address = word.word_id,
                    .lo = @intCast(word.lo.toU32()),
                    .hi = @intCast(word.hi.toU32()),
                    .weight = if (word.word_id < 8) 2 else if (word.direction == .emit_input) 1 else -1,
                });
            };
        }
        for (plan.calls, 0..) |call, call_index| {
            const id = base_id + @as(u32, @intCast(call_index));
            const words = schedule.referenceWords(blockWords(call.block));
            const rounds = sha.witness(call.state, call.block);
            if (!std.meta.eql(words, rounds.schedule)) return error.ShaScheduleMismatch;
            const feed_rows = feed.witness(call.state, rounds.states[64]);
            for (feed_rows, call.output) |row, expected| if (outputWord(row) != expected) return error.ShaFeedMismatch;

            // Schedule consumes the sixteen caller block words and emits all
            // 64 W words. The round AIR consumes the same 64 W addresses.
            for (0..16) |i| try events.append(allocator, event(.schedule, id, @as(u32, @intCast(8 + i)), words[i], -1));
            for (words, 0..) |word, i| try events.append(allocator, event(.schedule, id, schedule_base + @as(u32, @intCast(i)), word, 1));

            for (call.state, 0..) |word, i| try events.append(allocator, event(.round, id, @intCast(i), word, -1));
            for (words, 0..) |word, i| try events.append(allocator, event(.round, id, schedule_base + @as(u32, @intCast(i)), word, -1));
            for (rounds.states[64], 0..) |word, i| try events.append(allocator, event(.round, id, terminal_base + @as(u32, @intCast(i)), word, 1));

            for (call.state, 0..) |word, i| try events.append(allocator, event(.feed, id, @intCast(i), word, -1));
            for (rounds.states[64], 0..) |word, i| try events.append(allocator, event(.feed, id, terminal_base + @as(u32, @intCast(i)), word, -1));
            for (feed_rows, 0..) |row, i| try events.append(allocator, event(.feed, id, @as(u32, @intCast(24 + i)), outputWord(row), 1));
        }
    }
    if (events.items.len != count * events_per_call) return error.InvalidShaWordRoster;
    return events.toOwnedSlice(allocator);
}

pub fn balanced(allocator: std.mem.Allocator, events: []const Event) !bool {
    var counts = std.AutoHashMap(Key, i32).init(allocator);
    defer counts.deinit();
    for (events) |item| {
        const slot = try counts.getOrPut(item.key());
        if (!slot.found_existing) slot.value_ptr.* = 0;
        slot.value_ptr.* += item.weight;
    }
    var values = counts.valueIterator();
    while (values.next()) |value| if (value.* != 0) return false;
    return true;
}

/// Diagnostic algebraic claims for the four intended AIRs. These are computed
/// from host events, so their closure is a test vector for a future LogUp,
/// never an authentication check by itself.
pub fn diagnosticClaims(events: []const Event, elements: Elements) ![4]QM31 {
    var claims: [4]QM31 = @splat(QM31.zero());
    for (events) |item| {
        const values = tuple(M31, M31.fromCanonical(item.call_id), M31.fromCanonical(item.address), M31.fromCanonical(item.lo), M31.fromCanonical(item.hi));
        const inverse = try elements.denominator(M31, values).inv();
        const signed = if (item.weight < 0) inverse.neg() else inverse;
        var n: u8 = @intCast(@abs(item.weight));
        while (n > 0) : (n -= 1) {
            const index = @intFromEnum(item.source);
            claims[index] = claims[index].add(signed);
        }
    }
    return claims;
}

test "one and two private headers have exactly closed candidate direct-SHA word rosters" {
    const allocator = std.testing.allocator;
    var headers: [2][80]u8 = undefined;
    for (&headers[0], 0..) |*byte, i| byte.* = @truncate(i * 31 + 3);
    for (&headers[1], 0..) |*byte, i| byte.* = @truncate(i * 73 + 11);
    for ([_]usize{ 1, 2 }) |n_headers| {
        const events = try build(allocator, headers[0..n_headers], 1);
        defer allocator.free(events);
        try std.testing.expectEqual(n_headers * 3 * events_per_call, events.len);
        try std.testing.expect(try balanced(allocator, events));
        const elements = Elements.init(QM31.fromU32Unchecked(17, 3, 5, 7), QM31.fromU32Unchecked(11, 13, 19, 23));
        const claims = try diagnosticClaims(events, elements);
        var closure = QM31.zero();
        for (claims) |claim| closure = closure.add(claim);
        try std.testing.expect(closure.isZero());
        for (claims) |claim| try std.testing.expect(!claim.isZero());
        const altered = try allocator.dupe(Event, events);
        defer allocator.free(altered);
        altered[0].lo ^= 1;
        try std.testing.expect(!(try balanced(allocator, altered)));
        var broken = QM31.zero();
        for (try diagnosticClaims(altered, elements)) |claim| broken = broken.add(claim);
        try std.testing.expect(!broken.isZero());
        altered[0] = events[0];
        altered[0].call_id += 1;
        try std.testing.expect(!(try balanced(allocator, altered)));
        altered[0] = events[0];
        altered[0].weight = events[0].weight + 1;
        try std.testing.expect(!(try balanced(allocator, altered)));
    }
    try std.testing.expectError(error.InvalidShaCallId, build(allocator, &headers, 0));
}

test "round lookup expressions derive their addresses and words from committed round rows" {
    const allocator = std.testing.allocator;
    var header: [80]u8 = undefined;
    for (&header, 0..) |*byte, i| byte.* = @truncate(i * 29 + 7);
    const plan = plan_mod.prepare(header);
    const host = try build(allocator, &.{header}, 1);
    defer allocator.free(host);
    var comparison: std.ArrayList(Event) = .empty;
    defer comparison.deinit(allocator);
    for (host) |item| if (item.source == .round) {
        var inverse = item;
        inverse.weight = -item.weight;
        try comparison.append(allocator, inverse);
    };
    for (plan.calls, 0..) |call, call_index| {
        const witness = sha.witness(call.state, call.block);
        const statement = round.Statement{ .initial = call.state, .final = witness.states[64], .schedule = witness.schedule };
        var fixed = try round.writeFixed(allocator, statement.schedule);
        defer fixed.deinit();
        var main = try round.writeMain(allocator, statement);
        defer main.deinit();
        for (0..round.rows) |logical| {
            const storage = round.storageIndex(logical);
            var fixed_values: [round.fixed_width]M31 = undefined;
            for (&fixed_values, fixed.values) |*value, column| value.* = column.values[storage];
            var main_values: [round.main_width]M31 = undefined;
            for (&main_values, main.values) |*value, column| value.* = column.values[storage];
            const fixed_row = round.fixedAt(M31, fixed_values);
            const main_row = round.unflatten(M31, main_values);
            for (0..9) |slot| {
                const expr = roundEventExpr(M31, main_row, fixed_row, M31.fromCanonical(@intCast(call_index + 1)), slot);
                if (expr.weight.isZero()) continue;
                try comparison.append(allocator, .{
                    .source = .round,
                    .call_id = expr.values[1].toU32(),
                    .address = expr.values[2].toU32(),
                    .lo = @intCast(expr.values[3].toU32()),
                    .hi = @intCast(expr.values[4].toU32()),
                    .weight = if (expr.weight.eql(M31.one())) 1 else -1,
                });
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 3 * 80 * 2), comparison.items.len);
    try std.testing.expect(try balanced(allocator, comparison.items));
}
