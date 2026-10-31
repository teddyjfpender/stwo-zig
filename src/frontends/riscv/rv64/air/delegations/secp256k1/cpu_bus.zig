//! Positive CPU typed headers only. No field/group operation or RAM oracle.
//! Two independent affine counters keep both denominators linear; one stitched
//! secure prefix closes both kinds without per-call or per-kind inverse columns.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const E = @import("../../evaluation.zig");
const P = @import("program.zig");
const profile = @import("../../../execution_profile.zig");
const bridge = @import("bridge/equations.zig");
const physical = @import("../../witness.zig").physical;
pub const MAIN_COUNTERS = 2;
pub const INTERACTION = 4;
pub const CONSTRAINTS = 7;
pub const SELECTOR_CONSTRAINTS = 12;
/// Header bus over constant lane C: counts/IDs are integers natively, wires
/// externally (an external lane must assign `first_ids` explicitly).
pub fn BusFor(comptime C: type) type {
    return struct {
        challenges: bridge.CallChallengesFor(C),
        claim: C,
        calls: [2]E.CountFor(C),
        first_ids: [2]E.CountFor(C) = if (E.isExternalLane(C)) undefined else .{ 1, 1 },
        execution_profile: profile.Profile,
        pub fn validate(self: @This(), steps: u32) !void {
            if (self.execution_profile != .ethereum_services_v1 and self.execution_profile != .ethereum_services_v2) return error.InvalidSecpCpuProfile;
            if (steps == 0 or steps >= 1 << 22 or @as(u64, self.calls[0]) + self.calls[1] > steps) return error.InvalidSecpCpuCount;
            for (self.calls, self.first_ids) |count, first| if (first == 0 or first >= core.fields.m31.Modulus or @as(u64, first) + count > core.fields.m31.Modulus) return error.InvalidSecpCallSpan;
        }
    };
}
pub const Bus = BusFor(E.Q);
/// The caller invokes this once for all3 service families. Old K-only profiles
/// keep their existing authority; they must never silently accept these tags.
pub fn evaluateSelectors(view: E.View, flags: [3]E.Q, execution: profile.Profile, out: *E.Sink) void {
    return evaluateSelectorsGeneric(E.Q, view, flags, execution, out);
}
pub fn evaluateSelectorsGeneric(comptime F: type, view: E.ViewFor(F), flags: [3]F, execution: profile.Profile, out: *E.SinkFor(F)) void {
    std.debug.assert(execution == .ethereum_services_v1 or execution == .ethereum_services_v2);
    var sum = F.zero();
    for (flags) |flag| {
        out.emit(flag.mul(flag.sub(F.one())));
        sum = sum.add(flag);
    }
    const ecall = view.op(.ECALL);
    out.emit(sum.sub(ecall));
    const tags = [_]u64{ profile.KECCAK_TAG, if (execution == .ethereum_services_v1) profile.SECP_ADD_TAG else profile.SECP_ADD_WORD_TAG, if (execution == .ethereum_services_v1) profile.SECP_DOUBLE_TAG else profile.SECP_DOUBLE_WORD_TAG };
    for (0..8) |byte| {
        var expected = F.zero();
        for (tags, flags) |tag, flag| expected = expected.add(flag.mul(E.qFor(F, @intCast((tag >> @as(u6, @intCast(8 * byte))) & 255))));
        out.emit(ecall.mul(view.byte(.b, byte).sub(expected)));
    }
}
pub fn tuple(kind: P.Kind, counter: E.Q, tick: E.Q, pointer: [8]E.Q, first: u32) [11]E.Q {
    return tupleGeneric(E.Q, kind, counter, tick, pointer, first);
}
pub fn tupleGeneric(comptime F: type, kind: P.Kind, counter: F, tick: F, pointer: [8]F, first: E.CountFor(E.ConstFor(F))) [11]F {
    var value: [11]F = undefined;
    value[0] = E.qFor(F, @intFromEnum(kind));
    value[1] = counter.add(E.scalarMinusOneFor(F, first));
    value[2] = tick;
    @memcpy(value[3..], &pointer);
    return value;
}
pub fn evaluate(view: E.View, geometry: [3]E.Q, flags: [2]E.Q, counters: [2]E.Q, previous_counters: [2]E.Q, current: E.Q, previous: E.Q, bus: Bus, out: *E.Sink) void {
    return evaluateGeneric(E.Q, view, geometry, flags, counters, previous_counters, current, previous, bus, out);
}
pub fn evaluateGeneric(comptime F: type, view: E.ViewFor(F), geometry: [3]F, flags: [2]F, counters: [2]F, previous_counters: [2]F, current: E.SecureFor(F), previous: E.SecureFor(F), bus: BusFor(E.ConstFor(F)), out: *E.SinkFor(F)) void {
    for (0..2) |kind| {
        out.emit(counters[kind].sub(F.one().sub(geometry[1]).mul(previous_counters[kind])).sub(flags[kind]));
        out.emit(geometry[1].mul(counters[kind].sub(flags[kind])));
        out.emit(geometry[2].mul(counters[kind].sub(E.scalarFor(F, bus.calls[kind]))));
    }
    var pointer: [8]F = undefined;
    for (&pointer, 0..) |*v, i| v.* = view.byte(.a, i);
    const tick = geometry[0].mul(E.qFor(F, 4)).add(E.qFor(F, 4));
    const da = E.denominatorFor(F, bus.challenges.offset, &bus.challenges.coefficients, &tupleGeneric(F, .add, counters[0], tick, pointer, bus.first_ids[0]), true);
    const dd = E.denominatorFor(F, bus.challenges.offset, &bus.challenges.coefficients, &tupleGeneric(F, .double, counters[1], tick, pointer, bus.first_ids[1]), true);
    out.emit(current.sub(previous).add(E.mulBaseFor(F, E.splatFor(F, bus.claim), geometry[1])).mul(da).mul(dd).sub(E.mulBaseFor(F, dd, flags[0])).sub(E.mulBaseFor(F, da, flags[1])));
}
pub const Call = struct { kind: P.Kind, call_id: u64, clock: u64, pointer: u64 };
pub const Columns = struct {
    allocator: std.mem.Allocator,
    storage: []M,
    claim: E.Q,
    pub fn deinit(self: *Columns) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }
};
pub fn build(a: std.mem.Allocator, steps: u32, log: u32, calls: []const Call, first_ids: [2]u32, execution: profile.Profile, ch: bridge.CallChallenges) !Columns {
    var counts: [2]u32 = @splat(0);
    for (calls, 0..) |call, i| {
        if (call.clock == 0 or call.clock > steps or (i != 0 and calls[i - 1].clock >= call.clock)) return error.InvalidSecpCpuOrder;
        const kind: usize = if (call.kind == .add) 0 else 1;
        if (call.call_id != @as(u64, first_ids[kind]) + counts[kind]) return error.InvalidSecpCpuOrder;
        counts[kind] = try std.math.add(u32, counts[kind], 1);
    }
    try (Bus{ .calls = counts, .first_ids = first_ids, .execution_profile = execution, .challenges = ch, .claim = E.Q.zero() }).validate(steps);
    if (log < 5 or log > 22 or steps > (@as(u32, 1) << @intCast(log))) return error.InvalidSecpCpuGeometry;
    const n = @as(usize, 1) << @intCast(log);
    const data = try a.alloc(M, INTERACTION * n);
    errdefer a.free(data);
    var sum = E.Q.zero();
    var cursor: usize = 0;
    for (0..n) |i| {
        if (cursor < calls.len and calls[cursor].clock == i + 1) {
            const call = calls[cursor];
            var value: [11]E.Q = undefined;
            value[0] = E.q(@intFromEnum(call.kind));
            value[1] = E.q(@intCast(call.call_id));
            value[2] = E.q(@intCast(4 * call.clock));
            for (0..8) |byte| value[3 + byte] = E.q(@intCast((call.pointer >> @as(u6, @intCast(8 * byte))) & 255));
            sum = sum.add(try ch.denominator(&value).inv());
            cursor += 1;
        }
        const r = physical(i, log);
        for (sum.toM31Array(), 0..) |v, c| data[c * n + r] = v;
    }
    return .{ .allocator = a, .storage = data, .claim = sum };
}
