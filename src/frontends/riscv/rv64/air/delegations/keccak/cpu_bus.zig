//! Positive CPU ECALL headers. The bridge binds each header to exactly25 RAM
//! lane transitions and permutation I/O. This module never computes Keccak.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const E = @import("../../evaluation.zig");
const profile = @import("../../../execution_profile.zig");
const bridge = @import("bridge/trace.zig");
const equations = @import("bridge/equations.zig");
const secure = @import("../../program/provider.zig").secure;
const physical = @import("../../program/provider.zig").physical;
pub const INTERACTION = 8;
pub const CONSTRAINTS = 16;
/// Header bus over constant lane C: counts are integers natively, wires externally.
pub fn BusFor(comptime C: type) type {
    return struct {
        challenges: equations.CallChallengesFor(C),
        claim: C,
        calls: E.CountFor(C),
        first_call_id: E.CountFor(C),
        pub fn validate(self: @This(), steps: u32) !void {
            if (steps == 0 or steps >= 1 << 22 or self.calls > steps or self.first_call_id == 0 or self.first_call_id >= core.fields.m31.Modulus or @as(u64, self.first_call_id) + self.calls > core.fields.m31.Modulus) return error.InvalidRv64KeccakHeaderSpan;
        }
    };
}
pub const Bus = BusFor(E.Q);
pub fn evaluate(view: E.View, geometry: [3]E.Q, count: E.Q, previous_count: E.Q, current: *const [INTERACTION]E.Q, previous: *const [INTERACTION]E.Q, bus: Bus, out: *E.Sink) void {
    return evaluateWithSelector(view, geometry, count, previous_count, current, previous, bus, view.op(.ECALL), out);
}
/// Mixed service profiles prove the ECALL tag partition separately.
pub fn evaluateWithSelector(view: E.View, geometry: [3]E.Q, count: E.Q, previous_count: E.Q, current: *const [INTERACTION]E.Q, previous: *const [INTERACTION]E.Q, bus: Bus, enabled: E.Q, out: *E.Sink) void {
    return evaluateWithSelectorGeneric(E.Q, view, geometry, count, previous_count, current, previous, bus, enabled, out);
}
pub fn evaluateWithSelectorGeneric(comptime F: type, view: E.ViewFor(F), geometry: [3]F, count: F, previous_count: F, current: *const [INTERACTION]F, previous: *const [INTERACTION]F, bus: BusFor(E.ConstFor(F)), enabled: F, out: *E.SinkFor(F)) void {
    out.emit(count.sub(F.one().sub(geometry[1]).mul(previous_count)).sub(enabled));
    out.emit(geometry[1].mul(count.sub(enabled)));
    out.emit(geometry[2].mul(count.sub(E.scalarFor(F, bus.calls))));
    for (0..8) |i| out.emit(enabled.mul(view.byte(.b, i).sub(E.qFor(F, @intCast((profile.KECCAK_TAG >> @as(u6, @intCast(i * 8))) & 255)))));
    var tuple: [10]F = undefined;
    tuple[0] = count.add(E.scalarMinusOneFor(F, bus.first_call_id));
    tuple[1] = geometry[0].mul(E.qFor(F, 4)).add(E.qFor(F, 4));
    for (0..8) |i| tuple[2 + i] = view.byte(.a, i);
    const inverse = E.secureFor(F, current, 0);
    const sum = E.secureFor(F, current, 4);
    const prior = E.secureFor(F, previous, 4);
    out.emit(E.denominatorFor(F, bus.challenges.offset, &bus.challenges.coefficients, &tuple, true).mul(inverse).sub(E.liftFor(F, enabled)));
    out.emit(E.mulBaseFor(F, inverse, F.one().sub(enabled)));
    out.emit(sum.sub(E.mulBaseFor(F, prior, F.one().sub(geometry[1]))).sub(inverse));
    out.emit(E.mulBaseFor(F, sum.sub(inverse), geometry[1]));
    out.emit(E.mulBaseFor(F, sum.sub(E.splatFor(F, bus.claim)), geometry[2]));
}
pub const Columns = struct {
    allocator: std.mem.Allocator,
    storage: []M,
    claim: E.Q,
    pub fn deinit(self: *Columns) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }
};
pub fn build(a: std.mem.Allocator, steps: u32, log_size: u32, calls: []const bridge.Call, first_id: u32, challenges: equations.CallChallenges) !Columns {
    if (calls.len > steps) return error.InvalidRv64KeccakHeaderSpan;
    const bus = Bus{ .calls = @intCast(calls.len), .first_call_id = first_id, .challenges = challenges, .claim = E.Q.zero() };
    try bus.validate(steps);
    if (log_size < 5 or log_size > 22 or steps == 0 or steps > @as(usize, 1) << @intCast(log_size)) return error.InvalidRv64KeccakHeaderGeometry;
    for (calls, 0..) |call, i| if (call.clock == 0 or call.clock > steps or (i != 0 and calls[i - 1].clock >= call.clock) or call.call_id != @as(u64, first_id) + i) return error.InvalidRv64KeccakHeaderOrder;
    const n = @as(usize, 1) << @intCast(log_size);
    const data = try a.alloc(M, INTERACTION * n);
    errdefer a.free(data);
    var cursor: usize = 0;
    var sum = E.Q.zero();
    for (0..n) |i| {
        const row = physical(i, log_size);
        var inverse = E.Q.zero();
        if (cursor < calls.len and calls[cursor].clock == i + 1) {
            const call = calls[cursor];
            var tuple: [10]E.Q = undefined;
            tuple[0] = E.q(@intCast(call.call_id));
            tuple[1] = E.q(@intCast(4 * call.clock));
            for (0..8) |byte| tuple[2 + byte] = E.q(@intCast((call.pointer >> @as(u6, @intCast(byte * 8))) & 255));
            inverse = try challenges.denominator(&tuple).inv();
            cursor += 1;
        }
        sum = sum.add(inverse);
        for (inverse.toM31Array(), 0..) |part, c| data[c * n + row] = part;
        for (sum.toM31Array(), 0..) |part, c| data[(4 + c) * n + row] = part;
    }
    return .{ .allocator = a, .storage = data, .claim = sum };
}
