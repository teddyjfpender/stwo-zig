//! Positive CPU MUL-family requests. Sparse native advice is authenticated by
//! original CPU opcode selectors and full operand/result bytes at every point.
const std = @import("std");
const M = @import("stwo_core").fields.m31.M31;
const E = @import("../../evaluation.zig");
const L = @import("layout.zig");
const P = @import("provider.zig");
const T = @import("trace.zig");
const secure = @import("../../range/cpu.zig").secure;
const physical = @import("../../witness.zig").physical;
pub const INTERACTION = 8;
pub fn BusFor(comptime C: type) type {
    return struct { challenges: P.ChallengesFor(C), claim: C };
}
pub const Bus = BusFor(E.Q);
pub const IndexedRequest = struct { row: u32, request: T.Request };
pub const Columns = struct {
    allocator: std.mem.Allocator,
    storage: []M,
    claim: E.Q,
    pub fn deinit(self: *Columns) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }
};
pub fn evaluate(view: E.View, current: *const [INTERACTION]E.Q, previous: *const [INTERACTION]E.Q, first: E.Q, last: E.Q, bus: Bus, out: *E.Sink) void {
    return evaluateGeneric(E.Q, view, current, previous, first, last, bus, out);
}
pub fn evaluateGeneric(comptime F: type, view: E.ViewFor(F), current: *const [INTERACTION]F, previous: *const [INTERACTION]F, first: F, last: F, bus: BusFor(E.ConstFor(F)), out: *E.SinkFor(F)) void {
    const enabled = view.sum(&L.OPCODES);
    var tuple: [L.TUPLE]F = undefined;
    tuple[0] = F.zero();
    for (L.OPCODES) |op| tuple[0] = tuple[0].add(view.op(op).mul(E.qFor(F, @intFromEnum(op))));
    for ([_]E.L.Word{ .a, .b, .result }, 0..) |word, w| for (0..8) |i| {
        tuple[1 + 8 * w + i] = view.byte(word, i);
    };
    const inverse = E.secureFor(F, current, 0);
    const sum = E.secureFor(F, current, 4);
    const prior = E.secureFor(F, previous, 4);
    out.emit(E.denominatorFor(F, bus.challenges.offset, &bus.challenges.coefficients, &tuple, false).mul(inverse).sub(E.liftFor(F, enabled)));
    out.emit(E.mulBaseFor(F, inverse, F.one().sub(enabled)));
    out.emit(sum.sub(E.mulBaseFor(F, prior, F.one().sub(first))).sub(inverse));
    out.emit(E.mulBaseFor(F, sum.sub(inverse), first));
    out.emit(E.mulBaseFor(F, sum.sub(E.splatFor(F, bus.claim)), last));
}
pub fn build(a: std.mem.Allocator, steps: u32, log: u32, requests: []const IndexedRequest, ch: P.Challenges) !Columns {
    if (log < 5 or log > 22 or steps == 0 or steps >= 1 << 22 or steps > (@as(u32, 1) << @intCast(log)) or requests.len > steps) return error.InvalidRv64MultiplicationCpuGeometry;
    for (requests, 0..) |request, i| {
        if (request.row >= steps or (i != 0 and requests[i - 1].row >= request.row)) return error.InvalidRv64MultiplicationCpuOrder;
        _ = try L.opcodeIndex(request.request.opcode);
    }
    const n = @as(usize, 1) << @intCast(log);
    const data = try a.alloc(M, INTERACTION * n);
    errdefer a.free(data);
    var denominators: [512]E.Q = undefined;
    var prefixes: [512]E.Q = undefined;
    var packet_first: usize = 0;
    var packet_count: usize = 0;
    var cursor: usize = 0;
    var sum = E.Q.zero();
    for (0..n) |i| {
        var inverse = E.Q.zero();
        if (cursor < requests.len and requests[cursor].row == i) {
            if (cursor == packet_first + packet_count) {
                packet_first = cursor;
                packet_count = @min(512, requests.len - cursor);
                var product = E.Q.one();
                for (0..packet_count) |j| {
                    denominators[j] = ch.denominator(&try T.requestTuple(requests[cursor + j].request));
                    prefixes[j] = product;
                    product = product.mul(denominators[j]);
                }
                var inverse_product = try product.inv();
                var j = packet_count;
                while (j != 0) {
                    j -= 1;
                    const d = denominators[j];
                    denominators[j] = inverse_product.mul(prefixes[j]);
                    inverse_product = inverse_product.mul(d);
                }
            }
            inverse = denominators[cursor - packet_first];
            cursor += 1;
        }
        sum = sum.add(inverse);
        const r = physical(i, log);
        for (inverse.toM31Array(), 0..) |v, c| data[c * n + r] = v;
        for (sum.toM31Array(), 0..) |v, c| data[(4 + c) * n + r] = v;
    }
    return .{ .allocator = a, .storage = data, .claim = sum };
}
