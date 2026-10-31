//! Positive CPU requests on the same typed relation as the division service.
//! Sparse request advice is authenticated against committed CPU operands,
//! result and original opcode selectors by evaluate(), never by this recipe.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const E = @import("../../evaluation.zig");
const D = @import("layout.zig");
const P = @import("provider.zig");
const T = @import("trace.zig");
const rom = @import("../../program/provider.zig");
pub const Bus = struct { challenges: P.Challenges, claim: E.Q };
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
pub fn build(a: std.mem.Allocator, steps: u32, log_size: u32, requests: []const IndexedRequest, challenges: P.Challenges) !Columns {
    if (log_size < 5 or log_size > 22 or steps == 0 or steps > @as(usize, 1) << @intCast(log_size) or requests.len > steps) return error.InvalidRv64DivisionCpuGeometry;
    for (requests, 0..) |request, i| {
        if (request.row >= steps or (i != 0 and request.row <= requests[i - 1].row)) return error.InvalidRv64DivisionCpuOrder;
        _ = try D.opcodeIndex(request.request.opcode);
    }
    const n = @as(usize, 1) << @intCast(log_size);
    const data = try a.alloc(M, D.INTERACTION * n);
    errdefer a.free(data);
    var sum = E.Q.zero();
    var cursor: usize = 0;
    for (0..n) |i| {
        const row = rom.physical(i, log_size);
        var inverse = E.Q.zero();
        if (cursor < requests.len and requests[cursor].row == i) {
            const tuple = try T.requestTuple(requests[cursor].request);
            inverse = try challenges.denominator(&tuple).inv();
            cursor += 1;
        }
        sum = sum.add(inverse);
        for (inverse.toM31Array(), 0..) |value, c| data[c * n + row] = value;
        for (sum.toM31Array(), 0..) |value, c| data[(4 + c) * n + row] = value;
    }
    return .{ .allocator = a, .storage = data, .claim = sum };
}
pub fn evaluate(view: E.View, current: *const [D.INTERACTION]E.Q, previous: *const [D.INTERACTION]E.Q, first: E.Q, last: E.Q, bus: Bus, out: *E.Sink) void {
    return evaluateGeneric(E.Q, view, current, previous, first, last, bus, out);
}
pub fn evaluateGeneric(comptime F: type, view: E.ViewFor(F), current: *const [D.INTERACTION]F, previous: *const [D.INTERACTION]F, first: F, last: F, bus: Bus, out: *E.SinkFor(F)) void {
    const enabled = view.sum(&D.OPCODES);
    const tuple = D.tupleGeneric(F, view.f, view.m);
    const inverse = E.secureFor(F, current, 0);
    const sum = E.secureFor(F, current, 4);
    const prior = E.secureFor(F, previous, 4);
    out.emit(E.denominatorFor(F, bus.challenges.offset, &bus.challenges.coefficients, &tuple, false).mul(inverse).sub(E.liftFor(F, enabled)));
    out.emit(E.mulBaseFor(F, inverse, F.one().sub(enabled)));
    out.emit(sum.sub(E.mulBaseFor(F, prior, F.one().sub(first))).sub(inverse));
    out.emit(E.mulBaseFor(F, sum.sub(inverse), first));
    out.emit(E.mulBaseFor(F, sum.sub(E.splatFor(F, bus.claim)), last));
}
