//! Concrete degree-eight circuit lane: two QM31 wires and the native tower's
//! single Quadratic authority. Values supplied by a proof must use guess();
//! fromOm31/fromM31Array introduce explicitly public constants only.
const std = @import("std");
const core = @import("stwo_core");
const q = @import("circuit_lane.zig");
const Q = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
pub const O = core.fields.om31.OM31;
pub const Context = q.Context;
// Optional diagnostic counter. It changes no gates, witness or transcript.
pub const Operation = enum { add, sub, full_mul, mul_inner, square, mul_m31, neg, partial_evals };
pub const Count = struct { calls: u64 = 0, qm31_rows: u64 = 0 };
pub const Census = struct {
    operations: [std.meta.fields(Operation).len]Count = @splat(.{}),
    pub fn get(self: *const Census, operation: Operation) Count {
        return self.operations[@intFromEnum(operation)];
    }
    pub fn classifiedRows(self: *const Census) u64 {
        var total: u64 = 0;
        for (self.operations) |operation| total += operation.qm31_rows;
        return total;
    }
};
threadlocal var active_census: ?*Census = null;
threadlocal var census_context: ?*Context = null;
pub const CensusScope = struct {
    previous: ?*Census,
    pub fn init(census: *Census) CensusScope {
        const previous = active_census;
        active_census = census;
        return .{ .previous = previous };
    }
    pub fn deinit(self: *CensusScope) void {
        active_census = self.previous;
    }
};
pub fn begin(context: *Context) void {
    q.begin(context);
    census_context = context;
}
pub fn finish() !void {
    defer census_context = null;
    try q.finish();
}
fn recordedRows(context: *const Context) usize {
    const c = &context.circuit;
    return c.add.items.len + c.sub.items.len + c.mul.items.len + c.pointwise_mul.items.len;
}
fn beforeOperation() ?usize {
    if (active_census == null) return null;
    return recordedRows(census_context orelse return null);
}
fn recordOperation(operation: Operation, before: ?usize) void {
    const count_before = before orelse return;
    const census = active_census orelse return;
    const context = census_context orelse return;
    const count = &census.operations[@intFromEnum(operation)];
    count.calls += 1;
    count.qm31_rows += recordedRows(context) - count_before;
}
pub const check = q.check;
pub const StructuralScope = q.StructuralScope;
const Ops = struct {
    pub fn mulByU(x: q.Lane) q.Lane {
        return x.mul(q.Lane.fromQm31(core.fields.om31.NONRESIDUE));
    }
    pub fn square(x: q.Lane) q.Lane {
        return x.square();
    }
    pub fn scale(x: q.Lane, b: M31) q.Lane {
        return x.mul(q.Lane.fromBase(b));
    }
};
const A = core.fields.om31.Quadratic(q.Lane, Ops);
pub const FullMulHook = *const fn (Lane, Lane) @import("stwo_circuit_frontend").builder.context.Error!Lane;
threadlocal var full_mul_hook: ?FullMulHook = null;
pub const FullMulScope = struct {
    previous: ?FullMulHook,
    pub fn init(hook: FullMulHook) FullMulScope {
        const previous = full_mul_hook;
        full_mul_hook = hook;
        return .{ .previous = previous };
    }
    pub fn deinit(self: *FullMulScope) void {
        full_mul_hook = self.previous;
    }
};
fn delegated(x: Lane, y: Lane) ?Lane {
    const hook = full_mul_hook orelse return null;
    return hook(x, y) catch |err| {
        q.recordFailure(err);
        return Lane.zero();
    };
}
pub const Lane = struct {
    c0: q.Lane,
    c1: q.Lane,
    pub const InnerField = q.Lane;
    pub const rv64_external_lane = true;
    pub const rv64_extension_degree = 8;
    pub fn fromU32(input: u32) Lane {
        return fromBase(M31.fromCanonical(input));
    }
    pub fn fromQm31(input: Q) Lane {
        return .{ .c0 = q.Lane.fromQm31(input), .c1 = q.Lane.zero() };
    }
    pub fn fromPartialEvals(input: [8]Lane) Lane {
        const before = beforeOperation();
        defer recordOperation(.partial_evals, before);
        var values: [8]A = undefined;
        inline for (0..8) |i| values[i] = arithmetic(input[i]);
        return wrap(A.fromPartialEvals(values));
    }

    fn arithmetic(x: Lane) A {
        return .{ .c0 = x.c0, .c1 = x.c1 };
    }
    fn wrap(x: A) Lane {
        return .{ .c0 = x.c0, .c1 = x.c1 };
    }
    pub fn wire(c0: q.Var, c1: q.Var) Lane {
        return .{ .c0 = q.Lane.wire(c0), .c1 = q.Lane.wire(c1) };
    }
    pub fn guess(context: *Context, input: O) !Lane {
        return wire(try context.guess(input.c0), try context.guess(input.c1));
    }
    pub fn zero() Lane {
        return wrap(A.zero());
    }
    pub fn one() Lane {
        return wrap(A.one());
    }
    pub fn fromOm31(input: O) Lane {
        return .{ .c0 = q.Lane.fromQm31(input.c0), .c1 = q.Lane.fromQm31(input.c1) };
    }
    pub fn fromBase(input: M31) Lane {
        return wrap(A.fromBase(input));
    }
    pub fn fromM31Array(input: [8]M31) Lane {
        return fromOm31(O.fromM31Array(input));
    }
    pub fn fromInner(input: q.Lane) Lane {
        return wrap(A.fromInner(input));
    }
    pub fn add(x: Lane, y: Lane) Lane {
        const before = beforeOperation();
        defer recordOperation(.add, before);
        return wrap(arithmetic(x).add(arithmetic(y)));
    }
    pub fn sub(x: Lane, y: Lane) Lane {
        const before = beforeOperation();
        defer recordOperation(.sub, before);
        return wrap(arithmetic(x).sub(arithmetic(y)));
    }
    pub fn mul(x: Lane, y: Lane) Lane {
        if (q.structuralIdentitiesEnabled()) {
            // These are the builder's immutable zero wires, never a test of
            // a witness value. Use the original tower's inner-field product.
            if (y.c1.v.idx == 0) return x.mulInner(y.c0);
            if (x.c1.v.idx == 0) return y.mulInner(x.c0);
            if (delegated(x, y)) |result| return result;
            // Every QM31 add/sub/mul consumes one arithmetic row. The native
            // Karatsuba formula saves a multiplication but costs nine rows;
            // four schoolbook products plus the fixed-u map cost seven.
            // Both compute (a+bv)(c+dv)=(ac+u*bd)+(ad+bc)v.
            const before = beforeOperation();
            defer recordOperation(.full_mul, before);
            const ac = x.c0.mul(y.c0);
            const bd = x.c1.mul(y.c1);
            const ad = x.c0.mul(y.c1);
            const bc = x.c1.mul(y.c0);
            return .{ .c0 = ac.add(Ops.mulByU(bd)), .c1 = ad.add(bc) };
        }
        if (delegated(x, y)) |result| return result;
        const before = beforeOperation();
        defer recordOperation(.full_mul, before);
        return wrap(arithmetic(x).mul(arithmetic(y)));
    }
    pub fn square(x: Lane) Lane {
        const before = beforeOperation();
        defer recordOperation(.square, before);
        if (q.structuralIdentitiesEnabled() and x.c1.v.idx == 0) return fromInner(x.c0.square());
        return wrap(arithmetic(x).square());
    }
    pub fn neg(x: Lane) Lane {
        const before = beforeOperation();
        defer recordOperation(.neg, before);
        return wrap(arithmetic(x).neg());
    }
    pub fn double(x: Lane) Lane {
        return x.add(x);
    }
    pub fn mulM31(x: Lane, input: M31) Lane {
        const before = beforeOperation();
        defer recordOperation(.mul_m31, before);
        return wrap(arithmetic(x).mulBase(input));
    }
    pub fn mulInner(x: Lane, input: q.Lane) Lane {
        const before = beforeOperation();
        defer recordOperation(.mul_inner, before);
        return wrap(arithmetic(x).mulInner(input));
    }
    pub fn quadraticConjugate(x: Lane) Lane {
        return wrap(arithmetic(x).conjugate());
    }
    // A zero guessed norm emits the same topology and an unsatisfied inverse
    // equation through the QM31 lane; witness values never select the graph.
    pub fn inv(x: Lane) Lane {
        return wrap(arithmetic(x).conjugate().mulInner(arithmetic(x).norm().inv()));
    }
    pub fn div(x: Lane, y: Lane) Lane {
        return x.mul(y.inv());
    }
    pub fn value(x: Lane) O {
        return .{ .c0 = x.c0.value(), .c1 = x.c1.value() };
    }
};
