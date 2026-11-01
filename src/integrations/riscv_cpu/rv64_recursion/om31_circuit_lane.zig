//! Concrete degree-eight circuit lane: two QM31 wires and the native tower's
//! single Quadratic authority. Values supplied by a proof must use guess();
//! fromOm31/fromM31Array introduce explicitly public constants only.
const core = @import("stwo_core");
const q = @import("circuit_lane.zig");
const Q = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
pub const O = core.fields.om31.OM31;
pub const Context = q.Context;
pub const begin = q.begin;
pub const finish = q.finish;
pub const check = q.check;
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
pub const Lane = struct {
    c0: q.Lane,
    c1: q.Lane,
    pub const InnerField = q.Lane;
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
        return wrap(arithmetic(x).add(arithmetic(y)));
    }
    pub fn sub(x: Lane, y: Lane) Lane {
        return wrap(arithmetic(x).sub(arithmetic(y)));
    }
    pub fn mul(x: Lane, y: Lane) Lane {
        return wrap(arithmetic(x).mul(arithmetic(y)));
    }
    pub fn square(x: Lane) Lane {
        return wrap(arithmetic(x).square());
    }
    pub fn neg(x: Lane) Lane {
        return wrap(arithmetic(x).neg());
    }
    pub fn double(x: Lane) Lane {
        return x.add(x);
    }
    pub fn mulM31(x: Lane, input: M31) Lane {
        return wrap(arithmetic(x).mulBase(input));
    }
    pub fn mulInner(x: Lane, input: q.Lane) Lane {
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
