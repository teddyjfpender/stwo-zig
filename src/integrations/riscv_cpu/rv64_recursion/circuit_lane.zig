//! The circuit lane: an RV64 external arithmetic lane whose values are
//! circuit-builder wires. Instantiating the batch's constraint code with
//! this type emits, into the active `Context(QM31)`, exactly the arithmetic
//! the native verifier performs at the OODS point, so the leaf circuit and
//! the CPU verifier share one constraint authority.
//!
//! The lane is QM31-shaped (`rv64_external_lane`): every method mirrors the
//! `QM31` method it stands in for. Builder errors cannot surface through the
//! infallible lane signatures, so they are latched in `failure` and raised by
//! `finish` after the emission.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const core = @import("stwo_core");

const Q = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const builder = circuit.builder;
pub const Context = builder.Context(Q);
pub const Var = builder.Var;

threadlocal var active: ?*Context = null;
threadlocal var failure: ?builder.context.Error = null;

/// Binds the lane to `ctx` for the emission that follows; `finish` unbinds
/// it and reports the first builder error, if any.
pub fn begin(context: *Context) void {
    std.debug.assert(active == null);
    active = context;
    failure = null;
}
pub fn finish() builder.context.Error!void {
    active = null;
    defer failure = null;
    if (failure) |err| return err;
}

fn ctx() *Context {
    return active orelse @panic("circuit lane used outside begin/finish");
}
fn latch(result: builder.context.Error!Var) Var {
    return result catch |err| {
        if (failure == null) failure = err;
        return Lane.zero().v;
    };
}

pub const Lane = struct {
    v: Var,
    pub const rv64_external_lane = true;

    pub fn wire(v: Var) Lane {
        return .{ .v = v };
    }
    /// The builder's fixed wires 0 and 1 (`Context.init`), so that these
    /// are comptime-evaluable for struct defaults in the constraint code.
    pub fn zero() Lane {
        return .{ .v = .{ .idx = 0 } };
    }
    pub fn one() Lane {
        return .{ .v = .{ .idx = 1 } };
    }
    pub fn fromQm31(constant: Q) Lane {
        return .{ .v = latch(ctx().constant(constant)) };
    }
    pub fn fromBase(base: M31) Lane {
        return fromQm31(Q.fromBase(base));
    }
    pub fn fromU32(word: u32) Lane {
        return fromBase(M31.fromCanonical(word));
    }
    pub fn add(self: Lane, other: Lane) Lane {
        return .{ .v = latch(ctx().add(self.v, other.v)) };
    }
    pub fn sub(self: Lane, other: Lane) Lane {
        return .{ .v = latch(ctx().sub(self.v, other.v)) };
    }
    pub fn mul(self: Lane, other: Lane) Lane {
        return .{ .v = latch(ctx().mul(self.v, other.v)) };
    }
    pub fn neg(self: Lane) Lane {
        return .{ .v = latch(ctx().sub(zero().v, self.v)) };
    }
    pub fn square(self: Lane) Lane {
        return self.mul(self);
    }
    pub fn double(self: Lane) Lane {
        return self.add(self);
    }
    /// `QM31.fromPartialEvals`: the secure value from four coordinate lanes.
    pub fn fromPartialEvals(values: [4]Lane) Lane {
        return .{ .v = latch(builder.ops.fromPartialEvals(Q, ctx(), .{ values[0].v, values[1].v, values[2].v, values[3].v })) };
    }
    /// The guessed inverse, constrained to `self * inv = 1` (so `self != 0`).
    pub fn inv(self: Lane) Lane {
        return .{ .v = latch(ctx().inv(self.v)) };
    }
    /// The value of the wire in value mode (for parity checks).
    pub fn value(self: Lane) Q {
        return ctx().get(self.v);
    }
};

test "circuit lane: arithmetic matches QM31 in value mode" {
    var context = try Context.init(std.testing.allocator, 0);
    defer context.deinit();
    begin(&context);
    const a = Q.fromU32Unchecked(5, 7, 11, 13);
    const b = Q.fromU32Unchecked(2, 3, 4, 5);
    const x = Lane.fromQm31(a);
    const y = Lane.fromQm31(b);
    try std.testing.expect(x.add(y).value().eql(a.add(b)));
    try std.testing.expect(x.mul(y).sub(Lane.one()).value().eql(a.mul(b).sub(Q.one())));
    try std.testing.expect(x.inv().mul(x).value().eql(Q.one()));
    try finish();
    try context.finalize(false);
    try std.testing.expect(try context.isCircuitValid());
}
