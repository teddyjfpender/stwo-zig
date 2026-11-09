//! Canonical frontier equation IR, independent of witness/prover loop text.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("stwo_riscv_frontend").rv64_air.evaluation;
const Eq = @import("equations.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const Lane = E.symbolic.SymbolicLane(O);
fn next(counter: *u32) O {
    counter.* += 1;
    return O.fromBase(M.fromCanonical(counter.*));
}
pub fn digest(a: std.mem.Allocator) ![32]u8 {
    var record = E.symbolic.Recording(O).init(a);
    defer record.deinit();
    record.begin();
    defer record.end();
    const View = struct {
        pub fn fixed(_: *const @This(), c: usize) Lane {
            return Lane.input(0, c, 0);
        }
        pub fn main(_: *const @This(), c: usize) Lane {
            return Lane.input(1, c, 0);
        }
        pub fn previousMain(_: *const @This(), c: usize) Lane {
            return Lane.input(1, c, if (c == 0) -1 else 0);
        }
        pub fn interactionAt(_: *const @This(), c: usize, comptime shift: i32) Lane {
            return Lane.input(2, c, @intCast(shift));
        }
    };
    var counter: u32 = 100;
    var local: @import("provider.zig").Challenges = undefined;
    for (&local.offsets, &local.coefficients) |*offset, *coefficients| {
        offset.* = next(&counter);
        for (coefficients) |*v| v.* = next(&counter);
    }
    var wire: @import("stwo_riscv_frontend").rv64_air.crypto.secp256k1.equations.WireFor(O) = undefined;
    wire.offset = next(&counter);
    for (&wire.coefficients) |*v| v.* = next(&counter);
    var binding: Eq.Binding = undefined;
    for (&binding.weights) |*v| v.* = next(&counter);
    binding.eta = next(&counter);
    binding.target = next(&counter);
    const B = @import("../../word16_global_execution/services/gkr_local/binding.zig");
    const aux = B.AuxFor(Lane){ .first = Lane.fromConst(next(&counter)), .second = Lane.fromConst(next(&counter)), .carry = Lane.fromConst(next(&counter)), .eq0 = Lane.fromConst(next(&counter)), .eq1 = Lane.fromConst(next(&counter)) };
    var values: [Eq.Layout.CONSTRAINTS]Lane = undefined;
    var sink = E.SinkFor(Lane){ .values = &values };
    try Eq.emit(Lane, &View{}, .{ .calls = 10001, .epoch = 10002, .ordinal = 10003 }, local, wire, binding, aux, next(&counter), &sink);
    if (sink.count != values.len) return error.SpongeCpuConstraintCount;
    var roots: [values.len]u32 = undefined;
    for (values, &roots) |value, *out| out.* = value.id;
    var domain = std.crypto.hash.sha2.Sha256.init(.{});
    domain.update(@import("frame.zig").DOMAIN);
    domain.update("/frontier-equation-ir/v1");
    var program = try record.builder.finish(domain.finalResult(), &roots);
    defer program.deinit();
    const degrees = try program.degrees(a);
    defer a.free(degrees);
    for (program.roots) |root| if (degrees[root] > 3) return error.SpongeCpuConstraintDegree;
    return program.identity;
}
test "sponge CPU frontier canonical equations have degree at most three" {
    _ = try digest(std.testing.allocator);
}
