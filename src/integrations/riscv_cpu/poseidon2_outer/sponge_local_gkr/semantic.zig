//! Canonical equation-IR identity. Prover loops/witness builders are not keys.
//! Invocation parameters use distinct synthetic values so value interning never
//! accidentally aliases independently supplied public/challenge/claim slots.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const R = @import("authority.zig");
const Eq = @import("equations.zig");
const Fr = @import("fractions.zig");
const B = @import("../../word16_global_execution/services/gkr_local/binding.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const Lane = E.symbolic.SymbolicLane(O);
fn next(counter: *u32) O {
    counter.* += 1;
    return O.fromBase(M.fromCanonical(counter.*));
}
pub fn digest(a: std.mem.Allocator) ![32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(R.DOMAIN);
    hash.update("/equation-ir/v1");
    inline for (R.roles) |role| {
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
                return Lane.input(1, c, if (Eq.Layout(role).shifts(1, c).len == 2) -1 else 0);
            }
            pub fn interactionAt(_: *const @This(), c: usize, comptime shift: i32) Lane {
                return Lane.input(2, c, @intCast(shift));
            }
        };
        var counter: u32 = 100;
        var local: Fr.Challenges = undefined;
        local.owner.offset = next(&counter);
        for (&local.owner.coefficients) |*v| v.* = next(&counter);
        local.and_.offset = next(&counter);
        for (&local.and_.coefficients) |*v| v.* = next(&counter);
        local.u16 = next(&counter);
        local.u8 = next(&counter);
        var global: Eq.GlobalFor(O) = undefined;
        global.ram.offset = next(&counter);
        for (&global.ram.coefficients) |*v| v.* = next(&counter);
        global.io.offset = next(&counter);
        for (&global.io.coefficients) |*v| v.* = next(&counter);
        const instance = R.Instance{ .role = role, .row_log = 16 };
        var weights: [64]O = undefined;
        const lanes = @as(usize, 1) << @intCast(instance.laneLog());
        for (weights[0..lanes]) |*v| v.* = next(&counter);
        const binding = Eq.BindingFor(O){ .instance = instance, .weights = weights[0..lanes], .eta = next(&counter), .target = next(&counter) };
        const aux = B.AuxFor(Lane){ .first = Lane.fromConst(next(&counter)), .second = Lane.fromConst(next(&counter)), .carry = Lane.fromConst(next(&counter)), .eq0 = Lane.fromConst(next(&counter)), .eq1 = Lane.fromConst(next(&counter)) };
        const claims = [_]O{ next(&counter), next(&counter) };
        var values: [Eq.Layout(role).CONSTRAINTS]Lane = undefined;
        var sink = E.SinkFor(Lane){ .values = &values };
        try Eq.emit(role, Lane, &View{}, .{ .calls = 10001, .permutations = 10002, .first_id = 10003 }, local, global, binding, aux, claims, &sink);
        if (sink.count != values.len) return error.SpongeConstraintCount;
        var roots: [values.len]u32 = undefined;
        for (values, &roots) |v, *id| id.* = v.id;
        var domain = std.crypto.hash.sha2.Sha256.init(.{});
        domain.update(R.DOMAIN);
        var spec: [20]u8 = undefined;
        std.mem.writeInt(u32, spec[0..4], @intFromEnum(role), .little);
        std.mem.writeInt(u32, spec[4..8], @intCast(R.fixedWidth(role)), .little);
        std.mem.writeInt(u32, spec[8..12], @intCast(R.mainWidth(role)), .little);
        std.mem.writeInt(u32, spec[12..16], @intCast(R.interactionWidth(role)), .little);
        std.mem.writeInt(u32, spec[16..20], R.localQueries(role), .little);
        domain.update(&spec);
        var program = try record.builder.finish(domain.finalResult(), &roots);
        defer program.deinit();
        const degrees = try program.degrees(a);
        defer a.free(degrees);
        for (program.roots) |root| if (degrees[root] > 3) return error.SpongeConstraintDegree;
        hash.update(&program.identity);
    }
    return hash.finalResult();
}
test "serialized sponge semantic authority records full source equations" {
    const first = try digest(std.testing.allocator);
    const second = try digest(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &first, &second);
    try std.testing.expect(!std.mem.allEqual(u8, &first, 0));
}
