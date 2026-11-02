//! Current beta2/q256/P0/fold4 parameters with independently derived fixed
//! authority. Correctness at target parameters is not composed certification.
const std = @import("std");
const F = @import("../jumpdest_fixture.zig");
const R = @import("../roster.zig");
const C = @import("coordinator.zig");
const Fixed = @import("fixed_authority.zig").Fixed;
const Set = @import("fixed_authority_set.zig").Set;
const Candidate = @import("../../../word16_execution/om31_security_candidate.zig");
const a = std.testing.allocator;
test "bulk JUMPDEST beta2 candidate uses fresh immutable authority and closes physical cross-epoch RAM" {
    var captured = try F.Captured.init(a);
    defer captured.deinit();
    var keys: [2]R.CpuSetup = undefined;
    var fresh: [2]R.CpuSetup = undefined;
    var done: usize = 0;
    defer for (keys[0..done], fresh[0..done]) |*k, *f| {
        k.deinit();
        f.deinit();
    };
    for (&keys, &fresh, 0..) |*k, *f, i| {
        const g = try captured.native[i].geometry();
        k.* = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, g, F.bridges[i]);
        f.* = R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, g, F.bridges[i]) catch |err| {
            k.deinit();
            return err;
        };
        done += 1;
    }
    const cpus = [_]*const R.CpuSetup{ &keys[0], &keys[1] };
    const receiver_cpus = [_]*const R.CpuSetup{ &fresh[0], &fresh[1] };
    const config = Candidate.config();
    var cache = try Fixed.Cache.init(a, 1 << 30);
    defer cache.deinit();
    var authority = try Set.init(a, &cache, &cpus, &.{}, config);
    defer authority.deinit();
    var receiver_cache = try Fixed.Cache.init(a, 1 << 30);
    defer receiver_cache.deinit();
    var receiver_authority = try Set.init(a, &receiver_cache, &receiver_cpus, &.{}, config);
    defer receiver_authority.deinit();
    const expected = F.expectedFor(captured.program.identity);
    var bundle = try C.produceWithAuthority(a, &cpus, &.{}, &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expected, config, .{ .gkr_budget = 2 << 30, .defer_local_binding = true }, &authority);
    defer bundle.deinit(a);
    const accepted = try bundle.verifyWithAuthority(a, &receiver_cpus, &.{}, expected, config, &receiver_authority);
    try std.testing.expect(accepted.completed and accepted.physical_proofs == 2);
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const Wire = @import("bundle_wire.zig");
    try Wire.write(a, temp.dir, &cpus, &.{}, &bundle);
    var loaded = try Wire.read(a, temp.dir, .{});
    defer loaded.deinit(a);
    _ = try loaded.bundle.verifyWithAuthority(a, &receiver_cpus, &.{}, expected, config, &receiver_authority);
    std.debug.print("BULK_CANDIDATE beta2=true q256=true fresh_fixed_authority=true complete=true security_certified=false\n", .{});
}
test "unported secp row declarations cannot enter legacy GKR profile" {
    const T = @import("../types.zig");
    for ([_]T.Family{ .add, .double }) |family| try std.testing.expectError(error.GkrV3ServiceUnsupported, @import("v2_scope.zig").truthDeclaration(.{ .family = family, .logs = .{ 8, 0 }, .calls = 1, .first_id = 1 }));
}
