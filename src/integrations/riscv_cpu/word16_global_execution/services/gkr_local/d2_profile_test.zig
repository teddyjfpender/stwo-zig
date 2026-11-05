//! D2 actual native CPU proof gate; no GPU or Ethereum performance claim.
const std = @import("std");
const F = @import("../jumpdest_fixture.zig");
const R = @import("../roster.zig");
const C = @import("coordinator.zig");
const Fixed = @import("fixed_authority.zig").Fixed;
const Set = @import("fixed_authority_set.zig").Set;
const Candidate = @import("../../../word16_execution/om31_security_candidate.zig");
const W = @import("worker_protocol.zig");
const a = std.testing.allocator;
pub fn exercise(comptime selected: Candidate.Profile, comptime Hook: type) !void {
    const engine = @import("stwo_prover_engine");
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var pool_binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer pool_binding.deinit();
    var captured = try F.Captured.init(a);
    defer captured.deinit();
    var keys: [2]R.CpuSetup = undefined;
    var fresh: [2]R.CpuSetup = undefined;
    var made: usize = 0;
    defer for (keys[0..made], fresh[0..made]) |*key, *receiver| {
        key.deinit();
        receiver.deinit();
    };
    for (&keys, &fresh, 0..) |*key, *receiver, i| {
        const geometry = try captured.native[i].geometry();
        key.* = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, geometry, F.bridges[i]);
        receiver.* = R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, geometry, F.bridges[i]) catch |err| {
            key.deinit();
            return err;
        };
        made += 1;
    }
    const cpus = [_]*const R.CpuSetup{ &keys[0], &keys[1] };
    const receiver_cpus = [_]*const R.CpuSetup{ &fresh[0], &fresh[1] };
    const profile = selected;
    const config = Candidate.configFor(profile);
    try W.validateCandidateConfig(config);
    var cache = try Fixed.Cache.init(a, 1 << 30);
    defer cache.deinit();
    var authority = try Set.init(a, &cache, &cpus, &.{}, config);
    defer authority.deinit();
    var receiver_cache = try Fixed.Cache.init(a, 1 << 30);
    defer receiver_cache.deinit();
    var receiver = try Set.init(a, &receiver_cache, &receiver_cpus, &.{}, config);
    defer receiver.deinit();
    try std.testing.expectEqual(@as(?Candidate.Profile, profile), authority.at(0).profile);
    const expected = F.expectedFor(captured.program.identity);
    var bundle = try C.produceWithAuthority(a, &cpus, &.{}, &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expected, config, .{ .gkr_budget = 2 << 30, .defer_local_binding = true, .max_workers = 2, .schedule = .{ .lanes = 2, .workers_per_lane = 1, .memory_cap_bytes = 4 << 30 } }, &authority);
    defer bundle.deinit(a);
    const accepted = try bundle.verifyWithAuthority(a, &receiver_cpus, &.{}, expected, config, &receiver);
    try std.testing.expect(accepted.completed and accepted.physical_proofs == 2);
    if (selected != Candidate.DEFAULT_PROFILE) {
        var old_cache = try Fixed.Cache.init(a, 1 << 30);
        defer old_cache.deinit();
        var old_authority = try Set.init(a, &old_cache, &receiver_cpus, &.{}, Candidate.configFor(Candidate.DEFAULT_PROFILE));
        defer old_authority.deinit();
        if (bundle.verifyWithAuthority(a, &receiver_cpus, &.{}, expected, Candidate.configFor(Candidate.DEFAULT_PROFILE), &old_authority)) |_| return error.D2AcceptedUnderDefaultProfile else |_| {}
    }
    for (0..2) |case| {
        var proof = try W.decodePhysical(a, bundle.cpus[0].bytes);
        defer proof.deinit(a);
        if (case == 0) proof.commitment_scheme_proof.config.fri_config.n_queries -= 1 else proof.commitment_scheme_proof.proof_of_work +%= 1;
        const bytes = try W.encodePhysical(a, proof);
        defer a.free(bytes);
        const original = bundle.cpus[0].bytes;
        bundle.cpus[0].bytes = bytes;
        defer bundle.cpus[0].bytes = original;
        if (bundle.verifyWithAuthority(a, &receiver_cpus, &.{}, expected, config, &receiver)) |_| return error.D2AcceptedTamperedProof else |_| {}
    }
    var temp = std.testing.tmpDir(.{ .iterate = true });
    defer temp.cleanup();
    const Wire = @import("bundle_wire.zig");
    try Wire.write(a, temp.dir, &cpus, &.{}, &bundle);
    var loaded = try Wire.read(a, temp.dir, .{});
    defer loaded.deinit(a);
    _ = try loaded.bundle.verifyWithAuthority(a, &receiver_cpus, &.{}, expected, config, &receiver);
    try Hook.run(a, &cpus, &bundle, expected, config, &authority);
    std.debug.print("NATIVE_CPU_MINI profile={s} beta={} q={} pow={} fold={} physical=2 fresh_authority=true wire_reload=true tamper={} accepted=true certified=false\n", .{ selected.name(), config.fri_config.log_blowup_factor, config.fri_config.n_queries, config.pow_bits, config.fri_config.fold_step, @as(u32, if (selected == Candidate.DEFAULT_PROFILE) 2 else 3) });
}

test "D2 native CPU mini proves fresh verifies and rejects profile query and PoW tampering" {
    try exercise(.d2_native_b4_q54_p20_fold4, struct {
        pub fn run(_: std.mem.Allocator, _: anytype, _: anytype, _: anytype, _: anytype, _: anytype) !void {}
    });
}
