const std = @import("std");
const A = @import("../rv64_authenticated_execution.zig");
const C = @import("../rv64_execution_verifier_cache.zig");
const K = @import("../rv64_execution_verifier_key.zig");
const rv = A.frontend.rv64;
const wire = @import("stwo_proof_wire");
const a = std.testing.allocator;
const pc: u64 = 0x100001000;
const code = [_]u32{ 0x00300093, 0x02108133 }; // x1=3; x2=x1*x1
const program = A.rv.program.setup.Program{ .base = pc, .words = &code };
const Produced = struct {
    public: A.Public,
    claims: A.Claims,
    bytes: []u8,
    root: [32]u8,
    fn deinit(self: *Produced) void {
        a.free(self.bytes);
    }
};
fn produce(authority: *const A.Full.ProgramAuthority, policy: *const A.R.policy.Policy, steps: usize) !Produced {
    var memory = rv.memory.Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = pc, .size = 8, .permissions = .{ .read = true, .execute = true } });
    for (code, 0..) |raw, i| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, raw, .little);
        try memory.initialize(pc + 4 * i, &bytes);
    }
    var cpu = rv.machine.Cpu.init(pc, 0);
    var records: [2]rv.machine.Retirement = undefined;
    for (records[0..steps]) |*record| record.* = try cpu.step(&memory);
    var clocks: [32]u32 = @splat(0);
    clocks[1] = if (steps == 1) 3 else 6;
    if (steps == 2) clocks[2] = 7;
    const public = A.Public{ .cpu = .{ .execution_profile = .keccak_service_v1, .arithmetic_policy = .division_multiplication_services_v3, .state_policy = .cyclic_v2, .control_policy = .limbs24_v2, .division_roster = .none, .division_requests = 0, .multiplication_requests = if (steps == 2) 1 else 0, .roster = .none, .keccak_calls = 0, .statement = .{ .program = authority.expectedProgram(), .steps = @intCast(steps), .initial_pc = pc, .final_pc = cpu.pc, .initial_registers = @splat(0), .final_registers = cpu.regs, .cells = &.{}, .register_clocks = clocks, .memory_clocks = &.{}, .opcodes = authority.opcodes } }, .geometry = .chunk512, .before = @splat(0), .after = @splat(0), .policy_identity = policy.identity, .ram = null };
    var setup = try A.Prepared.initWithAuthority(a, public, policy, authority);
    defer setup.deinit();
    var trace = try A.CPU.Trace.init(a, records[0..steps], &.{}, public.cpu, &setup.cpu);
    defer trace.deinit();
    var bundle = try A.proveTrace(a, &setup, public, &trace, null);
    defer bundle.deinit(a);
    return .{ .public = public, .claims = bundle.claims, .bytes = try wire.encodeProofBytesBinary(a, bundle.proof), .root = setup.root };
}
fn reject(cache: *C.Cache, public: A.Public, produced: *const Produced) !void {
    if (cache.verifyOwned(public, produced.claims, try wire.decodeProofBytesBinary(a, produced.bytes))) |_| return error.AcceptedChangedExpectedRequest else |_| {}
}
test "narrow verifier cache reuses immutable count0/count1 key with fresh request validation" {
    var authority = try A.Full.ProgramAuthority.initWithControl(a, program, .keccak_service_v1, .limbs24_v2);
    defer authority.deinit();
    var policy = try A.R.policy.Policy.init(a, &.{.{ .first = pc, .last = pc + 7, .flags = 5 }});
    defer policy.deinit();
    var zero = try produce(&authority, &policy, 1);
    defer zero.deinit();
    var one = try produce(&authority, &policy, 2);
    defer one.deinit();
    try std.testing.expectEqualSlices(u8, &zero.root, &one.root);
    try std.testing.expect(std.meta.eql(try C.Signature.derive(&authority, &policy, zero.public), try C.Signature.derive(&authority, &policy, one.public)));
    var cache = try C.Cache.init(a, &authority, &policy, .{ .entries = 2 });
    defer cache.deinit();
    try cache.verifyOwned(zero.public, zero.claims, try wire.decodeProofBytesBinary(a, zero.bytes));
    try cache.verifyOwned(one.public, one.claims, try wire.decodeProofBytesBinary(a, one.bytes));
    try cache.verifyOwned(zero.public, zero.claims, try wire.decodeProofBytesBinary(a, zero.bytes));
    try std.testing.expectEqual(@as(u64, 1), cache.stats().misses);
    try std.testing.expectEqual(@as(u64, 2), cache.stats().hits);
    try std.testing.expectEqual(@as(usize, 1), cache.stats().entries);
    try std.testing.expect(cache.stats().peak_retained_bytes <= cache.limits.bytes);
    // Valid changed counts stay in the same key, but cannot reuse old proof/FS.
    var changed = one.public;
    changed.cpu.multiplication_requests = 0;
    try reject(&cache, changed, &one);
    const admitted_hits = cache.stats().hits;
    changed.cpu.multiplication_requests = 3;
    try reject(&cache, changed, &one);
    try std.testing.expectEqual(admitted_hits, cache.stats().hits); // before lookup
    changed = one.public;
    changed.cpu.control_policy = .bytes_v1;
    try reject(&cache, changed, &one);
    changed = one.public;
    changed.policy_identity[0] ^= 1;
    try reject(&cache, changed, &one);
    changed = one.public;
    changed.cpu.statement.opcodes[@intFromEnum(rv.decode.Opcode.SUB)] = true;
    try reject(&cache, changed, &one);
    var words = code;
    words[0] ^= 0x100000;
    changed = one.public;
    changed.cpu.statement.program = .{ .base = pc, .words = &words };
    try reject(&cache, changed, &one);
    changed = one.public;
    changed.cpu.statement.final_pc += 4;
    try reject(&cache, changed, &one);
    // Changed domain is a distinct independently derived expected key; an old
    // proof cannot become valid by a cache hit under the changed geometry.
    const misses = cache.stats().misses;
    changed = one.public;
    changed.cpu.multiplication_log = 6;
    try reject(&cache, changed, &one);
    try std.testing.expectEqual(misses + 1, cache.stats().misses);
    changed = one.public;
    changed.cpu.division_roster = .present;
    try reject(&cache, changed, &one);
    try std.testing.expectEqual(misses + 2, cache.stats().misses);
    try std.testing.expect(cache.stats().entries <= 2);
    try std.testing.expect(cache.stats().retained_bytes <= cache.limits.bytes);
    // Forced byte budget permits no retained key, yet valid cold verification
    // is unchanged and destroys all per-geometry fixed arrays before verifying.
    var uncached = try C.Cache.init(a, &authority, &policy, .{ .entries = 0, .bytes = @sizeOf(C.Cache) });
    defer uncached.deinit();
    try uncached.verifyOwned(one.public, one.claims, try wire.decodeProofBytesBinary(a, one.bytes));
    try std.testing.expectEqual(@as(usize, 0), uncached.stats().entries);
}
fn snapshot(a2: std.mem.Allocator, setup: *const A.Prepared, public: A.Public, authority: *const A.Full.ProgramAuthority) !void {
    var key = try K.ReceiverKey.fromPrepared(a2, setup, public, authority);
    defer key.deinit();
    try key.validate(public);
}
test "narrow key snapshot OOM cleanup and expected authority lifetime are explicit" {
    var authority = try A.Full.ProgramAuthority.initWithControl(a, program, .keccak_service_v1, .limbs24_v2);
    defer authority.deinit();
    var foreign = try A.Full.ProgramAuthority.initWithControl(a, program, .keccak_service_v1, .limbs24_v2);
    defer foreign.deinit();
    var policy = try A.R.policy.Policy.init(a, &.{.{ .first = pc, .last = pc + 7, .flags = 5 }});
    defer policy.deinit();
    var produced = try produce(&authority, &policy, 1);
    defer produced.deinit();
    var setup = try A.Prepared.initWithAuthority(a, produced.public, &policy, &authority);
    defer setup.deinit();
    try std.testing.expectError(error.InvalidReceiverKeyAuthority, K.ReceiverKey.fromPrepared(a, &setup, produced.public, &foreign));
    try std.testing.checkAllAllocationFailures(a, snapshot, .{ &setup, produced.public, &authority });
}
