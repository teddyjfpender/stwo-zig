const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const K = @import("air/block_v7_memory_composition_v1.zig");
const Families = @import("block_v7_memory_component_recursive_v1.zig");
const Fixture = @import("../prover/block_v7_execution_caller_test_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const Consumer = struct {
    pub const Result = void;
    pub fn consume(f: Fixture.Fixture) !void {
        const b = f.input.memory.separate;
        for (b.ram, 0..) |*ram, index| try check(.ram, f, .{ .policy = f.policy, .epoch = f.input.epoch, .roster = f.input.entries, .index = @intCast(index), .row_log = ram.geometry.row_log, .roots = ram.proof.roots, .sums = ram.proof.sums, .geometry = ram.geometry }, &ram.proof);
        inline for (.{ K.Family.interval, K.Family.range16, K.Family.terminal }) |kind| {
            const item = &@field(b, @tagName(kind));
            try check(kind, f, .{ .policy = f.policy, .epoch = f.input.epoch, .roster = f.input.entries, .index = 0, .row_log = if (kind == .interval) b.interval_log else if (kind == .range16) 16 else 4, .roots = item.roots, .sums = item.sums }, item);
        }
    }
};
fn check(comptime kind: K.Family, f: Fixture.Fixture, input: Families.For(kind).Profile.Input, proof: *const @import("../prover/block_v7_memory_bundle_v1.zig").Item(K.planes(kind))) !void {
    const F = Families.For(kind);
    const a = f.allocator;
    const profile = try F.Profile.Owned.derive(a, input, .{});
    defer profile.deinit();
    var capture = try F.Profile.verifyAndCapture(Cpu, a, profile, proof);
    defer capture.deinit();
    var live = try F.Preparation.prepare(a, profile, &capture, 2, .{});
    defer live.deinit();
    var cold = try F.FixedRoster.Owned.derive(a, input, 2, .{});
    defer cold.deinit();
    try cold.validateLive(&live);
    // The original receiver independently compiles the same fixed root.
    try F.Profile.requireFixedRoot(Cpu, a, profile);
    var values = try F.Public.reconstruct(a, profile);
    defer values.deinit();
    try F.Public.requireSameFrame(live.values, values);
    const base = try Parent.ForBackend(Cpu).deriveKeyFromFixed(a, cold.fixed, cold.context, .diagnostic_q8_pow0);
    const expected = [_]F.Protocol.Bus.Expected{.{ .profile = profile.seal, .epoch = input.epoch.digest, .roots = input.roots }};
    const key = try F.Protocol.Key.fromGeometry(base, cold.wires, &expected);
    const admission = try F.Protocol.Admission.init(key, try key.identity(), cold.wires, .{ .children = &.{live.values} }, &expected);
    const Plan = @import("blake3_native_parent_producer.zig").PlanForProtocol(Cpu, F.Protocol);
    const plan = try Plan.init(a, &live.recursive.rows, admission);
    defer plan.deinit();
    var parent = try plan.prove(a, &live.recursive.rows);
    defer parent.deinit();
    const bytes = try Parent.codec.encode(a, &parent, &admission);
    defer a.free(bytes);
    var decoded = try Parent.codec.decode(a, bytes, &admission);
    var verified = try Parent.verify(&decoded, &admission);
    defer verified.deinit();
    try verified.validate(&admission, try key.identity());
    const old = values.public[0];
    values.public[0] = old.add(core.fields.qm31.QM31.one());
    try std.testing.expectError(error.UntrustedV7MemoryComponentFrame, F.Public.requireSameFrame(values, live.values));
    values.public[0] = old;
    var detached = try F.Receiver.verify(a, bytes, profile, key, cold.wires);
    defer detached.deinit();
    try std.testing.expectEqualDeep(input.sums, detached.sums);
    var altered = input;
    altered.sums[0] = altered.sums[0].add(core.fields.qm31.QM31.one());
    const wrong = try F.Profile.Owned.derive(a, altered, .{});
    defer wrong.deinit();
    if (F.Receiver.verify(a, bytes, wrong, key, cold.wires)) |value| {
        var bad = value;
        bad.deinit();
        return error.AcceptedChangedPhysicalMemoryClaim;
    } else |_| {}
    std.debug.print("V7_SEPARATE_MEMORY_PARENT family={s} index={d} proof_bytes={d} cold_live_exact=true original_verified=true whole_memory_closed=false\n", .{ @tagName(kind), input.index, bytes.len });
}
test "v7 separate memory original components have exact cold live parent verifiers" {
    try Fixture.runFixture(false, false, Consumer);
}
