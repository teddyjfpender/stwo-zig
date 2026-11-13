const std = @import("std");
const cpu = @import("stwo_riscv_cpu_integration");
const front = @import("stwo_riscv_frontend");

test "execution providers: native image and memory authority remain caller-owned" {
    const N = cpu.rv64_execution;
    try std.testing.expect(N.word16.sources.Prepared == N.word16.prepared.Prepared);
    try std.testing.expect(@FieldType(N.word16.sources.Source, "materials") == *const N.word16.setup.Materials);
    try std.testing.expect(@FieldType(N.word16.components.Components, "materials") == *const N.word16.setup.Materials);
    try std.testing.expect(N.global.protocol.Setup == N.word16.setup.Setup);
    try std.testing.expect(N.global.protocol.Admission == N.word16.proof.Admission);
    try N.source.identity.pin("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    const Owner = struct {
        memory: *front.rv64.memory.Memory,
        policy: front.rv64_air.memory.policy.Policy,
        pub fn initialWord(self: *const @This(), address: u64) !u64 {
            return self.memory.load(address, 8);
        }
    };
    var memory = front.rv64.memory.Memory.init(std.testing.allocator, .{});
    defer memory.deinit();
    try memory.map(.{ .start = 0x1000, .size = 8, .permissions = .{ .read = true, .write = true } });
    const bytes = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    try memory.initialize(0x1000, &bytes);
    var owner = Owner{ .memory = &memory, .policy = try front.rv64_air.memory.policy.Policy.fromMemory(std.testing.allocator, &memory) };
    defer owner.policy.deinit();
    const image = N.memory.statement.fromOwner(&owner);
    try std.testing.expectEqual(@as(u64, 0x0807060504030201), try image.initialWord(0x1000));
    try std.testing.expectEqual(@as(u2, 3), try image.wordRights(0x1000));
    try std.testing.expectError(error.UnalignedMemoryWord, image.wordRights(0x1001));
    const geometry = N.word16.setup.Geometry{ .cpu_log = 5, .cpu_fused_tail = true, .cpu_u8_pairs = true };
    try N.services.scope.geometry(geometry);
}

test "execution providers: framing rejection order remains canonical" {
    const framing = front.prover_mod.guest_precompile.proof_artifact;
    try std.testing.expectError(error.UnsupportedArtifactVersion, framing.Header.decodeForVersion("", 0, .{}));
    try std.testing.expectError(error.EndOfStream, framing.Header.decodeForVersion("", 1, .{}));
    const raw: [80]u8 = @splat(0);
    try std.testing.expectError(error.InvalidArtifactMagic, framing.Header.decodeForVersion(&raw, 1, .{}));
    try std.testing.expectError(error.InvalidPcsConfig, framing.validatePcsConfig(.{ .pow_bits = 0, .fri_config = .{ .log_last_layer_degree_bound = 0, .log_blowup_factor = 0, .n_queries = 0, .fold_step = 1 } }, .{}));
}
