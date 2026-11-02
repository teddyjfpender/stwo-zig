const std = @import("std");
const A = @import("aggregate.zig");
const Native = @import("native_fixture.zig");
const Rom = @import("stwo_riscv_frontend").rv64_air.word16_cpu.rom;
const Q = @import("stwo_core").fields.qm31.QM31;
const Receipt = @import("receipt.zig");
const a = std.testing.allocator;

test "two true CPU shards close local state and shared BINARY truth after all real proofs verify" {
    const native = try Native.Fixture.init(a); // VM/Memory have already died.
    var program = try Rom.Setup.init(a, .{ .base = Native.BASE, .words = &Native.WORDS });
    defer program.deinit();
    const expected = try Native.expected(&program);
    var encoded = try A.produce(a, expected, &program, native.shards, .{ &native.records[0], &native.records[1] });
    defer encoded.deinit(a);
    try A.verify(a, expected, &program, &encoded);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try Receipt.write(tmp.dir, &encoded);
    try std.testing.expectEqualDeep(encoded.shards, try Receipt.readBoundaries(tmp.dir));
    try Receipt.readAndVerify(a, tmp.dir, expected, &program);
    var prepared = try A.Prepared.init(a, expected, &program, encoded.shards);
    defer prepared.deinit();
    try std.testing.checkAllAllocationFailures(a, decodeProbe, .{ tmp.dir, expected, &program, &prepared });
    // A hostile geometry must fail BEFORE any key/witness allocation.
    const raw_boundary = try tmp.dir.readFileAlloc(a, "boundaries.bin", 1360);
    defer a.free(raw_boundary);
    std.mem.writeInt(u32, raw_boundary[24..28], 22, .little);
    try tmp.dir.writeFile(.{ .sub_path = "boundaries.bin", .data = raw_boundary });
    var fail = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidDistributedCpuGeometry, Receipt.readAndVerify(fail.allocator(), tmp.dir, expected, &program));
    std.mem.writeInt(u32, raw_boundary[24..28], 5, .little);
    try tmp.dir.writeFile(.{ .sub_path = "boundaries.bin", .data = raw_boundary });
    try std.testing.expect(encoded.cpu[0].bytes.len > 1024 and encoded.cpu[1].bytes.len > 1024 and encoded.binary.bytes.len > 1024);
    // Changing BOTH middle snapshots satisfies adjacency but cannot change the
    // actual physical CPU proofs/manifest statement that were committed.
    const saved_shards = encoded.shards;
    encoded.shards[0].public.final_registers[1] ^= 1;
    encoded.shards[1].public.initial_registers[1] ^= 1;
    try expected.validate(&program, encoded.shards);
    try std.testing.expectError(error.DistributedInventoryMismatch, A.verify(a, expected, &program, &encoded));
    encoded.shards = saved_shards;
    var other = expected;
    other.final_registers[5] ^= 1;
    try std.testing.expectError(error.DistributedExecutionTerminalMismatch, A.verify(a, other, &program, &encoded));
    other = expected;
    other.initial_registers[1] +%= @as(u64, 1) << 48;
    try std.testing.expectError(error.DistributedExecutionGenesisMismatch, A.verify(a, other, &program, &encoded));
    encoded.shards[1].first_step += 1;
    try std.testing.expectError(error.DistributedExecutionCoverageGap, A.verify(a, expected, &program, &encoded));
    encoded.shards = saved_shards;
    // This balanced global FUNCTION forgery still sums to the original target.
    // CPU open-debt status must never bypass local physical proof verification.
    const first = encoded.cpu[0].claims.cpu.function;
    const provider = encoded.binary.claims.function;
    encoded.cpu[0].claims.cpu.function = first.add(Q.one());
    encoded.binary.claims.function = provider.sub(Q.one());
    if (A.verify(a, expected, &program, &encoded)) |_| return error.AcceptedBalancedFunctionForgery else |_| {}
    encoded.cpu[0].claims.cpu.function = first;
    encoded.binary.claims.function = provider;
    // Local REG debts cannot cancel across CPU instances, even if their sum
    // remains zero. Each local boundary provider closes its own REG argument.
    const reg0 = encoded.cpu[0].claims.cpu.register;
    const reg1 = encoded.cpu[1].claims.cpu.register;
    encoded.cpu[0].claims.cpu.register = reg0.add(Q.one());
    encoded.cpu[1].claims.cpu.register = reg1.sub(Q.one());
    try std.testing.expectError(error.UnclosedThinCpuLocalClaims, A.verify(a, expected, &program, &encoded));
    encoded.cpu[0].claims.cpu.register = reg0;
    encoded.cpu[1].claims.cpu.register = reg1;
    try A.verify(a, expected, &program, &encoded);
}

fn decodeProbe(allocator: std.mem.Allocator, dir: std.fs.Dir, expected: A.Expected, program: *const Rom.Setup, prepared: *const A.Prepared) !void {
    var parsed = try Receipt.readPrepared(allocator, dir, expected, program, prepared);
    defer parsed.deinit(allocator);
}
