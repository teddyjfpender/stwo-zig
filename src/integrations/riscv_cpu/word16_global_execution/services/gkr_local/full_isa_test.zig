//! Physical complete-ISA gate on the current services coordinator, without
//! inventing a second machine or accepting an unbound numerical child.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const core = @import("stwo_core");
const rv = front.rv64;
const A = front.rv64_air;
const Words = @import("../../../tests/rv64_all_ordinary_opcodes.zig").WORDS;
const Program = @import("../../../word16_execution/program.zig").Program;
const Native = @import("../../../word16_execution/prepared.zig").Prepared;
const Image = @import("../../../word16_execution/memory/statement.zig").Image;
const R = @import("../roster.zig");
const P = @import("../protocol.zig");
const Collector = @import("../collector.zig");
const C = @import("coordinator.zig");
const W = @import("worker_protocol.zig");
const Fixed = @import("fixed_authority.zig").Fixed;
const FixedSet = @import("fixed_authority_set.zig").Set;
const BASE: u64 = 4096;
const ADDRESS: u64 = 0x200004000;
const marker: u8 = 0;
fn initial(_: *const anyopaque, address: u64) !u64 {
    if (address != ADDRESS) return error.UnexpectedFullIsaAddress;
    return 0;
}
fn rights(_: *const anyopaque, address: u64) !u2 {
    return if (address >= ADDRESS and address < ADDRESS + 8) 3 else 0;
}
fn image() Image {
    return .{ .context = &marker, .initial_word = initial, .rights_at = rights };
}
fn verify(a: std.mem.Allocator, bundle: *const C.Bundle, setup: *const R.CpuSetup, expected: P.Expected, config: W.PcsConfig, authority: ?*const FixedSet) !@import("execution.zig").Verified {
    if (authority) |fixed| return bundle.verifyWithAuthority(a, &.{setup}, &.{}, expected, config, fixed);
    return bundle.verify(a, &.{setup}, &.{}, expected, config);
}
fn run(config: W.PcsConfig, candidate: bool) !void {
    const a = std.testing.allocator;
    var memory = rv.memory.Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = BASE, .size = Words.len * 4, .permissions = .{ .read = true, .execute = true } });
    for (Words, 0..) |word, index| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, word, .little);
        try memory.initialize(BASE + 4 * index, &bytes);
    }
    try memory.map(.{ .start = ADDRESS, .size = 8, .permissions = .{ .read = true, .write = true } });
    var cpu = rv.machine.Cpu.init(BASE, 0);
    cpu.regs[1] = ADDRESS;
    cpu.regs[2] = 0x8000000000000001;
    cpu.regs[4] = BASE + 4 * Words.len;
    const initial_registers = cpu.regs;
    var clocks: [32]u32 = @splat(0);
    var histogram: [65]u32 = @splat(0);
    var tape = try rv.compact_tape.Tape.init(a, Words.len, BASE, 0, .ethereum_services_v2);
    defer tape.deinit();
    for (Words, 0..) |_, index| {
        const retirement = try cpu.step(&memory);
        histogram[@intFromEnum(retirement.opcode)] += 1;
        try tape.append(retirement);
        const tick: u32 = @intCast(index * 4);
        if (retirement.rs1 != 0) clocks[retirement.rs1] = tick + 1;
        if (retirement.rs2 != 0) clocks[retirement.rs2] = tick + 2;
        if (retirement.writes_rd) clocks[retirement.rd] = tick + 3;
    }
    for (histogram[0..63]) |count| try std.testing.expectEqual(@as(u32, 1), count);
    const boundary = A.word16_execution.types.Boundary{ .steps = Words.len, .initial_pc = BASE, .final_pc = cpu.pc, .initial_registers = initial_registers, .final_registers = cpu.regs, .register_clocks = clocks };
    var program = try Program.init(a, .{ .base = BASE, .words = &Words });
    defer program.deinit();
    var native = try Native.init(a, &program, boundary, 1, 6, &tape, .{ .deduplicate_shift = true });
    defer native.deinit();
    var advice = try Collector.collect(a, &.{&native}, &.{&tape}, image());
    defer advice.deinit();
    const geometry = try native.geometry();
    var setup = try R.CpuSetup.initProgram(a, .{ .base = BASE, .words = &Words }, geometry, .{});
    defer setup.deinit();
    const expected = P.Expected{ .admission = .{ .image = image(), .image_identity = @splat(0x63), .initial_pc = BASE, .initial_registers = initial_registers, .max_prefix_steps = Words.len }, .program_identity = program.identity, .total_steps = Words.len, .max_total_steps = Words.len, .final_pc = cpu.pc, .final_registers = cpu.regs };
    var cache = try Fixed.Cache.init(a, 1 << 30);
    defer cache.deinit();
    var authority: ?FixedSet = if (candidate) try FixedSet.init(a, &cache, &.{&setup}, &.{}, config) else null;
    defer if (authority) |*fixed| fixed.deinit();
    var timer = try std.time.Timer.start();
    var bundle = try C.produceWithAuthority(a, &.{&setup}, &.{}, &.{&native}, &advice, expected, config, .{ .gkr_budget = 2 << 30 }, if (authority) |*fixed| fixed else null);
    defer bundle.deinit(a);
    const prove_ns = timer.lap();
    var fresh = try R.CpuSetup.initProgram(a, .{ .base = BASE, .words = &Words }, geometry, .{});
    defer fresh.deinit();
    var fresh_cache = try Fixed.Cache.init(a, 1 << 30);
    defer fresh_cache.deinit();
    var fresh_authority: ?FixedSet = if (candidate) try FixedSet.init(a, &fresh_cache, &.{&fresh}, &.{}, config) else null;
    defer if (fresh_authority) |*fixed| fixed.deinit();
    const fresh_ptr: ?*const FixedSet = if (fresh_authority) |*fixed| fixed else null;
    const accepted = try verify(a, &bundle, &fresh, expected, config, fresh_ptr);
    try std.testing.expect(accepted.completed);
    try std.testing.expectEqual(@as(u64, Words.len), accepted.total_steps);
    var wrong = expected;
    wrong.final_registers[3] ^= 1;
    if (verify(a, &bundle, &fresh, wrong, config, fresh_ptr)) |_| return error.AcceptedFullIsaWrongEndpoint else |_| {}
    const saved = bundle.cpus[0].bytes[bundle.cpus[0].bytes.len / 2];
    bundle.cpus[0].bytes[bundle.cpus[0].bytes.len / 2] ^= 1;
    if (verify(a, &bundle, &fresh, expected, config, fresh_ptr)) |_| return error.AcceptedFullIsaCorruptedProof else |_| {}
    bundle.cpus[0].bytes[bundle.cpus[0].bytes.len / 2] = saved;
    std.debug.print("OM_FULL_ISA candidate={} opcodes=63 steps={d} prove_ns={d} fresh_and_tamper_ns={d} physical_bytes={d}\n", .{ candidate, Words.len, prove_ns, timer.read(), bundle.cpus[0].bytes.len });
}
test "OM-GKR services all63 ordinary opcodes physically prove and fresh receiver rejects tampering" {
    try run(.{ .pow_bits = 0, .fri_config = try core.fri.ForField(W.O).FriConfig.init(0, 1, 12) }, false);
    try run(@import("../../../word16_execution/om31_security_candidate.zig").config(), true);
}
