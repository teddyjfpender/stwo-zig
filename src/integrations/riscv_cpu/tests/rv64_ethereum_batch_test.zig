const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64;
const R = frontend.rv64_air.memory;
const Full = @import("../rv64_full.zig");
const B = @import("../rv64_ethereum_batch.zig");
const F = @import("rv64_ethereum_fixture.zig");
const a = std.testing.allocator;

test "Ethereum batch derives local clocks counts immutable support and current openings without replay" {
    const fixture = try F.Fixture.create(a, .ethereum_services_v2);
    defer fixture.deinit();
    var authority = try Full.ProgramAuthority.init(a, fixture.public.statement.program, .ethereum_services_v2);
    defer authority.deinit();
    const offset: u64 = 1 << 40;
    var tape = try rv.compact_tape.Tape.init(a, F.program.len, F.pc, offset, .ethereum_services_v2);
    defer tape.deinit();
    var capture = try rv.boundary_capture.Capture.init(a, offset, F.program.len, 64);
    defer capture.deinit();
    var batch = try B.Batch.init(&authority, &tape, &capture, fixture.public.statement.initial_registers, .{ 1, 1, 1 });
    var k: usize = 0;
    var s: usize = 0;
    for (fixture.records) |record| {
        var global = record;
        global.clock += offset;
        if (record.opcode == .ECALL) {
            var invalid = global;
            invalid.rhs = rv.Word.fromInt(std.math.maxInt(u64));
            const clocks_before = batch.register_clocks;
            try std.testing.expectError(error.InvalidEthereumBatchService, batch.observe(invalid));
            try std.testing.expectEqualSlices(u32, &clocks_before, &batch.register_clocks);
        }
        try batch.observe(global);
        if (record.opcode != .ECALL) {
            try tape.append(global);
            try capture.append(global, &fixture.memory);
        } else {
            const event: rv.ethereum_services.Event = if (record.rhs.toInt() == rv.execution_profile.KECCAK_TAG) blk: {
                var call = fixture.kcalls[k];
                k += 1;
                call.clock += offset;
                try tape.appendService(call);
                break :blk .{ .keccak = call };
            } else blk: {
                var call = fixture.scalls[s];
                s += 1;
                call.clock += offset;
                try tape.appendSecp(call);
                break :blk .{ .secp = call };
            };
            try capture.appendEvent(event, &fixture.memory);
        }
    }
    var final_cpu = rv.machine.Cpu.init(fixture.public.statement.final_pc, 0);
    final_cpu.regs = fixture.public.statement.final_registers;
    final_cpu.retired = offset + fixture.records.len;
    var policy = try R.policy.Policy.init(a, &.{ .{ .first = F.pc, .last = F.pc + F.program.len * 4 - 1, .flags = 5 }, .{ .first = F.pointer, .last = F.pointer + 511, .flags = 3 } });
    defer policy.deinit();
    try std.testing.checkAllAllocationFailures(a, finishAndRelease, .{ &batch, &final_cpu, &fixture.memory, &policy });
    var finished = try batch.finish(a, &final_cpu, &fixture.memory, &policy, .chunk512);
    defer finished.deinit();
    batch.state_policy = .cyclic_canonical_v3;
    var canonical = try batch.finish(a, &final_cpu, &fixture.memory, &policy, .chunk512);
    defer canonical.deinit();
    try std.testing.expectEqual(frontend.rv64_air.state_policy.Policy.cyclic_canonical_v3, canonical.public.state_policy);
    try std.testing.expectEqualSlices(bool, &finished.public.statement.opcodes, &canonical.public.statement.opcodes);
    batch.state_policy = .cyclic_v2;
    try std.testing.expectEqual(@as(usize, 0), finished.public.statement.cells.len);
    try std.testing.expectEqualSlices(bool, &authority.opcodes, &finished.public.statement.opcodes);
    try std.testing.expectEqualSlices(u32, &fixture.public.statement.register_clocks, &finished.public.statement.register_clocks);
    try std.testing.expectEqualSlices(@import("../rv64_full_statement.zig").Cell, fixture.public.statement.cells, finished.cells);
    try std.testing.expectEqualSlices(u32, fixture.public.statement.memory_clocks, finished.memory_clocks);
    try std.testing.expectEqual(@as(u32, 1), finished.public.division_requests);
    try std.testing.expectEqual(@as(u32, 1), finished.public.multiplication_requests);
    try std.testing.expectEqual(@as(u32, 1), finished.public.keccak_calls);
    try std.testing.expectEqual(@as(u32, 1), finished.public.secp.add.calls);
    try std.testing.expectEqual(@as(u32, 1), finished.public.secp.double.calls);
    var openings = finished.takeOpenings().?;
    defer openings.deinit();
    try std.testing.expect(finished.openings == null);
    final_cpu.pc += 4;
    try std.testing.expectError(error.InvalidEthereumBatchBoundary, batch.finish(a, &final_cpu, &fixture.memory, &policy, .chunk512));
    var wrong_seed = tape;
    wrong_seed.execution_profile = .ethereum_services_v1;
    try std.testing.expectError(error.InvalidEthereumBatchSeed, B.Batch.init(&authority, &wrong_seed, &capture, fixture.public.statement.initial_registers, .{ 1, 1, 1 }));
}
fn finishAndRelease(allocator: std.mem.Allocator, batch: *const B.Batch, cpu: *const rv.machine.Cpu, memory: *const rv.memory.Memory, policy: *const R.policy.Policy) !void {
    var result = try batch.finish(allocator, cpu, memory, policy, .chunk512);
    result.deinit();
}

test "Ethereum batch omits empty RAM and crypto rosters without synthetic openings" {
    const pc: u64 = 4096;
    const program = [_]u32{0x01100093};
    var authority = try Full.ProgramAuthority.init(a, .{ .base = pc, .words = &program }, .ethereum_services_v2);
    defer authority.deinit();
    var memory = rv.memory.Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = pc, .size = 8, .permissions = .{ .read = true, .execute = true } });
    var raw: [4]u8 = undefined;
    std.mem.writeInt(u32, &raw, program[0], .little);
    try memory.initialize(pc, &raw);
    var tape = try rv.compact_tape.Tape.init(a, 1, pc, 0, .ethereum_services_v2);
    defer tape.deinit();
    var capture = try rv.boundary_capture.Capture.init(a, 0, 1, 1);
    defer capture.deinit();
    var cpu = rv.machine.Cpu.init(pc, 0);
    var batch = try B.Batch.init(&authority, &tape, &capture, cpu.regs, .{ 7, 11, 13 });
    const record = try cpu.step(&memory);
    var bad = record;
    bad.clock += 1;
    try std.testing.expectError(error.InvalidEthereumBatchClock, batch.observe(bad));
    try std.testing.expectEqual(@as(u32, 0), batch.steps);
    try batch.observe(record);
    try tape.append(record);
    try capture.append(record, &memory);
    var policy = try R.policy.Policy.init(a, &.{.{ .first = pc, .last = pc + 7, .flags = 5 }});
    defer policy.deinit();
    var result = try batch.finish(a, &cpu, &memory, &policy, .chunk512);
    defer result.deinit();
    try std.testing.expect(result.openings == null);
    try std.testing.expectEqual(@as(usize, 0), result.captured.len);
    try std.testing.expectEqual(@as(u32, 3), result.public.statement.register_clocks[1]);
    try std.testing.expectEqual(@import("../rv64_keccak_cpu.zig").Roster.none, result.public.roster);
    try std.testing.expectEqual(@import("../rv64_keccak_cpu.zig").ArithmeticRoster.none, result.public.division_roster);
    try std.testing.expectEqual(@import("../rv64_keccak_cpu.zig").ArithmeticRoster.none, result.public.multiplication_roster);
    try std.testing.expectEqual(@import("../rv64_ethereum_secp_context.zig").Roster.none, result.public.secp.add.roster);
    tape.initial_clock += 1;
    try std.testing.expectError(error.InvalidEthereumBatchSeed, batch.finish(a, &cpu, &memory, &policy, .chunk512));
    try std.testing.expectError(error.InvalidEthereumBatchSeed, batch.observe(record));
}
