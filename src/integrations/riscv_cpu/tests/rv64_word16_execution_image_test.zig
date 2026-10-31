const std = @import("std");
const front = @import("stwo_riscv_frontend");
const Image = @import("../word16_execution/expected_image.zig");
const Request = @import("../rv64_ethereum_request.zig");
const a = std.testing.allocator;
const symbols = front.rv64.ethereum_contract.Symbols{ .input_start = 0x800000, .input_end = 0xc00000, .halt_flag = 0xc00000, .output_len = 0xc00004, .output_data = 0xc00008, .output_end = 0x1000000, .stack_bottom = 0x1000000, .stack_top = 0x2000000, .heap_start = 0x2100000, .heap_end = 0x2200000 };
fn elfBytes() [128]u8 {
    var bytes: [128]u8 = @splat(0);
    @memcpy(bytes[0..7], "\x7fELF\x02\x01\x01");
    std.mem.writeInt(u16, bytes[16..18], 2, .little);
    std.mem.writeInt(u16, bytes[18..20], 243, .little);
    std.mem.writeInt(u32, bytes[20..24], 1, .little);
    std.mem.writeInt(u64, bytes[24..32], 4096, .little);
    std.mem.writeInt(u64, bytes[32..40], 64, .little);
    std.mem.writeInt(u16, bytes[52..54], 64, .little);
    std.mem.writeInt(u16, bytes[54..56], 56, .little);
    std.mem.writeInt(u16, bytes[56..58], 1, .little);
    std.mem.writeInt(u32, bytes[64..68], 1, .little);
    std.mem.writeInt(u32, bytes[68..72], 5, .little);
    std.mem.writeInt(u64, bytes[72..80], 120, .little);
    std.mem.writeInt(u64, bytes[80..88], 4096, .little);
    std.mem.writeInt(u64, bytes[96..104], 8, .little);
    std.mem.writeInt(u64, bytes[104..112], 8, .little);
    std.mem.writeInt(u64, bytes[112..120], 4, .little);
    std.mem.writeInt(u32, bytes[120..124], 0x01100093, .little);
    std.mem.writeInt(u32, bytes[124..128], 0x0000006f, .little);
    return bytes;
}
const Fixture = struct {
    temp: std.testing.TmpDir,
    elf: []u8,
    input: []u8,
    elf_sha: [64]u8,
    input_sha: [64]u8,
    output: [86]u8 = @splat('0'),
    fn init() !Fixture {
        var temp = std.testing.tmpDir(.{});
        errdefer temp.cleanup();
        const bytes = elfBytes();
        try temp.dir.writeFile(.{ .sub_path = "guest.elf", .data = &bytes });
        try temp.dir.writeFile(.{ .sub_path = "input.bin", .data = &.{0xaa} });
        const elf = try temp.dir.realpathAlloc(a, "guest.elf");
        errdefer a.free(elf);
        const input = try temp.dir.realpathAlloc(a, "input.bin");
        return .{ .temp = temp, .elf = elf, .input = input, .elf_sha = std.fmt.bytesToHex(Request.sha(&bytes), .lower), .input_sha = std.fmt.bytesToHex(Request.sha(&.{0xaa}), .lower) };
    }
    fn config(self: *const Fixture) Request.Config {
        return .{ .elf = self.elf, .input = self.input, .elf_sha256 = &self.elf_sha, .input_sha256 = &self.input_sha, .expected_output = &self.output, .symbols = symbols, .output_directory = "unused", .terminal_pc = 4100, .batch_steps = 32 };
    }
    fn deinit(self: *Fixture) void {
        a.free(self.input);
        a.free(self.elf);
        self.temp.cleanup();
    }
};
test "pristine expected image retains pinned ELF input and zero memory without Poseidon cache" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var owner = try Image.Owner.init(a, fixture.config());
    defer owner.deinit();
    try std.testing.expect(!@hasField(Image.Owner, "initial_cache"));
    try std.testing.expectEqual(@as(u64, 4096), owner.initial_pc);
    try std.testing.expectEqual(symbols.stack_top, owner.initial_registers[2]);
    try std.testing.expectEqual(@as(u64, 0), owner.initial_registers[1]);
    const count = owner.loaded.memory.pageCount();
    const cache = owner.loaded.memory.backing.cache;
    try std.testing.expectEqual(@as(u64, 0x0000006f01100093), try owner.initialWord(4096));
    try std.testing.expectEqual(@as(u64, 0xaa00000001), try owner.initialWord(symbols.input_start));
    try std.testing.expectEqual(@as(u64, 0), try owner.initialWord(symbols.heap_start));
    try std.testing.expectEqual(@as(u64, 0), try owner.initialWord(symbols.stack_top - 8));
    try std.testing.expectEqual(count, owner.loaded.memory.pageCount());
    try std.testing.expect(std.meta.eql(cache, owner.loaded.memory.backing.cache));
    try std.testing.expectError(error.MisalignedInitialWord, owner.initialWord(4097));
    try std.testing.expectError(error.RamPolicyAccessDenied, owner.policy.find(.word8, symbols.input_start, 2));
}
fn allocationCase(allocator: std.mem.Allocator, config: Request.Config) !void {
    var owner = try Image.Owner.init(allocator, config);
    defer owner.deinit();
}
test "pristine image pin terminal and all allocation failures reject without native execution" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var bad = fixture.config();
    bad.input_sha256 = &fixture.elf_sha;
    try std.testing.expectError(error.EthereumInputIdentityMismatch, Image.Owner.init(a, bad));
    bad = fixture.config();
    bad.terminal_pc = 4096;
    try std.testing.expectError(error.InvalidEthereumTerminalPc, Image.Owner.init(a, bad));
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{fixture.config()});
}

test "new execution packet path reads tape without legacy graph and rejects corruption" {
    const Packet = @import("../word16_execution/packet.zig");
    const Wire = @import("../rv64_prepared_work_packet.zig");
    const Batch = @import("../rv64_ethereum_batch.zig");
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var owner = try Image.Owner.init(a, fixture.config());
    defer owner.deinit();
    var tape = try front.rv64.compact_tape.Tape.init(a, 32, owner.initial_pc, 0, .ethereum_services_v2);
    defer tape.deinit();
    var capture = try front.rv64.boundary_capture.Capture.init(a, 0, 32, 1);
    defer capture.deinit();
    var cpu = front.rv64.machine.Cpu.init(owner.initial_pc, symbols.stack_top);
    var batch = try Batch.Batch.init(&owner.authority, &tape, &capture, cpu.regs, .{ 1, 1, 1 });
    batch.state_policy = fixture.config().state_policy;
    const row = try cpu.step(&owner.loaded.memory);
    try tape.append(row);
    try capture.append(row, &owner.loaded.memory);
    try batch.observe(row);
    var finished = try batch.finish(a, &cpu, &owner.loaded.memory, &owner.policy, .chunk512);
    defer finished.deinit();
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    var file = try temp.dir.createFile("job.work", .{ .read = true });
    defer file.close();
    _ = try Wire.write(file, .{ .metadata = .{ .identity = try Wire.identityFor(fixture.config(), &owner.authority, &owner.policy), .index = 0, .first_step = 0, .before = @splat(0), .after = @splat(0) }, .finished = &finished, .native = null, .tape = &tape });
    var packet = try Packet.read(a, file, &owner, fixture.config());
    defer packet.deinit();
    try std.testing.expect(!@hasField(Packet.Packet, "native"));
    const Coordinator = @import("../word16_execution/coordinator.zig");
    try Coordinator.requireGenesis(&owner, &packet);
    const boundary = Coordinator.boundary(&packet);
    try std.testing.expectEqual(@as(u32, 1), boundary.steps);
    packet.metadata.index = 1;
    try std.testing.expectError(error.UntrustedExecutionGenesis, Coordinator.requireGenesis(&owner, &packet));
    packet.metadata.index = 0;
    packet.public.statement.initial_registers[1] = 1;
    try std.testing.expectError(error.UntrustedExecutionGenesis, Coordinator.requireGenesis(&owner, &packet));
    packet.public.statement.initial_registers[1] = 0;
    try std.testing.expectEqual(@as(u32, 1), packet.tape.len);
    try std.testing.expectEqual(@as(u64, 17), packet.public.statement.final_registers[1]);
    try std.testing.expectEqual(@as(u64, 1), packet.opcode_counts[@intFromEnum(front.rv64.decode.Opcode.ADDI)]);
    const end = try file.getEndPos();
    try file.seekTo(end - 1);
    try file.writeAll(&.{0xff});
    try std.testing.expectError(error.WorkPacketContentMismatch, Packet.read(a, file, &owner, fixture.config()));
}

test "full execution mixed native fixture directly seals tape with pristine image intact" {
    const MixedFixture = @import("rv64_word16_execution_fixture.zig").Fixture;
    const Program = @import("../word16_execution/program.zig").Program;
    const Source = @import("../word16_execution/cpu_source.zig").Source;
    const Coverage = @import("../word16_execution/coverage.zig");
    var fixture = try MixedFixture.init(a);
    defer fixture.deinit();
    var program = try Program.initWithAuthority(a, &fixture.image.authority);
    defer program.deinit();
    var source = try Source.init(a, &program, fixture.boundary, 1, 5, &fixture.tape);
    defer source.deinit();
    const counts = try Coverage.Counts.fromTape(&program, &fixture.tape);
    try std.testing.expectEqual(@as(u32, 1), counts.jalr);
    try std.testing.expectEqual(@as(u32, 1), counts.multiplication);
    try std.testing.expectEqual(@as(u32, 2), counts.division);
    try std.testing.expectEqual(@as(u32, 4), counts.memory);
    try std.testing.expectEqual(@as(u64, 4096), fixture.boundary.final_registers[8]);
    try std.testing.expectEqual(@as(u64, 0), try fixture.image.initialWord(symbols.heap_start));
    try std.testing.expectEqual(@as(u64, 0), fixture.boundary.final_registers[14]);
}

test "full execution mixed native program closes seventeen physical chips and verifies fresh" {
    const MixedFixture = @import("rv64_word16_execution_fixture.zig").Fixture;
    const Setup = @import("../word16_execution/setup.zig");
    const Execution = @import("../word16_execution/execution.zig");
    const Memory = @import("../word16_execution/memory/statement.zig");
    var fixture = try MixedFixture.init(a);
    defer fixture.deinit();
    const geometry = Setup.Geometry{ .cpu_log = 5 };
    var setup = try Setup.Setup.initWithAuthority(a, &fixture.image.authority, geometry);
    defer setup.deinit();
    const admission = Execution.Admission{ .image = Memory.fromOwner(&fixture.image), .image_identity = fixture.image.identity, .initial_pc = fixture.image.initial_pc, .initial_registers = fixture.image.initial_registers };
    {
        const Sources = @import("../word16_execution/sources.zig");
        const Protocol = @import("../word16_execution/protocol.zig");
        const Components = @import("../word16_execution/components.zig").Components;
        var source = try Sources.Source.init(a, &setup.materials, admission.image, fixture.boundary, 1, &fixture.tape);
        defer source.deinit();
        var channel = Setup.T.P.Channel{};
        const draw = Protocol.draw(&channel);
        const claims = try source.generate(draw);
        var components = try Components.init(&setup.materials, source.request(), draw, claims);
        if (try @import("../word16_execution/native_diagnostic.zig").inspect(a, &components, &source)) |failure| {
            std.debug.print("NATIVE_FAIL role={s} row={d} constraint={d} value={any}\n", .{ @tagName(failure.role), failure.row, failure.constraint, failure.value });
            return error.NativeExecutionConstraintFailure;
        }
    }
    var encoded = try Execution.prove(a, &setup, admission, fixture.boundary, &fixture.tape, null);
    defer encoded.deinit(a);
    var receiver = try Setup.Setup.initWithAuthority(a, &fixture.image.authority, geometry);
    defer receiver.deinit();
    try Execution.verify(a, &receiver, admission, encoded);
    const FalseProver = @import("rv64_word16_execution_false_prover.zig");
    const fields = front.rv64_air.word16_execution.layout.main;
    try FalseProver.reject(a, &setup, admission, fixture.boundary, &fixture.tape, fields.a, 2);
    try FalseProver.reject(a, &setup, admission, fixture.boundary, &fixture.tape, fields.c + 3, 3);
    try FalseProver.reject(a, &setup, admission, fixture.boundary, &fixture.tape, fields.b, 10);
    try FalseProver.reject(a, &setup, admission, fixture.boundary, &fixture.tape, fields.immediate, 18);
    try FalseProver.reject(a, &setup, admission, fixture.boundary, &fixture.tape, fields.next_pc, 18);
    var balanced = encoded;
    balanced.claims.cpu = balanced.claims.cpu.add(front.rv64_air.evaluation.Q.one());
    balanced.claims.rom = balanced.claims.rom.sub(front.rv64_air.evaluation.Q.one());
    if (Execution.verify(a, &receiver, admission, balanced)) |_| return error.BalancedExecutionClaimsAccepted else |_| {}

    var bad = encoded;
    bad.request.cpu.final_pc +%= 4;
    if (Execution.verify(a, &receiver, admission, bad)) |_| return error.ForgedExecutionAccepted else |_| {}
}
