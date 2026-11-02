//! Zbb route native batch / work-packet authority: the v2-decoded legacy
//! statement plus the ethereum_services_v3_zbb execution ROM. The legacy byte
//! ROM keeps every Zbb word invalid; only `Authority.instructionAt` under a
//! Zbb execution ROM exposes those rows (to native bookkeeping, never to a
//! legacy proof), and every other profile pairing fails closed.
const std = @import("std");
const W = @import("../rv64_prepared_work_packet.zig");
const H = @import("../rv64_work_packet_header.zig");
const IO = @import("../rv64_work_packet_io.zig");
const Admission = @import("../rv64_work_packet_admission.zig");
const A = @import("../rv64_authenticated_execution.zig");
const B = @import("../rv64_ethereum_batch.zig");
const Request = @import("../rv64_ethereum_request.zig");
const rv = A.frontend.rv64;
const R = A.R;
const Profile = rv.execution_profile.Profile;
const a = std.testing.allocator;
const pc: u64 = 0x1000;
const pointer: u64 = 0x8000;
const STEPS: u32 = 4;
fn rev8(rd: u32, rs1: u32) u32 {
    return (0x6b8 << 20) | (rs1 << 15) | (5 << 12) | (rd << 7) | 0x13;
}
fn andn(rd: u32, rs1: u32, rs2: u32) u32 {
    return (0x20 << 25) | (rs2 << 20) | (rs1 << 15) | (7 << 12) | (rd << 7) | 0x33;
}
/// rev8 x3,x2; andn x4,x3,x2; sd x4,0(x1); j -12; then two never-executed
/// words the legacy ROM keeps invalid: an all-zero word and EBREAK (a base
/// opcode no Ethereum profile admits).
const words = [_]u32{ rev8(3, 2), andn(4, 3, 2), 0x0040b023, 0xff5ff06f, 0x00000000, 0x00100073 };
const ZBB = Profile.ethereum_services_v3_zbb;
const V2 = Profile.ethereum_services_v2;

fn authority(rom: Profile) !A.Full.ProgramAuthority {
    return A.Full.ProgramAuthority.initWithRom(a, .{ .base = pc, .words = &words }, V2, rom, .limbs24_v2);
}
fn config() Request.Config {
    return .{ .elf = "", .input = "", .elf_sha256 = "00" ** 32, .input_sha256 = "11" ** 32, .expected_output = "22" ** 43, .symbols = std.mem.zeroes(rv.ethereum_contract.Symbols), .output_directory = "", .terminal_pc = pc + 12, .batch_steps = STEPS, .max_steps = std.math.maxInt(u64), .execution_profile = ZBB, .control_policy = .limbs24_v2, .state_policy = .cyclic_canonical_v3 };
}

const Run = struct {
    memory: rv.memory.Memory,
    tape: rv.compact_tape.Tape,
    finished: B.Finished,
    policy: R.policy.Policy,
    /// Pre-execution RAM cache (the packet's `before` root).
    cache: R.values.Cache,
    /// The rev8 retirement (step 1), for forged-record checks.
    first: rv.machine.Retirement,
    fn init(auth: *const A.Full.ProgramAuthority) !Run {
        var memory = rv.memory.Memory.init(a, .{});
        errdefer memory.deinit();
        try memory.map(.{ .start = pc, .size = 4 * words.len, .permissions = .{ .read = true, .execute = true } });
        try memory.map(.{ .start = pointer, .size = 512, .permissions = .{ .read = true, .write = true } });
        for (words, 0..) |word, i| {
            var raw: [4]u8 = undefined;
            std.mem.writeInt(u32, &raw, word, .little);
            try memory.initialize(pc + 4 * i, &raw);
        }
        var policy = try R.policy.Policy.fromMemory(a, &memory);
        errdefer policy.deinit();
        var cache = try R.values.Cache.fromMemory(a, .chunk512, &memory);
        errdefer cache.deinit();
        var cpu = rv.machine.Cpu.init(pc, 0);
        cpu.regs[1] = pointer;
        cpu.regs[2] = 0x0102_0304_0506_0708;
        var session = try rv.ethereum_services.Session.initWithProfile(a, cpu, &memory, .{ .max_retirements = 64 }, ZBB);
        defer session.deinit();
        var tape = try rv.compact_tape.Tape.init(a, STEPS, pc, 0, ZBB);
        errdefer tape.deinit();
        var capture = try rv.boundary_capture.Capture.init(a, 0, STEPS, 1);
        defer capture.deinit();
        var batch = try B.Batch.init(auth, &tape, &capture, session.keccak.base.cpu.regs, .{ 1, 1, 1 });
        batch.state_policy = .cyclic_canonical_v3;
        var event: rv.ethereum_services.Event = undefined;
        const first = (try session.step(&event)) orelse return error.UnexpectedService;
        try std.testing.expectEqual(rv.decode.Opcode.REV8, first.opcode);
        try tape.append(first);
        try capture.append(first, session.keccak.base.memory);
        try batch.observe(first);
        for (1..STEPS) |_| try B.captureNext(&session, &tape, &capture, &batch);
        const regs = session.keccak.base.cpu.regs;
        try std.testing.expectEqual(@byteSwap(@as(u64, 0x0102_0304_0506_0708)), regs[3]);
        try std.testing.expectEqual(regs[3] & ~regs[2], regs[4]);
        const finished = try batch.finish(a, &session.keccak.base.cpu, &memory, &policy, .chunk512);
        return .{ .memory = memory, .tape = tape, .finished = finished, .policy = policy, .cache = cache, .first = first };
    }
    fn deinit(self: *Run) void {
        self.cache.deinit();
        self.finished.deinit();
        self.tape.deinit();
        self.policy.deinit();
        self.memory.deinit();
    }
};

test "Zbb route authority decodes Zbb rows only under the v3_zbb ROM; legacy rows, invalid words and pairings fail closed" {
    var zbb = try authority(ZBB);
    defer zbb.deinit();
    var plain = try authority(V2);
    defer plain.deinit();
    // The legacy byte ROM is identical (v2 decode, Zbb rows invalid) in both.
    try std.testing.expectEqualSlices(u8, &plain.program.identity, &zbb.program.identity);
    try std.testing.expectError(error.InvalidRv64RomExecution, zbb.program.lookup(pc));
    try std.testing.expectEqual(rv.decode.Opcode.REV8, (try zbb.instructionAt(pc)).instruction.opcode);
    try std.testing.expectEqual(rv.decode.Opcode.ANDN, (try zbb.instructionAt(pc + 4)).instruction.opcode);
    try std.testing.expectEqual(rv.decode.Opcode.SD, (try zbb.instructionAt(pc + 8)).instruction.opcode);
    try std.testing.expectEqual(rv.decode.Opcode.SD, (try plain.instructionAt(pc + 8)).instruction.opcode);
    // Without the Zbb ROM a Zbb row is an invalid ROM row.
    try std.testing.expectError(error.InvalidRv64RomExecution, plain.instructionAt(pc));
    try std.testing.expectError(error.InvalidRv64RomExecution, plain.instructionAt(pc + 4));
    // An invalid word, or a base opcode the legacy ROM rejects (EBREAK), never
    // decodes through the Zbb path; unmapped/misaligned PCs stay rejected.
    for ([_]*const A.Full.ProgramAuthority{ &zbb, &plain }) |auth| {
        try std.testing.expectError(error.InvalidRv64RomExecution, auth.instructionAt(pc + 16));
        try std.testing.expectError(error.InvalidRv64RomExecution, auth.instructionAt(pc + 20));
        try std.testing.expectError(error.InvalidRv64RomExecution, auth.instructionAt(pc + 24));
        try std.testing.expectError(error.InvalidRv64RomExecution, auth.instructionAt(pc + 2));
    }
    // Only the (v2 statement, v3_zbb ROM) pairing is constructible.
    for ([_][2]Profile{ .{ .ethereum_services_v1, ZBB }, .{ .ethereum_services_v3, ZBB }, .{ V2, .ethereum_services_v3 }, .{ ZBB, V2 } }) |pair| {
        try std.testing.expectError(error.UnsupportedRv64RomProfile, A.Full.ProgramAuthority.initWithRom(a, .{ .base = pc, .words = &words }, pair[0], pair[1], .limbs24_v2));
    }
    // A v3_zbb legacy statement itself has no legacy byte-AIR plan.
    try std.testing.expectError(error.UnsupportedRv64ServiceExecutionProfile, A.Full.ProgramAuthority.initWithRom(a, .{ .base = pc, .words = &words }, ZBB, ZBB, .limbs24_v2));
    // The packet program key binds the execution ROM on the Zbb route only.
    var control = try A.Full.ProgramAuthority.initWithControl(a, .{ .base = pc, .words = &words }, V2, .limbs24_v2);
    defer control.deinit();
    try std.testing.expectEqualSlices(u8, &W.programKey(&control), &W.programKey(&plain));
    try std.testing.expect(!std.mem.eql(u8, &W.programKey(&zbb), &W.programKey(&plain)));
    // Tape admission truth table: unchanged without a separate ROM; the Zbb
    // route admits exactly v3_zbb tapes, and a v3_zbb tape nothing else.
    const T = struct { tape: Profile, statement: Profile, rom: Profile, ok: bool };
    for ([_]T{
        .{ .tape = V2, .statement = V2, .rom = V2, .ok = true },
        .{ .tape = .ethereum_services_v3, .statement = V2, .rom = V2, .ok = true },
        .{ .tape = ZBB, .statement = V2, .rom = V2, .ok = false },
        .{ .tape = ZBB, .statement = V2, .rom = ZBB, .ok = true },
        .{ .tape = .ethereum_services_v3, .statement = V2, .rom = ZBB, .ok = false },
        .{ .tape = V2, .statement = V2, .rom = ZBB, .ok = false },
        .{ .tape = ZBB, .statement = ZBB, .rom = ZBB, .ok = true },
        .{ .tape = ZBB, .statement = .ethereum_services_v1, .rom = ZBB, .ok = false },
    }) |row| try std.testing.expectEqual(row.ok, B.tapeAdmits(row.tape, row.statement, row.rom));
}

test "Zbb route native batch: Zbb rows retire under the Zbb ROM; a v2 ROM, a forged opcode and a mismatched tape are rejected" {
    var zbb = try authority(ZBB);
    defer zbb.deinit();
    var run = try Run.init(&zbb);
    defer run.deinit();
    try std.testing.expectEqual(V2, run.finished.public.execution_profile);
    try std.testing.expectEqual(@as(?Profile, ZBB), run.finished.rom_profile);
    try std.testing.expectEqual(STEPS, run.finished.public.statement.steps);
    // A v2-only authority cannot seed a v3_zbb batch, nor a Zbb authority a v3 tape.
    var plain = try authority(V2);
    defer plain.deinit();
    var capture = try rv.boundary_capture.Capture.init(a, 0, STEPS, 1);
    defer capture.deinit();
    var zbb_tape = try rv.compact_tape.Tape.init(a, STEPS, pc, 0, ZBB);
    defer zbb_tape.deinit();
    try std.testing.expectError(error.InvalidEthereumBatchSeed, B.Batch.init(&plain, &zbb_tape, &capture, run.finished.public.statement.initial_registers, .{ 1, 1, 1 }));
    var v3_tape = try rv.compact_tape.Tape.init(a, STEPS, pc, 0, .ethereum_services_v3);
    defer v3_tape.deinit();
    try std.testing.expectError(error.InvalidEthereumBatchSeed, B.Batch.init(&zbb, &v3_tape, &capture, run.finished.public.statement.initial_registers, .{ 1, 1, 1 }));
    // A retirement claiming another Zbb opcode at the rev8 row is rejected.
    var batch = try B.Batch.init(&zbb, &zbb_tape, &capture, run.finished.public.statement.initial_registers, .{ 1, 1, 1 });
    var record = run.first;
    record.opcode = .ANDN;
    try std.testing.expectError(error.InvalidEthereumBatchInstruction, batch.observe(record));
    // ... and so is one claiming the base opcode the raw word does not encode.
    record = run.first;
    record.opcode = .SRLI;
    try std.testing.expectError(error.InvalidEthereumBatchInstruction, batch.observe(record));
    try batch.observe(run.first);
}

test "Zbb route work packet: the Zbb-aware admission walk counts Zbb rows; legacy readers and a v2 ROM fail closed" {
    var zbb = try authority(ZBB);
    defer zbb.deinit();
    var run = try Run.init(&zbb);
    defer run.deinit();
    const identity = try W.identityFor(config(), &zbb, &run.policy);
    const cache = &run.cache;
    var native: ?R.native_frontier.Prepared = if (run.finished.openings) |*value| try R.native_frontier.Prepared.init(a, cache, value) else null;
    defer if (native) |*value| value.deinit();
    const metadata = W.Metadata{ .identity = identity, .index = 0, .first_step = 0, .before = cache.root(), .after = if (native) |value| value.witness.after else cache.root() };
    const view = W.View{ .metadata = metadata, .finished = &run.finished, .native = if (native) |*value| value else null, .tape = &run.tape };
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const file = try temp.dir.createFile("job", .{ .read = true });
    defer file.close();
    _ = try W.write(file, view);
    const expected = W.Expected{ .identity = identity, .authority = &zbb, .policy = &run.policy, .state_policy = .cyclic_canonical_v3 };
    try file.seekTo(0);
    var raw: [H.BYTES]u8 = undefined;
    try IO.exact(file, &raw);
    const header = try H.decode(&raw, try file.getEndPos(), expected, .{});
    const counts = try Admission.check(file, header, run.finished.public, &zbb);
    try std.testing.expectEqual(@as(u64, 1), counts[@intFromEnum(rv.decode.Opcode.REV8)]);
    try std.testing.expectEqual(@as(u64, 1), counts[@intFromEnum(rv.decode.Opcode.ANDN)]);
    try std.testing.expectEqual(@as(u64, 1), counts[@intFromEnum(rv.decode.Opcode.SD)]);
    // The same walk under a v2 ROM rejects the v3_zbb tape.
    var plain = try authority(V2);
    defer plain.deinit();
    try std.testing.expectError(error.InvalidWorkPacketBoundary, Admission.check(file, header, run.finished.public, &plain));
    // The legacy packet reader (legacy worker) never accepts a Zbb packet:
    // it does not re-derive the execution ROM, so the tape is not admitted.
    try std.testing.expectError(error.InvalidWorkPacketBoundary, W.read(a, file, expected, .{}));
    // And a v2-ROM receiver identity rejects it before any walk.
    const plain_expected = W.Expected{ .identity = try W.identityFor(config(), &plain, &run.policy), .authority = &plain, .policy = &run.policy, .state_policy = .cyclic_canonical_v3 };
    try std.testing.expectError(error.WorkPacketIdentityMismatch, W.read(a, file, plain_expected, .{}));
}
