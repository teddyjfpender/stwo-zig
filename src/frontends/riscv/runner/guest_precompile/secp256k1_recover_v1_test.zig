//! Transaction, cryptographic, and fail-atomic tests for signer recovery.

const std = @import("std");
const access_clock = @import("../../access_clock.zig");
const custom0 = @import("../../isa/custom0.zig");
const abi = @import("../../isa/ethereum_signer_recovery.zig");
const Cpu = @import("../cpu.zig").Cpu;
const Memory = @import("../memory.zig").Memory;
const MemoryLayout = @import("../memory_state.zig").MemoryLayout;
const StateChainTracker = @import("../state_chain.zig").StateChainTracker;
const call_buffer = @import("secp256k1_recover_call_buffer.zig");
const subject = @import("secp256k1_recover_v1.zig");

const ValidFixture = struct {
    digest: [32]u8,
    r: [32]u8,
    s: [32]u8,
    public_key: [64]u8,
};

fn validFixture() ValidFixture {
    var digest: [32]u8 = @splat(0);
    digest[31] = 1;
    const base = std.crypto.ecc.Secp256k1.basePoint;
    const coordinates = base.affineCoordinates();
    const r = coordinates.x.toBytes(.big);
    const r_scalar = std.crypto.ecc.Secp256k1.scalar.Scalar.fromBytes(r, .big) catch
        unreachable;
    const s = r_scalar.add(.one).toBytes(.big);
    const sec1 = base.toUncompressedSec1();
    return .{
        .digest = digest,
        .r = r,
        .s = s,
        .public_key = sec1[1..65].*,
    };
}

fn testLayout() MemoryLayout {
    return .{
        .program_base = 0x1000,
        .program_end = 0x1100,
        .data_base = 0x2000,
        .data_end = 0x3000,
        .stack_bottom = 0x4000,
        .stack_top = 0x5000,
        .io_base = 0x6000,
        .io_end = 0x7000,
        .input_base = 0x6000,
        .input_end = 0x6100,
        .output_len_addr = 0x6200,
        .output_data_addr = 0x6204,
        .output_base = 0x6200,
        .output_end = 0x7000,
    };
}

fn writeRecord(memory: *Memory, ptr: u32, fixture: ValidFixture, recovery_id: u32) void {
    memory.writeSlice(ptr + abi.digest_offset, &fixture.digest);
    memory.writeSlice(ptr + abi.r_offset, &fixture.r);
    memory.writeSlice(ptr + abi.s_offset, &fixture.s);
    memory.writeU32(ptr + abi.recovery_id_offset, recovery_id);
    memory.writeSlice(ptr + abi.public_key_offset, &(.{0xa5} ** abi.public_key_size));
    memory.writeU32(ptr + abi.status_offset, 0xfeed_beef);
}

fn recordBytes(memory: *const Memory, ptr: u32) [abi.record_size]u8 {
    var bytes: [abi.record_size]u8 = undefined;
    memory.readSlice(ptr, &bytes);
    return bytes;
}

test "signer recovery: fixed d=1 k=1 vector returns the base point" {
    const fixture = validFixture();
    const recovered = try subject.recoverSigner(
        fixture.digest,
        fixture.r,
        fixture.s,
        0,
    );
    try std.testing.expectEqual(fixture.public_key, recovered);

    // Keep the independent verification off the production hot path.
    var signature_bytes: [64]u8 = undefined;
    signature_bytes[0..32].* = fixture.r;
    signature_bytes[32..64].* = fixture.s;
    var sec1: [65]u8 = undefined;
    sec1[0] = 4;
    sec1[1..65].* = recovered;
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
    const signature = Ecdsa.Signature.fromBytes(signature_bytes);
    const public_key = try Ecdsa.PublicKey.fromSec1(&sec1);
    try signature.verifyPrehashed(fixture.digest, public_key);
}

test "signer recovery: transaction commits exact words clocks and typed rows" {
    var memory = try Memory.initFallible(std.testing.allocator);
    defer memory.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    var calls = try call_buffer.Builder.init(std.testing.allocator, 2);
    defer calls.deinit();
    var rows = try subject.ExecutionRowsBuilder.init(std.testing.allocator, 2);
    defer rows.deinit();
    var cpu = Cpu.init(0x1000, 0x4000);
    const ptr: u32 = 0x2000;
    cpu.writeReg(5, ptr);
    const fixture = validFixture();
    writeRecord(&memory, ptr, fixture, 0);

    try subject.execute(
        .rv32im_zkvm_ethereum_v1,
        custom0.encodeSecp256k1Recover(5),
        3,
        &cpu,
        &memory,
        testLayout(),
        &tracker,
        &calls,
        &rows,
    );

    var actual_key: [abi.public_key_size]u8 = undefined;
    memory.readSlice(ptr + abi.public_key_offset, &actual_key);
    try std.testing.expectEqual(fixture.public_key, actual_key);
    try std.testing.expectEqual(abi.success_status, memory.readU32(ptr + abi.status_offset));
    try std.testing.expectEqual(@as(u32, 0x1004), cpu.pc);
    try std.testing.expectEqual(@as(usize, 1), calls.len());
    try std.testing.expectEqual(@as(usize, 1), rows.len());
    try std.testing.expectEqual(@as(u32, 3), calls.records()[0].execution_clock);
    try std.testing.expectEqual(@as(u32, 0x1000), calls.records()[0].pc);
    try std.testing.expectEqual(@as(u32, ptr), calls.records()[0].io_ptr);
    try std.testing.expectEqual(@as(u5, 5), calls.records()[0].pointer_register);
    try std.testing.expectEqual(@as(u32, 0), calls.records()[0].pointer_previous_clock);
    try std.testing.expectEqual(fixture.digest, calls.records()[0].digest_big_endian);
    try std.testing.expectEqual(fixture.public_key, calls.records()[0].public_key_xy_big_endian);
    try std.testing.expectEqual(@as(u32, 0), rows.rows()[0].call_index);
    try std.testing.expectEqual(
        custom0.encodeSecp256k1Recover(5),
        rows.rows()[0].inst_word,
    );
    try std.testing.expectEqual(@as(usize, abi.memory_word_count + 1), tracker.accesses.items.len);
    try std.testing.expectEqual(access_clock.encode(3, .first), tracker.reg_last_clk[5]);
    for (0..abi.input_word_count) |index| {
        try std.testing.expectEqual(
            @as(u32, 0),
            calls.records()[0].input_previous_clocks[index],
        );
        try std.testing.expectEqual(
            access_clock.encode(3, .second),
            tracker.mem_last_clk.get(abi.inputWordAddress(ptr, index)).?,
        );
    }
    for (0..abi.output_word_count) |index| {
        const expected_previous: u32 = if (index + 1 == abi.output_word_count)
            0xfeed_beef
        else
            0xa5a5_a5a5;
        try std.testing.expectEqual(
            expected_previous,
            calls.records()[0].output_previous_words[index],
        );
        try std.testing.expectEqual(
            @as(u32, 0),
            calls.records()[0].output_previous_clocks[index],
        );
        try std.testing.expectEqual(
            access_clock.encode(3, .second),
            tracker.mem_last_clk.get(abi.outputWordAddress(ptr, index)).?,
        );
    }
}

test "signer recovery: invalid inputs and profile fail before architecture" {
    const Case = struct {
        profile: subject.ExecutionProfile = .rv32im_zkvm_ethereum_v1,
        word: u32 = custom0.encodeSecp256k1Recover(5),
        pointer: u32 = 0x2000,
        recovery_id: u32 = 0,
        zero_r: bool = false,
        zero_s: bool = false,
        unit_s: bool = false,
        small_r: ?u8 = null,
        expected: anyerror,
    };
    const cases = [_]Case{
        .{ .recovery_id = 2, .expected = error.InvalidRecoveryId },
        .{ .zero_r = true, .expected = error.InvalidSignatureScalar },
        .{ .zero_s = true, .expected = error.InvalidSignatureScalar },
        .{ .unit_s = true, .expected = error.InvalidRecoveredPublicKey },
        .{ .small_r = 5, .expected = error.InvalidRecoveryPoint },
        .{ .pointer = 0x2002, .expected = error.PrecompileAddressMisaligned },
        .{ .pointer = 0x2f80, .expected = error.PrecompileSpanOutsideRwMemory },
        .{
            .profile = .rv32im_zkvm_keccakf_v1,
            .expected = error.InvalidPrecompileEncoding,
        },
        .{
            .word = custom0.encodeKeccakf(5),
            .expected = error.InvalidPrecompileEncoding,
        },
    };
    for (cases) |case| {
        var memory = try Memory.initFallible(std.testing.allocator);
        defer memory.deinit();
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        var calls = try call_buffer.Builder.init(std.testing.allocator, 1);
        defer calls.deinit();
        var rows = try subject.ExecutionRowsBuilder.init(std.testing.allocator, 1);
        defer rows.deinit();
        var cpu = Cpu.init(0x1000, 0x4000);
        cpu.writeReg(5, case.pointer);
        var fixture = validFixture();
        if (case.zero_r) fixture.r = @splat(0);
        if (case.zero_s) fixture.s = @splat(0);
        if (case.unit_s) {
            fixture.s = @splat(0);
            fixture.s[31] = 1;
        }
        if (case.small_r) |value| {
            fixture.r = @splat(0);
            fixture.r[31] = value;
        }
        writeRecord(&memory, 0x2000, fixture, case.recovery_id);
        const memory_before = recordBytes(&memory, 0x2000);
        const cpu_before = cpu;

        try std.testing.expectError(case.expected, subject.execute(
            case.profile,
            case.word,
            1,
            &cpu,
            &memory,
            testLayout(),
            &tracker,
            &calls,
            &rows,
        ));
        try std.testing.expectEqualDeep(cpu_before, cpu);
        try std.testing.expectEqual(memory_before, recordBytes(&memory, 0x2000));
        try std.testing.expectEqual(@as(usize, 0), tracker.accesses.items.len);
        try std.testing.expectEqual(@as(usize, 0), calls.len());
        try std.testing.expectEqual(@as(usize, 0), rows.len());
    }
}

test "signer recovery: exhausted call tape cannot publish a valid recovery" {
    var memory = try Memory.initFallible(std.testing.allocator);
    defer memory.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    var calls = try call_buffer.Builder.init(std.testing.allocator, 0);
    defer calls.deinit();
    var rows = try subject.ExecutionRowsBuilder.init(std.testing.allocator, 1);
    defer rows.deinit();
    var cpu = Cpu.init(0x1000, 0x4000);
    const ptr: u32 = 0x2000;
    cpu.writeReg(5, ptr);
    writeRecord(&memory, ptr, validFixture(), 0);
    const before = recordBytes(&memory, ptr);

    try std.testing.expectError(error.PrecompileCallLimitExceeded, subject.execute(
        .rv32im_zkvm_ethereum_v1,
        custom0.encodeSecp256k1Recover(5),
        1,
        &cpu,
        &memory,
        testLayout(),
        &tracker,
        &calls,
        &rows,
    ));
    try std.testing.expectEqual(before, recordBytes(&memory, ptr));
    try std.testing.expectEqual(@as(u32, 0x1000), cpu.pc);
    try std.testing.expectEqual(@as(usize, 0), tracker.accesses.items.len);
}
