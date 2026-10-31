//! Streams pinned RVFI bytes while executing once into compact Tape. No oracle
//! retirement array, secondary native run, or copied architectural interpreter.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const rv = front.rv64;
const Image = @import("sail_image.zig");
const Capture = @import("csp_capture.zig").Capture;
pub fn run(a: std.mem.Allocator, image: *const Image.Owner) !Capture {
    const oracle = image.parsed.value;
    var file = try std.fs.cwd().openFile(image.config.rvfi, .{});
    defer file.close();
    if (try file.getEndPos() != 88 * @as(u64, oracle.steps)) return error.InvalidSailTraceSize;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var expected_hash: [32]u8 = undefined;
    if (oracle.rvfi_sha256.len != 64) return error.InvalidSailTraceDigest;
    _ = try std.fmt.hexToBytes(&expected_hash, oracle.rvfi_sha256);
    var loaded = try Image.Owner.load(a, image.elf, oracle);
    defer loaded.deinit();
    var session = try rv.Session.init(a, rv.machine.Cpu.init(oracle.initial_pc, 0), &loaded.memory, .{ .max_retirements = oracle.steps });
    defer session.deinit();
    var tape = try rv.compact_tape.Tape.init(a, oracle.steps, oracle.initial_pc, 0, .rv64im);
    errdefer tape.deinit();
    var clocks: [32]u32 = @splat(0);
    var histogram: [65]u64 = @splat(0);
    var oracle_registers: [32]u64 = @splat(0);
    for (0..oracle.steps) |i| {
        var raw: [88]u8 = undefined;
        if (try file.readAll(&raw) != raw.len) return error.TruncatedSailTrace;
        // Authenticate the exact bytes consumed, rather than hashing once and
        // rereading a mutable file after the pin check.
        hash.update(&raw);
        if (u64At(&raw, 0) != i) return error.InvalidSailRetirementOrder;
        const record = try session.step();
        try compare(record, raw, oracle_registers);
        if (raw[84] != 0) oracle_registers[raw[84]] = u64At(&raw, 48);
        try tape.append(record);
        histogram[@intFromEnum(record.opcode)] += 1;
        const effect = rv.decode.effects(record.opcode);
        const tick: u32 = @intCast(4 * i);
        if (effect.reads_rs1 and record.rs1 != 0) clocks[record.rs1] = tick + 1;
        if (effect.reads_rs2 and record.rs2 != 0) clocks[record.rs2] = tick + 2;
        if (effect.writes_rd and record.rd != 0) clocks[record.rd] = tick + 3;
    }
    var trailing: [1]u8 = undefined;
    if (try file.read(&trailing) != 0) return error.InvalidSailTraceSize;
    if (!std.mem.eql(u8, &expected_hash, &hash.finalResult())) return error.SailTraceDigestMismatch;
    if (session.cpu.pc != oracle.final_pc or !std.mem.eql(u64, &session.cpu.regs, &oracle.final_registers)) return error.SailCpuEndpointMismatch;
    for (0..16) |i| if (try loaded.memory.load(oracle.data_address + i, 1) != oracle.data_final[i]) return error.SailMemoryEndpointMismatch;
    return .{ .tape = tape, .histogram = histogram, .boundary = .{ .steps = oracle.steps, .initial_pc = oracle.initial_pc, .final_pc = session.cpu.pc, .initial_registers = @splat(0), .final_registers = session.cpu.regs, .register_clocks = clocks } };
}
fn u64At(raw: *const [88]u8, offset: usize) u64 {
    return std.mem.readInt(u64, raw[offset..][0..8], .little);
}
pub fn compare(record: rv.machine.Retirement, raw: [88]u8, oracle_registers: [32]u64) !void {
    if (raw[85] != 0 or raw[86] != 0 or raw[87] != 0 or u64At(&raw, 8) != record.pc.toInt() or u64At(&raw, 16) != record.next_pc.toInt() or u64At(&raw, 24) != record.instruction) return error.SailRetirementIdentityMismatch;
    const effect = rv.decode.effects(record.opcode);
    // This pinned model leaves the RVFI input-register extension zero. Recover
    // the independent pre-state from ALL prior Sail rd updates instead. This
    // is register bookkeeping, not a second implementation of ISA arithmetic.
    if (effect.reads_rs1 and oracle_registers[record.rs1] != record.lhs.toInt()) return error.SailOperandMismatch;
    if (effect.reads_rs2 and oracle_registers[record.rs2] != record.rhs.toInt()) return error.SailOperandMismatch;
    if (raw[82] != 0 and (raw[82] != record.rs1 or u64At(&raw, 32) != record.lhs.toInt())) return error.SailOperandMismatch;
    if (raw[83] != 0 and (raw[83] != record.rs2 or u64At(&raw, 40) != record.rhs.toInt())) return error.SailOperandMismatch;
    if (record.writes_rd) {
        if (raw[84] != record.rd or u64At(&raw, 48) != record.result.toInt()) return error.SailRegisterMismatch;
    } else if (raw[84] != 0) return error.SailRegisterMismatch;
    if (record.memory) |event| {
        const mask: u8 = @intCast((@as(u16, 1) << @intCast(event.width)) - 1);
        const value_mask = @as(u64, std.math.maxInt(u64)) >> @as(u6, @intCast(8 * (8 - @as(u7, event.width))));
        if (u64At(&raw, 56) != event.address.toInt() or raw[80] != (if (event.write) @as(u8, 0) else mask) or raw[81] != (if (event.write) mask else @as(u8, 0)) or (u64At(&raw, if (event.write) 72 else 64) & value_mask) != event.value.toInt()) return error.SailMemoryEffectMismatch;
    } else if (raw[80] != 0 or raw[81] != 0) return error.SailMemoryEffectMismatch;
}
