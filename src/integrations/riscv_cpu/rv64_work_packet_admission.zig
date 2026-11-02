//! Reject header-controlled wide allocation inflation before allocating even
//! narrow payloads. This walks immutable decoded ROM and PC advice only; it
//! never executes an instruction or constructs arithmetic/wide witness hints.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64;
const air = frontend.rv64_air;
const CPU = @import("rv64_keccak_cpu.zig");
const Secp = @import("delegations/secp256k1/context.zig");
const Full = @import("rv64_full.zig");
const H = @import("rv64_work_packet_header.zig");
const IO = @import("rv64_work_packet_io.zig");
pub const OpcodeCounts = [@typeInfo(rv.decode.Opcode).@"enum".fields.len]u64;
pub fn check(file: std.fs.File, h: H.Header, public: CPU.Public, authority: *const Full.ProgramAuthority) !OpcodeCounts {
    try canonical(public);
    const tape_start = try std.math.add(usize, H.BYTES + try h.bodyBytes(), h.graph_bytes);
    try file.seekTo(tape_start);
    var raw: [rv.compact_tape_wire.HEADER_BYTES]u8 = undefined;
    try IO.exact(file, &raw);
    const tape_profile = std.meta.intToEnum(rv.execution_profile.Profile, std.mem.readInt(u32, raw[8..12], .little)) catch return error.InvalidWorkPacketBoundary;
    // raw[28..32]: v3 SHA-256 record count; bit 31 announces the v3
    // extension (arith256_mod, then curve records) after the SHA-256 records.
    const sha_word = std.mem.readInt(u32, raw[28..32], .little);
    const extended = sha_word & (1 << 31) != 0;
    const sha256_expected = sha_word & ~@as(u32, 1 << 31);
    if (!@import("rv64_ethereum_batch.zig").tapeMatches(tape_profile, public.execution_profile) or std.mem.readInt(u64, raw[32..40], .little) != public.statement.initial_pc or std.mem.readInt(u64, raw[40..48], .little) != h.metadata.first_step) return error.InvalidWorkPacketBoundary;
    var reader = IO.Reader{ .file = file, .remaining = try std.math.mul(usize, public.statement.steps, 48) };
    var pc = public.statement.initial_pc;
    var division: u32 = 0;
    var multiplication: u32 = 0;
    var memory: u32 = 0;
    var calls: [3]u32 = @splat(0);
    var sha256: u32 = 0;
    var arith: u32 = 0;
    var curve: u32 = 0;
    var bulk: u32 = 0;
    var opcodes: OpcodeCounts = @splat(0);
    for (0..public.statement.steps) |_| {
        var step: [48]u8 = undefined;
        try reader.bytes(&step);
        // lookup validates row.valid BEFORE accessing its decoded cache entry.
        const index = try authority.program.lookup(pc);
        const opcode = authority.program.decoded[index].instruction.opcode;
        opcodes[@intFromEnum(opcode)] += 1;
        switch (opcode) {
            .DIV, .DIVU, .REM, .REMU, .DIVW, .DIVUW, .REMW, .REMUW => division += 1,
            .MUL, .MULH, .MULHSU, .MULHU, .MULW => multiplication += 1,
            .ECALL => {
                const tag = std.mem.readInt(u64, step[16..24], .little);
                if (rv.execution_profile.admitsV3(tape_profile, tag)) {
                    if (rv.execution_profile.isPayloadFreeTag(tag)) bulk += 1 else if (tag == rv.execution_profile.ARITH256_MOD_TAG) arith += 1 else if (rv.execution_profile.isCurveTag(tag)) curve += 1 else sha256 += 1;
                } else {
                    const kind: usize = if (tag == rv.execution_profile.KECCAK_TAG) 0 else switch (public.execution_profile) {
                        .ethereum_services_v1 => if (tag == rv.execution_profile.SECP_ADD_TAG) 1 else if (tag == rv.execution_profile.SECP_DOUBLE_TAG) 2 else return error.InvalidWorkPacketService,
                        .ethereum_services_v2 => if (tag == rv.execution_profile.SECP_ADD_WORD_TAG) 1 else if (tag == rv.execution_profile.SECP_DOUBLE_WORD_TAG) 2 else return error.InvalidWorkPacketService,
                        else => return error.WorkPacketAuthorityMismatch,
                    };
                    calls[kind] += 1;
                }
            },
            else => {},
        }
        const has_memory = rv.execution_profile.effects(public.execution_profile, opcode).memory_width != 0;
        const memory_index = std.mem.readInt(u32, step[40..44], .little);
        if (has_memory) {
            if (memory_index != memory) return error.InvalidWorkPacketBoundary;
            memory += 1;
        } else if (memory_index != rv.compact_tape.NO_MEMORY) return error.InvalidWorkPacketBoundary;
        pc = std.mem.readInt(u64, step[0..8], .little);
    }
    try reader.finish();
    // v3 tapes: the arith256_mod count sits in the extension that follows
    // the SHA-256 records (compact_tape_wire), present only when flagged.
    var arith_expected: u32 = 0;
    var curve_expected: u32 = 0;
    if (rv.execution_profile.isV3(tape_profile) and extended) {
        const keccak_records = std.mem.readInt(u32, raw[20..24], .little);
        const secp_records = std.mem.readInt(u32, raw[24..28], .little);
        var at = try std.math.add(usize, tape_start, rv.compact_tape_wire.HEADER_BYTES);
        at = try std.math.add(usize, at, try std.math.mul(usize, public.statement.steps, 48));
        at = try std.math.add(usize, at, try std.math.mul(usize, std.mem.readInt(u32, raw[16..20], .little), 8));
        at = try std.math.add(usize, at, try std.math.mul(usize, keccak_records, 432));
        at = try std.math.add(usize, at, try std.math.mul(usize, secp_records, 424));
        at = try std.math.add(usize, at, try std.math.mul(usize, sha256_expected, 224));
        try file.seekTo(at);
        var extension: [8]u8 = undefined;
        try IO.exact(file, &extension);
        arith_expected = std.mem.readInt(u32, extension[0..4], .little);
        curve_expected = std.mem.readInt(u32, extension[4..8], .little);
        if (arith_expected == 0 and curve_expected == 0) return error.InvalidWorkPacketService;
    } else if (extended or arith != 0 or curve != 0) return error.InvalidWorkPacketService;
    if (!rv.execution_profile.isV3(tape_profile) and bulk != 0) return error.InvalidWorkPacketService;
    const expected_calls = [_]u32{ public.keccak_calls, public.secp.add.calls, public.secp.double.calls };
    if (pc != public.statement.final_pc or division != public.division_requests or multiplication != public.multiplication_requests or memory != std.mem.readInt(u32, raw[16..20], .little) or !std.mem.eql(u32, &calls, &expected_calls) or sha256 != sha256_expected or arith != arith_expected or curve != curve_expected) return error.InvalidWorkPacketRequestCount;
    const ram_bound = @as(u64, memory) + 25 * @as(u64, calls[0]) + 32 * (@as(u64, calls[1]) + calls[2]) + 12 * @as(u64, sha256) + 20 * @as(u64, arith) + rv.ethereum_services.curves.MAX_WORDS * @as(u64, curve) + rv.execution_profile.BULK_MAX_TOUCHED_WORDS * @as(u64, bulk);
    if (h.cells > ram_bound) return error.InvalidWorkPacketRequestCount;
    return opcodes;
}
fn requestLog(count: u32) u32 {
    return @max(5, std.math.log2_int_ceil(u32, @max(1, count)));
}
fn canonical(public: CPU.Public) !void {
    if (public.division_log != requestLog(public.division_requests) or public.multiplication_log != requestLog(public.multiplication_requests)) return error.NoncanonicalWorkPacketGeometry;
    if (public.keccak_calls == 0) {
        if (public.roster != .none or public.keccak_log != 5 or public.bridge_log != 5) return error.NoncanonicalWorkPacketGeometry;
    } else if (public.roster != .paired or public.keccak_log != try air.crypto.keccak.layout.logSize(public.keccak_calls) or public.bridge_log != try air.crypto.keccak.bridge.trace.logSize(public.keccak_calls)) return error.NoncanonicalWorkPacketGeometry;
    for (public.secp.groups(), 0..) |group, k| {
        const expected = if (group.calls == 0) (Secp.Group{}).geometry else try Secp.Source.Geometry.minimal(if (k == 0) .add else .double, group.calls);
        if (!std.meta.eql(group.geometry, expected) or (group.roster == .none) != (group.calls == 0)) return error.NoncanonicalWorkPacketGeometry;
    }
}
