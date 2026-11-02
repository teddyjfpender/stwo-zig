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
/// Tape-wire facts the step walk is checked against (header + v3 extension).
const Facts = struct {
    profile: rv.execution_profile.Profile,
    initial_pc: u64,
    first_step: u64,
    memory: u32,
    sha256: u32,
    extended: bool,
    arith: u32 = 0,
    curve: u32 = 0,
};
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
    var facts = Facts{ .profile = tape_profile, .initial_pc = std.mem.readInt(u64, raw[32..40], .little), .first_step = std.mem.readInt(u64, raw[40..48], .little), .memory = std.mem.readInt(u32, raw[16..20], .little), .sha256 = sha_word & ~@as(u32, 1 << 31), .extended = sha_word & (1 << 31) != 0 };
    try header(facts, h, public, authority);
    const FileSteps = struct {
        reader: IO.Reader,
        fn next(self: *@This(), step: *[48]u8) !void {
            try self.reader.bytes(step);
        }
    };
    var steps = FileSteps{ .reader = .{ .file = file, .remaining = try std.math.mul(usize, public.statement.steps, 48) } };
    var walked = try walk(&steps, facts, public, authority);
    try steps.reader.finish();
    if (rv.execution_profile.isV3(tape_profile) and facts.extended) {
        const keccak_records = std.mem.readInt(u32, raw[20..24], .little);
        const secp_records = std.mem.readInt(u32, raw[24..28], .little);
        var at = try std.math.add(usize, tape_start, rv.compact_tape_wire.HEADER_BYTES);
        at = try std.math.add(usize, at, try std.math.mul(usize, public.statement.steps, 48));
        at = try std.math.add(usize, at, try std.math.mul(usize, facts.memory, 8));
        at = try std.math.add(usize, at, try std.math.mul(usize, keccak_records, 432));
        at = try std.math.add(usize, at, try std.math.mul(usize, secp_records, 424));
        at = try std.math.add(usize, at, try std.math.mul(usize, facts.sha256, 224));
        try file.seekTo(at);
        var extension: [8]u8 = undefined;
        try IO.exact(file, &extension);
        facts.arith = std.mem.readInt(u32, extension[0..4], .little);
        facts.curve = std.mem.readInt(u32, extension[4..8], .little);
    }
    return finish(&walked, facts, h.cells, public);
}
/// In-process twin of `check` for a tape that never crossed the wire: the
/// same canonical-geometry, ROM/PC walk, request-count and RAM-cell bound
/// checks, with the facts the wire header would carry derived from the tape
/// exactly as `compact_tape_wire.write` derives them.
pub fn checkTape(tape: *const rv.compact_tape.Tape, metadata: H.Metadata, cells: u32, public: CPU.Public, authority: *const Full.ProgramAuthority) !OpcodeCounts {
    try canonical(public);
    if (tape.len != public.statement.steps or tape.len > tape.storage.len) return error.InvalidWorkPacketBoundary;
    const sha256: u32 = std.math.cast(u32, tape.sha256_calls.items.len) orelse return error.InvalidWorkPacketService;
    // Bit 31 of the wire word is the v3 extension flag, so the wire can carry
    // at most 2^31 - 1 SHA-256 records (`compact_tape_wire.write` refuses more).
    if (sha256 >= 1 << 31) return error.InvalidWorkPacketService;
    const arith: u32 = std.math.cast(u32, tape.arith256_mod_calls.items.len) orelse return error.InvalidWorkPacketService;
    const curve: u32 = std.math.cast(u32, tape.curve_calls.items.len) orelse return error.InvalidWorkPacketService;
    const memory: u32 = std.math.cast(u32, tape.memory_before.items.len) orelse return error.InvalidWorkPacketBoundary;
    const facts = Facts{ .profile = tape.execution_profile, .initial_pc = tape.initial_pc, .first_step = tape.initial_clock, .memory = memory, .sha256 = sha256, .extended = arith != 0 or curve != 0, .arith = arith, .curve = curve };
    const h = H.Header{ .metadata = metadata, .cells = cells, .chunks = 0, .graph_bytes = 0, .tape_bytes = 0 };
    try header(facts, h, public, authority);
    const TapeSteps = struct {
        steps: []const rv.compact_tape.Step,
        at: usize = 0,
        fn next(self: *@This(), out: *[48]u8) !void {
            if (self.at == self.steps.len) return error.InvalidWorkPacketBoundary;
            const step = self.steps[self.at];
            self.at += 1;
            for ([_]u64{ step.next_pc, step.lhs, step.rhs, step.previous_rd, step.result }, 0..) |word, i| std.mem.writeInt(u64, out[8 * i ..][0..8], word, .little);
            std.mem.writeInt(u32, out[40..44], step.memory_index, .little);
            std.mem.writeInt(u32, out[44..48], step.flags, .little);
        }
    };
    var steps = TapeSteps{ .steps = tape.storage[0..tape.len] };
    var walked = try walk(&steps, facts, public, authority);
    return finish(&walked, facts, cells, public);
}
fn header(facts: Facts, h: H.Header, public: CPU.Public, authority: *const Full.ProgramAuthority) !void {
    if (public.execution_profile != authority.profile or !@import("rv64_ethereum_batch.zig").tapeAdmitted(facts.profile, authority) or facts.initial_pc != public.statement.initial_pc or facts.first_step != h.metadata.first_step) return error.InvalidWorkPacketBoundary;
}
const Walked = struct {
    pc: u64,
    division: u32 = 0,
    multiplication: u32 = 0,
    memory: u32 = 0,
    calls: [3]u32 = @splat(0),
    sha256: u32 = 0,
    arith: u32 = 0,
    curve: u32 = 0,
    bulk: u32 = 0,
    opcodes: OpcodeCounts = @splat(0),
};
fn walk(source: anytype, facts: Facts, public: CPU.Public, authority: *const Full.ProgramAuthority) !Walked {
    const tape_profile = facts.profile;
    var w = Walked{ .pc = public.statement.initial_pc };
    for (0..public.statement.steps) |_| {
        var step: [48]u8 = undefined;
        try source.next(&step);
        // instructionAt validates row.valid BEFORE accessing its decoded cache
        // entry; an invalid row decodes only as a Zbb row of a Zbb ROM.
        const opcode = (try authority.instructionAt(w.pc)).instruction.opcode;
        w.opcodes[@intFromEnum(opcode)] += 1;
        switch (opcode) {
            .DIV, .DIVU, .REM, .REMU, .DIVW, .DIVUW, .REMW, .REMUW => w.division += 1,
            .MUL, .MULH, .MULHSU, .MULHU, .MULW => w.multiplication += 1,
            .ECALL => {
                const tag = std.mem.readInt(u64, step[16..24], .little);
                if (rv.execution_profile.admitsV3(tape_profile, tag)) {
                    if (rv.execution_profile.isPayloadFreeTag(tag)) w.bulk += 1 else if (tag == rv.execution_profile.ARITH256_MOD_TAG) w.arith += 1 else if (rv.execution_profile.isCurveTag(tag)) w.curve += 1 else w.sha256 += 1;
                } else {
                    const kind: usize = if (tag == rv.execution_profile.KECCAK_TAG) 0 else switch (public.execution_profile) {
                        .ethereum_services_v1 => if (tag == rv.execution_profile.SECP_ADD_TAG) 1 else if (tag == rv.execution_profile.SECP_DOUBLE_TAG) 2 else return error.InvalidWorkPacketService,
                        .ethereum_services_v2 => if (tag == rv.execution_profile.SECP_ADD_WORD_TAG) 1 else if (tag == rv.execution_profile.SECP_DOUBLE_WORD_TAG) 2 else return error.InvalidWorkPacketService,
                        else => return error.WorkPacketAuthorityMismatch,
                    };
                    w.calls[kind] += 1;
                }
            },
            else => {},
        }
        const has_memory = rv.execution_profile.effects(authority.rom_profile, opcode).memory_width != 0;
        const memory_index = std.mem.readInt(u32, step[40..44], .little);
        if (has_memory) {
            if (memory_index != w.memory) return error.InvalidWorkPacketBoundary;
            w.memory += 1;
        } else if (memory_index != rv.compact_tape.NO_MEMORY) return error.InvalidWorkPacketBoundary;
        w.pc = std.mem.readInt(u64, step[0..8], .little);
    }
    return w;
}
fn finish(w: *const Walked, facts: Facts, cells: u32, public: CPU.Public) !OpcodeCounts {
    const tape_profile = facts.profile;
    // v3 tapes: the arith256_mod count sits in the extension that follows
    // the SHA-256 records (compact_tape_wire), present only when flagged.
    var arith_expected: u32 = 0;
    var curve_expected: u32 = 0;
    if (rv.execution_profile.isV3(tape_profile) and facts.extended) {
        arith_expected = facts.arith;
        curve_expected = facts.curve;
        if (arith_expected == 0 and curve_expected == 0) return error.InvalidWorkPacketService;
    } else if (facts.extended or w.arith != 0 or w.curve != 0) return error.InvalidWorkPacketService;
    if (!rv.execution_profile.isV3(tape_profile) and w.bulk != 0) return error.InvalidWorkPacketService;
    const expected_calls = [_]u32{ public.keccak_calls, public.secp.add.calls, public.secp.double.calls };
    if (w.pc != public.statement.final_pc or w.division != public.division_requests or w.multiplication != public.multiplication_requests or w.memory != facts.memory or !std.mem.eql(u32, &w.calls, &expected_calls) or w.sha256 != facts.sha256 or w.arith != arith_expected or w.curve != curve_expected) return error.InvalidWorkPacketRequestCount;
    const ram_bound = @as(u64, w.memory) + 25 * @as(u64, w.calls[0]) + 32 * (@as(u64, w.calls[1]) + w.calls[2]) + 12 * @as(u64, w.sha256) + 20 * @as(u64, w.arith) + rv.ethereum_services.curves.MAX_WORDS * @as(u64, w.curve) + rv.execution_profile.BULK_MAX_TOUCHED_WORDS * @as(u64, w.bulk);
    if (cells > ram_bound) return error.InvalidWorkPacketRequestCount;
    return w.opcodes;
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
