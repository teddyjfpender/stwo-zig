//! Portable, bounded native advice for a prepared batch worker. These bytes are
//! witness data, never execution or program authority. The admitted ROM and AIR
//! still authenticate every row. Tape is the final section of a work packet.
const std = @import("std");
const builtin = @import("builtin");
const T = @import("compact_tape.zig");
const profile = @import("execution_profile.zig");
const K = @import("service_session.zig");
const S = @import("ethereum_services/session.zig");
pub const MAGIC = "RV64TP01";
pub const HEADER_BYTES = 48;
pub const Limits = struct { steps: u32 = T.MAX_STEPS, bytes: usize = 512 * 1024 * 1024 };
/// raw[28..32] was reserved-zero; v3 tapes store the SHA-256 record count
/// in its low 31 bits, so every pre-v3 tape is byte-identical. Bit 31
/// (`V3_EXTENSION_FLAG`, v3 only) announces a v3 extension that follows the
/// SHA-256 records: u32 arith256_mod record count, u32 curve record count
/// (formerly reserved zero; at least one count is nonzero), then the
/// arith256_mod records, then the curve records. Without arith256_mod or curve
/// calls the flag and the extension are absent, so a SHA-only v3 tape is
/// byte-identical to the pre-arith v3 encoding, and an arith-only tape to the
/// pre-curve one. Canonical section order: steps, memory, Keccak, secp,
/// SHA-256, [extension, arith256_mod, curves]. Bulk memory has no tape section
/// (the ECALL step's lhs/rhs carry pointer and tag).
const Header = struct { steps: u32, memory: u32, keccak: u32, secp: u32, sha256: u32 = 0, arith256_mod: u32 = 0, curves: u32 = 0, execution: profile.Profile, pc: u64, clock: u64 };
const SHA256_RECORD = 32 + 96 + 96;
const V3_EXTENSION_FLAG: u32 = 1 << 31;
const V3_EXTENSION = 8;
const ARITH256_RECORD = 32 + 160 + 160;
/// u32 op, u32 zero, id/clock/pc/pointer, 24 before and 24 after words
/// (words beyond the op's packet are zero).
const CURVE_RECORD = 8 + 32 + 192 + 192;
comptime {
    if (@sizeOf(T.Step) != 48 or @offsetOf(T.Step, "next_pc") != 0 or @offsetOf(T.Step, "lhs") != 8 or @offsetOf(T.Step, "rhs") != 16 or @offsetOf(T.Step, "previous_rd") != 24 or @offsetOf(T.Step, "result") != 32 or @offsetOf(T.Step, "memory_index") != 40 or @offsetOf(T.Step, "flags") != 44) @compileError("native tape layout needs an explicit wire migration");
}
pub fn encodedBytes(tape: *const T.Tape) !usize {
    return size(try header(tape));
}
fn header(tape: *const T.Tape) !Header {
    if (tape.len == 0 or tape.len > T.MAX_STEPS or tape.len > tape.storage.len or tape.memory_before.items.len > tape.len or tape.service_calls.items.len > tape.len or tape.secp_calls.items.len > tape.len - tape.service_calls.items.len or tape.sha256_calls.items.len > tape.len - tape.service_calls.items.len - tape.secp_calls.items.len or tape.arith256_mod_calls.items.len > tape.len - tape.service_calls.items.len - tape.secp_calls.items.len - tape.sha256_calls.items.len or tape.curve_calls.items.len > tape.len - tape.service_calls.items.len - tape.secp_calls.items.len - tape.sha256_calls.items.len - tape.arith256_mod_calls.items.len) return error.InvalidTapeWireGeometry;
    return .{ .steps = @intCast(tape.len), .memory = @intCast(tape.memory_before.items.len), .keccak = @intCast(tape.service_calls.items.len), .secp = @intCast(tape.secp_calls.items.len), .sha256 = @intCast(tape.sha256_calls.items.len), .arith256_mod = @intCast(tape.arith256_mod_calls.items.len), .curves = @intCast(tape.curve_calls.items.len), .execution = tape.execution_profile, .pc = tape.initial_pc, .clock = tape.initial_clock };
}
fn size(h: Header) !usize {
    var result: usize = HEADER_BYTES;
    for ([_]usize{ h.steps, h.memory, h.keccak, h.secp, h.sha256 }, [_]usize{ 48, 8, 432, 424, SHA256_RECORD }) |count, width| result = try std.math.add(usize, result, try std.math.mul(usize, count, width));
    if (h.arith256_mod != 0 or h.curves != 0) result = try std.math.add(usize, result, try std.math.add(usize, V3_EXTENSION, try std.math.add(usize, try std.math.mul(usize, h.arith256_mod, ARITH256_RECORD), try std.math.mul(usize, h.curves, CURVE_RECORD))));
    return result;
}
/// Caller owns the file and its atomic/durable publication. A valid tape is
/// checked before its first byte is written; unused capacity/padding never goes
/// on the wire. Little-endian hosts transfer initialized48B records directly.
pub fn write(file: std.fs.File, tape: *const T.Tape) !void {
    const h = try header(tape);
    try validate(tape);
    var raw: [HEADER_BYTES]u8 = @splat(0);
    @memcpy(raw[0..8], MAGIC);
    put(u32, raw[8..12], @intFromEnum(h.execution));
    put(u32, raw[12..16], h.steps);
    put(u32, raw[16..20], h.memory);
    put(u32, raw[20..24], h.keccak);
    put(u32, raw[24..28], h.secp);
    if (h.sha256 >= V3_EXTENSION_FLAG) return error.InvalidTapeWireGeometry;
    put(u32, raw[28..32], h.sha256 | if (h.arith256_mod != 0 or h.curves != 0) V3_EXTENSION_FLAG else 0);
    put(u64, raw[32..40], h.pc);
    put(u64, raw[40..48], h.clock);
    try file.writeAll(&raw);
    if (builtin.cpu.arch.endian() == .little) {
        try file.writeAll(std.mem.sliceAsBytes(tape.steps()));
        try file.writeAll(std.mem.sliceAsBytes(tape.memory_before.items));
    } else {
        for (tape.steps()) |step| {
            var encoded: [48]u8 = undefined;
            for ([_]u64{ step.next_pc, step.lhs, step.rhs, step.previous_rd, step.result }, 0..) |word, i| put(u64, encoded[8 * i ..][0..8], word);
            put(u32, encoded[40..44], step.memory_index);
            put(u32, encoded[44..48], step.flags);
            try file.writeAll(&encoded);
        }
        for (tape.memory_before.items) |word| {
            var encoded: [8]u8 = undefined;
            put(u64, &encoded, word);
            try file.writeAll(&encoded);
        }
    }
    for (tape.service_calls.items) |call| {
        var encoded: [432]u8 = undefined;
        for ([_]u64{ call.call_id, call.clock, call.pc, call.pointer }, 0..) |word, i| put(u64, encoded[8 * i ..][0..8], word);
        for (call.before, 0..) |word, i| put(u64, encoded[32 + 8 * i ..][0..8], word);
        for (call.after, 0..) |word, i| put(u64, encoded[232 + 8 * i ..][0..8], word);
        try file.writeAll(&encoded);
    }
    for (tape.secp_calls.items) |call| {
        var encoded: [424]u8 = undefined;
        put(u32, encoded[0..4], @intFromEnum(call.kind));
        put(u32, encoded[4..8], @intFromEnum(call.packet_format));
        for ([_]u64{ call.call_id, call.clock, call.pc, call.pointer }, 0..) |word, i| put(u64, encoded[8 + 8 * i ..][0..8], word);
        for (call.before, 0..) |word, i| put(u64, encoded[40 + 8 * i ..][0..8], word);
        for (call.after, 0..) |word, i| put(u64, encoded[232 + 8 * i ..][0..8], word);
        try file.writeAll(&encoded);
    }
    for (tape.sha256_calls.items) |call| {
        var encoded: [SHA256_RECORD]u8 = undefined;
        for ([_]u64{ call.call_id, call.clock, call.pc, call.pointer }, 0..) |word, i| put(u64, encoded[8 * i ..][0..8], word);
        for (call.before, 0..) |word, i| put(u64, encoded[32 + 8 * i ..][0..8], word);
        for (call.after, 0..) |word, i| put(u64, encoded[128 + 8 * i ..][0..8], word);
        try file.writeAll(&encoded);
    }
    if (h.arith256_mod != 0 or h.curves != 0) {
        var extension: [V3_EXTENSION]u8 = @splat(0);
        put(u32, extension[0..4], h.arith256_mod);
        put(u32, extension[4..8], h.curves);
        try file.writeAll(&extension);
    }
    for (tape.arith256_mod_calls.items) |call| {
        var encoded: [ARITH256_RECORD]u8 = undefined;
        for ([_]u64{ call.call_id, call.clock, call.pc, call.pointer }, 0..) |word, i| put(u64, encoded[8 * i ..][0..8], word);
        for (call.before, 0..) |word, i| put(u64, encoded[32 + 8 * i ..][0..8], word);
        for (call.after, 0..) |word, i| put(u64, encoded[192 + 8 * i ..][0..8], word);
        try file.writeAll(&encoded);
    }
    for (tape.curve_calls.items) |call| {
        var encoded: [CURVE_RECORD]u8 = @splat(0);
        put(u32, encoded[0..4], @intFromEnum(call.op));
        for ([_]u64{ call.call_id, call.clock, call.pc, call.pointer }, 0..) |word, i| put(u64, encoded[8 + 8 * i ..][0..8], word);
        for (call.before, 0..) |word, i| put(u64, encoded[40 + 8 * i ..][0..8], word);
        for (call.after, 0..) |word, i| put(u64, encoded[232 + 8 * i ..][0..8], word);
        try file.writeAll(&encoded);
    }
}
/// Counts and byte budget are admitted before allocation. Consumes through EOF
/// and rejects trailing bytes; a work-packet container must put this section last.
pub fn readTail(a: std.mem.Allocator, file: std.fs.File, limits: Limits) !T.Tape {
    var raw: [HEADER_BYTES]u8 = undefined;
    try exact(file, &raw);
    if (!std.mem.eql(u8, raw[0..8], MAGIC)) return error.InvalidTapeWireHeader;
    const execution = std.meta.intToEnum(profile.Profile, get(u32, raw[8..12])) catch return error.InvalidTapeWireProfile;
    if (!profile.isV3(execution) and get(u32, raw[28..32]) != 0) return error.InvalidTapeWireHeader;
    const sha_word = get(u32, raw[28..32]);
    const extended_v3 = sha_word & V3_EXTENSION_FLAG != 0;
    const h = Header{ .execution = execution, .steps = get(u32, raw[12..16]), .memory = get(u32, raw[16..20]), .keccak = get(u32, raw[20..24]), .secp = get(u32, raw[24..28]), .sha256 = sha_word & ~V3_EXTENSION_FLAG, .pc = get(u64, raw[32..40]), .clock = get(u64, raw[40..48]) };
    if (h.steps == 0 or h.steps > T.MAX_STEPS or h.steps > limits.steps or h.memory > h.steps or h.keccak > h.steps or h.secp > h.steps - h.keccak or h.sha256 > h.steps - h.keccak - h.secp or (h.execution == .rv64im and h.keccak != 0) or ((h.execution == .rv64im or h.execution == .keccak_service_v1) and h.secp != 0) or try size(h) > limits.bytes) return error.InvalidTapeWireGeometry;
    var tape = try T.Tape.init(a, h.steps, h.pc, h.clock, h.execution);
    errdefer tape.deinit();
    tape.len = h.steps;
    try tape.memory_before.resize(a, h.memory);
    try exact(file, std.mem.sliceAsBytes(tape.storage));
    try exact(file, std.mem.sliceAsBytes(tape.memory_before.items));
    if (builtin.cpu.arch.endian() != .little) {
        for (tape.storage) |*step| {
            inline for (.{ "next_pc", "lhs", "rhs", "previous_rd", "result", "memory_index", "flags" }) |field| @field(step, field) = @byteSwap(@field(step, field));
        }
        for (tape.memory_before.items) |*word| word.* = @byteSwap(word.*);
    }
    try tape.service_calls.ensureTotalCapacityPrecise(a, h.keccak);
    for (0..h.keccak) |_| {
        var encoded: [432]u8 = undefined;
        try exact(file, &encoded);
        var call = K.Call{ .call_id = get(u64, encoded[0..8]), .clock = get(u64, encoded[8..16]), .pc = get(u64, encoded[16..24]), .pointer = get(u64, encoded[24..32]), .before = undefined, .after = undefined };
        for (&call.before, 0..) |*word, i| word.* = get(u64, encoded[32 + 8 * i ..][0..8]);
        for (&call.after, 0..) |*word, i| word.* = get(u64, encoded[232 + 8 * i ..][0..8]);
        tape.service_calls.appendAssumeCapacity(call);
    }
    try tape.secp_calls.ensureTotalCapacityPrecise(a, h.secp);
    for (0..h.secp) |_| {
        var encoded: [424]u8 = undefined;
        try exact(file, &encoded);
        const kind = std.meta.intToEnum(S.secp256k1.Kind, get(u32, encoded[0..4])) catch return error.InvalidTapeWireService;
        const format = std.meta.intToEnum(profile.SecpPacketFormat, get(u32, encoded[4..8])) catch return error.InvalidTapeWireService;
        var call = S.SecpCall{ .kind = kind, .packet_format = format, .call_id = get(u64, encoded[8..16]), .clock = get(u64, encoded[16..24]), .pc = get(u64, encoded[24..32]), .pointer = get(u64, encoded[32..40]), .before = undefined, .after = undefined };
        for (&call.before, 0..) |*word, i| word.* = get(u64, encoded[40 + 8 * i ..][0..8]);
        for (&call.after, 0..) |*word, i| word.* = get(u64, encoded[232 + 8 * i ..][0..8]);
        tape.secp_calls.appendAssumeCapacity(call);
    }
    try tape.sha256_calls.ensureTotalCapacityPrecise(a, h.sha256);
    for (0..h.sha256) |_| {
        var encoded: [SHA256_RECORD]u8 = undefined;
        try exact(file, &encoded);
        var call = S.Sha256Call{ .call_id = get(u64, encoded[0..8]), .clock = get(u64, encoded[8..16]), .pc = get(u64, encoded[16..24]), .pointer = get(u64, encoded[24..32]), .before = undefined, .after = undefined };
        for (&call.before, 0..) |*word, i| word.* = get(u64, encoded[32 + 8 * i ..][0..8]);
        for (&call.after, 0..) |*word, i| word.* = get(u64, encoded[128 + 8 * i ..][0..8]);
        tape.sha256_calls.appendAssumeCapacity(call);
    }
    if (extended_v3) {
        var extension: [V3_EXTENSION]u8 = undefined;
        try exact(file, &extension);
        const count = get(u32, extension[0..4]);
        const curve_count = get(u32, extension[4..8]);
        var extended = h;
        extended.arith256_mod = count;
        extended.curves = curve_count;
        if ((count == 0 and curve_count == 0) or count > h.steps - h.keccak - h.secp - h.sha256 or curve_count > h.steps - h.keccak - h.secp - h.sha256 - count or try size(extended) > limits.bytes) return error.InvalidTapeWireGeometry;
        try tape.arith256_mod_calls.ensureTotalCapacityPrecise(a, count);
        for (0..count) |_| {
            var encoded: [ARITH256_RECORD]u8 = undefined;
            try exact(file, &encoded);
            var call = S.Arith256ModCall{ .call_id = get(u64, encoded[0..8]), .clock = get(u64, encoded[8..16]), .pc = get(u64, encoded[16..24]), .pointer = get(u64, encoded[24..32]), .before = undefined, .after = undefined };
            for (&call.before, 0..) |*word, i| word.* = get(u64, encoded[32 + 8 * i ..][0..8]);
            for (&call.after, 0..) |*word, i| word.* = get(u64, encoded[192 + 8 * i ..][0..8]);
            tape.arith256_mod_calls.appendAssumeCapacity(call);
        }
        try tape.curve_calls.ensureTotalCapacityPrecise(a, curve_count);
        for (0..curve_count) |_| {
            var encoded: [CURVE_RECORD]u8 = undefined;
            try exact(file, &encoded);
            const op = std.meta.intToEnum(S.curves.Op, get(u32, encoded[0..4])) catch return error.InvalidTapeWireService;
            if (get(u32, encoded[4..8]) != 0) return error.InvalidTapeWireService;
            var call = S.CurveCall{ .op = op, .call_id = get(u64, encoded[8..16]), .clock = get(u64, encoded[16..24]), .pc = get(u64, encoded[24..32]), .pointer = get(u64, encoded[32..40]), .before = undefined, .after = undefined };
            for (&call.before, 0..) |*word, i| word.* = get(u64, encoded[40 + 8 * i ..][0..8]);
            for (&call.after, 0..) |*word, i| word.* = get(u64, encoded[232 + 8 * i ..][0..8]);
            tape.curve_calls.appendAssumeCapacity(call);
        }
    }
    var trailing: [1]u8 = undefined;
    if (try file.read(&trailing) != 0) return error.TrailingTapeWireData;
    try validate(&tape);
    for (tape.secp_calls.items) |call| tape.last_secp_ids[@intFromEnum(call.kind) - 1] = call.call_id;
    for (tape.curve_calls.items) |call| tape.last_curve_ids[S.curves.index(call.op)] = call.call_id;
    return tape;
}
fn validate(tape: *const T.Tape) !void {
    _ = try header(tape);
    if (tape.initial_pc & 3 != 0 or tape.initial_clock > std.math.maxInt(u64) - tape.len) return error.InvalidTapeWireGeometry;
    if ((!profile.hasServices(tape.execution_profile) and tape.service_calls.items.len != 0) or ((tape.execution_profile == .rv64im or tape.execution_profile == .keccak_service_v1) and tape.secp_calls.items.len != 0)) return error.InvalidTapeWireService;
    var memories: usize = 0;
    for (tape.steps()) |step| {
        if (step.next_pc & 3 != 0 or step.flags > 1) return error.InvalidTapeWireStep;
        if (step.memory_index != T.NO_MEMORY) {
            if (step.memory_index != memories) return error.InvalidTapeWireStep;
            memories += 1;
        }
    }
    if (memories != tape.memory_before.items.len) return error.InvalidTapeWireStep;
    var previous_k: ?K.Call = null;
    for (tape.service_calls.items) |call| {
        if (previous_k) |prior| if (prior.clock >= call.clock or prior.call_id == std.math.maxInt(u64) or call.call_id != prior.call_id + 1) return error.InvalidTapeWireService;
        try service(tape, call.clock, call.pc, call.pointer, profile.KECCAK_TAG, call.call_id);
        previous_k = call;
    }
    var previous_clock: u64 = 0;
    var ids: [2]?u64 = @splat(null);
    for (tape.secp_calls.items) |call| {
        const format: profile.SecpPacketFormat = if (profile.secpWords(tape.execution_profile)) .little_endian_words_v2 else .big_endian_bytes_v1;
        if (call.packet_format != format or call.clock <= previous_clock) return error.InvalidTapeWireService;
        const family = @intFromEnum(call.kind) - 1;
        if (ids[family]) |prior| if (prior == std.math.maxInt(u64) or call.call_id != prior + 1) return error.InvalidTapeWireService;
        if (call.kind == .double) for (call.before[12..], call.after[12..]) |before, after| if (before != 0 or after != 0) return error.InvalidTapeWireService;
        try service(tape, call.clock, call.pc, call.pointer, call.tag(), call.call_id);
        previous_clock = call.clock;
        ids[family] = call.call_id;
    }
    if (!profile.isV3(tape.execution_profile) and tape.sha256_calls.items.len != 0) return error.InvalidTapeWireService;
    var previous_sha: ?S.Sha256Call = null;
    for (tape.sha256_calls.items) |call| {
        if (previous_sha) |prior| if (prior.clock >= call.clock or prior.call_id == std.math.maxInt(u64) or call.call_id != prior.call_id + 1) return error.InvalidTapeWireService;
        if (call.pointer & 31 != 0) return error.InvalidTapeWireService;
        for (call.before[S.Sha256Call.WRITTEN..], call.after[S.Sha256Call.WRITTEN..]) |before, after| if (before != after) return error.InvalidTapeWireService;
        try service(tape, call.clock, call.pc, call.pointer, call.tag(), call.call_id);
        previous_sha = call;
    }
    if (!profile.isV3(tape.execution_profile) and tape.arith256_mod_calls.items.len != 0) return error.InvalidTapeWireService;
    var previous_arith: ?S.Arith256ModCall = null;
    for (tape.arith256_mod_calls.items) |call| {
        if (previous_arith) |prior| if (prior.clock >= call.clock or prior.call_id == std.math.maxInt(u64) or call.call_id != prior.call_id + 1) return error.InvalidTapeWireService;
        if (call.pointer & 31 != 0) return error.InvalidTapeWireService;
        for (call.before[0..S.Arith256ModCall.FIRST_WRITTEN], call.after[0..S.Arith256ModCall.FIRST_WRITTEN]) |before, after| if (before != after) return error.InvalidTapeWireService;
        try service(tape, call.clock, call.pc, call.pointer, call.tag(), call.call_id);
        previous_arith = call;
    }
    if (!profile.isV3(tape.execution_profile) and tape.curve_calls.items.len != 0) return error.InvalidTapeWireService;
    var curve_clock: u64 = 0;
    var curve_ids: [S.curves.COUNT]?u64 = @splat(null);
    for (tape.curve_calls.items) |call| {
        const k = S.curves.index(call.op);
        if (call.clock <= curve_clock or call.pointer & 31 != 0) return error.InvalidTapeWireService;
        if (curve_ids[k]) |prior| if (prior == std.math.maxInt(u64) or call.call_id != prior + 1) return error.InvalidTapeWireService;
        for (call.before[call.writtenWords()..], call.after[call.writtenWords()..], call.writtenWords()..) |before, after, i| {
            if (before != after or (i >= call.wordCount() and before != 0)) return error.InvalidTapeWireService;
        }
        try service(tape, call.clock, call.pc, call.pointer, call.tag(), call.call_id);
        curve_clock = call.clock;
        curve_ids[k] = call.call_id;
    }
}
fn service(tape: *const T.Tape, clock: u64, pc: u64, pointer: u64, tag: u64, id: u64) !void {
    if (id == 0 or pointer & 7 != 0 or clock <= tape.initial_clock or clock > tape.initial_clock + tape.len) return error.InvalidTapeWireService;
    const index: usize = @intCast(clock - tape.initial_clock - 1);
    const step = tape.storage[index];
    const actual_pc = if (index == 0) tape.initial_pc else tape.storage[index - 1].next_pc;
    if (pc != actual_pc or step.next_pc != pc +% 4 or step.lhs != pointer or step.rhs != tag or step.previous_rd != 0 or step.result != 0 or step.flags != 0 or step.memory_index != T.NO_MEMORY) return error.InvalidTapeWireService;
}
fn exact(file: std.fs.File, bytes: []u8) !void {
    if (try file.readAll(bytes) != bytes.len) return error.TruncatedTapeWireData;
}
fn put(comptime I: type, bytes: *[(@bitSizeOf(I) + 7) / 8]u8, value: I) void {
    std.mem.writeInt(I, bytes, value, .little);
}
fn get(comptime I: type, bytes: *const [(@bitSizeOf(I) + 7) / 8]u8) I {
    return std.mem.readInt(I, bytes, .little);
}
