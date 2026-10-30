//! Disabled same-ROM macro certificate for an existing five-instruction RV32
//! byte-copy loop. This is not a new opcode, a STARK, or a source receipt.
//! A future verifier must independently rebuild the ELF image, prove the call
//! bounds/byte transfer, and authenticate all exposed relation contributions.
const std = @import("std");
const core = @import("stwo_core");
const Decode = @import("../program/decode.zig");
const Image = @import("../../prover/block_v7_program_image_v1.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
pub const production_active = false;
pub const whole_source_qualified = false;
pub const INSTRUCTIONS_PER_BYTE: u32 = 5;
pub const words = [5]u32{ 0x0005c703, 0x00e68023, 0x00168693, 0x00158593, 0xfec698e3 };
pub const registers = [4]u5{ 11, 13, 14, 12 };
pub const FirstAccess = [4]u32{ 1, 5, 2, 18 };
pub const LastAccess = [4]u32{ 14, 17, 6, 18 };
pub const Fetch = struct { tuple: [5]u32, count: u32 };
pub const Certificate = struct {
    pc: u32,
    program_root: [32]u8,
    tuples: [5][5]u32,
    pub fn fromWords(pc: u32, proposed: [5]u32, program_root: [32]u8) !Certificate {
        if (pc % 4 != 0 or pc > (1 << 30) - 24 or std.mem.allEqual(u8, &program_root, 0)) return error.InvalidByteLoopCertificate;
        if (!std.meta.eql(proposed, words)) return error.UnrecognizedByteLoop;
        var tuples: [5][5]u32 = undefined;
        for (words, &tuples, 0..) |word, *tuple, i| {
            tuple[0] = pc + 4 * @as(u32, @intCast(i));
            const decoded = try Decode.decodeProgramWord(word);
            @memcpy(tuple[1..], &decoded);
        }
        return .{ .pc = pc, .program_root = program_root, .tuples = tuples };
    }
    /// Image is independently reconstructed from admitted ELF bytes/policy.
    /// This constructor never treats an alleged source hash as ROM authority.
    pub fn fromProgramImage(image: *const Image.Owned, pc: u32) !Certificate {
        try @import("../program/blake3_root_cache.zig").validate(image.leaves, image.root);
        const certificate = try fromWords(pc, words, image.root.bytes);
        for (certificate.tuples) |tuple| for (0..4) |i| {
            const index = tuple[0] + @as(u32, @intCast(i));
            var low: usize = 0;
            var high = image.leaves.len;
            while (low < high) {
                const mid = low + (high - low) / 2;
                if (image.leaves[mid].index < index) low = mid + 1 else high = mid;
            }
            if (low == image.leaves.len or image.leaves[low].index != index or image.leaves[low].value != tuple[i + 1]) return error.UnrecognizedByteLoop;
        };
        return certificate;
    }
    pub fn validate(self: Certificate) !void {
        if (!std.meta.eql(self, try fromWords(self.pc, words, self.program_root))) return error.InvalidByteLoopCertificate;
    }
    pub fn require(self: Certificate, independently_rebuilt: Certificate) !void {
        if (!std.meta.eql(self, independently_rebuilt)) return error.UntrustedByteLoopCertificate;
    }
    pub fn fetches(self: Certificate, count: u32) ![5]Fetch {
        try self.validate();
        if (count == 0 or count > (1 << 24) / 5) return error.InvalidByteLoopLength;
        var result: [5]Fetch = undefined;
        for (&result, self.tuples) |*fetch, tuple| fetch.* = .{ .tuple = tuple, .count = count };
        return result;
    }
};
pub const WordPlan = struct {
    destination_word: u32,
    source_low_word: ?u32,
    source_high_word: ?u32,
    start: u2,
    end: u3,
    shift: u2,
    first_store_clock: u32,
    final_store_clock: u32,
};
pub const Call = struct {
    entry_cycle: u32,
    source: u32,
    destination: u32,
    destination_end: u32,
    length: u32,
    max_instruction_cycle: u32,
    pub fn validate(self: Call) !void {
        if (self.entry_cycle == 0 or self.length == 0 or self.max_instruction_cycle > 1 << 24) return error.InvalidByteLoopCall;
        const retired = try std.math.mul(u32, self.length, INSTRUCTIONS_PER_BYTE);
        const last = try std.math.add(u32, self.entry_cycle, retired - 1);
        if (last > self.max_instruction_cycle) return error.InvalidByteLoopCall;
        const source_end = try std.math.add(u32, self.source, self.length);
        const destination_after = try std.math.add(u32, self.destination, self.length);
        if (source_end > 1 << 30 or destination_after > self.destination_end or self.destination_end > 1 << 30) return error.InvalidByteLoopCall;
        // Atomic word collapse is used only for disjoint aligned word spans.
        // All excluded aliases retain ordinary RV32 execution.
        const s0 = self.source / 4;
        const s1 = (source_end + 3) / 4;
        const d0 = self.destination / 4;
        const d1 = (destination_after + 3) / 4;
        if (!(s1 <= d0 or d1 <= s0)) return error.OverlappingByteLoopWords;
    }
    pub fn retiredInstructions(self: Call) !u32 {
        try self.validate();
        return self.length * 5;
    }
    pub fn nextCycle(self: Call) !u32 {
        return self.entry_cycle + try self.retiredInstructions();
    }
    pub fn nextPc(self: Call, certificate: Certificate) !u32 {
        try self.validate();
        return if (self.destination + self.length == self.destination_end) certificate.pc + 20 else certificate.pc;
    }
    pub fn finalRegisterValues(self: Call, last_loaded_byte: u8) ![4]u32 {
        try self.validate();
        return .{ self.source + self.length, self.destination + self.length, last_loaded_byte, self.destination_end };
    }
    pub fn firstRegisterClocks(self: Call) ![4]u32 {
        try self.validate();
        const base = 4 * (self.entry_cycle - 1);
        var result: [4]u32 = undefined;
        for (&result, FirstAccess) |*value, delta| value.* = base + delta;
        return result;
    }
    pub fn finalRegisterClocks(self: Call) ![4]u32 {
        try self.validate();
        const base = 4 * (self.entry_cycle - 1) + 20 * (self.length - 1);
        var result: [4]u32 = undefined;
        for (&result, LastAccess) |*value, delta| value.* = base + delta;
        return result;
    }
    pub fn destinationWordCount(self: Call) !u32 {
        try self.validate();
        return ((self.destination & 3) + self.length + 3) / 4;
    }
    pub fn sourceWordCount(self: Call) !u32 {
        try self.validate();
        return ((self.source & 3) + self.length + 3) / 4;
    }
    /// Geometry only; the AIR must prove this mapping. Optional source ports
    /// suppress an unused word before address zero or beyond the copied span.
    pub fn destinationWordPlan(self: Call, index: u32) !WordPlan {
        if (index >= try self.destinationWordCount()) return error.InvalidByteLoopWord;
        const destination_word = (self.destination & ~@as(u32, 3)) + 4 * index;
        const start: u2 = if (index == 0) @truncate(self.destination) else 0;
        const end: u3 = @intCast(@min(@as(u32, 4), self.destination + self.length - destination_word));
        const mapped = @as(i64, self.source) + @as(i64, destination_word) - @as(i64, self.destination);
        const source_low = @divFloor(mapped, 4) * 4;
        const shift: u2 = @intCast(@mod(mapped, 4));
        const need_low = @as(u32, start) + shift < 4;
        const need_high = @as(u32, end) + shift > 4;
        if ((need_low and (source_low < 0 or source_low >= 1 << 30)) or (need_high and (source_low + 4 < 0 or source_low + 4 >= 1 << 30))) return error.InvalidByteLoopWord;
        return .{ .destination_word = destination_word, .source_low_word = if (need_low) @intCast(source_low) else null, .source_high_word = if (need_high) @intCast(source_low + 4) else null, .start = start, .end = end, .shift = shift, .first_store_clock = try self.firstWordClock(false, destination_word), .final_store_clock = try self.finalWordClock(false, destination_word) };
    }
    /// Previous external word timestamps must precede this FIRST real access,
    /// even though a macro exports only the final per-word transition time.
    pub fn firstWordClock(self: Call, source_word: bool, word_address: u32) !u32 {
        try self.validate();
        if (word_address % 4 != 0 or word_address >= 1 << 30) return error.InvalidByteLoopWord;
        const start = if (source_word) self.source else self.destination;
        const end = start + self.length;
        if (word_address + 4 <= start or word_address >= end) return error.InvalidByteLoopWord;
        const first_address = @max(word_address, start);
        return 4 * (self.entry_cycle - 1) + 20 * (first_address - start) + (if (source_word) @as(u32, 3) else 7);
    }
    /// The final real load of a source word / store of a destination word.
    /// These clocks preserve external native endpoints; duplicate local value
    /// queries MUST NOT be emitted as duplicate external RAM transitions.
    pub fn finalWordClock(self: Call, source_word: bool, word_address: u32) !u32 {
        try self.validate();
        if (word_address % 4 != 0 or word_address >= 1 << 30) return error.InvalidByteLoopWord;
        const start = if (source_word) self.source else self.destination;
        const end = start + self.length;
        if (word_address + 4 <= start or word_address >= end) return error.InvalidByteLoopWord;
        const final_address = @min(word_address + 3, end - 1);
        const iteration = final_address - start;
        return 4 * (self.entry_cycle - 1) + 20 * iteration + (if (source_word) @as(u32, 3) else 7);
    }
};
/// Pure contribution arithmetic, never original proof authentication. Call
/// length and the last byte must be linked to proved macro/word rows first.
pub fn programContribution(certificate: Certificate, call: Call, relations: anytype) !Q {
    try call.validate();
    var result = Q.zero();
    for (try certificate.fetches(call.length)) |fetch| {
        var tuple: [5]M = undefined;
        for (&tuple, fetch.tuple) |*value, word| value.* = M.fromCanonical(word);
        result = result.sub(try (try relations.get(.program_access).combineBase(&tuple)).inv());
        // The request multiplicity is exactly N for EACH of the five PCs.
    }
    return result.mulM31(M.fromCanonical(call.length));
}

pub fn stateContribution(certificate: Certificate, call: Call, relations: anytype) !Q {
    try certificate.validate();
    try call.validate();
    const before = [2]M{ M.fromCanonical(certificate.pc), M.fromCanonical(call.entry_cycle) };
    const after = [2]M{ M.fromCanonical(try call.nextPc(certificate)), M.fromCanonical(try call.nextCycle()) };
    return (try (try relations.get(.registers_state).combineBase(&after)).inv()).sub(try (try relations.get(.registers_state).combineBase(&before)).inv());
}
pub fn registerContribution(call: Call, previous_clocks: [4]u32, initial_scratch: u32, last_loaded_byte: u8, relations: anytype) !Q {
    try call.validate();
    const first = try call.firstRegisterClocks();
    const final = try call.finalRegisterClocks();
    const initial_values = [4]u32{ call.source, call.destination, initial_scratch, call.destination_end };
    const final_values = try call.finalRegisterValues(last_loaded_byte);
    var result = Q.zero();
    for (registers, previous_clocks, first, final, initial_values, final_values) |reg, previous, first_clock, final_clock, initial_value, final_value| {
        if (previous >= first_clock or (previous != 0 and previous % 4 == 0)) return error.InvalidByteLoopRegisterPredecessor;
        var before = [7]M{ M.zero(), M.fromCanonical(reg), M.fromCanonical(previous), M.zero(), M.zero(), M.zero(), M.zero() };
        var after = [7]M{ M.zero(), M.fromCanonical(reg), M.fromCanonical(final_clock), M.zero(), M.zero(), M.zero(), M.zero() };
        for (0..4) |byte| {
            before[3 + byte] = M.fromCanonical((initial_value >> @as(u5, @intCast(8 * byte))) & 255);
            after[3 + byte] = M.fromCanonical((final_value >> @as(u5, @intCast(8 * byte))) & 255);
        }
        result = result.sub(try (try relations.get(.memory_access).combineBase(&before)).inv()).add(try (try relations.get(.memory_access).combineBase(&after)).inv());
    }
    return result;
}
