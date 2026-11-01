//! Admitted bulk-memory call metadata, challenges, claims and geometry bounds.
//! Calls: memcpy (aligned or unaligned source), memset, memcmp.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../../evaluation.zig");
const R = @import("../../memory/closed_ram/mod.zig");
const Owner = @import("../../memory/load_store_v2/types.zig");
const Scalar = @import("../../providers/scalar_range.zig");
pub const Q = E.Q;
pub const State = R.types.State;

pub const MEMCPY_TAG: u64 = 0x0003_0001;
pub const MEMSET_TAG: u64 = 0x0003_0002;
pub const MEMCMP_TAG: u64 = 0x0003_0003;
/// Largest admitted call: 2^20 bytes = 2^17 words. Guests split larger copies.
pub const MAX_BYTES: u64 = 1 << 20;
pub const MAX_WORDS: u64 = MAX_BYTES / 8;
/// OWNER19 slot-0 values of the call tokens. CPU OWNER tuples carry a decoded
/// opcode (< 256) in slot 0, so tokens never meet CPU, LS or bridge tuples.
pub const TOKEN_COPY: u32 = 0x424D_0001;
pub const TOKEN_SET: u32 = 0x424D_0002;
/// memcmp call token (desc -> body) and result token (last body row -> desc).
pub const TOKEN_CMP: u32 = 0x424D_0003;
pub const TOKEN_CMP_RESULT: u32 = 0x424D_0004;

pub const Op = enum(u2) { copy = 0, set = 1, cmp = 2 };
/// One admitted call. `dst` is the destination (copy/set) or `a` (cmp);
/// `word1` the source address (copy, any alignment), the fill word (set; only
/// its low byte is used) or `b` (cmp). `packet` are the RAM predecessors of
/// the packet words (cmp: four, the fourth is the written result word).
/// cmp: `examined` word pairs are read (first difference index + 1, or all)
/// and `result` is written.
pub const Call = struct {
    op: Op,
    pointer: u64,
    epoch: u16,
    tick: u24,
    dst: u64,
    word1: u64,
    len: u64,
    packet: [4]State,
    examined: u32 = 0,
    result: i2 = 0,
    /// Destination words (copy/set) or the word length (cmp).
    pub fn count(self: Call) u32 {
        return @intCast(self.len / 8);
    }
    pub fn tag(self: Call) u64 {
        return switch (self.op) {
            .copy => MEMCPY_TAG,
            .set => MEMSET_TAG,
            .cmp => MEMCMP_TAG,
        };
    }
    pub fn fill(self: Call) u8 {
        return @truncate(self.word1);
    }
    /// Byte offset of an unaligned memcpy source inside its aligned word.
    pub fn shift(self: Call) u3 {
        return if (self.op == .copy) @truncate(self.word1) else 0;
    }
    pub fn packetWords(self: Call) usize {
        return if (self.op == .cmp) 4 else 3;
    }
    /// `Word` entries (= body rows) of this call: one per destination word;
    /// an unaligned copy has one more (a lead row reading source word 0); a
    /// memcmp one per examined word pair.
    pub fn entries(self: Call) u32 {
        return switch (self.op) {
            .copy => self.count() + @intFromBool(self.shift() != 0),
            .set => self.count(),
            .cmp => self.examined,
        };
    }
    /// The body kind that proves this call.
    pub fn body(self: Call) Kind {
        return switch (self.op) {
            .copy => if (self.shift() == 0) .copy else .ucopy,
            .set => .set,
            .cmp => .cmp,
        };
    }
    /// The descriptor kind of this call.
    pub fn descriptor(self: Call) Kind {
        return if (self.op == .cmp) .cdesc else .desc;
    }
};
const Kind = @import("layout.zig").Kind;
/// Predecessor states of one body row. copy: `dst`, `src` of word j. set:
/// `dst`. unaligned copy row r: `src` = source word r, `dst` = destination
/// word r - 1 (unused on the lead row r = 0). cmp row j: `dst` = word j of
/// `a`, `src` = word j of `b`.
pub const Word = struct { dst: State, src: State = .{ .value = 0, .rights = 0 } };
/// The memcmp result of two words compared byte by byte in memory order.
pub fn compareWords(a: u64, b: u64) i2 {
    if (a == b) return 0;
    const shift_: u6 = @intCast(@ctz(a ^ b) & ~@as(u32, 7));
    return if ((a >> shift_) & 0xff < (b >> shift_) & 0xff) -1 else 1;
}
/// Destination word from source words `lo`, `hi` at byte shift `r`.
pub fn shifted(lo: u64, hi: u64, r: u3) u64 {
    if (r == 0) return lo;
    const s: u6 = @as(u6, r) * 8;
    return (lo >> s) | (hi << @intCast(64 - @as(u7, s)));
}

pub const Challenges = struct { ram: R.types.RamChallenges, owner: Owner.OwnerChallenges, range16: Scalar.Challenges };
pub const Claims = struct {
    ram: Q,
    owner: Q,
    range16: Q,
    pub fn zero() @This() {
        return .{ .ram = Q.zero(), .owner = Q.zero(), .range16 = Q.zero() };
    }
    pub fn values(self: @This()) [3]Q {
        return .{ self.ram, self.owner, self.range16 };
    }
};

/// `rows` active rows must leave at least one inactive row (wrap-around guard).
pub fn validateGeometry(kind: @import("layout.zig").Kind, rows: u64, log: u32) !usize {
    if (log < 5 or log > 24) return error.InvalidBulkMemoryGeometry;
    const n = @as(usize, 1) << @intCast(log);
    if (rows >= n) return error.InvalidBulkMemoryGeometry;
    // Every per-row relation mass (RAM <= 8, OWNER <= 3, range16 <= 18 per row)
    // stays below the M31 characteristic for each component on its own.
    if (@as(u64, @import("layout.zig").range16Count(kind)) * n >= core.fields.m31.Modulus) return error.BulkMemoryMassBound;
    return n;
}

pub fn validateCall(call: Call, words: []const Word) !void {
    const max = std.math.maxInt(u64);
    if (call.epoch == 0 or call.tick == 0 or call.tick & 3 != 0) return error.InvalidBulkMemoryClock;
    const packet_bytes: u64 = 8 * call.packetWords();
    if (call.pointer & 7 != 0 or call.pointer > max - (packet_bytes - 1)) return error.InvalidBulkMemoryPacket;
    if (call.len == 0 or call.len % 8 != 0 or call.len > MAX_BYTES) return error.InvalidBulkMemoryLength;
    if (call.dst & 7 != 0 or call.dst > max - (call.len - 1)) return error.InvalidBulkMemoryRange;
    // Words read on the second operand: the source words holding a copied
    // byte (len/8, plus one when unaligned) or the b range (cmp).
    const second = call.word1 & ~@as(u64, 7);
    const second_len: u64 = call.len + (if (call.op == .copy and call.shift() != 0) @as(u64, 8) else 0);
    if (call.op == .cmp and call.word1 & 7 != 0) return error.InvalidBulkMemoryRange;
    if (call.op != .set and second > max - (second_len - 1)) return error.InvalidBulkMemoryRange;
    if (words.len != call.entries()) return error.InvalidBulkMemoryWords;
    if (call.op == .cmp and (call.examined == 0 or call.examined > call.count())) return error.InvalidBulkMemoryWords;
    const packet = [3]u64{ call.dst, call.word1, call.len };
    for (call.packet[0..3], packet) |state, value| {
        if (state.value != value or state.rights & 1 == 0) return error.InvalidBulkMemoryPredecessor;
        try before(state, call);
    }
    if (call.op == .cmp) {
        if (call.packet[3].rights != 3) return error.InvalidBulkMemoryPredecessor;
        try before(call.packet[3], call);
    }
    for (words, 0..) |word, j| {
        const writes = switch (call.op) {
            .copy => call.shift() == 0 or j != 0,
            .set => true,
            .cmp => false,
        };
        if (writes) {
            if (word.dst.rights != 3) return error.InvalidBulkMemoryPredecessor;
            try before(word.dst, call);
        }
        if (call.op == .cmp) {
            if (word.dst.rights & 1 == 0) return error.InvalidBulkMemoryPredecessor;
            try before(word.dst, call);
        }
        if (call.op != .set) {
            if (word.src.rights & 1 == 0) return error.InvalidBulkMemoryPredecessor;
            try before(word.src, call);
        }
    }
    if (call.op == .cmp) {
        for (words[0 .. words.len - 1]) |w| if (w.dst.value != w.src.value) return error.InvalidBulkMemoryResult;
        const last = words[words.len - 1];
        const r = compareWords(last.dst.value, last.src.value);
        if (r != call.result or (r == 0 and call.examined != call.count())) return error.InvalidBulkMemoryResult;
    }
    // Pairwise distinct words: the shared tick makes any alias unprovable.
    const p0 = call.pointer;
    const d0 = call.dst;
    if (overlaps(p0, packet_bytes, d0, call.len)) return error.BulkMemoryOverlap;
    if (call.op != .set) {
        if (overlaps(p0, packet_bytes, second, second_len) or overlaps(d0, call.len, second, second_len)) return error.BulkMemoryOverlap;
    }
}
fn before(state: State, call: Call) !void {
    if (state.epoch > call.epoch or (state.epoch == call.epoch and state.tick >= call.tick)) return error.InvalidBulkMemoryPredecessor;
}
pub fn overlaps(a: u64, a_len: u64, b: u64, b_len: u64) bool {
    return @as(u65, a) < @as(u65, b) + b_len and @as(u65, b) < @as(u65, a) + a_len;
}
