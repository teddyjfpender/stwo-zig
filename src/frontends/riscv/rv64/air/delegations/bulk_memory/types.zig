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
/// EVM JUMPDEST analysis (proposals/jumpdest-bitmap.md): packet `code, len,
/// bitmap`; the code (64-aligned, `len/8` words) is analyzed into
/// `ceil(len/64)` bitmap words.
pub const JUMPDEST_TAG: u64 = 0x0003_0040;
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
/// JUMPDEST call token (jdesc -> first jscan row) and transition-table
/// lookup tuples (jscan bytes -> jtab rows).
pub const TOKEN_JD: u32 = 0x424D_0005;
pub const TOKEN_JD_TABLE: u32 = 0x424D_0006;

/// JUMPDEST analysis transition of one byte: `pending` PUSH-data bytes still
/// to skip before byte `b` (0..32) -> pending after it and the JUMPDEST bit.
pub const OP_JUMPDEST: u8 = 0x5b;
pub const MAX_PENDING: u32 = 32;
pub const Transition = struct { next: u8, jumpdest: u1 };
pub fn transition(pending: u8, b: u8) Transition {
    if (pending > 0) return .{ .next = pending - 1, .jumpdest = 0 };
    if (b >= 0x60 and b <= 0x7f) return .{ .next = b - 0x5f, .jumpdest = 0 };
    return .{ .next = 0, .jumpdest = @intFromBool(b == OP_JUMPDEST) };
}
/// The fixed transition table: entry `pending * 256 + b` for pending 0..32.
pub const TABLE_ENTRIES: usize = (MAX_PENDING + 1) * 256;
pub const TABLE_LOG: u32 = 14;
pub const TableEntry = struct { pending: u8, byte: u8, next: u8, jumpdest: u1 };
/// Rows past `TABLE_ENTRIES` repeat entry 0 (a valid entry) with multiplicity 0.
pub fn tableEntry(row: usize) TableEntry {
    const e = if (row < TABLE_ENTRIES) row else 0;
    const pending: u8 = @intCast(e / 256);
    const b: u8 = @intCast(e % 256);
    const t = transition(pending, b);
    return .{ .pending = pending, .byte = b, .next = t.next, .jumpdest = t.jumpdest };
}
/// Pending counters at each 64-byte row start and the bitmap words of a code
/// image (`words` u64 code words): the canonical evmone analysis.
pub fn analyzeWords(words: []const u64, pending_at_row: []u8, bitmap: []u64) void {
    std.debug.assert(pending_at_row.len == bitmap.len and bitmap.len == (words.len + 7) / 8);
    @memset(bitmap, 0);
    var pending: u8 = 0;
    for (words, 0..) |w, k| {
        if (k % 8 == 0) pending_at_row[k / 8] = pending;
        for (0..8) |i| {
            const t = transition(pending, @truncate(w >> @intCast(8 * i)));
            bitmap[k / 8] |= @as(u64, t.jumpdest) << @intCast(8 * (k % 8) + i);
            pending = t.next;
        }
    }
}

pub const Op = enum(u2) { copy = 0, set = 1, cmp = 2, jumpdest = 3 };
/// One admitted call. `dst` is the destination (copy/set) or `a` (cmp);
/// `word1` the source address (copy, any alignment), the fill word (set; only
/// its low byte is used) or `b` (cmp). `packet` are the RAM predecessors of
/// the packet words (cmp: four, the fourth is the written result word).
/// cmp: `examined` word pairs are read (first difference index + 1, or all)
/// and `result` is written. jumpdest: `dst` is the code address (64-aligned),
/// `word1` the bitmap address; `len / 8` code words are read and
/// `ceil(len / 64)` bitmap words written.
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
            .jumpdest => JUMPDEST_TAG,
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
    /// memcmp one per examined word pair; jumpdest one per code word (`src`
    /// predecessors) followed by one per bitmap word (`dst` predecessors).
    pub fn entries(self: Call) u32 {
        return switch (self.op) {
            .copy => self.count() + @intFromBool(self.shift() != 0),
            .set => self.count(),
            .cmp => self.examined,
            .jumpdest => self.count() + self.bitmapWords(),
        };
    }
    /// jumpdest: bitmap words written = body rows (8 code words per row).
    pub fn bitmapWords(self: Call) u32 {
        return (self.count() + 7) / 8;
    }
    /// Rows of the body kind: one per entry, except jumpdest (one per 8 code words).
    pub fn bodyRows(self: Call) u32 {
        return if (self.op == .jumpdest) self.bitmapWords() else self.entries();
    }
    /// The body kind that proves this call.
    pub fn body(self: Call) Kind {
        return switch (self.op) {
            .copy => if (self.shift() == 0) .copy else .ucopy,
            .set => .set,
            .cmp => .cmp,
            .jumpdest => .jscan,
        };
    }
    /// The descriptor kind of this call.
    pub fn descriptor(self: Call) Kind {
        return switch (self.op) {
            .cmp => .cdesc,
            .jumpdest => .jdesc,
            else => .desc,
        };
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

/// Challenges and claims over constant lane C (QM31 natively, a circuit
/// wire lane for recursion); the native aliases are unchanged.
pub fn ChallengesFor(comptime C: type) type {
    return struct { ram: R.types.RamChallengesFor(C), owner: Owner.OwnerChallengesFor(C), range16: Scalar.ChallengesFor(C) };
}
pub const Challenges = ChallengesFor(Q);
pub fn ClaimsFor(comptime C: type) type {
    return struct {
        ram: C,
        owner: C,
        range16: C,
        pub fn zero() @This() {
            return .{ .ram = C.zero(), .owner = C.zero(), .range16 = C.zero() };
        }
        pub fn values(self: @This()) [3]C {
            return .{ self.ram, self.owner, self.range16 };
        }
    };
}
pub const Claims = ClaimsFor(Q);
/// The public active-row count: a native integer, or a lane wire together
/// with its `rows != 0` Boolean wire for an external lane.
pub fn RowsFor(comptime C: type) type {
    return if (E.isExternalLane(C)) struct { rows: C, nonempty: C } else u32;
}

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
    // The tick stride (4, or 1 under the wide-clock CPU) is the producing CPU's
    // encoding; collectors check it against the CPU log (word16_execution.layout.ramStride).
    if (call.epoch == 0 or call.tick == 0) return error.InvalidBulkMemoryClock;
    const packet_bytes: u64 = 8 * call.packetWords();
    if (call.pointer & 7 != 0 or call.pointer > max - (packet_bytes - 1)) return error.InvalidBulkMemoryPacket;
    if (call.len == 0 or call.len % 8 != 0 or call.len > MAX_BYTES) return error.InvalidBulkMemoryLength;
    if (call.op == .jumpdest) return validateJumpdest(call, words);
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
            .jumpdest => unreachable,
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

/// jumpdest: code 64-aligned (each row's eight code words share limbs 1..3),
/// bitmap 8-aligned, no wrap, packet/code/bitmap pairwise disjoint, readable
/// packet and code, rights-3 bitmap words, every predecessor before the call.
fn validateJumpdest(call: Call, words: []const Word) !void {
    const max = std.math.maxInt(u64);
    const code_len = call.len;
    const bitmap_len: u64 = 8 * @as(u64, call.bitmapWords());
    if (call.dst & 63 != 0 or call.dst > max - (code_len - 1)) return error.InvalidBulkMemoryRange;
    if (call.word1 & 7 != 0 or call.word1 > max - (bitmap_len - 1)) return error.InvalidBulkMemoryRange;
    if (words.len != call.entries()) return error.InvalidBulkMemoryWords;
    const packet = [3]u64{ call.dst, call.len, call.word1 };
    for (call.packet[0..3], packet) |state, value| {
        if (state.value != value or state.rights & 1 == 0) return error.InvalidBulkMemoryPredecessor;
        try before(state, call);
    }
    const n = call.count();
    for (words[0..n]) |w| {
        if (w.src.rights & 1 == 0) return error.InvalidBulkMemoryPredecessor;
        try before(w.src, call);
    }
    for (words[n..]) |w| {
        if (w.dst.rights != 3) return error.InvalidBulkMemoryPredecessor;
        try before(w.dst, call);
    }
    if (overlaps(call.pointer, 24, call.dst, code_len) or overlaps(call.pointer, 24, call.word1, bitmap_len) or
        overlaps(call.dst, code_len, call.word1, bitmap_len)) return error.BulkMemoryOverlap;
}
