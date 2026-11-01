//! Admitted bulk-memory call metadata, challenges, claims and geometry bounds.
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
/// Largest admitted call: 2^20 bytes = 2^17 words. Guests split larger copies.
pub const MAX_BYTES: u64 = 1 << 20;
pub const MAX_WORDS: u64 = MAX_BYTES / 8;
/// OWNER19 slot-0 values of the call tokens. CPU OWNER tuples carry a decoded
/// opcode (< 256) in slot 0, so tokens never meet CPU, LS or bridge tuples.
pub const TOKEN_COPY: u32 = 0x424D_0001;
pub const TOKEN_SET: u32 = 0x424D_0002;

pub const Op = enum(u1) { copy = 0, set = 1 };
/// One admitted call. `word1` is the source address (copy) or the fill word
/// (set; only its low byte is used). `packet` are the RAM predecessors of the
/// three packet words, `words` the predecessors of every touched data word.
pub const Call = struct {
    op: Op,
    pointer: u64,
    epoch: u16,
    tick: u24,
    dst: u64,
    word1: u64,
    len: u64,
    packet: [3]State,
    pub fn count(self: Call) u32 {
        return @intCast(self.len / 8);
    }
    pub fn tag(self: Call) u64 {
        return if (self.op == .copy) MEMCPY_TAG else MEMSET_TAG;
    }
    pub fn fill(self: Call) u8 {
        return @truncate(self.word1);
    }
};
/// Predecessor states of one data word: `dst` always, `src` for copies only.
pub const Word = struct { dst: State, src: State = .{ .value = 0, .rights = 0 } };

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
    // Every per-row relation mass (RAM <= 6, OWNER <= 3, range16 <= 17 per row)
    // stays below the M31 characteristic for each component on its own.
    if (@as(u64, @import("layout.zig").range16Count(kind)) * n >= core.fields.m31.Modulus) return error.BulkMemoryMassBound;
    return n;
}

pub fn validateCall(call: Call, words: []const Word) !void {
    const max = std.math.maxInt(u64);
    if (call.epoch == 0 or call.tick == 0 or call.tick & 3 != 0) return error.InvalidBulkMemoryClock;
    if (call.pointer & 7 != 0 or call.pointer > max - 23) return error.InvalidBulkMemoryPacket;
    if (call.len == 0 or call.len % 8 != 0 or call.len > MAX_BYTES) return error.InvalidBulkMemoryLength;
    if (call.dst & 7 != 0 or call.dst > max - (call.len - 1)) return error.InvalidBulkMemoryRange;
    if (call.op == .copy and (call.word1 & 7 != 0 or call.word1 > max - (call.len - 1))) return error.InvalidBulkMemoryRange;
    if (words.len != call.count()) return error.InvalidBulkMemoryWords;
    const packet = [3]u64{ call.dst, call.word1, call.len };
    for (call.packet, packet) |state, value| {
        if (state.value != value or state.rights & 1 == 0) return error.InvalidBulkMemoryPredecessor;
        try before(state, call);
    }
    for (words) |word| {
        if (word.dst.rights != 3) return error.InvalidBulkMemoryPredecessor;
        try before(word.dst, call);
        if (call.op == .copy) {
            if (word.src.rights & 1 == 0) return error.InvalidBulkMemoryPredecessor;
            try before(word.src, call);
        }
    }
    // Pairwise distinct words: the shared tick makes any alias unprovable.
    const p0 = call.pointer;
    const d0 = call.dst;
    if (overlaps(p0, 24, d0, call.len)) return error.BulkMemoryOverlap;
    if (call.op == .copy) {
        const s0 = call.word1;
        if (overlaps(p0, 24, s0, call.len) or overlaps(d0, call.len, s0, call.len)) return error.BulkMemoryOverlap;
    }
}
fn before(state: State, call: Call) !void {
    if (state.epoch > call.epoch or (state.epoch == call.epoch and state.tick >= call.tick)) return error.InvalidBulkMemoryPredecessor;
}
pub fn overlaps(a: u64, a_len: u64, b: u64, b_len: u64) bool {
    return @as(u65, a) < @as(u65, b) + b_len and @as(u65, b) < @as(u65, a) + a_len;
}
