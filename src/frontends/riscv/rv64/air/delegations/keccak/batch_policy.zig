//! Explicit lookup clearing policy; default v2 remains triple.
//! `throughput_v1` reinterprets the same MAIN witness through the RV32
//! throughput tables (one chi lookup per five-lane row, one xor5 lookup per
//! three parity positions; `keccakf_throughput_tables_v1.zig`). Its identity is
//! mixed before roots by every owner that selects it.
const L = @import("layout.zig");
const authority = @import("../../../../air/guest_precompile/keccakf_authority.zig");
pub const THROUGHPUT_CHI = authority.geometry.chi_lookups_per_round;
pub const THROUGHPUT_XOR5 = authority.geometry.xor5_lookups_per_round;
pub const THROUGHPUT_LOOKUPS = THROUGHPUT_CHI + THROUGHPUT_XOR5;
pub const Table = enum { chi, xor5 };
pub const Policy = enum {
    triple_v2,
    quartet_v3,
    throughput_v1,
    pub fn width(self: Policy) usize {
        return if (self == .quartet_v3) 4 else 3;
    }
    /// Round-row lookups (each chi/xor5 query owns one fraction).
    pub fn lookups(self: Policy) usize {
        return if (self == .throughput_v1) THROUGHPUT_LOOKUPS else L.LOOKUPS;
    }
    pub fn chiLookups(self: Policy) usize {
        return if (self == .throughput_v1) THROUGHPUT_CHI else L.STATE;
    }
    pub fn xor5Lookups(self: Policy) usize {
        return if (self == .throughput_v1) THROUGHPUT_XOR5 else L.PARITY;
    }
    /// A trailing partial batch holds dummy entries (denominator one, weight zero).
    pub fn roundBatches(self: Policy) usize {
        return (self.lookups() + self.width() - 1) / self.width();
    }
    pub fn ioBatches(self: Policy) usize {
        return (L.IO_LANES + self.width() - 1) / self.width();
    }
    pub fn batches(self: Policy) usize {
        return self.roundBatches() + self.ioBatches();
    }
    pub fn interactionCount(self: Policy) usize {
        return 4 * self.batches();
    }
    pub fn constraints(self: Policy) usize {
        return L.DIRECT + self.batches();
    }
    pub fn degree(self: Policy) u8 {
        return @intCast(self.width() + 1);
    }
    pub fn tableLog(self: Policy, table: Table) u32 {
        return switch (self) {
            .throughput_v1 => if (table == .chi) 21 else 16,
            else => if (table == .chi) 13 else 10,
        };
    }
    /// New authority is mixed before roots/challenges by the experimental owner.
    /// Legacy owners never call this and retain their old transcript exactly.
    pub fn mix(self: Policy, channel: anytype) void {
        channel.mixU32s(&.{ 0x4b424154, 1, @intFromEnum(self), @intCast(self.width()), @intCast(self.interactionCount()), self.degree() });
        // Throughput also binds its table universes and per-row query counts.
        if (self == .throughput_v1) channel.mixU32s(&.{ 0x4b545055, 1, self.tableLog(.chi), self.tableLog(.xor5), @intCast(THROUGHPUT_CHI), @intCast(THROUGHPUT_XOR5), @intCast(self.batches()) });
    }
};
comptime {
    // Design receipt: 143 round + 9 IO batches, 608 interaction columns, degree 4.
    if (Policy.throughput_v1.roundBatches() != 143 or Policy.throughput_v1.batches() != 152 or Policy.throughput_v1.interactionCount() != 608 or Policy.throughput_v1.degree() != 4) @compileError("throughput Keccak batch geometry drifted");
    if (Policy.triple_v2.batches() != L.BATCHES) @compileError("triple Keccak batch geometry drifted");
}
