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
    /// Throughput tables and tuples (identical MAIN, tables and multiplicities
    /// to `throughput_v1`) cleared four per degree-five batch: 107 round
    /// batches (the last holds three queries and one dummy) + 7 IO batches =
    /// 114 batches, 456 interaction columns (throughput-v1: 152 / 608).
    throughput_quartet_v1,
    /// Throughput-quartet lookups on the 27-row slot (`L.Geometry.pair27`):
    /// one complemented A plane per direction instead of two planes, so the
    /// IO lookups split into an A group (planes) and a B group (packed
    /// state minus plane): 50 IO entries in 13 quartets. 107 + 13 = 120
    /// batches, 480 interaction columns, 27 rows per pair (pair29: 29).
    throughput_r27_v1,
    pub fn width(self: Policy) usize {
        return if (self == .quartet_v3 or self == .throughput_quartet_v1 or self == .throughput_r27_v1) 4 else 3;
    }
    /// True for every profile that commits the RV32 throughput tables
    /// (2^21 chi, 2^16 xor5) and the throughput query tuples.
    pub fn throughputTables(self: Policy) bool {
        return self == .throughput_v1 or self == .throughput_quartet_v1 or self == .throughput_r27_v1;
    }
    pub fn geometry(self: Policy) L.Geometry {
        return if (self == .throughput_r27_v1) .pair27 else .pair29;
    }
    /// IO11 entries per row: 25 lanes, or 25 A-group + 25 B-group lanes.
    pub fn ioLookups(self: Policy) usize {
        return if (self == .throughput_r27_v1) 2 * L.IO_LANES else L.IO_LANES;
    }
    /// Round-row lookups (each chi/xor5 query owns one fraction).
    pub fn lookups(self: Policy) usize {
        return if (self.throughputTables()) THROUGHPUT_LOOKUPS else L.LOOKUPS;
    }
    pub fn chiLookups(self: Policy) usize {
        return if (self.throughputTables()) THROUGHPUT_CHI else L.STATE;
    }
    pub fn xor5Lookups(self: Policy) usize {
        return if (self.throughputTables()) THROUGHPUT_XOR5 else L.PARITY;
    }
    /// A trailing partial batch holds dummy entries (denominator one, weight zero).
    pub fn roundBatches(self: Policy) usize {
        return (self.lookups() + self.width() - 1) / self.width();
    }
    pub fn ioBatches(self: Policy) usize {
        return (self.ioLookups() + self.width() - 1) / self.width();
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
            .throughput_v1, .throughput_quartet_v1, .throughput_r27_v1 => if (table == .chi) 21 else 16,
            else => if (table == .chi) 13 else 10,
        };
    }
    /// New authority is mixed before roots/challenges by the experimental owner.
    /// Legacy owners never call this and retain their old transcript exactly.
    pub fn mix(self: Policy, channel: anytype) void {
        channel.mixU32s(&.{ 0x4b424154, 1, @intFromEnum(self), @intCast(self.width()), @intCast(self.interactionCount()), self.degree() });
        // Throughput also binds its table universes and per-row query counts.
        if (self.throughputTables()) channel.mixU32s(&.{ 0x4b545055, 1, self.tableLog(.chi), self.tableLog(.xor5), @intCast(THROUGHPUT_CHI), @intCast(THROUGHPUT_XOR5), @intCast(self.batches()) });
        // The 27-row slot also binds its geometry and IO grouping.
        if (self.geometry() == .pair27) channel.mixU32s(&.{ 0x4b523237, 1, @intCast(self.geometry().rowsPerPair()), @intCast(self.ioLookups()), @intCast(self.ioBatches()) });
    }
};
comptime {
    // Design receipt: 143 round + 9 IO batches, 608 interaction columns, degree 4.
    if (Policy.throughput_v1.roundBatches() != 143 or Policy.throughput_v1.batches() != 152 or Policy.throughput_v1.interactionCount() != 608 or Policy.throughput_v1.degree() != 4) @compileError("throughput Keccak batch geometry drifted");
    // Throughput quartet: 107 round + 7 IO batches, 456 interaction columns, degree 5.
    if (Policy.throughput_quartet_v1.roundBatches() != 107 or Policy.throughput_quartet_v1.ioBatches() != 7 or Policy.throughput_quartet_v1.batches() != 114 or Policy.throughput_quartet_v1.interactionCount() != 456 or Policy.throughput_quartet_v1.degree() != 5) @compileError("throughput quartet Keccak batch geometry drifted");
    // 27-row throughput: 107 round + 13 IO batches, 480 interaction columns, degree 5.
    if (Policy.throughput_r27_v1.roundBatches() != 107 or Policy.throughput_r27_v1.ioBatches() != 13 or Policy.throughput_r27_v1.batches() != 120 or Policy.throughput_r27_v1.interactionCount() != 480 or Policy.throughput_r27_v1.degree() != 5) @compileError("27-row throughput Keccak batch geometry drifted");
    if (Policy.triple_v2.batches() != L.BATCHES) @compileError("triple Keccak batch geometry drifted");
}
