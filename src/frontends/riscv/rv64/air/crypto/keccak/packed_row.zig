//! Native witness metadata only. AIR/domain/OODS equations still consume the
//! committed polynomial columns. The two planes encode each sliced bit a+8b.
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const L = @import("layout.zig");
const Native = @import("../../../../air/guest_precompile/keccakf_witness.zig").Row;
pub const PackedRow = struct {
    state_a: [25]u64 = @splat(0),
    state_b: [25]u64 = @splat(0),
    parity_a: [5]u64 = @splat(0),
    parity_b: [5]u64 = @splat(0),
    id: u32 = 0,
    flags: u8 = 0,
    pub fn fromNative(row: *const Native, id: u32) PackedRow {
        var out = PackedRow{ .id = id, .flags = row.in_use_a | (row.in_use_b << 1) };
        for (row.state, 0..) |v, i| {
            const bit: u6 = @intCast(i % 64);
            out.state_a[i / 64] |= @as(u64, v & 1) << bit;
            out.state_b[i / 64] |= @as(u64, (v >> 3) & 1) << bit;
        }
        for (row.parity, 0..) |v, i| {
            const bit: u6 = @intCast(i % 64);
            out.parity_a[i / 64] |= @as(u64, v & 1) << bit;
            out.parity_b[i / 64] |= @as(u64, (v >> 3) & 1) << bit;
        }
        return out;
    }
    pub fn expand(self: *const PackedRow) ![L.MAIN]M {
        if (self.id >= core.fields.m31.Modulus or self.flags > 3) return error.InvalidKeccakMetadata;
        var row: [L.MAIN]M = undefined;
        for (row[0..L.STATE], 0..) |*v, i| {
            const bit: u6 = @intCast(i % 64);
            v.* = M.fromCanonical(@intCast(((self.state_a[i / 64] >> bit) & 1) | (((self.state_b[i / 64] >> bit) & 1) << 3)));
        }
        for (row[L.STATE..L.ACTIVE_A], 0..) |*v, i| {
            const bit: u6 = @intCast(i % 64);
            v.* = M.fromCanonical(@intCast(((self.parity_a[i / 64] >> bit) & 1) | (((self.parity_b[i / 64] >> bit) & 1) << 3)));
        }
        row[L.ACTIVE_A] = M.fromCanonical(self.flags & 1);
        row[L.ACTIVE_B] = M.fromCanonical((self.flags >> 1) & 1);
        row[L.BASE_ID] = M.fromCanonical(self.id);
        return row;
    }
};

comptime {
    if (@import("../../../../air/guest_precompile/keccakf_authority.zig").geometry.slot_base != 8) @compileError("Keccak packed metadata requires a+8b slices");
}
