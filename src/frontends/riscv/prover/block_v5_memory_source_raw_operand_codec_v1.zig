//! Raw-only durable operands. Independent admitted kind selects size/framing;
//! restoring dropped cells to zero must reproduce every original private bit.
//! File integrity remains a proposal; genuine replay recommits actual roots.
const std = @import("std");
const Eq = @import("../recursion/air/block_v5_memory_source_equations_v1.zig");
pub const MAX_BYTES: usize = 96;
pub fn size(kind: Eq.Kind) !usize {
    return switch (kind) {
        .sha => 96,
        .record => |r| switch (r.stream) {
            .input_words, .rw_words, .first_touches => 12,
            .endpoints => 20,
            .public_input => error.InvalidSourceRawOperandKind,
        },
        else => error.InvalidSourceRawOperandKind,
    };
}
pub fn decode(kind: Eq.Kind, bytes: []const u8) !Eq.Witness {
    if (bytes.len != try size(kind)) return error.InvalidSourceRawOperandLength;
    var w = Eq.Witness{};
    switch (kind) {
        .sha => {
            @memcpy(&w.raw, bytes[0..64]);
            for (&w.state, 0..) |*v, i| v.* = std.mem.readInt(u32, bytes[64 + 4 * i ..][0..4], .little);
        },
        .record => |r| {
            w.address = std.mem.readInt(u32, bytes[0..4], .little);
            w.previous_address = std.mem.readInt(u32, bytes[4..8], .little);
            switch (r.stream) {
                .input_words, .rw_words => w.after = std.mem.readInt(u32, bytes[8..12], .little),
                .first_touches => w.before = std.mem.readInt(u32, bytes[8..12], .little),
                .endpoints => {
                    w.clock = std.mem.readInt(u64, bytes[8..16], .little);
                    w.after = std.mem.readInt(u32, bytes[16..20], .little);
                },
                .public_input => unreachable,
            }
        },
        else => unreachable,
    }
    return w;
}
pub fn encode(kind: Eq.Kind, w: Eq.Witness, out: []u8) !void {
    if (out.len != try size(kind)) return error.InvalidSourceRawOperandLength;
    switch (kind) {
        .sha => {
            @memcpy(out[0..64], &w.raw);
            for (w.state, 0..) |v, i| std.mem.writeInt(u32, out[64 + 4 * i ..][0..4], v, .little);
        },
        .record => |r| {
            std.mem.writeInt(u32, out[0..4], w.address, .little);
            std.mem.writeInt(u32, out[4..8], w.previous_address, .little);
            switch (r.stream) {
                .input_words, .rw_words => std.mem.writeInt(u32, out[8..12], w.after, .little),
                .first_touches => std.mem.writeInt(u32, out[8..12], w.before, .little),
                .endpoints => {
                    std.mem.writeInt(u64, out[8..16], w.clock, .little);
                    std.mem.writeInt(u32, out[16..20], w.after, .little);
                },
                .public_input => unreachable,
            }
        },
        else => unreachable,
    }
    if (!std.meta.eql(w, try decode(kind, out))) return error.NonCanonicalSourceRawOperand;
}
