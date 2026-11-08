//! Canonical vector derived and locked by `core/channel/blake2s.zig`.

pub const Vector = struct {
    source: [12]u32,
    secure: [12]u32,
    queries: [13]u32,
};

pub const canonical = Vector{
    .source = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 },
    .secure = .{
        0x2de3_3d85, 0x1867_60f3, 0x016d_fb8f, 0x5526_159e,
        0x033d_fdd3, 0x5743_5736, 0x76ae_db39, 0x79a6_e4ab,
        0x5f39_484b, 0x7350_5dbc, 0x310d_05c0, 0x4581_f67d,
    },
    .queries = .{
        0x48606d, 0x3b1f59, 0xec55d9, 0xa6ea6c, 0x9bceba,
        0x7fc92c, 0xdb979b, 0x92cb97, 0x8192ec, 0xe06454,
        0x7faf73, 0x006ed0, 0x4577cb,
    },
};
