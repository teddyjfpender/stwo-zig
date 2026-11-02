//! Scope of the authenticated OM GKR / wide services route: the v2 roster only
//! (CPU bridges and truths for Keccak, secp256k1 ADD and DOUBLE). Its CPU
//! roles, global layouts, masses, statements and truth components enumerate
//! exactly those three families. Every v3 extension of the classic services
//! route (SHA-256, arith256_mod, curve/field families, bulk memory incl. the
//! unaligned ucopy/cdesc/cmp and JUMPDEST jdesc/jscan/jtab kinds, Keccak
//! sponge, the LS-D64 aligned-doubleword load/store head/tail components, and
//! the throughput_v1 Keccak-f truth profile) and every v3 CPU AIR layout
//! (fused-tail interaction, U8 byte-pair queries) is rejected here, at each admission boundary, instead of being
//! silently dropped or mis-typed as a secp bridge. Lifting this requires
//! porting each v3 family into the GKR roles and global authorities.
const T = @import("../types.zig");
const P = @import("../protocol.zig");
const R = @import("../roster.zig");

pub fn family(f: T.Family) !void {
    if (@intFromEnum(f) >= T.V2_FAMILIES) return error.GkrV3ServiceUnsupported;
}
pub fn bridges(logs: T.Logs) !void {
    for (T.V3) |f| if (logs.at(f) != null) return error.GkrV3ServiceUnsupported;
    if (logs.bulk.any() or logs.sponge.any()) return error.GkrV3ServiceUnsupported;
    // LS-D64 has no GKR role, mass or statement; every LD/SD stays LS32 here.
    if (logs.ls_dword != null or logs.ls_dword_tail != null) return error.GkrV3ServiceUnsupported;
}
/// CPU geometry: the local GKR lane replaces the CPU LogUp interaction with
/// its own term layout (`roster.terms(.cpu)`) over the historical 40-column
/// CPU AIR and the single-multiplicity AND table; it has no fused-tail or
/// byte-pair variant.
pub fn geometry(g: @import("../../../word16_execution/geometry.zig").Geometry) !void {
    if (g.cpu_fused_tail or g.cpu_u8_pairs) return error.UnsupportedFusedTailInLocalGkr;
}
/// CPU declaration (wire/plan admission): geometry and bridges.
pub fn declaration(d: @import("../wire.zig").CpuDeclaration) !void {
    try geometry(d.geometry);
    try bridges(d.bridges);
}
pub fn setup(s: *const R.CpuSetup) !void {
    try geometry(s.materials.geometry);
    return bridges(s.bridges);
}
pub fn calls(all: [T.FAMILIES]u32, bulk: T.BulkCounts, sponge: T.SpongeCounts, ls_dword: u32) !void {
    for (all[T.V2_FAMILIES..]) |n| if (n != 0) return error.GkrV3ServiceUnsupported;
    if (bulk.any() or sponge.any() or ls_dword != 0) return error.GkrV3ServiceUnsupported;
}
pub fn request(r: P.Request) !void {
    return calls(r.calls, r.bulk, r.sponge, r.ls_dword);
}
/// Whole captured advice: every shard must be v2-only (used before any
/// v2-only diagnostic such as the capture digest or shape planning).
pub fn advice(a: *const @import("../collector.zig").Advice) !void {
    if (a.sha256.len != a.keccak.len or a.arith256_mod.len != a.keccak.len or a.curves.len != a.keccak.len or a.bulk.len != a.keccak.len or a.sponge.len != a.keccak.len) return error.InvalidCombinedInventory;
    for (0..a.keccak.len) |i| try calls(@import("../pipeline.zig").adviceCalls(a, i), a.bulk[i].counts(), a.sponge[i].counts(), 0);
}
pub fn truth(t: R.Truth) !void {
    return switch (t) {
        // Only the compact triple_v2 Keccak-f lookup profile has GKR roles,
        // masses and statements; the throughput profile is v3-only.
        .keccak => |k| if (k.setup.policy != .triple_v2) error.GkrV3ServiceUnsupported,
        .secp => {},
        else => error.GkrV3ServiceUnsupported,
    };
}
/// Wire truth declaration: v2 family, and for Keccak the compact profile
/// word (logs[1] == 0); logs[1] == 21 names the throughput truth.
pub fn truthDeclaration(d: @import("../wire.zig").TruthDeclaration) !void {
    try family(d.family);
    if (d.family == .keccak and d.logs[1] != 0) return error.GkrV3ServiceUnsupported;
    if (d.family != .keccak and d.logs[1] == 0) return error.GkrV3ServiceUnsupported;
}
/// Widen a v2 first-ID vector for shared v3-aware source construction. The
/// v3 entries are unused because admitted setups have no v3 bridges.
pub fn widenFirstIds(ids: [T.V2_FAMILIES]u32) [T.FAMILIES]u32 {
    return ids ++ @as([T.FAMILIES - T.V2_FAMILIES]u32, @splat(1));
}
