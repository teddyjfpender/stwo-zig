//! Scope of the authenticated OM GKR / wide services route: the v2 roster only
//! (CPU bridges and truths for Keccak, secp256k1 ADD and DOUBLE). Its CPU
//! roles, global layouts, masses, statements and truth components enumerate
//! exactly those three families. Every v3 extension of the classic services
//! route (SHA-256, arith256_mod, curve/field families, bulk memory incl. the
//! unaligned ucopy/cdesc/cmp kinds, Keccak
//! sponge) is rejected here, at each admission boundary, instead of being
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
}
pub fn setup(s: *const R.CpuSetup) !void {
    return bridges(s.bridges);
}
pub fn calls(all: [T.FAMILIES]u32, bulk: T.BulkCounts, sponge: T.SpongeCounts) !void {
    for (all[T.V2_FAMILIES..]) |n| if (n != 0) return error.GkrV3ServiceUnsupported;
    if (bulk.any() or sponge.any()) return error.GkrV3ServiceUnsupported;
}
pub fn request(r: P.Request) !void {
    return calls(r.calls, r.bulk, r.sponge);
}
pub fn truth(t: R.Truth) !void {
    return switch (t) {
        .keccak, .secp => {},
        else => error.GkrV3ServiceUnsupported,
    };
}
/// Widen a v2 first-ID vector for shared v3-aware source construction. The
/// v3 entries are unused because admitted setups have no v3 bridges.
pub fn widenFirstIds(ids: [T.V2_FAMILIES]u32) [T.FAMILIES]u32 {
    return ids ++ @as([T.FAMILIES - T.V2_FAMILIES]u32, @splat(1));
}
