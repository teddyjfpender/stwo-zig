//! LS-D64: aligned LD/SD only. MAIN39 physical columns expand affinely into the
//! audited V1 logical79 row; INTER28 = RAM inverse+prefix, four strict local
//! pair inverses and one local prefix. Design: rv64-ls-dword-fast-row.md.
const std = @import("std");
const E = @import("../../evaluation.zig");
const Specs = @import("../../memory_constraints.zig");
const V = @import("../load_store_v1/layout.zig");
const V2 = @import("../load_store_v2/layout.zig");
pub const LOGICAL_MAIN = 79;
/// Committed logical coordinates, ascending. Everything else is virtual.
/// RAM transition (27 of 28: owner tick 3 and address limb 4 are virtual),
/// A[4], B[4], the address quotient and the four address carries.
pub const STORED = [_]usize{ 0, 1, 2, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 36, 37, 38, 39, 68, 75, 76, 77, 78 };
pub const MAIN = STORED.len;
pub const FIXED = 3;
/// Strict queries kept from LS32: after clock (lo U16, hi U8), strict gaps
/// (epoch_gap U16, gap_lo U16, gap_hi U8) and the address quotient (U16).
/// The selection lookup and the b_low/b_high U8 queries are dropped: they
/// constrain only selected_byte/signs/b bytes, which LD/SD never read.
pub const LOGICAL_U16 = [_]usize{ 12, 24, 25, 68 };
pub const LOGICAL_U8 = [_]usize{ 13, 26 };
/// OWNER plus the six range queries, in pair order (owner, after_lo),
/// (epoch_gap, gap_lo), (q, after_hi), (gap_hi).
pub const LOCAL_FRACTIONS = 1 + LOGICAL_U16.len + LOGICAL_U8.len;
pub const LOCAL_PAIRS = (LOCAL_FRACTIONS + 1) / 2;
pub const LOCAL_INVERSES = 8;
pub const LOCAL_PREFIX = LOCAL_INVERSES + 4 * LOCAL_PAIRS;
pub const INTERACTION = LOCAL_PREFIX + 4;
/// Native metadata reuses the LS32 relation caches (same logical coordinates).
pub const U16_CACHE = cacheIndices(&LOGICAL_U16, &V2.RELATION_U16);
pub const U8_CACHE = cacheIndices(&LOGICAL_U8, &V2.RELATION_U8);
/// Index of LD in load_specs and of SD in store_specs (V1 flag order).
pub const LD_FLAG = flagIndex(.LD);
pub const SD_FLAG = flagIndex(.SD);
pub const LD_OPCODE: u32 = @intFromEnum(@import("../../../decode.zig").Opcode.LD);
pub const SD_OPCODE: u32 = @intFromEnum(@import("../../../decode.zig").Opcode.SD);

pub fn widths() [3]usize {
    return .{ FIXED, MAIN, INTERACTION };
}
/// Opt-in fused-pair LS-D64 layout (Geometry.ls_dword_fused_pairs): RAM
/// fraction fused into the RAM prefix (no inverse); the two U8 queries become
/// one tagged AND-relation byte pair (b13, b26); K0=(OWNER,U16_0) and
/// K1=(U16_1,U16_2) are degree-one fraction witnesses and (U16_3, pair) is
/// fused into the local prefix. INTER 28 -> 16.
pub const fused = struct {
    pub const RAM_PREFIX = 0;
    pub const WITNESS = 4;
    pub const WITNESSES = 2;
    pub const LOCAL_PREFIX = WITNESS + 4 * WITNESSES;
    pub const INTERACTION = WITNESS + 4 * WITNESSES + 4;
    /// RAM inverse, two local pair inverses and the single U8 inverse leave;
    /// the fused tail adds one residual.
    pub const CONSTRAINTS = 255 - 3;
    pub const PAIR_QUERIES = 1;
};
pub fn widthsFor(fused_pairs: bool) [3]usize {
    return if (fused_pairs) .{ FIXED, MAIN, fused.INTERACTION } else widths();
}
pub fn previousInterFor(fused_pairs: bool, c: usize) bool {
    return if (fused_pairs) c < 4 or c >= fused.LOCAL_PREFIX else previousInter(c);
}
pub fn previousMain(c: usize) bool {
    return c == 0;
}
pub fn previousInter(c: usize) bool {
    return (c >= 4 and c < 8) or c >= LOCAL_PREFIX;
}
pub fn column(logical: usize) usize {
    for (STORED, 0..) |c, physical| if (c == logical) return physical;
    unreachable;
}
pub fn projectFor(comptime F: type, logical: []const F) [MAIN]F {
    std.debug.assert(logical.len == LOGICAL_MAIN);
    var physical: [MAIN]F = undefined;
    for (STORED, &physical) |c, *v| v.* = logical[c];
    return physical;
}
/// Affine expansion onto the V1 logical row. No product of trace values.
pub fn expandFor(comptime F: type, physical: []const F) [LOGICAL_MAIN]F {
    std.debug.assert(physical.len == MAIN);
    var m: [LOGICAL_MAIN]F = @splat(F.zero());
    for (STORED, physical) |c, v| m[c] = v;
    const active = m[0];
    const store = m[1];
    // Owner tick = after clock; word address limb 0 = 8 * quotient.
    m[3] = m[12].add(m[13].mul(q(F, 65536)));
    m[4] = m[V.quotient].mul(q(F, 8));
    // Natural alignment: EA = word address (offset 0 only).
    for (0..4) |c| m[V.effective + c] = m[4 + c];
    // Immediate limbs are the exact field residue of the committed addition;
    // OWNER binds them to the CPU's canonical ROM immediate.
    for (0..4) |c| {
        const carry_in = if (c == 0) F.zero() else m[V.address_carries + c - 1];
        m[V.immediate + c] = m[V.effective + c].add(m[V.address_carries + c].mul(q(F, 65536))).sub(m[V.a + c]).sub(carry_in);
    }
    // LD reads C = before = after (B = 0); SD writes after = B with C = 0.
    for (0..4) |c| m[V.c + c] = m[18 + c].sub(m[V.b + c]);
    const load = active.sub(store);
    m[V.flags + LD_FLAG] = load;
    m[V.flags + Specs.load_specs.len + SD_FLAG] = store;
    m[V.opcode] = load.mul(q(F, LD_OPCODE)).add(store.mul(q(F, SD_OPCODE)));
    m[V.offsets] = active;
    // Width-8 selected limb is before[3]; byte/sign facts are unread by LD/SD.
    m[V.selected_limb] = m[17];
    m[V.b_low] = m[V.b];
    return m;
}

fn q(comptime F: type, value: u32) F {
    if (F == @import("stwo_core").fields.m31.M31) return F.fromCanonical(value);
    return E.qFor(F, value);
}
fn flagIndex(comptime opcode: @import("../../../decode.zig").Opcode) usize {
    for (Specs.load_specs, 0..) |s, i| if (s.opcode == opcode) return i;
    for (Specs.store_specs, 0..) |s, i| if (s.opcode == opcode) return i;
    @compileError("not a load/store opcode");
}
fn cacheIndices(comptime queries: []const usize, comptime cached: []const usize) [queries.len]usize {
    var result: [queries.len]usize = undefined;
    for (queries, 0..) |c, at| {
        result[at] = for (cached, 0..) |x, i| {
            if (x == c) break i;
        } else @compileError("missing retained LS relation coordinate");
    }
    return result;
}

comptime {
    if (MAIN != 39 or LOCAL_FRACTIONS != 7 or LOCAL_PAIRS != 4 or INTERACTION != 28) @compileError("LS-D64 ledger mismatch");
    if (fused.INTERACTION != 16 or LOGICAL_U8.len != 2 * fused.PAIR_QUERIES) @compileError("LS-D64 fused-pair ledger mismatch");
    if (Specs.load_specs[LD_FLAG].width != 8 or Specs.store_specs[SD_FLAG].width != 8) @compileError("LS-D64 requires the width-8 specs");
    for (STORED, 0..) |c, i| if (i > 0 and STORED[i - 1] >= c) @compileError("STORED must ascend");
    for (LOGICAL_U16 ++ LOGICAL_U8) |c| {
        var stored = false;
        for (STORED) |s| stored = stored or s == c;
        if (!stored) @compileError("range query must be a committed column");
    }
}
