//! Cold qualification catalog and scalar row fixtures, never production admission.
const std = @import("std");
const core = @import("stwo_core");
const G = @import("projection_codegen.zig");
const Source = G.Source;
const T = Source.Types;
pub const count = std.enums.values(Source.RoleId).len - 2 + 3 + T.FAMILIES + T.bulk_kinds.len + T.sponge_kinds.len + T.DWORD_INSTANCES;
pub fn descriptors() [count]Source.Descriptor {
    var out: [count]Source.Descriptor = undefined;
    var at: usize = 0;
    for (std.enums.values(Source.RoleId)) |role| {
        if (role == .initial or role == .terminal) continue;
        out[at] = .{ .origin = .{ .core = role } };
        at += 1;
    }
    out[at] = .{ .origin = .{ .core = .cpu }, .cpu_u8_pairs = true };
    at += 1;
    out[at] = .{ .origin = .{ .core = .cpu }, .cpu_u8_pairs = true, .cpu_compact_decode = true };
    at += 1;
    out[at] = .{ .origin = .{ .core = .and_table }, .cpu_u8_pairs = true };
    at += 1;
    for (std.enums.values(T.Family)) |family| {
        out[at] = .{ .origin = .{ .bridge = family } };
        at += 1;
    }
    for (T.bulk_kinds) |kind| {
        out[at] = .{ .origin = .{ .bulk = kind } };
        at += 1;
    }
    for (T.sponge_kinds) |kind| {
        out[at] = .{ .origin = .{ .sponge = kind } };
        at += 1;
    }
    for (0..T.DWORD_INSTANCES) |kind| {
        out[at] = .{ .origin = .{ .dword = @intCast(kind) } };
        at += 1;
    }
    std.debug.assert(at == count);
    return out;
}
pub fn random(rng: std.Random) core.fields.om31.OM31 {
    var c: [8]core.fields.m31.M31 = undefined;
    for (&c) |*v| v.* = core.fields.m31.M31.fromCanonical(rng.uintLessThan(u32, 2147483647));
    return core.fields.om31.OM31.fromM31Array(c);
}
pub fn challenge(ch: Source.Challenges.For(core.fields.om31.OM31), slot: u32) core.fields.om31.OM31 {
    const relation = slot / G.slot_stride;
    const coordinate = slot % G.slot_stride;
    return if (coordinate == 0) ch.offsets[relation] else ch.coefficients[relation][coordinate - 1];
}
