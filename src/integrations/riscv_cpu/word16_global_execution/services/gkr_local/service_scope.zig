//! Explicit v3 service scope. Receiver components and budgets establish proof
//! authority; this whitelist alone never promotes the Ethereum production CLI.
const A = @import("stwo_riscv_frontend").rv64_air;
const T = @import("../types.zig");
const R = @import("../roster.zig");
const P = @import("../protocol.zig");
pub fn geometry(g: @import("../../../word16_execution/geometry.zig").Geometry) !void {
    // These classic encodings change MAIN or provider-query authority. GKR keeps its
    // separately qualified query authority until both projections are adapted.
    if (g.cpu_compact_decode or g.mul_u8_pairs or g.ls_fused_pairs or g.alu_fused_tail or g.ls_dword_fused_pairs) return error.UnsupportedClassicEncodingInLocalGkr;
    try g.validate();
    if (g.cpu_log > 22) return error.InvalidLocalGkrGeometry;
}
pub fn bridges(logs: T.Logs) !void {
    for (T.sponge_kinds) |kind| if (logs.sponge.at(kind)) |log| {
        if (log < 5 or log > 22) return error.InvalidLocalGkrGeometry;
    };
    for (0..T.DWORD_INSTANCES) |i| if (logs.dwordLog(i)) |log| {
        if (log < 5 or log > T.DWORD_MAX_LOG) return error.InvalidLocalGkrGeometry;
    };
    inline for (T.bulk_kinds) |kind| if (logs.bulk.at(kind)) |log| {
        if (log > 22) return error.InvalidLocalGkrGeometry;
        _ = try A.crypto.bulk_memory.types.validateGeometry(kind, 0, log);
        if (kind == .jtab and log != A.crypto.bulk_memory.types.TABLE_LOG) return error.InvalidBulkMemoryGeometry;
    };
    for (@import("std").enums.values(T.Family)) |family| if (logs.at(family)) |log| {
        if (log < 5 or log > 22) return error.InvalidLocalGkrGeometry;
    };
}
pub fn setup(s: *const R.CpuSetup) !void {
    try geometry(s.materials.geometry);
    try bridges(s.bridges);
}
pub fn declaration(d: @import("../wire.zig").CpuDeclaration) !void {
    try geometry(d.geometry);
    try bridges(d.bridges);
}
pub fn request(r: P.Request) !void {
    try calls(r.calls, r.bulk, r.sponge, r.ls_dword);
}
pub fn calls(_: [T.FAMILIES]u32, _: T.BulkCounts, _: T.SpongeCounts, _: u32) !void {}
pub fn truth(t: R.Truth) !void {
    if (t == .keccak or t == .secp) return @import("truth_profile.zig").validate(t);
    return @import("truth_v3_catalog.zig").validate(t);
}
pub fn truthDeclaration(d: @import("../wire.zig").TruthDeclaration) !void {
    if (d.family == .keccak or ((d.family == .add or d.family == .double) and d.logs[1] != 0)) return @import("truth_profile.zig").validateDeclaration(d);
    _ = try @import("truth_v3_catalog.zig").descriptorForDeclaration(d);
}

pub fn advice(a: *const @import("../collector.zig").Advice) !void {
    if (a.events.len != a.keccak.len or a.secp.len != a.keccak.len or a.sha256.len != a.keccak.len or a.arith256_mod.len != a.keccak.len or a.curves.len != a.keccak.len or a.bulk.len != a.keccak.len or a.sponge.len != a.keccak.len) return error.InvalidCombinedInventory;
}

test "new classic defaults cannot silently enter authenticated GKR query shapes" {
    const std = @import("std");
    const G = @import("../../../word16_execution/geometry.zig").Geometry;
    const base = G{ .cpu_log = 5, .cpu_fused_tail = true, .cpu_u8_pairs = true };
    try geometry(base);
    const layout = @import("../../ethereum/plan.zig").CpuLayout.forGkrProfile(.ethereum_services_v3);
    try std.testing.expect(!layout.compact_decode);
    inline for (.{ "mul_u8_pairs", "ls_fused_pairs", "alu_fused_tail", "ls_dword_fused_pairs", "cpu_compact_decode" }) |field| {
        var changed = base;
        @field(changed, field) = true;
        try std.testing.expectError(error.UnsupportedClassicEncodingInLocalGkr, geometry(changed));
    }
}
