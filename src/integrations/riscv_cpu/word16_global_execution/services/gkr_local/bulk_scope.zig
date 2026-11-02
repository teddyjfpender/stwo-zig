//! Qualified bulk-only extension of the native services workers. Ethereum's
//! candidate CLI retains v2_scope until the other v3 services are authenticated.
const V2 = @import("v2_scope.zig");
const T = @import("../types.zig");
const A = @import("stwo_riscv_frontend").rv64_air;
pub const geometry = V2.geometry;
pub const truth = V2.truth;
pub const truthDeclaration = V2.truthDeclaration;
pub const widenFirstIds = V2.widenFirstIds;
pub fn bridges(logs: T.Logs) !void {
    var legacy = logs;
    legacy.bulk = .{};
    try V2.bridges(legacy);
    inline for (T.bulk_kinds) |kind| if (logs.bulk.at(kind)) |log| {
        if (log > 22) return error.InvalidLocalGkrGeometry;
        _ = try A.crypto.bulk_memory.types.validateGeometry(kind, 0, log);
        if (kind == .jtab and log != A.crypto.bulk_memory.types.TABLE_LOG) return error.InvalidBulkMemoryGeometry;
    };
}
pub fn setup(s: *const @import("../roster.zig").CpuSetup) !void {
    try geometry(s.materials.geometry);
    if (s.materials.geometry.cpu_log > 22) return error.InvalidLocalGkrGeometry;
    try bridges(s.bridges);
}
pub fn declaration(d: @import("../wire.zig").CpuDeclaration) !void {
    try geometry(d.geometry);
    if (d.geometry.cpu_log > 22) return error.InvalidLocalGkrGeometry;
    try bridges(d.bridges);
}
pub fn request(r: @import("../protocol.zig").Request) !void {
    try calls(r.calls, r.bulk, r.sponge, r.ls_dword);
}
pub fn calls(all: [T.FAMILIES]u32, _: T.BulkCounts, sponge: T.SpongeCounts, ls_dword: u32) !void {
    try V2.calls(all, .{}, sponge, ls_dword);
}
