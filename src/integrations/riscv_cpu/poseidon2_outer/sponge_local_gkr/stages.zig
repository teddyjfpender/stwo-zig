//! Shared physical stage helpers; preserves the established fragment framing.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const R = @import("authority.zig");
const Component = @import("component.zig");
const Eq = @import("equations.zig");
const W = @import("../pure_p2_worker_protocol.zig").W;
const M = core.fields.m31.M31;
const O = core.fields.om31.OM31;
pub fn columns(data: []const M, log: u32, out: []engine.pcs.ColumnEvaluation) void {
    const rows = @as(usize, 1) << @intCast(log);
    std.debug.assert(data.len == rows * out.len);
    for (out, 0..) |*c, i| c.* = .{ .log_size = log, .values = data[i * rows ..][0..rows] };
}
pub fn tupleTypes(comptime Data: bool, comptime detached: bool) type {
    comptime var types: [8]type = undefined;
    inline for (comptime R.rolesFor(detached), 0..) |role, i| types[i] = if (Data) Component.Data(role) else Component.Component(role);
    return std.meta.Tuple(&types);
}
pub fn globalDraw(manifest: [36]u8) !Eq.GlobalFor(O) {
    const shared = try @import("../pure_p2_manifest.zig").drawShared(manifest);
    return .{ .ram = .{ .offset = shared.ram.offset, .coefficients = shared.ram.coefficients }, .io = .{ .offset = shared.kio.offset, .coefficients = shared.kio.coefficients }, .wire = shared.wire };
}
pub fn mix(channel: *W.Channel, scope: anytype, receipt: [36]u8, owner: O, claims: [8][3]O) void {
    const detached = comptime !@hasField(@TypeOf(scope), "boundary");
    channel.mixU32s(if (detached) &.{ 0x53504753, 1, 9, 24 } else &.{ 0x53504752, 1, 9, 17 });
    channel.mixRoot(scope.manifest);
    channel.mixRoot(receipt);
    if (!detached) channel.mixFelts(&.{owner});
    for (claims) |pair| channel.mixFelts(pair[0..if (detached) 3 else 2]);
}
pub fn totalWidth(tree: usize, comptime detached: bool) usize {
    var count: usize = 0;
    inline for (comptime R.rolesFor(detached)) |role| count += switch (tree) {
        0 => R.fixedWidth(role),
        1 => R.mainWidth(role),
        else => R.interactionWidth(role),
    };
    return count;
}
