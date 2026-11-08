const std = @import("std");
const core = @import("stwo_core");
const C = @import("common.zig");
const Public = @import("frame.zig");
const Child = @import("native_gkr_child.zig");
const V2 = @import("../../word16_global_execution/services/native_gkr/v2.zig");
const S = @import("../../word16_global_execution/services/native_gkr/section.zig");
const R = @import("../../word16_global_execution/services/native_gkr/roster.zig");
const a = std.testing.allocator;
const scope = S.Scope{ .ordinal = 3, .statement = @splat(11), .fixed = @splat(13), .main = @splat(17), .shared = @splat(0xff) };
const prefix = [_]u32{ 0x4d375445, 0x50534331 };
const Builder = struct {
    pub fn build(_: @This(), allocator: std.mem.Allocator, roster: *const R.Roster, elements: V2.LocalElements) !S.Inputs {
        var out = try S.syntheticInputs(allocator, roster, 32);
        errdefer out.deinit(allocator);
        for (roster.instances, out.numerators, out.denominators) |instance, ns, ds| {
            if (instance.kind == .local) @memset(ns, core.fields.m31.M31.zero());
            const rows = @as(usize, 1) << @intCast(instance.row_log);
            for (ds, 0..) |*d, i| if (i / rows < instance.terms) {
                d.* = d.mul(elements.z[0].add(C.O.one()));
            };
        }
        return out;
    }
};
fn exercise(mutation: enum { none, scope, mask, salt }, trace_only: bool) !bool {
    const Role = @import("../../word16_execution/geometry.zig").Role;
    const specs = [_]R.ComponentSpec{
        .{ .origin = .{ 0, @intFromEnum(Role.ls) }, .row_log = 5, .terms = .{ 2, 2, 0, 0 } },
        .{ .origin = .{ 0, @intFromEnum(Role.initial) }, .row_log = 5, .terms = .{ 0, 1, 0, 0 } },
        .{ .origin = .{ 0, @intFromEnum(Role.terminal) }, .row_log = 5, .terms = .{ 0, 1, 0, 0 } },
    };
    var roster = try V2.derive(a, &specs);
    defer roster.deinit();
    var native = S.RawChannel.init();
    native.mixU32s(&prefix);
    var section = try V2.proveCpu(a, &native, &roster, &scope, Builder{});
    defer section.deinit(a);
    var expected = try V2.verify(a, &native, &roster, &scope, &section);
    defer expected.deinit(a);
    const binding = try V2.drawBinding(&native, &roster);
    var ctx = if (trace_only) try C.Context.initTraceOnly(a, 0) else try C.Context.initWithWitnessOrigins(a, 0);
    defer ctx.deinit();
    C.lane.begin(&ctx);
    var active = true;
    defer if (active) C.lane.finish() catch {};
    var frame = Public.Frame.init(&ctx);
    var public = Child.Scope{ .ordinal = (try frame.guessU32(scope.ordinal)).word, .statement = try frame.guessDigest(scope.statement), .fixed = try frame.guessDigest(scope.fixed), .main = try frame.guessDigest(scope.main), .shared = try frame.guessDigest(scope.shared) };
    if (mutation == .scope) public.shared[7] = (try frame.guessU32(42)).word;
    var wired = try Child.wire(&ctx, &roster, &section);
    if (mutation == .mask) wired.proof.layer_masks_by_instance[0][0].columns[0][0] = wired.proof.layer_masks_by_instance[0][0].columns[0][0].add(C.F.one());
    if (mutation == .salt) wired.salt = C.F.fromBase(core.fields.m31.M31.fromCanonical(S.MAX_SALT_ATTEMPTS));
    var channel = try C.Channel.init(&ctx);
    try channel.mixConstU32s(&ctx, &prefix);
    var checked = try Child.verify(&ctx, &channel, public, &roster, &wired);
    defer checked.deinit(&ctx);
    try std.testing.expectEqual(expected.draws + 1 + @as(u32, @intCast(roster.instances.len)), checked.draws);
    if (mutation == .none) {
        for (checked.local.z, expected.elements.z) |wire, value| try C.eq(&ctx, wire, C.F.fromOm31(value));
        for (checked.local.alpha, expected.elements.alpha) |wire, value| try C.eq(&ctx, wire, C.F.fromOm31(value));
        for (checked.artifact.ood_point, expected.artifact.ood_point) |wire, value| try C.eq(&ctx, wire, C.F.fromOm31(value));
        try C.eq(&ctx, checked.binding.gamma, C.F.fromOm31(binding.gamma));
        for (checked.binding.rho[0..roster.instances.len], binding.rho[0..roster.instances.len]) |wire, value| try C.eq(&ctx, wire, C.F.fromOm31(value));
        inline for (std.meta.fields(@TypeOf(expected.global_split))) |field| try C.eq(&ctx, @field(checked.global, field.name), C.F.fromOm31(@field(expected.global_split, field.name)));
        try Public.requireDigest(&ctx, channel.raw.inner.digest, native.digestBytes());
    }
    try C.lane.finish();
    active = false;
    try ctx.finalize(false);
    if (trace_only) return true;
    return ctx.isCircuitValid();
}
test "native GKR circuit section continues actual PCS channel with exact strict draws, roots and binding" {
    try std.testing.expect(try exercise(.none, false));
}
test "native GKR circuit section rejects changed chi, numerical mask and out of range salt" {
    try std.testing.expect(!try exercise(.scope, false));
    try std.testing.expect(!try exercise(.mask, false));
    try std.testing.expect(!try exercise(.salt, false));
}
test "native GKR circuit section supports trace only witness provenance" {
    try std.testing.expect(try exercise(.none, true));
}
