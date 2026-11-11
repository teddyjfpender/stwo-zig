//! Fresh physical reception. Every source key/recipe is independently admitted
//! before this helper runs; zero-sum claims are checked only after ALL proofs.
const std = @import("std");
const core = @import("stwo_core");
const O = core.fields.om31.OM31;
const I = @import("inventory.zig");
const M = @import("manifest.zig");
const C = @import("worker.zig");
const N = @import("native.zig");
const D = @import("../sponge_local_gkr/worker.zig");
const Miller = @import("../pure_p2_tower_worker.zig");
const LocalMiller = @import("../miller_local_gkr/worker.zig");
const Tower = @import("../pure_p2_op_inventory.zig").MillerDeclaration;
const Truth = @import("../pure_p2_truth_worker.zig");
const LocalTruth = @import("../truth_local_gkr/worker.zig");
const Wire = @import("wire.zig");
const G = @import("../../word16_global_execution/services/gkr_local/manifest.zig");
const ChildWire = @import("../../word16_global_execution/services/gkr_local/wire.zig");
pub const Capture = @import("../pure_p2_op_bundle.zig").Capture;
/// Borrowed pending fragment only. Callback buffers/keys may not escape; a
/// consumer must wait for whole closure AND runtime Terminal before acceptance.
pub const Verified = struct {
    ordinal: usize,
    manifest: *const M.Pending,
    main: [36]u8,
    capture: *const Capture,
    source: union(enum) {
        cpu: struct { value: I.Cpu, first: [@import("../../word16_global_execution/services/types.zig").FAMILIES]u32, encoded: *const C.Encoded },
        detached: struct { value: I.Detached, encoded: *const D.Encoded },
        catalog: struct { value: I.Catalog, encoded: *const Truth.Encoded },
        local_catalog: struct { value: I.Catalog, encoded: *const LocalTruth.Encoded },
        miller: struct { value: Tower, encoded: *const Miller.Encoded },
        local_miller: struct { value: Tower, encoded: *const LocalMiller.Encoded },
    },
};
pub const Hooks = struct { context: ?*anyopaque = null, fragment: ?*const fn (?*anyopaque, std.mem.Allocator, Verified) anyerror!void = null };
pub const Closed = struct {
    pending: M.Pending,
    claims: []G.Claims,
    pub fn deinit(self: *Closed, a: std.mem.Allocator) void {
        a.free(self.claims);
        self.pending.deinit(a);
        self.* = undefined;
    }
};
pub fn verify(a: std.mem.Allocator, inventory: *const I.Inventory, cpus: []const I.Cpu, detached: []const I.Detached, catalogs: []const I.Catalog, towers: []const Tower, bundle: *const Wire.Bundle) !Closed {
    return verifyWithHooks(a, inventory, cpus, detached, catalogs, towers, bundle, .{});
}
pub fn verifyWithHooks(a: std.mem.Allocator, inventory: *const I.Inventory, cpus: []const I.Cpu, detached: []const I.Detached, catalogs: []const I.Catalog, towers: []const Tower, bundle: *const Wire.Bundle, hooks: Hooks) !Closed {
    if (bundle.fragments.len != inventory.workers.len or cpus.len != inventory.cpu_count or detached.len != inventory.detached_count or catalogs.len != inventory.truth_count or cpus.len + detached.len + catalogs.len + towers.len != inventory.workers.len or !std.mem.eql(u8, &bundle.execution, &inventory.execution)) return error.DetachedInventoryRoster;
    const stages = try a.alloc(M.StageOne, inventory.workers.len);
    defer a.free(stages);
    const children = try a.alloc(?ChildWire.Owned, cpus.len);
    defer a.free(children);
    @memset(children, null);
    defer for (children) |*child| if (child.*) |*value| value.deinit();
    for (bundle.fragments, stages, 0..) |f, *stage, ordinal| {
        stage.* = .{ .main = f.main };
        if (ordinal < cpus.len) {
            const receipt = f.receipt orelse return error.MissingGlobalGkrLocalChild;
            children[ordinal] = try N.decode(a, inventory.rosters[ordinal].instances, f.local);
            stage.local = .{ .proof = &children[ordinal].?.proof, .receipt = receipt };
        }
    }
    var pending = try M.verifyAndSeal(a, inventory.execution, inventory.workers, stages);
    errdefer pending.deinit(a);
    const claims = try a.alloc(G.Claims, bundle.fragments.len);
    errdefer a.free(claims);
    for (cpus, bundle.fragments[0..cpus.len], claims[0..cpus.len], 0..) |cpu, f, *claim, ordinal| {
        try pending.checkPhysicalRoots(ordinal, cpu.key.root, f.main);
        const encoded = C.Encoded{ .bytes = f.native, .local = f.local, .receipt = f.receipt orelse return error.MissingGlobalGkrLocalChild, .claims = f.claims };
        if (hooks.fragment) |callback| {
            var capture: Capture = undefined;
            claim.* = try C.verifyWithCapture(a, cpu.setup, cpu.request, cpu.span, inventory.first_ids[ordinal], @intCast(ordinal), cpu.key, pending.digest, f.main, &encoded, &capture);
            defer capture.deinit(a);
            try callback(hooks.context, a, .{ .ordinal = ordinal, .manifest = &pending, .main = f.main, .capture = &capture, .source = .{ .cpu = .{ .value = cpu, .first = inventory.first_ids[ordinal], .encoded = &encoded } } });
        } else claim.* = try C.verify(a, cpu.setup, cpu.request, cpu.span, inventory.first_ids[ordinal], @intCast(ordinal), cpu.key, pending.digest, f.main, &encoded);
    }
    for (detached, 0..) |source, j| {
        const ordinal = cpus.len + j;
        const f = bundle.fragments[ordinal];
        if (f.claims.len != 24) return error.DetachedClaimCount;
        var data: [8][3]O = undefined;
        for (&data, 0..) |*row, i| @memcpy(row, f.claims[3 * i ..][0..3]);
        try pending.checkPhysicalRoots(ordinal, source.key.root, f.main);
        const encoded = D.Encoded{ .bytes = f.native, .local = f.local, .receipt = f.receipt orelse return error.MissingGlobalGkrLocalChild, .claims = data };
        if (hooks.fragment) |callback| {
            var capture: Capture = undefined;
            claims[ordinal] = try D.verifyWithCapture(a, source.geometry, source.key, @intCast(ordinal), pending.digest, f.main, &encoded, &capture);
            defer capture.deinit(a);
            try callback(hooks.context, a, .{ .ordinal = ordinal, .manifest = &pending, .main = f.main, .capture = &capture, .source = .{ .detached = .{ .value = source, .encoded = &encoded } } });
        } else claims[ordinal] = try D.verify(a, source.geometry, source.key, @intCast(ordinal), pending.digest, f.main, &encoded);
    }
    for (catalogs, 0..) |source, j| {
        const ordinal = cpus.len + detached.len + j;
        const f = bundle.fragments[ordinal];
        try pending.checkPhysicalRoots(ordinal, source.key.root, f.main);
        if (source.local_key) |key| {
            if (f.claims.len != 2) return error.DetachedClaimCount;
            const encoded = LocalTruth.Encoded{ .bytes = f.native, .local = f.local, .receipt = f.receipt orelse return error.MissingGlobalGkrLocalChild, .claims = f.claims[0..2].* };
            if (hooks.fragment) |callback| {
                var capture: Capture = undefined;
                claims[ordinal] = try LocalTruth.verifySealedWithCapture(a, key, source.truth, try key.expected(source.truth, @intCast(ordinal)), .{ .manifest = pending.digest, .main = f.main }, &encoded, &capture);
                defer capture.deinit(a);
                try callback(hooks.context, a, .{ .ordinal = ordinal, .manifest = &pending, .main = f.main, .capture = &capture, .source = .{ .local_catalog = .{ .value = source, .encoded = &encoded } } });
            } else claims[ordinal] = try LocalTruth.verifySealed(a, key, source.truth, try key.expected(source.truth, @intCast(ordinal)), .{ .manifest = pending.digest, .main = f.main }, &encoded);
        } else {
            if (f.receipt != null or f.local.len != 0) return error.DetachedUnexpectedLocal;
            const encoded = Truth.Encoded{ .bytes = f.native, .claims = f.claims };
            if (hooks.fragment) |callback| {
                var capture: Capture = undefined;
                claims[ordinal] = try Truth.verifySealedWithCapture(a, source.key, source.truth, try source.key.expected(source.truth, @intCast(ordinal)), .{ .manifest = pending.digest, .main = f.main }, &encoded, &capture);
                defer capture.deinit(a);
                try callback(hooks.context, a, .{ .ordinal = ordinal, .manifest = &pending, .main = f.main, .capture = &capture, .source = .{ .catalog = .{ .value = source, .encoded = &encoded } } });
            } else claims[ordinal] = try Truth.verifySealed(a, source.key, source.truth, try source.key.expected(source.truth, @intCast(ordinal)), .{ .manifest = pending.digest, .main = f.main }, &encoded);
        }
    }
    for (towers, 0..) |source, j| {
        const ordinal = cpus.len + detached.len + catalogs.len + j;
        const f = bundle.fragments[ordinal];
        try pending.checkPhysicalRoots(ordinal, source.key.root, f.main);
        if (source.local_key) |key| {
            if (f.claims.len != 2) return error.DetachedClaimCount;
            const encoded = LocalMiller.Encoded{ .bytes = f.native, .local = f.local, .receipt = f.receipt orelse return error.MissingGlobalGkrLocalChild, .claims = f.claims[0..2].* };
            if (hooks.fragment) |callback| {
                var capture: Capture = undefined;
                claims[ordinal] = try LocalMiller.verifySealedWithCapture(a, key, source.span, try key.expected(source.span, @intCast(ordinal)), .{ .manifest = pending.digest, .main = f.main }, &encoded, &capture);
                defer capture.deinit(a);
                try callback(hooks.context, a, .{ .ordinal = ordinal, .manifest = &pending, .main = f.main, .capture = &capture, .source = .{ .local_miller = .{ .value = source, .encoded = &encoded } } });
            } else claims[ordinal] = try LocalMiller.verifySealed(a, key, source.span, try key.expected(source.span, @intCast(ordinal)), .{ .manifest = pending.digest, .main = f.main }, &encoded);
        } else {
            if (f.receipt != null or f.local.len != 0) return error.DetachedUnexpectedLocal;
            if (f.claims.len != 4) return error.DetachedClaimCount;
            const encoded = Miller.Encoded{ .bytes = f.native, .claims = f.claims[0..4].* };
            if (hooks.fragment) |callback| {
                var capture: Capture = undefined;
                claims[ordinal] = try Miller.verifySealedWithCapture(a, source.key, source.span, try source.key.expected(source.span, @intCast(ordinal)), .{ .manifest = pending.digest, .main = f.main }, &encoded, &capture);
                defer capture.deinit(a);
                try callback(hooks.context, a, .{ .ordinal = ordinal, .manifest = &pending, .main = f.main, .capture = &capture, .source = .{ .miller = .{ .value = source, .encoded = &encoded } } });
            } else claims[ordinal] = try Miller.verifySealed(a, source.key, source.span, try source.key.expected(source.span, @intCast(ordinal)), .{ .manifest = pending.digest, .main = f.main }, &encoded);
        }
    }
    try pending.checkGlobalClosure(claims);
    return .{ .pending = pending, .claims = claims };
}
