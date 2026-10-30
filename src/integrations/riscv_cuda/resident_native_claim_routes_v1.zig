//! Cold routes for the ORIGINAL native public transcript. Every live claim
//! coordinate is located by the original statement constructor, never by a
//! guessed frame offset. No claim or challenge is computed by this planner.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Profile = @import("../../frontends/riscv/recursion/block_v7_native_fixed_profile_v1.zig");
const Statement = @import("../../frontends/riscv/recursion/air/block_v7_native_statement_v1.zig");
const Fused = @import("../../frontends/riscv/prover/block_v5_native_projection_fused_proof_v2.zig");
const Memory = @import("../../frontends/riscv/prover/block_v5_opcode_memory_sidecar_proof_v1.zig");
/// Global claims use original order: transition, universal, countQ, range0..6.
pub const Kind = enum(u32) { word, field, count };
pub const Route = extern struct { source: u32, destination: u32, kind: Kind, maximum: u32 = 0 };
pub const Plan = struct {
    backing: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    statement: Statement.Statement,
    routes: []const Route,
    source_words: usize,
    projection_count: usize,
    access_count: usize,
    profile_identity: [32]u8,
    pub fn init(backing: std.mem.Allocator, profile: *const Profile.Owned) !*Plan {
        try profile.validate();
        const self = try backing.create(Plan);
        errdefer backing.destroy(self);
        self.backing = backing;
        self.arena = std.heap.ArenaAllocator.init(backing);
        errdefer self.arena.deinit();
        const a = self.arena.allocator();
        const claims = try a.alloc(Fused.Claim, profile.projections.len);
        for (claims, profile.projections) |*c, slot| c.* = .{ .sum = Q.zero(), .row_count = slot.n_rows };
        const memory = try a.alloc(Memory.Claim, profile.slots.len);
        for (memory) |*c| c.* = .{ .transition_sum = Q.zero(), .universal_sum = Q.zero(), .active_count = 0, .range_claims = @splat(Q.zero()) };
        self.statement = try Statement.init(a, profile, claims, memory);
        var routes: std.ArrayList(Route) = .empty;
        for (claims, 0..) |*claim, i| for (0..4) |limb| {
            claim.sum = basis(limb);
            var changed = try Statement.init(a, profile, claims, memory);
            defer changed.deinit();
            try routes.append(a, try locate(&self.statement, &changed, @intCast(i * 4 + limb), false, 0));
            claim.sum = Q.zero();
        };
        for (memory, profile.slots, 0..) |*claim, slot, i| {
            for (0..10) |stream| {
                if (stream == 2) {
                    claim.active_count = 1;
                    var changed = try Statement.init(a, profile, claims, memory);
                    defer changed.deinit();
                    try routes.append(a, try locate(&self.statement, &changed, @intCast(claims.len * 4 + i * 40 + 8), true, @as(u32, 1) << @intCast(slot.log_size)));
                    claim.active_count = 0;
                } else for (0..4) |limb| {
                    const target = switch (stream) {
                        0 => &claim.transition_sum,
                        1 => &claim.universal_sum,
                        else => &claim.range_claims[stream - 3],
                    };
                    target.* = basis(limb);
                    var changed = try Statement.init(a, profile, claims, memory);
                    defer changed.deinit();
                    try routes.append(a, try locate(&self.statement, &changed, @intCast(claims.len * 4 + i * 40 + stream * 4 + limb), false, 0));
                    target.* = Q.zero();
                }
            }
        }
        for (routes.items, 0..) |route, i| for (routes.items[0..i]) |prior| {
            if ((route.kind == .field) == (prior.kind == .field) and route.destination == prior.destination)
                return error.AliasedNativeClaimRoute;
        };
        self.routes = routes.items;
        self.source_words = claims.len * 4 + memory.len * 40;
        self.projection_count = claims.len;
        self.access_count = memory.len;
        self.profile_identity = profile.seal;
        return self;
    }
    pub fn deinit(self: *Plan) void {
        const backing = self.backing;
        self.statement.deinit();
        self.arena.deinit();
        backing.destroy(self);
    }
};
fn basis(limb: usize) Q {
    var values: [4]M = @splat(M.zero());
    values[limb] = M.one();
    return Q.fromM31Array(values);
}
fn locate(base: *const Statement.Statement, changed: *const Statement.Statement, source: u32, count: bool, maximum: u32) !Route {
    if (base.words.len != changed.words.len or base.felts.len != changed.felts.len or base.claims.len != changed.claims.len)
        return error.UnstableNativeClaimFraming;
    for (base.claims, changed.claims) |x, y| if (!std.meta.eql(x, y)) return error.UnstableNativeClaimFraming;
    var found: ?Route = null;
    for (base.words, changed.words, 0..) |x, y, i| if (x != y) {
        if (x != 0 or y != 1 or found != null) return error.NonLinearNativeClaimRoute;
        var covered = false;
        for (base.claims) |step| switch (step) {
            .words => |span| {
                if (!count and i >= span.first and i < @as(usize, span.first) + span.len) covered = true;
            },
            .integer => |first| {
                if (count and i == first and i + 1 < base.words.len and base.words[i + 1] == 0) covered = true;
            },
            else => {},
        };
        if (!covered) return error.InvalidNativeClaimRoute;
        found = .{ .source = source, .destination = @intCast(i), .kind = if (count) .count else .word, .maximum = maximum };
    };
    for (base.felts, changed.felts, 0..) |x, y, i| for (x.toM31Array(), y.toM31Array(), 0..) |u, v, limb| if (u.v != v.v) {
        if (count or u.v != 0 or v.v != 1 or found != null) return error.NonLinearNativeClaimRoute;
        found = .{ .source = source, .destination = @intCast(i * 4 + limb), .kind = .field };
    };
    return found orelse error.MissingNativeClaimRoute;
}
