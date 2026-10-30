//! Original arithmetic equations at independently derived compact placements.
//! Inactive objects may be constructed, but no inactive handle enters the AIR.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const P = @import("blake3_ethereum_sha_profile.zig");
const Ethereum = @import("guest_precompile/ethereum_assembly.zig");
const Sha = @import("../air/guest_precompile/sha256_component_profile.zig");
const ShaOwner = @import("../recursion/air/universal_component_owner.zig").ForRoster(Sha.Roster);
const Layout = @import("block_v7_caller_active_layout_v1.zig").Layout;
pub fn Assembly(comptime direction: Ethereum.Direction) type {
    const Handle = if (direction == .prover) engine.air.component_prover.ComponentProver else core.air.components.Component;
    return struct {
        const Self = @This();
        relations: P.Relations,
        ethereum: *Ethereum.Assembly(direction),
        sha_owner: ?*ShaOwner = null,
        placements: [19]P.PlacementDescriptor,
        handles: [19]Handle,
        len: usize,
        pub fn init(a: std.mem.Allocator, statement: *const P.admission.Statement, steps: u32, relations: *const P.Relations, claims: *const P.ExtensionClaim) !*Self {
            const layout = try Layout.derive(statement, steps);
            try layout.requireClaims(statement, claims);
            var placements: Ethereum.Placements = undefined;
            placements.keccak = .{ .preprocessed_offset = layout.placed[0][0], .main_offset = layout.placed[0][1], .interaction_offset = layout.placed[0][2] };
            inline for (.{ "chi", "xor5" }, 1..) |name, i| {
                var tuples: [6]usize = undefined;
                for (&tuples, 0..) |*v, j| v.* = layout.placed[i][0] + 1 + j;
                @field(placements, name) = .{ .is_first_col_idx = layout.placed[i][0], .tuple_col_indices = tuples, .main_col_offset = layout.placed[i][1], .interaction_col_offset = layout.placed[i][2] };
            }
            for (&placements.secp, 3..) |*placement, i| placement.* = .{ .preprocessed_offset = layout.placed[i][0], .main_offset = layout.placed[i][1], .interaction_offset = layout.placed[i][2] };
            const self = try a.create(Self);
            errdefer a.destroy(self);
            self.relations = relations.*;
            self.sha_owner = null;
            for (&self.placements, layout.placed) |*placement, position| placement.* = .{ .preprocessed_offset = position[0], .main_offset = position[1], .interaction_offset = position[2] };
            self.ethereum = try Ethereum.Assembly(direction).createPlaced(a, &statement.ethereum, &self.relations.ethereum, &.{}, &claims.ethereum, placements, @import("block_v5_precompile_protocol_v1.zig").circuit_profile);
            errdefer self.ethereum.destroy(a);
            self.len = 0;
            var constraints: usize = 0;
            for (self.ethereum.active(), 0..) |handle, i| if (layout.active[i]) {
                self.handles[self.len] = handle;
                self.len += 1;
                constraints = try std.math.add(usize, constraints, handle.nConstraints());
            };
            if (!layout.active[14]) return self;
            const manifest = try statement.sha.manifestForRecipe(.{ .columns = .{ @intCast(layout.placed[14][0]), @intCast(layout.placed[14][1]), @intCast(layout.placed[14][2]), @intCast(constraints) }, .claimed_sum_index = @intCast(self.len) }, false);
            const parameters: [Sha.Airs.len][0]core.fields.m31.M31 = @splat(.{});
            self.sha_owner = try ShaOwner.init(a, &manifest, parameters, self.relations.sha, claims.sha);
            errdefer self.sha_owner.?.deinit();
            const handles = if (direction == .prover) try self.sha_owner.?.proverHandles() else try self.sha_owner.?.verifierHandles();
            @memcpy(self.handles[self.len..][0..handles.len], &handles);
            self.len += handles.len;
            return self;
        }
        pub fn active(self: *const Self) []const Handle {
            return self.handles[0..self.len];
        }
        pub fn extensionPlacements(self: *const Self) [19]P.PlacementDescriptor {
            return self.placements;
        }
        pub fn destroy(self: *Self, a: std.mem.Allocator) void {
            if (self.sha_owner) |owner| owner.deinit();
            self.ethereum.destroy(a);
            a.destroy(self);
        }
    };
}
