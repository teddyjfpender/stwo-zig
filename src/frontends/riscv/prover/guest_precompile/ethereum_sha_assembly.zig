//! Stable combined component ownership; all offsets follow admitted geometry.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const ethereum = @import("ethereum_assembly.zig");
const sha = @import("../../air/guest_precompile/sha256_component_profile.zig");
const ShaOwner = @import("../../recursion/air/universal_component_owner.zig").ForRoster(sha.Roster);
const LocalZeroShaOwner = @import("../../recursion/air/universal_component_owner.zig").ForRoster(sha.LocalZeroRoster);
const Relations = @import("ethereum_sha_relations.zig").Relations;
const Claim = @import("ethereum_sha_types.zig").ExtensionClaim;
const Statement = @import("../blake3_ethereum_sha_statement.zig").Statement;
pub const PlacementDescriptor = ethereum.PlacementDescriptor;
pub const component_count = @import("ethereum_sha_types.zig").component_count;

pub fn Assembly(comptime direction: ethereum.Direction) type {
    const Handle = if (direction == .prover) engine.air.component_prover.ComponentProver else core.air.components.Component;
    const Ethereum = ethereum.Assembly(direction);
    return struct {
        const Self = @This();
        relations: Relations,
        ethereum: *Ethereum,
        sha_owner: *ShaOwner,
        sha_owner_local_zero: ?*LocalZeroShaOwner,
        placements: [component_count]PlacementDescriptor,
        handles: [ethereum.max_handles + sha.Airs.len]Handle,
        len: usize,

        pub fn createBlake3WithRanges(a: std.mem.Allocator, native: *const @import("../../air/statement.zig").Blake3ExecutionStatement, statement: *const Statement, pin: @import("../blake3_commitment_plan.zig").Admission, logs: @import("../blake3_ethereum_statement.zig").HashLogs, relations: *const Relations, prefix: []const Handle, claims: *const Claim, ranges: ?@import("../../recursion/air/compact_range_geometry.zig").Plan) !*Self {
            try claims.validate(statement);
            const self = try a.create(Self);
            errdefer a.destroy(self);
            self.relations = relations.*;
            self.ethereum = try Ethereum.createBlake3WithSha(a, native, statement, pin, logs, &self.relations.ethereum, prefix, &claims.ethereum, ranges);
            errdefer self.ethereum.destroy(a);
            return self.finishSha(a, statement, claims);
        }

        pub fn createBlockV5Standalone(a: std.mem.Allocator, statement: *const Statement, total_steps: u32, relations: *const Relations, claims: *const Claim) !*Self {
            return createBlockV5StandaloneForCircuitProfileV1(a, statement, total_steps, relations, claims, @import("../block_v5_precompile_protocol_v1.zig").circuit_profile);
        }

        pub fn createBlockV5StandaloneForCircuitProfileV1(a: std.mem.Allocator, statement: *const Statement, total_steps: u32, relations: *const Relations, claims: *const Claim, circuit_profile: @import("../ethereum_circuit_profile_v1.zig").CircuitProfileV1) !*Self {
            try circuit_profile.requireCallerExecution(.rv32im_zkvm_ethereum_sha_v1);
            try statement.ethereum.validateGeometryWithCircuitProfileV1(total_steps, circuit_profile);
            try claims.validate(statement);
            try statement.sha.validateForRecipe(total_steps, circuit_profile.localZeroCustody());
            const self = try a.create(Self);
            errdefer a.destroy(self);
            self.relations = relations.*;
            self.ethereum = try Ethereum.createBlockV5StandaloneForCircuitProfileV1(a, &statement.ethereum, total_steps, &self.relations.ethereum, &claims.ethereum, circuit_profile);
            errdefer self.ethereum.destroy(a);
            return self.finishSha(a, statement, claims);
        }

        fn finishSha(self: *Self, a: std.mem.Allocator, statement: *const Statement, claims: *const Claim) !*Self {
            return if (statement.ethereum.localZeroCustody()) self.finishShaForRecipe(true, a, statement, claims) else self.finishShaForRecipe(false, a, statement, claims);
        }
        fn finishShaForRecipe(self: *Self, comptime local_zero: bool, a: std.mem.Allocator, statement: *const Statement, claims: *const Claim) !*Self {
            const placements = self.ethereum.extensionPlacements();
            @memcpy(self.placements[0..placements.len], &placements);
            const last = placements[placements.len - 1];
            const desc = statement.ethereum.components[placements.len - 1];
            var constraints: usize = 0;
            for (self.ethereum.active()) |handle| constraints = try std.math.add(usize, constraints, handle.nConstraints());
            const manifest = try statement.sha.manifestForRecipe(.{ .columns = .{
                try offset(last.preprocessed_offset, desc.preprocessed_columns),
                try offset(last.main_offset, desc.main_columns),
                try offset(last.interaction_offset, desc.interaction_columns),
                std.math.cast(u32, constraints) orelse return error.Overflow,
            }, .claimed_sum_index = std.math.cast(u32, self.ethereum.active().len) orelse return error.Overflow }, local_zero);
            const parameters: [sha.Airs.len][0]core.fields.m31.M31 = @splat(.{});
            const RecipeOwner = if (local_zero) LocalZeroShaOwner else ShaOwner;
            const owner = try RecipeOwner.init(a, &manifest, parameters, self.relations.sha, claims.sha);
            errdefer owner.deinit();
            if (local_zero) {
                self.sha_owner = undefined;
                self.sha_owner_local_zero = owner;
            } else {
                self.sha_owner = owner;
                self.sha_owner_local_zero = null;
            }
            const sha_handles = if (direction == .prover) try owner.proverHandles() else try owner.verifierHandles();
            const base = self.ethereum.active();
            @memcpy(self.handles[0..base.len], base);
            @memcpy(self.handles[base.len..][0..sha_handles.len], &sha_handles);
            self.len = base.len + sha_handles.len;
            inline for (0..sha.Airs.len) |i| {
                const placement = try manifest.placement(@enumFromInt(i));
                self.placements[placements.len + i] = .{ .preprocessed_offset = placement.preprocessed_offset, .main_offset = placement.main_offset, .interaction_offset = placement.interaction_offset };
            }
            return self;
        }
        pub fn active(self: *const Self) []const Handle {
            return self.handles[0..self.len];
        }
        pub fn extensionPlacements(self: *const Self) [component_count]PlacementDescriptor {
            return self.placements;
        }
        pub fn destroy(self: *Self, a: std.mem.Allocator) void {
            if (self.sha_owner_local_zero) |owner| owner.deinit() else self.sha_owner.deinit();
            self.ethereum.destroy(a);
            a.destroy(self);
        }
    };
}
fn offset(start: usize, width: u32) !u32 {
    return std.math.cast(u32, try std.math.add(usize, start, width)) orelse error.Overflow;
}
