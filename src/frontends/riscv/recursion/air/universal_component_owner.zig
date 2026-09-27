//! Stable ownership for typed component handles in joined proving systems.
//! The caller supplies independently admitted geometry and transcript challenges.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const binding = @import("universal_relation_binding.zig");
const universal = @import("universal_challenges.zig");
const composition = @import("roster_composition_geometry.zig");

pub fn ForRoster(comptime Roster: type) type {
    return struct {
        const Self = @This();
        allocator: std.mem.Allocator,
        relations: universal.UniversalRelations,
        components: Roster.Tuple(.component),

        /// Compile each canonical AIR once. Arenas are released immediately;
        /// components retain checked scalar programs, never borrowed ASTs.
        pub fn init(a: std.mem.Allocator, manifest: *const Roster.Manifest, parameters: anytype, relations: universal.UniversalRelations, claims: [Roster.Airs.len]core.fields.qm31.QM31) !*Self {
            try relations.validate();
            const self = try a.create(Self);
            errdefer a.destroy(self);
            self.* = .{ .allocator = a, .relations = relations, .components = undefined };
            inline for (Roster.Airs, 0..) |Air, i| {
                var definition = if (@hasDecl(Air, "Location")) try Air.build(a, .generated) else try Air.build(a);
                defer definition.deinit();
                const plan = try binding.Binding(Air).authenticate(&definition);
                self.components[i] = try Roster.Component(Air).init(&definition, plan, manifest, @enumFromInt(i), manifest.log_sizes[i], parameters[i], &self.relations, claims[i]);
            }
            return self;
        }

        /// Reuse the same authenticated definitions/plans used for interaction
        /// generation. They remain borrowed only for this construction call.
        pub fn initPrepared(a: std.mem.Allocator, manifest: *const Roster.Manifest, definitions: *const Roster.Tuple(.definition), plans: *const Roster.Tuple(.plan), parameters: anytype, relations: universal.UniversalRelations, claims: [Roster.Airs.len]core.fields.qm31.QM31) !*Self {
            try relations.validate();
            const self = try a.create(Self);
            errdefer a.destroy(self);
            self.* = .{ .allocator = a, .relations = relations, .components = undefined };
            inline for (Roster.Airs, 0..) |Air, i| self.components[i] = try Roster.Component(Air).init(&definitions[i], plans[i], manifest, @enumFromInt(i), manifest.log_sizes[i], parameters[i], &self.relations, claims[i]);
            return self;
        }

        pub fn deinit(self: *Self) void {
            const a = self.allocator;
            self.* = undefined;
            a.destroy(self);
        }

        /// Handles borrow this stable owner and must not outlive it.
        pub fn proverHandles(self: *const Self) ![Roster.Airs.len]engine.air.component_prover.ComponentProver {
            var result: [Roster.Airs.len]engine.air.component_prover.ComponentProver = undefined;
            inline for (Roster.Airs, 0..) |Air, i| result[i] = try composition.ForAirs(Roster.Airs).component(Air, self.components[i].asProverComponent());
            return result;
        }
        pub fn verifierHandles(self: *const Self) ![Roster.Airs.len]core.air.components.Component {
            var result: [Roster.Airs.len]core.air.components.Component = undefined;
            inline for (Roster.Airs, 0..) |Air, i| result[i] = try composition.ForAirs(Roster.Airs).component(Air, self.components[i].asVerifierComponent());
            return result;
        }
    };
}

test "SHA provider joined component owner keeps challenges alive after AST teardown" {
    const profile = @import("../../air/guest_precompile/sha256_component_profile.zig");
    const admitted = try profile.Profile.canonical(0);
    const manifest = try admitted.manifest(.{});
    const parameters: [profile.Airs.len][0]core.fields.m31.M31 = @splat(.{});
    const relations = try @import("../../air/guest_precompile/sha256_relations.zig").fromDraws(universal.UniversalRelations.dummy(), .{ core.fields.qm31.QM31.one(), core.fields.qm31.QM31.fromU32Unchecked(2, 0, 0, 0) });
    const owner = try ForRoster(profile.Roster).init(std.testing.allocator, &manifest, parameters, relations, @splat(core.fields.qm31.QM31.zero()));
    defer owner.deinit();
    try std.testing.expectEqual(profile.Airs.len, (try owner.proverHandles()).len);
    try std.testing.expectEqual(profile.Airs.len, (try owner.verifierHandles()).len);
    inline for (0..profile.Airs.len) |i| try std.testing.expect(owner.components[i].relations == &owner.relations);
}
