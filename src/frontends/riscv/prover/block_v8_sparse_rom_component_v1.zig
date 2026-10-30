//! Canonical typed public-program AIR over sparse ELF-derived fixed rows.
//! No polynomial is removed or replaced; preprocessing authority is versioned.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Source = @import("block_v8_sparse_rom_v1.zig");
const Original = @import("block_v5_program_table_proof_v1.zig");
const Air = Original.Air;
const Binding = @import("../recursion/air/universal_relation_binding.zig").Binding(Air);
const Framework = @import("../recursion/air/framework_interaction.zig");
const Runtime = Framework.Runtime(Binding.Runtime);
const U = @import("../recursion/air/universal_challenges.zig").UniversalRelations;
const Column = engine.pcs.ColumnEvaluation;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
pub const Owner = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    relations: U,
    fixed: [6]Column,
    interaction: []Column,
    claim: Q,
    prover: engine.air.component_prover.ComponentProver,
    verifier: core.air.components.Component,
    pub fn create(a: std.mem.Allocator, plan: *const Source.Owned, universal: U, supplied_claim: ?Q) !*Owner {
        const self = try a.create(Owner);
        errdefer a.destroy(self);
        self.allocator = a;
        self.arena = std.heap.ArenaAllocator.init(a);
        self.relations = universal;
        errdefer self.arena.deinit();
        try self.relations.validate();
        const t = self.arena.allocator();
        self.fixed = try plan.fixedColumns(t);
        const definition = try t.create(Air.Definition);
        definition.* = try Air.build(t);
        const relation = try Binding.authenticate(definition);
        self.interaction = &.{};
        if (supplied_claim) |claim| {
            for (claim.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.InvalidSparseRomClaim;
            self.claim = claim;
        } else {
            var workspace = try Runtime.Workspace.init(t, @min(plan.log_size, Framework.OWNED_TILE_LOG_SIZE));
            defer workspace.deinit();
            const view = Runtime.ColumnRows{ .columns = @splat(&.{}), .count = plan.rows.len, .main_count = 0, .metadata = plan.rows };
            const generated = try Runtime.generatePreparedOwnedColumnsTiledWithWorkspace(t, &workspace, &relation, view, plan.log_size, &self.relations, @as(Air.Row, @splat(M.zero())));
            self.claim = generated.claimed_sum;
            self.interaction = try t.alloc(Column, Air.INTERACTION_COLUMN_COUNT);
            for (generated.columns, self.interaction) |values, *c| c.* = .{ .log_size = plan.log_size, .values = values };
        }
        const manifest = try t.create(Original.Roster.Manifest);
        manifest.* = .{ .log_sizes = .{plan.log_size} };
        const component = try t.create(Original.Roster.Component(Air));
        component.* = try Original.Roster.Component(Air).init(definition, relation, manifest, .program, plan.log_size, .{}, &self.relations, self.claim);
        const geometry: core.air.components.CompositionGeometryOverrideV1 = .{ .max_constraint_log_degree_bound_delta = 1, .composition_log_split = 2 };
        self.prover = try component.asProverComponent().withCompositionGeometryOverrideV1(geometry);
        self.verifier = try component.asVerifierComponent().withCompositionGeometryOverrideV1(geometry);
        return self;
    }
    pub fn deinit(self: *Owner) void {
        const a = self.allocator;
        self.arena.deinit();
        a.destroy(self);
    }
};
pub fn recordClaim(channel: anytype, digest: [32]u8, claim: Q) !void {
    for (claim.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.InvalidSparseRomClaim;
    channel.mixU32s(&.{ Source.TAG, Source.VERSION, 6, 0, 4 });
    channel.mixRoot(digest);
    channel.mixFelts(&.{claim});
}
