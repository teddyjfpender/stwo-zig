//! Original decoded-ROM equations and interactions for a finite heterogeneous
//! STARK. This prepares an OPEN component; it creates no proof or receipt.
const std = @import("std");
const core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const Source = @import("block_v7_program_provider_v1.zig");
const Original = @import("block_v5_program_table_proof_v1.zig");
const Air = Original.Air;
const Binding = @import("../recursion/air/universal_relation_binding.zig").Binding(Air);
const Framework = @import("../recursion/air/framework_interaction.zig");
const Runtime = Framework.Runtime(Binding.Runtime);
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Column = Engine.pcs.ColumnEvaluation;
pub const Policy = Source.Policy;
pub const Claims = Q;
pub const Context = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    policy: Policy,
    claims: Claims,
    logs: [3][]u32,
    fixed_columns: []Column,
    interaction: []Column,
    provers: []Engine.air.component_prover.ComponentProver,
    verifiers: []core.air.components.Component,
    pub fn recordAfterChallenges(self: *const Context, ch: anytype) !void {
        try Source.recordAfterChallenges(ch, self.policy, self.claims);
    }
    pub fn deinit(self: *Context) void {
        const a = self.allocator;
        self.arena.deinit();
        a.destroy(self);
    }
};
fn begin(a: std.mem.Allocator) !*Context {
    const self = try a.create(Context);
    self.allocator = a;
    self.arena = std.heap.ArenaAllocator.init(a);
    return self;
}
fn finish(self: *Context, policy: Policy, claims: Claims, definition: *Air.Definition, relation: anytype, drawn: anytype, interaction: []Column) !void {
    const a = self.arena.allocator();
    const fixed = try policy.plan.fixedColumns(a);
    self.fixed_columns = try a.alloc(Column, fixed.len);
    for (fixed, self.fixed_columns) |values, *column| column.* = .{ .log_size = policy.plan.log_size, .values = values };
    inline for (.{ Air.PREPROCESSED_COLUMN_COUNT, 0, Air.INTERACTION_COLUMN_COUNT }, 0..) |count, tree| {
        self.logs[tree] = try a.alloc(u32, count);
        @memset(self.logs[tree], policy.plan.log_size);
    }
    const manifest = try a.create(Original.Roster.Manifest);
    manifest.* = .{ .log_sizes = .{policy.plan.log_size} };
    const component = try a.create(Original.Roster.Component(Air));
    component.* = try Original.Roster.Component(Air).init(definition, relation, manifest, .program, policy.plan.log_size, .{}, &drawn.word.universal_prefix, claims);
    self.provers = try a.alloc(Engine.air.component_prover.ComponentProver, 1);
    self.verifiers = try a.alloc(core.air.components.Component, 1);
    const geometry: core.air.components.CompositionGeometryOverrideV1 = .{ .max_constraint_log_degree_bound_delta = 1, .composition_log_split = 2 };
    self.provers[0] = try component.asProverComponent().withCompositionGeometryOverrideV1(geometry);
    self.verifiers[0] = try component.asVerifierComponent().withCompositionGeometryOverrideV1(geometry);
    self.policy = policy;
    self.claims = claims;
    self.interaction = interaction;
}
pub fn prepare(comptime Backend: type, a: std.mem.Allocator, first: *const Source.ForBackend(Backend).FirstRound, policy: Policy) !*Context {
    try policy.admit();
    if (!first.owns_scheme or !std.meta.eql(first.scheme.config, policy.epoch.config) or !std.meta.eql(first.plan_digest, try policy.plan.digest()) or !std.meta.eql(first.roots, policy.roots)) return error.UntrustedV7ProgramFirstRound;
    const self = try begin(a);
    errdefer self.deinit();
    const temp = self.arena.allocator();
    const drawn = try temp.create(@import("block_v7_execution_epoch_v1.zig").Drawn);
    drawn.* = try policy.epoch.draw(temp);
    const definition = try temp.create(Air.Definition);
    definition.* = try Air.build(temp);
    const relation = try Binding.authenticate(definition);
    const rows = try temp.alloc(Air.Row, policy.plan.multiplicities.len);
    for (rows, 0..) |*row, i| row.* = try policy.plan.row(i);
    var workspace = try Runtime.Workspace.init(temp, @min(policy.plan.log_size, Framework.OWNED_TILE_LOG_SIZE));
    defer workspace.deinit();
    const view = Runtime.ColumnRows{ .columns = @splat(&.{}), .count = rows.len, .main_count = 0, .metadata = rows };
    const generated = try Runtime.generatePreparedOwnedColumnsTiledWithWorkspace(temp, &workspace, &relation, view, policy.plan.log_size, &drawn.word.universal_prefix, @as(Air.Row, @splat(M.zero())));
    const interaction = try temp.alloc(Column, Air.INTERACTION_COLUMN_COUNT);
    for (generated.columns, interaction) |values, *column| column.* = .{ .log_size = policy.plan.log_size, .values = values };
    try finish(self, policy, generated.claimed_sum, definition, relation, drawn, interaction);
    return self;
}
/// Independently reconstruct fixed data and original verifier equations from
/// admitted ELF policy and proposed public claim, before the union STARK check.
pub fn verifier(comptime Backend: type, a: std.mem.Allocator, policy: Policy, claims: Claims) !*Context {
    try Source.ForBackend(Backend).requireFixedRoots(a, policy);
    const self = try begin(a);
    errdefer self.deinit();
    const temp = self.arena.allocator();
    const drawn = try temp.create(@import("block_v7_execution_epoch_v1.zig").Drawn);
    drawn.* = try policy.epoch.draw(temp);
    var ch = drawn.channel;
    try Source.recordAfterChallenges(&ch, policy, claims);
    const definition = try temp.create(Air.Definition);
    definition.* = try Air.build(temp);
    try finish(self, policy, claims, definition, try Binding.authenticate(definition), drawn, &.{});
    return self;
}
