//! Finite compact/dense lookup provider preparation using original equations.
//! Contexts are OPEN inputs to a combined STARK, not verification receipts.
const std = @import("std");
const core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const Source = @import("block_v7_lookup_compact_proof_v1.zig");
const Algebra = @import("block_v7_lookup_compact_algebra_v1.zig");
const Trace = @import("block_v7_lookup_compact_trace_v1.zig");
const Matrix = @import("block_v7_memory_trace_v1.zig");
const Air = @import("block_v7_lookup_compact_air_v1.zig");
const Relations = @import("block_v7_memory_relations_v1.zig");
const Shared = @import("../recursion/air/universal_provider_relations.zig");
const Column = Engine.pcs.ColumnEvaluation;
pub const Policy = Source.Policy;
pub const Claims = [6]Relations.Q;
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
fn finish(self: *Context, policy: Policy, claims: Claims, relations: Shared.SharedProviderRelations, fixed: *const [6]Matrix.Matrix, interaction: []Column) !void {
    const a = self.arena.allocator();
    const owner = try Air.Owner.init(a, policy.layout, relations, claims);
    self.provers = &owner.provers;
    self.verifiers = &owner.verifiers;
    self.fixed_columns = try a.alloc(Column, policy.layout.columns[0]);
    var offset: usize = 0;
    for (fixed) |m| {
        @memcpy(self.fixed_columns[offset..][0..m.columns.len], m.columns);
        offset += m.columns.len;
    }
    if (offset != self.fixed_columns.len) return error.InvalidCompleteLookupColumns;
    for (&self.logs, 0..) |*logs, tree| logs.* = try policy.layout.logs(a, tree);
    self.policy = policy;
    self.claims = claims;
    self.interaction = interaction;
}
/// Original Stage must outlive the context: fixed values are borrowed and
/// original committed MAIN ownership remains with Stage for union adoption.
pub fn prepare(comptime Backend: type, a: std.mem.Allocator, stage: *const Source.For(Backend).Stage, policy: Policy) !*Context {
    try policy.validate();
    if (!stage.owns or !std.meta.eql(stage.config, policy.epoch.config) or !std.meta.eql(stage.roots, policy.roots) or !std.meta.eql(try stage.entry(), try policy.entry())) return error.InvalidCompactLookupPhase;
    const self = try begin(a);
    errdefer self.deinit();
    const temp = self.arena.allocator();
    const drawn = try policy.epoch.draw(temp);
    const relations = try Shared.SharedProviderRelations.init(&drawn.word.universal_prefix);
    const generated = try temp.alloc(Matrix.Generated(1), 6);
    var claims: Claims = undefined;
    inline for (0..6) |i| {
        inline for (.{ Algebra.Mode.dense, Algebra.Mode.sparse }) |mode| if (stage.layout.parts[i].mode == mode) {
            const Spec = Algebra.For(@enumFromInt(i), mode);
            const Terms = struct {
                fixed: Matrix.Matrix,
                relation: Relations.Relation(Relations.Q, Algebra.Schema.arity(@enumFromInt(i))),
                pub fn termsAt(c: @This(), matrix: Matrix.Matrix, row: usize) ![1]Relations.Term(Relations.Q) {
                    return .{Spec.term(Relations.Q, c.relation, c.fixed.row(Spec.FIXED_COUNT, 0, row), matrix.row(Spec.MAIN_COUNT, 0, row))};
                }
            };
            generated[i] = try Matrix.interactions(1, temp, stage.main[i], Terms{ .fixed = stage.fixed[i], .relation = .from(@field(relations.native, @tagName(@as(Algebra.Schema.Kind, @enumFromInt(i))))) }, stage.limits.max_matrix_bytes);
            claims[i] = generated[i].sums[0];
        };
    }
    const interaction = try temp.alloc(Column, stage.layout.columns[2]);
    for (generated, stage.layout.parts) |g, part| @memcpy(interaction[part.offset[2]..][0..part.width[2]], g.matrix.columns);
    try finish(self, policy, claims, relations, &stage.fixed, interaction);
    return self;
}
pub fn verifier(comptime Backend: type, a: std.mem.Allocator, policy: Policy, claims: Claims, limits: Source.Limits) !*Context {
    try Source.For(Backend).requireFixedRoots(a, policy, limits);
    const self = try begin(a);
    errdefer self.deinit();
    const temp = self.arena.allocator();
    const drawn = try policy.epoch.draw(temp);
    var ch = drawn.channel;
    try Source.recordAfterChallenges(&ch, policy, claims);
    const fixed = try temp.create([6]Matrix.Matrix);
    for (policy.layout.parts, fixed) |part, *m| m.* = try Trace.fixed(temp, part, limits.max_matrix_bytes);
    try finish(self, policy, claims, try Shared.SharedProviderRelations.init(&drawn.word.universal_prefix), fixed, &.{});
    return self;
}
