//! Reuse shipped exact lookup AIRs at standalone fixed/main/interaction origin.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const tables = @import("../air/lookups/tables/mod.zig");
const shared = @import("../recursion/air/universal_provider_relations.zig");
const Q = core.fields.qm31.QM31;
pub const Count = tables.schema.KIND_COUNT;
pub const Owner = struct {
    relations: shared.SharedProviderRelations,
    tuples: [Count][tables.schema.MAX_ARITY]usize,
    components: [Count]tables.component.LookupTableComponent,
    pub fn init(a: std.mem.Allocator, relations: shared.SharedProviderRelations, claims: [Count]Q) !*Owner {
        const self = try a.create(Owner);
        errdefer a.destroy(self);
        self.relations = relations;
        var fixed_at: usize = 0;
        for (&self.components, &self.tuples, claims, 0..) |*component, *tuple, claim, index| {
            const kind: tables.schema.Kind = @enumFromInt(index);
            const arity = tables.schema.arity(kind);
            for (tuple[0..arity], 0..) |*offset, limb| offset.* = fixed_at + 1 + limb;
            component.* = try tables.component.LookupTableComponent.initProver(kind, fixed_at, tuple[0..arity], index, index * 4, &self.relations.native, claim);
            fixed_at += arity + 1;
        }
        return self;
    }
    pub fn destroy(self: *Owner, a: std.mem.Allocator) void {
        a.destroy(self);
    }
    pub fn proverHandles(self: *const Owner) [Count]engine.air.component_prover.ComponentProver {
        var handles: [Count]engine.air.component_prover.ComponentProver = undefined;
        for (&self.components, &handles) |*component, *handle| handle.* = component.asProverComponent();
        return handles;
    }
    pub fn verifierHandles(self: *const Owner) [Count]core.air.components.Component {
        var handles: [Count]core.air.components.Component = undefined;
        for (&self.components, &handles) |*component, *handle| handle.* = component.asVerifierComponent();
        return handles;
    }
};
pub const Tree = enum { fixed, main, interaction };
pub fn logs(a: std.mem.Allocator, tree: Tree) ![]u32 {
    var values: std.ArrayList(u32) = .empty;
    errdefer values.deinit(a);
    for (0..Count) |index| {
        const kind: tables.schema.Kind = @enumFromInt(index);
        const width: usize = switch (tree) {
            .fixed => tables.schema.arity(kind) + 1,
            .main => 1,
            .interaction => 4,
        };
        try values.appendNTimes(a, tables.schema.logSize(kind), width);
    }
    return values.toOwnedSlice(a);
}
