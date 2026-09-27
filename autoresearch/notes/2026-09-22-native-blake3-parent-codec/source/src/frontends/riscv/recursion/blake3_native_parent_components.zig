//! Stable verifier component owner shared by proof preflight and verification.
const std = @import("std");
const core = @import("stwo_core");
const protocol = @import("blake3_native_parent_protocol.zig");
const artifact = @import("blake3_native_parent_artifact.zig");
const native = @import("air/blake3_native_parent_rows.zig");
const Roster = @import("air/blake3_native_parent_roster.zig").Roster;
const binding = @import("air/universal_relation_binding.zig");
const typed = @import("air/universal_typed_verifier_component.zig");
const universal = @import("air/universal_challenges.zig");
const schema = @import("../air/lookups/tables/schema.zig");
const Table = @import("../air/lookups/tables/verifier.zig").LookupTableVerifier;
const KINDS = [_]schema.Kind{ .bitwise, .range_check_8_8 };
fn Components() type {
    var types: [Roster.Airs.len]type = undefined;
    for (Roster.Airs, &types) |Air, *T| T.* = typed.ComponentForManifest(Air, binding.Binding(Air), Roster);
    return std.meta.Tuple(&types);
}
const Providers = @import("air/universal_provider_relations.zig").SharedProviderRelations;
pub const Owned = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    logs: [18]u32,
    definitions: Roster.Tuple(.definition),
    plans: Roster.Tuple(.plan),
    columns: [3]std.ArrayList(u32),
    table_pp: [2]usize,
    table_main: usize,
    table_interaction: usize,
    relations: universal.UniversalRelations,
    providers: Providers,
    components: Components(),
    tables: [2]Table,
    verifiers: [artifact.CLAIM_COUNT]core.air.components.Component,
    pub fn init(a: std.mem.Allocator, admission: *const protocol.Admission) !*Owned {
        try admission.validate();
        const self = try a.create(Owned);
        errdefer a.destroy(self);
        self.* = undefined;
        self.allocator = a;
        self.arena = std.heap.ArenaAllocator.init(a);
        errdefer self.arena.deinit();
        self.logs = admission.key.log_sizes;
        self.columns = @splat(.empty);
        const temp = self.arena.allocator();
        inline for (Roster.Airs, 0..) |Air, i| {
            self.definitions[i] = if (@hasDecl(Air, "Location")) try Air.build(temp, .generated) else try Air.build(temp);
            self.plans[i] = try binding.Binding(Air).authenticate(&self.definitions[i]);
            inline for (.{ Air.PREPROCESSED_COLUMN_COUNT, Air.PHYSICAL_MAIN_COLUMN_COUNT, Air.INTERACTION_COLUMN_COUNT }, 0..) |count, tree| {
                try self.columns[tree].appendNTimes(temp, self.logs[i], count);
            }
        }
        self.table_main = self.columns[1].items.len;
        self.table_interaction = self.columns[2].items.len;
        for (KINDS, &self.table_pp) |kind, *offset| {
            offset.* = self.columns[0].items.len;
            try self.columns[0].appendNTimes(temp, schema.logSize(kind), 1 + schema.arity(kind));
            try self.columns[1].append(temp, schema.logSize(kind));
            try self.columns[2].appendNTimes(temp, schema.logSize(kind), 4);
        }
        return self;
    }
    pub fn bind(self: *Owned, relations: universal.UniversalRelations, claims: artifact.Claims) !void {
        self.relations = relations;
        self.providers = try Providers.init(&self.relations);
        const manifest = Roster.Manifest{ .log_sizes = self.logs };
        inline for (Roster.Airs, 0..) |Air, i| {
            const parameters = if (i >= 3 and i <= 5) native.selectors else [0]core.fields.m31.M31{};
            self.components[i] = try typed.ComponentForManifest(Air, binding.Binding(Air), Roster).init(&self.definitions[i], self.plans[i], &manifest, @enumFromInt(i), self.logs[i], parameters, &self.relations, claims[i]);
            self.verifiers[i] = self.components[i].asVerifierComponent();
        }
        for (&self.tables, KINDS, self.table_pp, 0..) |*table, kind, offset, i| {
            var tuple: [schema.MAX_ARITY]usize = undefined;
            for (tuple[0..schema.arity(kind)], 0..) |*column, j| column.* = offset + 1 + j;
            table.* = try Table.initVerifier(kind, offset, tuple[0..schema.arity(kind)], self.table_main + i, self.table_interaction + 4 * i, &self.providers.native, claims[Roster.Airs.len + i]);
            self.verifiers[Roster.Airs.len + i] = table.asVerifierComponent();
        }
    }
    pub fn deinit(self: *Owned) void {
        const a = self.allocator;
        self.arena.deinit();
        a.destroy(self);
    }
    pub fn admitted(self: *const Owned) core.air.components.Components {
        return .{ .components = &self.verifiers, .n_preprocessed_columns = self.columns[0].items.len };
    }
};
