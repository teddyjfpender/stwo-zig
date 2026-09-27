//! Immutable leaf component collection with verifier-only dependencies.
const std = @import("std");
const core = @import("stwo_core");
const catalog = @import("air/segment_leaf_catalog_v2.zig");
const binding = @import("air/universal_relation_binding.zig");
const typed = @import("air/universal_typed_verifier_component.zig");
const provider_relations = @import("air/universal_provider_relations.zig");
const admission = @import("air/universal_provider_admission.zig");
const range = @import("air/range_check_8_8_contract.zig");
const table = @import("../air/lookups/tables/verifier.zig").LookupTableVerifier;
const poseidon = @import("../air/memory_commitment/poseidon2_degree3_verifier.zig");
const Wide = poseidon.Component(@import("../air/memory_commitment/poseidon2_wide_equations.zig"));
pub const manifest_mod = @import("air/segment_outer_manifest_contract_v2.zig");
pub const Relations = @import("air/universal_challenges.zig").UniversalRelations;
pub const LOGICAL_ROWS = catalog.LOGICAL_ROWS;

pub fn Component(comptime entry: catalog.Entry) type {
    @setEvalBranchQuota(500_000);
    return typed.ComponentForManifest(entry.Air, Relation(entry), manifest_mod);
}

fn Relation(comptime entry: catalog.Entry) type {
    if (entry.row == .statement_source_v2 or entry.row == .public_logup_source_v2)
        return struct {
            pub const Runtime = entry.Air.Runtime;
        };
    return binding.Binding(entry.Air);
}

const contract = @import("detached_segment_admission_v1.zig");
pub const ParametersV1 = contract.AdmissionParametersV1;
pub const ClaimsV1 = contract.ClaimsV1;
const parametersFor = @import("segment_leaf_parameters_v2.zig").parametersFor;
const definitions_mod = @import("detached_segment_definitions_v1.zig");

fn ComponentTuple() type {
    var types: [LOGICAL_ROWS.len]type = undefined;
    for (LOGICAL_ROWS, 0..) |entry, index| types[index] = Component(entry);
    return std.meta.Tuple(&types);
}

/// All adapter pointers target this immutable heap owner. Parameters are copied
/// into adapters at admission; this owner never borrows key slice storage.
pub const OwnedComponentsV1 = opaque {
    const Self = @This();
    const Storage = struct {
        allocator: std.mem.Allocator,
        manifest: manifest_mod.Manifest,
        relations: Relations,
        providers: provider_relations.SharedProviderRelations,
        definitions: definitions_mod.Definitions,
        logical: ComponentTuple(),
        poseidon: Wide,
        range_component: table,
        components: [manifest_mod.COMPONENT_COUNT]core.air.components.Component = undefined,
        count: usize = 0,
    };

    pub fn init(allocator: std.mem.Allocator, manifest: *const manifest_mod.Manifest, parameters: ParametersV1, relations: *const Relations, claims: ClaimsV1) !*Self {
        _ = try parameters.validate(manifest);
        _ = try claims.vector(manifest);
        try relations.validate();
        const storage = try allocator.create(Storage);
        storage.* = .{
            .allocator = allocator,
            .manifest = manifest.*,
            .relations = relations.*,
            .providers = undefined,
            .definitions = definitions_mod.Definitions.init(allocator),
            .logical = undefined,
            .poseidon = undefined,
            .range_component = undefined,
        };
        const self: *Self = @ptrCast(storage);
        errdefer self.deinit();
        storage.providers = try provider_relations.SharedProviderRelations.init(&storage.relations);
        inline for (LOGICAL_ROWS[0..34], 0..) |entry, index| try initLogical(storage, entry, index, parameters, claims);
        storage.poseidon = try initPoseidon(storage, parameters, claims);
        try append(storage, 34, storage.poseidon.asVerifierComponent());
        try storage.definitions.initRange();
        const definition = &storage.definitions.range_definition;
        const placement = try admission.rangeCheck(manifest_mod, definition, &try range.Binding.canonical(definition), &storage.manifest, &storage.providers, &storage.relations, claims.values[35]);
        const offset: usize = placement.preprocessed_offset;
        storage.range_component = try table.initVerifier(range.TABLE_KIND, offset, &.{ offset + 1, offset + 2 }, placement.main_offset, placement.interaction_offset, &storage.providers.native, claims.values[35]);
        try append(storage, 35, storage.range_component.asVerifierComponent());
        inline for (LOGICAL_ROWS[34..], 34..) |entry, index| try initLogical(storage, entry, index, parameters, claims);
        if (storage.count != storage.manifest.roster_count) return error.AdapterCountMismatch;
        return self;
    }

    fn initLogical(storage: *Storage, comptime entry: catalog.Entry, comptime index: usize, parameters: ParametersV1, claims: ClaimsV1) !void {
        const row = @intFromEnum(entry.row);
        try storage.definitions.initLogical(index);
        const relation = if (comptime entry.row == .statement_source_v2 or entry.row == .public_logup_source_v2)
            try entry.Air.authenticate(&storage.definitions.logical[index])
        else
            try binding.Binding(entry.Air).authenticate(&storage.definitions.logical[index]);
        storage.logical[index] = try Component(entry).init(&storage.definitions.logical[index], relation, &storage.manifest, entry.row, storage.manifest.placements[row].?.geometry.log_size, try parametersFor(entry, parameters), &storage.relations, claims.values[row]);
        try append(storage, row, storage.logical[index].asVerifierComponent());
    }

    pub fn deinit(self: *Self) void {
        const storage: *Storage = @ptrCast(@alignCast(self));
        storage.definitions.deinit();
        storage.allocator.destroy(storage);
    }

    pub fn verifierComponents(self: *const Self) ![]const core.air.components.Component {
        const storage: *const Storage = @ptrCast(@alignCast(self));
        return storage.components[0..storage.count];
    }

    fn append(storage: *Storage, row: usize, component: core.air.components.Component) !void {
        if (storage.count >= storage.manifest.roster_count) return error.AdapterCountMismatch;
        if (storage.manifest.roster_rows[storage.count] != row) return error.AdapterOrderMismatch;
        storage.components[storage.count] = component;
        storage.count += 1;
    }

    fn initPoseidon(storage: *Storage, parameters: ParametersV1, claims: ClaimsV1) !Wide {
        const placement = try admission.poseidon(manifest_mod, false, .canonical_only, storage.allocator, &storage.manifest, storage.manifest.placements[34].?.geometry.log_size, parameters.poseidon_active_rows, &storage.providers, &storage.relations, claims.poseidon_partials);
        const component = Wide{
            .log_size = placement.geometry.log_size,
            .n_rows = parameters.poseidon_active_rows,
            .is_first_col_idx = placement.preprocessed_offset,
            .is_active_col_idx = placement.preprocessed_offset,
            .main_col_offset = placement.main_offset,
            .interaction_col_offset = placement.interaction_offset,
            .relations = &storage.providers.native,
            .claims = claims.poseidon_partials,
        };
        try component.validate();
        return component;
    }
};
