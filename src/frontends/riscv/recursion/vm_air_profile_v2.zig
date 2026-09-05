//! Authenticated physical VM-AIR profile for SegmentV2 lookup batching.
//!
//! The frozen V1 profile derives opcode lookup geometry from compatibility
//! batches. SegmentV2 instead commits the selected physical lookup manifest;
//! this disjoint profile records that exact component order and checks the
//! verifier vtables against it before publishing a pointer-free authority.

const std = @import("std");
const stwo_core = @import("stwo_core");
const core_components = stwo_core.air.components;
const m31 = stwo_core.fields.m31;
const verifier_types = stwo_core.verifier_types;

const base_assembly = @import("../prover/base_component_assembly.zig");
const lookup_physical_v2 = @import("../air/lang/lookup_physical_manifest_v2.zig");
const relation_challenges = @import("../air/relation_challenges.zig");
const registry = @import("vm_air_profile_v2_registry.zig");
const semantic_eval = @import("../air/semantic_eval.zig");
const statement_mod = @import("../air/statement.zig");
const transcript_claims = @import("../air/transcript/claims.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const PROFILE_DOMAIN = "stwo-zig/riscv/recursion/vm-air-profile/v2\x00";

pub const Error = std.mem.Allocator.Error || error{
    AirInstructionCountOverflow,
    ClaimedSumCountOverflow,
    ColumnCountOverflow,
    ComponentBoundMismatch,
    ComponentCountMismatch,
    ConstraintCountMismatch,
    EmptyComponentManifest,
    InconsistentCompositionLogSplit,
    InvalidComponentEntry,
    InvalidInputProfile,
    InvalidProfileIdentity,
    InvalidStatementShape,
    ProfileMismatch,
};

pub const AdapterRoleV2 = enum(u8) {
    opcode_semantic = 1,
    opcode_lookup = 2,
    infrastructure = 3,
};

pub const TreeSpanV2 = struct {
    offset: u32,
    sampled_columns: u32,
    declared_columns: u32,

    fn validate(self: TreeSpanV2) Error!void {
        if (self.declared_columns > self.sampled_columns)
            return error.InvalidComponentEntry;
        _ = try self.end();
    }

    fn end(self: TreeSpanV2) Error!u32 {
        return std.math.add(u32, self.offset, self.sampled_columns) catch
            error.ColumnCountOverflow;
    }
};

pub const OpcodeSemanticKeyV2 = struct {
    descriptor: statement_mod.FamilyComponentDesc,
    typed_authority_identity: [32]u8,
};

pub const OpcodeLookupKeyV2 = struct {
    family: @import("../runner/trace.zig").OpcodeFamily,
    typed_authority_identity: [32]u8,
    component_identity: [32]u8,
    partition_identity: [32]u8,
    layout_identity: [32]u8,
    program_identity: [32]u8,
};

pub const InfrastructureKeyV2 = struct {
    kind: statement_mod.InfraKind,
    adapter_kind: base_assembly.InfrastructureAdapterKind,
};

/// Typed registry key. Infrastructure uses its closed enum/adapter pair;
/// opcode adapters additionally retain the reviewed authority digests.
pub const RegistryKeyV2 = union(AdapterRoleV2) {
    opcode_semantic: OpcodeSemanticKeyV2,
    opcode_lookup: OpcodeLookupKeyV2,
    infrastructure: InfrastructureKeyV2,
};

pub const EntryV2 = struct {
    physical_index: u32,
    shard_ordinal: u32,
    active: bool,
    registry: RegistryKeyV2,
    log_size: u32,
    n_rows: u32,
    preprocessed: TreeSpanV2,
    main: TreeSpanV2,
    interaction: TreeSpanV2,
    constraint_count: u32,
    relation_event_count: u32,
    interaction_batch_count: u32,
    claimed_sum_offset: u32,
    claimed_sum_count: u32,
    max_constraint_log_degree_bound: u32,
    composition_log_split: u32,

    fn validate(self: EntryV2) Error!void {
        if (!self.active or self.log_size == 0 or self.log_size >= 31 or
            self.n_rows > (@as(u32, 1) << @intCast(self.log_size)) or
            self.constraint_count == 0 or
            self.max_constraint_log_degree_bound <= self.composition_log_split or
            self.composition_log_split == 0)
        {
            return error.InvalidComponentEntry;
        }
        try self.preprocessed.validate();
        try self.main.validate();
        try self.interaction.validate();
        if (self.claimed_sum_count != self.interaction_batch_count) {
            return error.InvalidComponentEntry;
        }
        switch (self.registry) {
            .opcode_semantic => |key| {
                if (key.descriptor.log_size != self.log_size or
                    key.descriptor.n_rows != self.n_rows or
                    self.preprocessed.sampled_columns != 1 or
                    self.preprocessed.declared_columns != 1 or
                    self.main.sampled_columns != key.descriptor.n_columns or
                    self.main.declared_columns != key.descriptor.n_columns or
                    self.interaction.sampled_columns != 0 or
                    self.claimed_sum_offset != 0 or
                    self.claimed_sum_count != 0)
                {
                    return error.InvalidComponentEntry;
                }
            },
            .opcode_lookup => {
                if (self.preprocessed.sampled_columns != 1 or
                    self.preprocessed.declared_columns != 1 or
                    self.main.sampled_columns == 0 or
                    self.main.declared_columns != 0 or
                    self.interaction.sampled_columns == 0 or
                    self.interaction.sampled_columns !=
                        self.interaction.declared_columns or
                    self.claimed_sum_count == 0)
                {
                    return error.InvalidComponentEntry;
                }
            },
            .infrastructure => {
                if (self.preprocessed.sampled_columns == 0 or
                    self.preprocessed.sampled_columns !=
                        self.preprocessed.declared_columns or
                    self.main.sampled_columns == 0 or
                    self.main.sampled_columns != self.main.declared_columns or
                    self.interaction.sampled_columns == 0 or
                    self.interaction.sampled_columns !=
                        self.interaction.declared_columns or
                    self.claimed_sum_count == 0)
                {
                    return error.InvalidComponentEntry;
                }
            },
        }
    }
};

/// Counts consumed by the row-18 composition graph. The sampled-value count
/// is supplied only from a successful proof capture by the ContextV2 owner.
pub const InputProfileV2 = struct {
    sampled_value_count: u32,
    claimed_sum_count: u32,
    relation_challenge_count: u32,
    transcript_claimed_sum_count: u32,

    pub fn validate(self: InputProfileV2) Error!void {
        if (self.sampled_value_count == 0 or self.claimed_sum_count == 0 or
            self.relation_challenge_count !=
                @as(u32, relation_challenges.RELATION_COUNT) or
            self.transcript_claimed_sum_count !=
                @as(u32, transcript_claims.COMPONENT_COUNT) or
            self.sampled_value_count >= m31.Modulus or
            self.claimed_sum_count >= m31.Modulus)
        {
            return error.InvalidInputProfile;
        }
    }
};

pub const ProfileV2 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    lookup_manifest_identity: [32]u8,
    lookup_authenticated_manifest_identity: [32]u8,
    lookup_statement_format_version: u16,
    lookup_statement_identity: [32]u8,
    lookup_activation_identity: [32]u8,
    entries: []EntryV2,
    physical_component_count: u32,
    preprocessed_column_count: u32,
    main_column_count: u32,
    interaction_column_count: u32,
    air_instruction_count: u32,
    input_profile: InputProfileV2,
    composition_log_split: u32,
    composition_log_degree_bound: u32,
    max_log_degree_bound: u32,
    identity_digest: [32]u8,

    pub fn deinit(self: *ProfileV2) void {
        self.allocator.free(self.entries);
        self.* = undefined;
    }

    pub fn validate(self: *const ProfileV2) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or self.entries.len == 0 or
            self.entries.len != @as(usize, self.physical_component_count) or
            self.air_instruction_count == 0 or
            self.composition_log_split == 0 or
            self.composition_log_degree_bound <= self.composition_log_split or
            self.max_log_degree_bound != self.composition_log_degree_bound -
                self.composition_log_split)
        {
            return error.InvalidStatementShape;
        }
        try self.input_profile.validate();
        var claims: u32 = 0;
        var instructions: u32 = 0;
        var preprocessed_columns: u32 = 0;
        var main_columns: u32 = 0;
        var interaction_columns: u32 = 0;
        for (self.entries, 0..) |entry, index| {
            try entry.validate();
            if (entry.physical_index != @as(u32, @intCast(index)))
                return error.InvalidComponentEntry;
            preprocessed_columns = @max(
                preprocessed_columns,
                try entry.preprocessed.end(),
            );
            main_columns = @max(main_columns, try entry.main.end());
            interaction_columns = @max(
                interaction_columns,
                try entry.interaction.end(),
            );
            if (entry.claimed_sum_count != 0) {
                if (entry.claimed_sum_offset != claims)
                    return error.InvalidComponentEntry;
                claims = std.math.add(
                    u32,
                    claims,
                    entry.claimed_sum_count,
                ) catch return error.ClaimedSumCountOverflow;
            }
            instructions = std.math.add(
                u32,
                instructions,
                entry.constraint_count,
            ) catch return error.AirInstructionCountOverflow;
        }
        if (claims != self.input_profile.claimed_sum_count or
            instructions != self.air_instruction_count or
            preprocessed_columns != self.preprocessed_column_count or
            main_columns != self.main_column_count or
            interaction_columns != self.interaction_column_count)
        {
            return error.InvalidStatementShape;
        }
        if (allZero(&self.lookup_manifest_identity) or
            allZero(&self.lookup_authenticated_manifest_identity) or
            allZero(&self.lookup_statement_identity) or
            allZero(&self.lookup_activation_identity) or
            !std.mem.eql(
                u8,
                &self.lookup_manifest_identity,
                &self.lookup_authenticated_manifest_identity,
            ) or
            self.lookup_statement_format_version !=
                lookup_physical_v2.STATEMENT_FORMAT_VERSION)
        {
            return error.EmptyComponentManifest;
        }
        const expected = self.computeIdentity();
        if (!std.mem.eql(u8, &expected, &self.identity_digest))
            return error.InvalidProfileIdentity;
    }

    pub fn validateAgainst(
        self: *const ProfileV2,
        allocator: std.mem.Allocator,
        statement: *const statement_mod.RiscVStatement,
        manifest: *const lookup_physical_v2.Manifest,
        authenticated: *const lookup_physical_v2.AuthenticatedStatement,
        components: []const core_components.Component,
        sampled_value_count: u32,
    ) !void {
        var expected = try derive(
            allocator,
            statement,
            manifest,
            authenticated,
            components,
            sampled_value_count,
        );
        defer expected.deinit();
        if (!profilesEqual(self, &expected)) return error.ProfileMismatch;
    }

    /// Cold revalidation for a retained verifier-minted profile. Component
    /// vtables are checked at mint time by `derive`; this path independently
    /// reconstructs every expected fact from the closed typed registry and
    /// exact selected lookup manifest before a later capture is consumed.
    pub fn validateAuthority(
        self: *const ProfileV2,
        allocator: std.mem.Allocator,
        statement: *const statement_mod.RiscVStatement,
        manifest: *const lookup_physical_v2.Manifest,
        authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    ) !void {
        var expected = try deriveFromSource(
            allocator,
            statement,
            manifest,
            authenticated,
            ExpectedSource{ .statement = statement, .manifest = manifest },
            self.input_profile.sampled_value_count,
        );
        defer expected.deinit();
        if (!profilesEqual(self, &expected)) return error.ProfileMismatch;
    }

    fn computeIdentity(self: *const ProfileV2) [32]u8 {
        var hash = Sha256.init(.{});
        hash.update(PROFILE_DOMAIN);
        hashInt(&hash, u16, self.format_version);
        hashInt(&hash, u16, self.schema_version);
        hash.update(&self.lookup_manifest_identity);
        hash.update(&self.lookup_authenticated_manifest_identity);
        hashInt(&hash, u16, self.lookup_statement_format_version);
        hash.update(&self.lookup_statement_identity);
        hash.update(&self.lookup_activation_identity);
        hashInt(&hash, u32, self.physical_component_count);
        hashInt(&hash, u32, self.preprocessed_column_count);
        hashInt(&hash, u32, self.main_column_count);
        hashInt(&hash, u32, self.interaction_column_count);
        hashInt(&hash, u32, self.air_instruction_count);
        hashInputProfile(&hash, self.input_profile);
        hashInt(&hash, u32, self.composition_log_split);
        hashInt(&hash, u32, self.composition_log_degree_bound);
        hashInt(&hash, u32, self.max_log_degree_bound);
        hashInt(&hash, u32, @as(u32, @intCast(self.entries.len)));
        for (self.entries) |entry| hashEntry(&hash, entry);
        return hash.finalResult();
    }
};

pub fn derive(
    allocator: std.mem.Allocator,
    statement: *const statement_mod.RiscVStatement,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    components: []const core_components.Component,
    sampled_value_count: u32,
) !ProfileV2 {
    return deriveFromSource(
        allocator,
        statement,
        manifest,
        authenticated,
        NativeSource{ .components = components },
        sampled_value_count,
    );
}

/// Verifier-owned profile reconstruction from the closed typed registry.
///
/// Unlike `derive`, this accepts no live component handles and therefore is
/// suitable for cold recursive ingress.  The statement and authenticated
/// physical lookup manifest determine every component fact; the sampled
/// value count remains an independently derived proof-shape input.
pub fn deriveAuthority(
    allocator: std.mem.Allocator,
    statement: *const statement_mod.RiscVStatement,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    sampled_value_count: u32,
) !ProfileV2 {
    return deriveFromSource(
        allocator,
        statement,
        manifest,
        authenticated,
        ExpectedSource{ .statement = statement, .manifest = manifest },
        sampled_value_count,
    );
}

pub const Facts = struct {
    n_constraints: usize,
    max_constraint_log_degree_bound: u32,
    composition_log_split: u32,
};

const NativeSource = struct {
    components: []const core_components.Component,

    fn len(self: NativeSource) usize {
        return self.components.len;
    }

    fn facts(self: NativeSource, index: usize) Facts {
        const component = self.components[index];
        return .{
            .n_constraints = component.nConstraints(),
            .max_constraint_log_degree_bound = component.maxConstraintLogDegreeBound(),
            .composition_log_split = component.compositionLogSplit(),
        };
    }
};

const ExpectedSource = struct {
    statement: *const statement_mod.RiscVStatement,
    manifest: *const lookup_physical_v2.Manifest,

    fn len(self: ExpectedSource) usize {
        return 2 * @as(usize, self.statement.n_components) +
            self.statement.n_infra;
    }

    fn facts(self: ExpectedSource, index: usize) Facts {
        const opcode_count = 2 * @as(usize, self.statement.n_components);
        if (index < opcode_count) {
            const descriptor = self.statement.component_descs[index / 2];
            if (index % 2 == 0) return .{
                .n_constraints = semantic_eval.constraintCount(
                    descriptor.family,
                ),
                .max_constraint_log_degree_bound = semantic_eval.constraintLogDegreeBound(
                    descriptor.family,
                    descriptor.log_size,
                ),
                .composition_log_split = verifier_types.COMPOSITION_LOG_SPLIT,
            };
            const physical = self.manifest.entryForFamily(descriptor.family);
            return .{
                .n_constraints = physical.detailed_claim_count,
                .max_constraint_log_degree_bound = descriptor.log_size + 1,
                .composition_log_split = verifier_types.COMPOSITION_LOG_SPLIT,
            };
        }
        const descriptor = self.statement.infra_descs[index - opcode_count];
        return .{
            .n_constraints = registry.constraintCount(descriptor.kind),
            .max_constraint_log_degree_bound = descriptor.log_size + 1,
            .composition_log_split = verifier_types.COMPOSITION_LOG_SPLIT,
        };
    }
};

fn deriveFromSource(
    allocator: std.mem.Allocator,
    statement: *const statement_mod.RiscVStatement,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    source: anytype,
    sampled_value_count: u32,
) !ProfileV2 {
    try manifest.validate();
    try authenticated.validateAgainst(statement, manifest);
    if (statement.n_components == 0 or
        statement.n_components > statement_mod.MAX_COMPONENTS or
        statement.n_infra == 0 or
        statement.n_infra > statement_mod.MAX_INFRA_COMPONENTS)
    {
        return error.InvalidStatementShape;
    }
    const expected_count = std.math.add(
        usize,
        std.math.mul(usize, statement.n_components, 2) catch
            return error.ComponentCountMismatch,
        statement.n_infra,
    ) catch return error.ComponentCountMismatch;
    if (source.len() != expected_count) return error.ComponentCountMismatch;
    const entries = try allocator.alloc(EntryV2, expected_count);
    errdefer allocator.free(entries);

    var state = BuildState{ .entries = entries };
    var family_shards = [_]u32{0} ** lookup_physical_v2.FAMILY_COUNT;
    var preprocessed_columns: u32 = 0;
    var main_columns: u32 = 0;
    var interaction_columns: u32 = 0;
    for (statement.component_descs[0..statement.n_components]) |descriptor| {
        if (!semantic_eval.isTraceCompatible(descriptor.family))
            return error.InvalidStatementShape;
        const physical = manifest.entryForFamily(descriptor.family);
        const family_index: usize = @intFromEnum(descriptor.family);
        const shard_ordinal = family_shards[family_index];
        family_shards[family_index] = std.math.add(
            u32,
            shard_ordinal,
            1,
        ) catch return error.ComponentCountMismatch;
        const semantic = EntryV2{
            .physical_index = @intCast(state.index),
            .shard_ordinal = shard_ordinal,
            .active = true,
            .registry = .{ .opcode_semantic = .{
                .descriptor = descriptor,
                .typed_authority_identity = physical.typed_authority_identity,
            } },
            .log_size = descriptor.log_size,
            .n_rows = descriptor.n_rows,
            .preprocessed = .{
                .offset = preprocessed_columns + 1,
                .sampled_columns = 1,
                .declared_columns = 1,
            },
            .main = .{
                .offset = main_columns,
                .sampled_columns = descriptor.n_columns,
                .declared_columns = descriptor.n_columns,
            },
            .interaction = .{
                .offset = interaction_columns,
                .sampled_columns = 0,
                .declared_columns = 0,
            },
            .constraint_count = @intCast(semantic_eval.constraintCount(
                descriptor.family,
            )),
            .relation_event_count = physical.lookup_authority.entry_count,
            .interaction_batch_count = 0,
            .claimed_sum_offset = 0,
            .claimed_sum_count = 0,
            .max_constraint_log_degree_bound = semantic_eval.constraintLogDegreeBound(
                descriptor.family,
                descriptor.log_size,
            ),
            .composition_log_split = verifier_types.COMPOSITION_LOG_SPLIT,
        };
        try state.append(source.facts(state.index), semantic);
        const lookup = EntryV2{
            .physical_index = @intCast(state.index),
            .shard_ordinal = shard_ordinal,
            .active = true,
            .registry = .{ .opcode_lookup = .{
                .family = descriptor.family,
                .typed_authority_identity = physical.typed_authority_identity,
                .component_identity = physical.lookup_authority.component_identity,
                .partition_identity = physical.lookup_authority.partition_identity,
                .layout_identity = physical.lookup_authority.layout_identity,
                .program_identity = physical.lookup_authority.program_identity,
            } },
            .log_size = descriptor.log_size,
            .n_rows = descriptor.n_rows,
            .preprocessed = .{
                .offset = preprocessed_columns,
                .sampled_columns = 1,
                .declared_columns = 1,
            },
            .main = .{
                .offset = main_columns,
                .sampled_columns = descriptor.n_columns,
                .declared_columns = 0,
            },
            .interaction = .{
                .offset = interaction_columns,
                .sampled_columns = physical.interaction_column_count,
                .declared_columns = physical.interaction_column_count,
            },
            .constraint_count = physical.detailed_claim_count,
            .relation_event_count = physical.lookup_authority.entry_count,
            .interaction_batch_count = physical.detailed_claim_count,
            .claimed_sum_offset = state.claimed_sum_count,
            .claimed_sum_count = physical.detailed_claim_count,
            .max_constraint_log_degree_bound = descriptor.log_size + 1,
            .composition_log_split = verifier_types.COMPOSITION_LOG_SPLIT,
        };
        try state.append(source.facts(state.index), lookup);
        preprocessed_columns = try addColumns(preprocessed_columns, 2);
        main_columns = try addColumns(main_columns, descriptor.n_columns);
        interaction_columns = try addColumns(
            interaction_columns,
            physical.interaction_column_count,
        );
    }

    const opcode_cursor = @import("../air/lang/opcode_composition_manifest.zig")
        .PlacementCursor{
        .component_count = @intCast(statement.n_components),
        .adapter_count = 2 * @as(usize, statement.n_components),
        .preprocessed_columns = preprocessed_columns,
        .main_columns = main_columns,
        .interaction_columns = interaction_columns,
    };
    var infra_cursor = base_assembly.InfrastructureCursor.init(opcode_cursor);
    for (statement.infra_descs[0..statement.n_infra], 0..) |descriptor, ordinal| {
        const placement = try infra_cursor.append(
            descriptor.kind,
            descriptor.n_columns,
        );
        const batches = statement_mod.nClaimedSumsForInfra(descriptor.kind);
        const entry = EntryV2{
            .physical_index = @intCast(state.index),
            .shard_ordinal = @intCast(ordinal),
            .active = true,
            .registry = .{ .infrastructure = .{
                .kind = descriptor.kind,
                .adapter_kind = placement.adapter_kind,
            } },
            .log_size = descriptor.log_size,
            .n_rows = descriptor.n_rows,
            .preprocessed = .{
                .offset = @intCast(placement.preprocessed_column_offset),
                .sampled_columns = @intCast(placement.preprocessed_columns),
                .declared_columns = @intCast(placement.preprocessed_columns),
            },
            .main = .{
                .offset = @intCast(placement.main_column_offset),
                .sampled_columns = @intCast(placement.main_columns),
                .declared_columns = @intCast(placement.main_columns),
            },
            .interaction = .{
                .offset = @intCast(placement.interaction_column_offset),
                .sampled_columns = @intCast(placement.interaction_columns),
                .declared_columns = @intCast(placement.interaction_columns),
            },
            .constraint_count = @intCast(registry.constraintCount(descriptor.kind)),
            .relation_event_count = batches,
            .interaction_batch_count = batches,
            .claimed_sum_offset = state.claimed_sum_count,
            .claimed_sum_count = batches,
            .max_constraint_log_degree_bound = descriptor.log_size + 1,
            .composition_log_split = verifier_types.COMPOSITION_LOG_SPLIT,
        };
        try state.append(source.facts(state.index), entry);
    }
    if (state.index != entries.len) return error.ComponentCountMismatch;

    const input_profile = InputProfileV2{
        .sampled_value_count = sampled_value_count,
        .claimed_sum_count = state.claimed_sum_count,
        .relation_challenge_count = relation_challenges.RELATION_COUNT,
        .transcript_claimed_sum_count = transcript_claims.COMPONENT_COUNT,
    };
    try input_profile.validate();
    const composition_log_split = state.composition_log_split orelse
        return error.InvalidComponentEntry;
    var result = ProfileV2{
        .allocator = allocator,
        .lookup_manifest_identity = manifest.identity,
        .lookup_authenticated_manifest_identity = authenticated.manifest_identity,
        .lookup_statement_format_version = authenticated.format_version,
        .lookup_statement_identity = authenticated.statement_identity,
        .lookup_activation_identity = authenticated.activation_identity,
        .entries = entries,
        .physical_component_count = @intCast(entries.len),
        .preprocessed_column_count = @intCast(infra_cursor.preprocessed_columns),
        .main_column_count = @intCast(infra_cursor.main_columns),
        .interaction_column_count = @intCast(infra_cursor.interaction_columns),
        .air_instruction_count = state.air_instruction_count,
        .input_profile = input_profile,
        .composition_log_split = composition_log_split,
        .composition_log_degree_bound = state.max_constraint_log_degree_bound,
        .max_log_degree_bound = state.max_constraint_log_degree_bound -
            composition_log_split,
        .identity_digest = undefined,
    };
    result.identity_digest = result.computeIdentity();
    try result.validate();
    return result;
}

const BuildState = struct {
    entries: []EntryV2,
    index: usize = 0,
    claimed_sum_count: u32 = 0,
    air_instruction_count: u32 = 0,
    composition_log_split: ?u32 = null,
    max_constraint_log_degree_bound: u32 = 0,

    fn append(self: *BuildState, facts: Facts, entry: EntryV2) Error!void {
        if (self.index >= self.entries.len or
            entry.physical_index != @as(u32, @intCast(self.index)))
            return error.ComponentCountMismatch;
        if (facts.n_constraints != @as(usize, entry.constraint_count))
            return error.ConstraintCountMismatch;
        if (facts.max_constraint_log_degree_bound !=
            entry.max_constraint_log_degree_bound)
        {
            return error.ComponentBoundMismatch;
        }
        if (facts.composition_log_split != entry.composition_log_split)
            return error.InconsistentCompositionLogSplit;
        if (self.composition_log_split) |split| {
            if (split != facts.composition_log_split)
                return error.InconsistentCompositionLogSplit;
        } else self.composition_log_split = facts.composition_log_split;
        try entry.validate();
        self.entries[self.index] = entry;
        self.index += 1;
        self.claimed_sum_count = std.math.add(
            u32,
            self.claimed_sum_count,
            entry.claimed_sum_count,
        ) catch return error.ClaimedSumCountOverflow;
        self.air_instruction_count = std.math.add(
            u32,
            self.air_instruction_count,
            entry.constraint_count,
        ) catch return error.AirInstructionCountOverflow;
        self.max_constraint_log_degree_bound = @max(
            self.max_constraint_log_degree_bound,
            entry.max_constraint_log_degree_bound,
        );
    }
};

fn addColumns(lhs: u32, rhs: anytype) Error!u32 {
    return std.math.add(u32, lhs, @intCast(rhs)) catch
        error.ColumnCountOverflow;
}

fn profilesEqual(lhs: *const ProfileV2, rhs: *const ProfileV2) bool {
    return lhs.format_version == rhs.format_version and
        lhs.schema_version == rhs.schema_version and
        std.mem.eql(u8, &lhs.lookup_manifest_identity, &rhs.lookup_manifest_identity) and
        std.mem.eql(
            u8,
            &lhs.lookup_authenticated_manifest_identity,
            &rhs.lookup_authenticated_manifest_identity,
        ) and
        lhs.lookup_statement_format_version ==
            rhs.lookup_statement_format_version and
        std.mem.eql(u8, &lhs.lookup_statement_identity, &rhs.lookup_statement_identity) and
        std.mem.eql(u8, &lhs.lookup_activation_identity, &rhs.lookup_activation_identity) and
        lhs.physical_component_count == rhs.physical_component_count and
        lhs.preprocessed_column_count == rhs.preprocessed_column_count and
        lhs.main_column_count == rhs.main_column_count and
        lhs.interaction_column_count == rhs.interaction_column_count and
        lhs.air_instruction_count == rhs.air_instruction_count and
        std.meta.eql(lhs.input_profile, rhs.input_profile) and
        lhs.composition_log_split == rhs.composition_log_split and
        lhs.composition_log_degree_bound == rhs.composition_log_degree_bound and
        lhs.max_log_degree_bound == rhs.max_log_degree_bound and
        std.mem.eql(u8, &lhs.identity_digest, &rhs.identity_digest) and
        entriesEqual(lhs.entries, rhs.entries);
}

fn entriesEqual(lhs: []const EntryV2, rhs: []const EntryV2) bool {
    if (lhs.len != rhs.len) return false;
    for (lhs, rhs) |left, right| {
        if (!std.meta.eql(left, right)) return false;
    }
    return true;
}

fn hashEntry(hash: *Sha256, entry: EntryV2) void {
    hashInt(hash, u32, entry.physical_index);
    hashInt(hash, u32, entry.shard_ordinal);
    hashInt(hash, u8, @intFromBool(entry.active));
    hashInt(hash, u8, @intFromEnum(entry.registry));
    switch (entry.registry) {
        .opcode_semantic => |key| {
            hashInt(hash, u8, @intFromEnum(key.descriptor.family));
            hashInt(hash, u32, key.descriptor.log_size);
            hashInt(hash, u32, key.descriptor.n_rows);
            hashInt(hash, u32, key.descriptor.n_columns);
            hash.update(&key.typed_authority_identity);
        },
        .opcode_lookup => |key| {
            hashInt(hash, u8, @intFromEnum(key.family));
            hash.update(&key.typed_authority_identity);
            hash.update(&key.component_identity);
            hash.update(&key.partition_identity);
            hash.update(&key.layout_identity);
            hash.update(&key.program_identity);
        },
        .infrastructure => |key| {
            hashInt(hash, u32, @intFromEnum(key.kind));
            hashInt(hash, u8, @intFromEnum(key.adapter_kind));
        },
    }
    hashInt(hash, u32, entry.log_size);
    hashInt(hash, u32, entry.n_rows);
    hashTreeSpan(hash, entry.preprocessed);
    hashTreeSpan(hash, entry.main);
    hashTreeSpan(hash, entry.interaction);
    hashInt(hash, u32, entry.constraint_count);
    hashInt(hash, u32, entry.relation_event_count);
    hashInt(hash, u32, entry.interaction_batch_count);
    hashInt(hash, u32, entry.claimed_sum_offset);
    hashInt(hash, u32, entry.claimed_sum_count);
    hashInt(hash, u32, entry.max_constraint_log_degree_bound);
    hashInt(hash, u32, entry.composition_log_split);
}

fn hashTreeSpan(hash: *Sha256, value: TreeSpanV2) void {
    hashInt(hash, u32, value.offset);
    hashInt(hash, u32, value.sampled_columns);
    hashInt(hash, u32, value.declared_columns);
}

fn hashInputProfile(hash: *Sha256, value: InputProfileV2) void {
    hashInt(hash, u32, value.sampled_value_count);
    hashInt(hash, u32, value.claimed_sum_count);
    hashInt(hash, u32, value.relation_challenge_count);
    hashInt(hash, u32, value.transcript_claimed_sum_count);
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn allZero(value: []const u8) bool {
    var aggregate: u8 = 0;
    for (value) |byte| aggregate |= byte;
    return aggregate == 0;
}

pub const testing = struct {
    pub fn expectedFacts(
        allocator: std.mem.Allocator,
        statement: *const statement_mod.RiscVStatement,
        manifest: *const lookup_physical_v2.Manifest,
    ) ![]Facts {
        const source = ExpectedSource{
            .statement = statement,
            .manifest = manifest,
        };
        const count = source.len();
        const facts = try allocator.alloc(Facts, count);
        for (facts, 0..) |*fact, index| fact.* = source.facts(index);
        return facts;
    }

    pub fn deriveFromFacts(
        allocator: std.mem.Allocator,
        statement: *const statement_mod.RiscVStatement,
        manifest: *const lookup_physical_v2.Manifest,
        authenticated: *const lookup_physical_v2.AuthenticatedStatement,
        fact_values: []const Facts,
        sampled_value_count: u32,
    ) !ProfileV2 {
        const Source = struct {
            values: []const Facts,
            fn len(self: @This()) usize {
                return self.values.len;
            }
            fn facts(self: @This(), index: usize) Facts {
                return self.values[index];
            }
        };
        return deriveFromSource(
            allocator,
            statement,
            manifest,
            authenticated,
            Source{ .values = fact_values },
            sampled_value_count,
        );
    }
};
