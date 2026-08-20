//! Canonical extension manifest and digest.
//!
//! This is cold-path protocol identity. Strings remain audit metadata here;
//! authenticated row construction consumes the numeric registry plan instead.

const std = @import("std");
const base_relation = @import("../lang/relation.zig");
const poseidon_identity = @import("../lang/typed_poseidon2_identity_golden.zig");
const execution_profile = @import("../../isa/execution_profile.zig");
const components = @import("component_registry.zig");
const hashing = @import("identity_hash.zig");
const relation_registry = @import("relation_registry.zig");

pub const Digest = hashing.Digest;
pub const manifest_format_version: u16 = 1;
pub const statement_schema_version: u16 = 1;
pub const artifact_format_version: u16 = 1;
pub const claim_order_version: u16 = 2;
pub const challenge_order_version: u16 = 1;
pub const interaction_order_version: u16 = 1;
pub const base_relation_count: u16 = 12;
pub const relation_count: u16 = 13;
pub const digest_domain = "stwo-zig/riscv/guest-poseidon2-manifest/v1";
pub const canonical_digest_golden = Digest{
    0x26, 0x5d, 0xf5, 0x24, 0xca, 0x93, 0xba, 0x5f,
    0x24, 0x0a, 0xec, 0x9e, 0x5c, 0xe2, 0xf9, 0xf6,
    0x16, 0xc3, 0x02, 0x85, 0x04, 0x10, 0xee, 0x81,
    0x2c, 0x22, 0x0a, 0xa3, 0xe5, 0x9f, 0xb8, 0x91,
};

pub const MemoryAdmissionPolicy = enum(u32) {
    authenticated_rw_root_membership_v1 = 0x5257_4d31,
    _,
};

pub const memory_admission_policy =
    MemoryAdmissionPolicy.authenticated_rw_root_membership_v1;

pub const ManifestComponent = struct {
    slot: components.Slot,
    kind: components.Kind,
    name: []const u8,
    version: u16,
    preprocessed_columns: u16,
    main_columns: u16,
    interaction_columns: u16,
    events: u16,
    batches: u16,
};

pub const Identity = struct {
    format_version: u16,
    statement_version: u16,
    profile: execution_profile.ExecutionProfile,
    profile_name: []const u8,
    capability_bits: u64,
    capability_name: []const u8,
    abi_version: u16,
    opcode_id: u16,
    semantic_digest: Digest,
    base_components: u16,
    total_components: u16,
    base_relations: u16,
    total_relations: u16,
    active_prefix: components.ActivePrefixPolicy,
    minimum_log_size: u32,
    memory_policy: MemoryAdmissionPolicy,
    guest_relation_id: u16,
    guest_relation_version: u16,
    guest_relation_name: []const u8,
    guest_relation_abi: []const u8,
    guest_relation_arity: u16,
    guest_relation_roles: u8,
    components: [components.extension_component_count]ManifestComponent,
    caller_layout: components.CallerLayout,
    caller_constraint_identity: components.CallerConstraintIdentity,
    caller_fixed_table_demand: components.FixedTableDemand,
    provider_layout_digest: Digest,
    provider_enabled_mode: u8,
    provider_io_mode: u8,
    provider_wide_mode: u8,
    claim_order: u16,
    challenge_order: u16,
    interaction_order: u16,

    pub fn canonical() Identity {
        return .{
            .format_version = manifest_format_version,
            .statement_version = statement_schema_version,
            .profile = .rv32im_zkvm_poseidon2_v1,
            .profile_name = execution_profile.poseidon2_name,
            .capability_bits = execution_profile.poseidon2_capability_bit,
            .capability_name = execution_profile.poseidon2_capability,
            .abi_version = execution_profile.poseidon2_abi_version,
            .opcode_id = components.guest_opcode_id,
            .semantic_digest = execution_profile.poseidon2_semantic_digest,
            .base_components = components.base_component_count,
            .total_components = components.component_count,
            .base_relations = base_relation_count,
            .total_relations = relation_count,
            .active_prefix = components.active_prefix_policy,
            .minimum_log_size = components.minimum_log_size,
            .memory_policy = memory_admission_policy,
            .guest_relation_id = relation_registry.guest_schema_numeric_id,
            .guest_relation_version = relation_registry.guest_schema_version,
            .guest_relation_name = relation_registry.guest_relation_name,
            .guest_relation_abi = relation_registry.guest_relation_abi,
            .guest_relation_arity = relation_registry.guest_relation_arity,
            .guest_relation_roles = relation_registry.guest_schema.allowed_roles.bits,
            .components = .{
                manifestComponent(components.caller_identity),
                manifestComponent(components.provider_identity),
            },
            .caller_layout = components.caller_layout,
            .caller_constraint_identity = components.CallerConstraintIdentity.canonical(),
            .caller_fixed_table_demand = components.caller_fixed_table_demand,
            .provider_layout_digest = poseidon_identity.layout,
            .provider_enabled_mode = 1,
            .provider_io_mode = 1,
            .provider_wide_mode = 0,
            .claim_order = claim_order_version,
            .challenge_order = challenge_order_version,
            .interaction_order = interaction_order_version,
        };
    }

    pub fn validate(self: Identity) Error!void {
        const expected = Identity.canonical();
        if (self.format_version != expected.format_version)
            return error.ManifestFormatMismatch;
        if (self.statement_version != expected.statement_version)
            return error.StatementVersionMismatch;
        if (self.profile != expected.profile or
            !std.mem.eql(u8, self.profile_name, expected.profile_name))
        {
            return error.ProfileMismatch;
        }
        if (self.capability_bits != expected.capability_bits or
            !std.mem.eql(u8, self.capability_name, expected.capability_name) or
            self.abi_version != expected.abi_version or
            self.opcode_id != expected.opcode_id)
        {
            return error.AbiMismatch;
        }
        if (!std.mem.eql(u8, &self.semantic_digest, &expected.semantic_digest))
            return error.SemanticDigestMismatch;
        if (self.base_components != expected.base_components or
            self.total_components != expected.total_components or
            self.base_relations != expected.base_relations or
            self.total_relations != expected.total_relations)
        {
            return error.RegistryGeometryMismatch;
        }
        if (self.active_prefix != expected.active_prefix or
            self.minimum_log_size != expected.minimum_log_size)
        {
            return error.ActivePrefixMismatch;
        }
        if (self.memory_policy != expected.memory_policy)
            return error.MemoryPolicyMismatch;
        if (self.guest_relation_id != expected.guest_relation_id or
            self.guest_relation_version != expected.guest_relation_version or
            self.guest_relation_arity != expected.guest_relation_arity or
            self.guest_relation_roles != expected.guest_relation_roles or
            !std.mem.eql(u8, self.guest_relation_name, expected.guest_relation_name) or
            !std.mem.eql(u8, self.guest_relation_abi, expected.guest_relation_abi))
        {
            return error.RelationIdentityMismatch;
        }
        for (self.components, expected.components) |actual, wanted|
            try validateComponent(actual, wanted);
        try self.caller_layout.validate();
        try self.caller_constraint_identity.validate();
        if (!std.meta.eql(
            self.caller_fixed_table_demand,
            expected.caller_fixed_table_demand,
        )) return error.FixedTableDemandMismatch;
        if (!std.mem.eql(
            u8,
            &self.provider_layout_digest,
            &expected.provider_layout_digest,
        )) return error.ProviderLayoutMismatch;
        if (self.provider_enabled_mode != expected.provider_enabled_mode or
            self.provider_io_mode != expected.provider_io_mode or
            self.provider_wide_mode != expected.provider_wide_mode)
        {
            return error.ProviderModeMismatch;
        }
        if (self.claim_order != expected.claim_order or
            self.challenge_order != expected.challenge_order or
            self.interaction_order != expected.interaction_order)
        {
            return error.ProtocolOrderMismatch;
        }
    }

    pub fn digest(self: Identity) Error!Digest {
        try self.validate();
        var hash = hashing.init(digest_domain);
        hashing.hashInt(&hash, u16, self.format_version);
        hashing.hashInt(&hash, u16, self.statement_version);
        hashing.hashInt(&hash, u16, @intFromEnum(self.profile));
        hashing.hashString(&hash, self.profile_name);
        hashing.hashInt(&hash, u64, self.capability_bits);
        hashing.hashString(&hash, self.capability_name);
        hashing.hashInt(&hash, u16, self.abi_version);
        hashing.hashInt(&hash, u16, self.opcode_id);
        hashDigest(&hash, self.semantic_digest);
        hashing.hashInt(&hash, u16, self.base_components);
        hashing.hashInt(&hash, u16, self.total_components);
        hashing.hashInt(&hash, u16, self.base_relations);
        hashing.hashInt(&hash, u16, self.total_relations);
        hashing.hashInt(&hash, u32, @intFromEnum(self.active_prefix));
        hashing.hashInt(&hash, u32, self.minimum_log_size);
        hashing.hashInt(&hash, u32, @intFromEnum(self.memory_policy));
        hashing.hashInt(&hash, u16, self.guest_relation_id);
        hashing.hashInt(&hash, u16, self.guest_relation_version);
        hashing.hashString(&hash, self.guest_relation_name);
        hashing.hashString(&hash, self.guest_relation_abi);
        hashing.hashInt(&hash, u16, self.guest_relation_arity);
        hashing.hashInt(&hash, u8, self.guest_relation_roles);
        hashing.hashInt(&hash, u16, @intCast(self.components.len));
        for (self.components) |component| hashComponent(&hash, component);
        hashCallerLayout(&hash, self.caller_layout);
        hashCallerConstraintIdentity(&hash, self.caller_constraint_identity);
        for (self.caller_fixed_table_demand) |demand|
            hashing.hashInt(&hash, u16, demand);
        hashEvents(&hash, &components.caller_events);
        hashBatches(&hash, &components.caller_batches);
        hashProviderCompatibility(&hash);
        hashDigest(&hash, self.provider_layout_digest);
        hashing.hashInt(&hash, u8, self.provider_enabled_mode);
        hashing.hashInt(&hash, u8, self.provider_io_mode);
        hashing.hashInt(&hash, u8, self.provider_wide_mode);
        hashEvents(&hash, &components.provider_events);
        hashBatches(&hash, &components.provider_batches);
        hashing.hashInt(&hash, u16, self.claim_order);
        hashing.hashInt(&hash, u16, self.challenge_order);
        hashing.hashInt(&hash, u16, self.interaction_order);
        return hashing.finish(&hash);
    }
};

pub const Error = components.Error || error{
    AbiMismatch,
    ActivePrefixMismatch,
    ComponentIdentityMismatch,
    FixedTableDemandMismatch,
    ManifestFormatMismatch,
    MemoryPolicyMismatch,
    ProfileMismatch,
    ProtocolOrderMismatch,
    ProviderLayoutMismatch,
    ProviderModeMismatch,
    RegistryGeometryMismatch,
    RelationIdentityMismatch,
    SemanticDigestMismatch,
    StatementVersionMismatch,
};

pub fn canonicalDigest() Digest {
    return Identity.canonical().digest() catch unreachable;
}

fn manifestComponent(identity: components.StaticIdentity) ManifestComponent {
    return .{
        .slot = identity.slot,
        .kind = identity.kind,
        .name = identity.name,
        .version = identity.version,
        .preprocessed_columns = identity.preprocessed_columns,
        .main_columns = identity.main_columns,
        .interaction_columns = identity.interaction_columns,
        .events = identity.events,
        .batches = identity.batches,
    };
}

fn validateComponent(actual: ManifestComponent, expected: ManifestComponent) Error!void {
    if (actual.slot != expected.slot or actual.kind != expected.kind or
        actual.version != expected.version or
        actual.preprocessed_columns != expected.preprocessed_columns or
        actual.main_columns != expected.main_columns or
        actual.interaction_columns != expected.interaction_columns or
        actual.events != expected.events or actual.batches != expected.batches or
        !std.mem.eql(u8, actual.name, expected.name))
    {
        return error.ComponentIdentityMismatch;
    }
}

fn hashComponent(hash: *hashing.Sha256, component: ManifestComponent) void {
    hashing.hashInt(hash, u16, @intFromEnum(component.slot));
    hashing.hashInt(hash, u32, @intFromEnum(component.kind));
    hashing.hashString(hash, component.name);
    hashing.hashInt(hash, u16, component.version);
    hashing.hashInt(hash, u16, component.preprocessed_columns);
    hashing.hashInt(hash, u16, component.main_columns);
    hashing.hashInt(hash, u16, component.interaction_columns);
    hashing.hashInt(hash, u16, component.events);
    hashing.hashInt(hash, u16, component.batches);
}

fn hashCallerLayout(hash: *hashing.Sha256, layout: components.CallerLayout) void {
    inline for (@typeInfo(components.CallerLayout).@"struct".fields) |field| {
        hashing.hashInt(hash, u16, @field(layout, field.name));
    }
}

fn hashCallerConstraintIdentity(
    hash: *hashing.Sha256,
    identity: components.CallerConstraintIdentity,
) void {
    hashing.hashInt(hash, u32, identity.policy_id);
    hashing.hashInt(hash, u16, identity.version);
    hashing.hashInt(hash, u8, identity.maximum_constraint_degree);
    hashing.hashInt(hash, u8, identity.lanes);
    hashing.hashInt(hash, u8, identity.word_bytes);
    hashing.hashInt(hash, u8, identity.address_bits);
    hashing.hashInt(hash, u8, identity.span_words);
    hashing.hashInt(hash, u8, identity.canonical_words);
    hashing.hashInt(hash, u8, identity.canonical_materializations_per_word);
    hashing.hashInt(hash, u8, identity.clock_stride);
    hashing.hashInt(hash, u8, identity.pointer_access_ordinal);
    hashing.hashInt(hash, u8, identity.lane_access_ordinal);
    hashing.hashInt(hash, u16, identity.opcode_id);
}

fn hashEvents(hash: *hashing.Sha256, events: []const components.EventPlan) void {
    hashing.hashInt(hash, u16, @intCast(events.len));
    for (events) |event| {
        hashing.hashInt(hash, u8, event.ordinal);
        hashing.hashInt(hash, u16, @intFromEnum(event.schema));
        hashing.hashInt(hash, u16, event.schema_version);
        hashing.hashInt(hash, u8, event.arity);
        hashing.hashInt(hash, u8, @intFromEnum(event.role));
        if (event.access_ordinal) |ordinal| {
            hashing.hashInt(hash, u8, 1);
            hashing.hashInt(hash, u8, ordinal);
        } else hashing.hashInt(hash, u8, 0);
        hashing.hashInt(hash, u8, @intFromEnum(event.projection));
        hashing.hashInt(hash, u8, event.index);
        hashing.hashInt(hash, u8, event.part);
        hashing.hashInt(hash, u8, @intFromEnum(event.numerator));
    }
}

fn hashBatches(hash: *hashing.Sha256, batches: []const components.BatchPlan) void {
    hashing.hashInt(hash, u16, @intCast(batches.len));
    for (batches) |batch| {
        hashing.hashInt(hash, u8, batch.ordinal);
        hashing.hashInt(hash, u8, batch.first_event);
        if (batch.second_event) |second| {
            hashing.hashInt(hash, u8, 1);
            hashing.hashInt(hash, u8, second);
        } else hashing.hashInt(hash, u8, 0);
        hashing.hashInt(hash, u16, batch.interaction_column_start);
    }
}

fn hashProviderCompatibility(hash: *hashing.Sha256) void {
    const identity = components.ProviderCompatibilityIdentity.canonical();
    hashing.hashInt(hash, u16, identity.format_version);
    hashing.hashInt(hash, u32, identity.policy_id);
    hashing.hashInt(hash, u16, identity.policy_version);
    hashing.hashInt(hash, u8, identity.maximum_constraint_degree);
    hashing.hashInt(hash, u16, identity.width);
    hashing.hashInt(hash, u16, identity.materializations);
    hashing.hashInt(hash, u16, identity.main_columns);
}

fn hashDigest(hash: *hashing.Sha256, digest: Digest) void {
    hash.update(&digest);
}

comptime {
    if (base_relation.schemas.len != base_relation_count or
        relation_registry.guest_schema_numeric_id + 1 != relation_count)
    {
        @compileError("extension relation count drifted");
    }
}
