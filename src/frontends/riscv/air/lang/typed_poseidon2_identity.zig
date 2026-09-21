//! Canonical, backend-neutral identity for the typed Poseidon2-M31 program.
//!
//! Four independently versioned identities are composed without hashing raw
//! Zig memory: the logical AIR, physical main/interaction/claim layout, H-005
//! executable, and H-006 relation plan. All integers are fixed-width little
//! endian and all variants use explicit numeric tags. Source paths, spans,
//! allocation state, backend names, product revisions, and AOT metadata are
//! intentionally outside this proof-facing identity.

const std = @import("std");
const compat = @import("typed_poseidon2_compat.zig");
const golden = @import("typed_poseidon2_identity_golden.zig");
const semantic = @import("digest.zig");
const materializer = @import("degree3_materializer.zig");
const relations = @import("typed_poseidon2_relations.zig");
const types = @import("types.zig");
const witness = @import("typed_poseidon2_witness.zig");

const codec = @import("typed_poseidon2_identity_codec.zig");
pub const Digest = codec.Digest;
pub const LAYOUT_DIGEST_FORMAT_VERSION = codec.LAYOUT_DIGEST_FORMAT_VERSION;
pub const LAYOUT_DIGEST_DOMAIN_SEPARATOR = codec.LAYOUT_DIGEST_DOMAIN_SEPARATOR;
pub const PROGRAM_IDENTITY_FORMAT_VERSION = codec.PROGRAM_IDENTITY_FORMAT_VERSION;
pub const PROGRAM_IDENTITY_DOMAIN_SEPARATOR = codec.PROGRAM_IDENTITY_DOMAIN_SEPARATOR;
pub const PROGRAM_COMPONENT_ID = codec.PROGRAM_COMPONENT_ID;
pub const PROGRAM_IDENTITY_MAGIC = codec.PROGRAM_IDENTITY_MAGIC;
pub const CANONICAL_SEMANTIC_DIGEST = codec.CANONICAL_SEMANTIC_DIGEST;
pub const CANONICAL_LAYOUT_DIGEST = codec.CANONICAL_LAYOUT_DIGEST;
pub const CANONICAL_EXECUTOR_DIGEST = codec.CANONICAL_EXECUTOR_DIGEST;
pub const CANONICAL_RELATION_DIGEST = codec.CANONICAL_RELATION_DIGEST;
pub const CANONICAL_COMBINED_DIGEST = codec.CANONICAL_COMBINED_DIGEST;
pub const CANONICAL_RECEIPT_SHA256 = codec.CANONICAL_RECEIPT_SHA256;
pub const CANONICAL_PREIMAGE_LEN = codec.CANONICAL_PREIMAGE_LEN;
pub const RECEIPT_BYTES_LEN = codec.RECEIPT_BYTES_LEN;

pub const LayoutError = compat.ValidationError || relations.Error || error{
    BindingEntryCountMismatch,
    ComponentIdentityMismatch,
    DuplicateMaterializationMapping,
    LayoutClaimMismatch,
    LayoutColumnMismatch,
    LayoutInteractionMismatch,
    MaterializationMappingOutOfRange,
};

pub const IdentityError = LayoutError || witness.ExecutionError || error{
    InvalidIdentityEncoding,
    ProgramIdentityMismatch,
    UnsupportedIdentityEncoding,
};

pub const MaterializationColumn = struct {
    placement: compat.Materialization,
    plan_materialization: materializer.MaterializationId,
    value: types.ValueId,
};

pub const MainColumn = union(enum) {
    enabler,
    input: u8,
    materialization: MaterializationColumn,
    wide,
    io,
};

pub const InteractionColumn = struct {
    index: u8,
    batch_ordinal: u8,
    first: relations.EventId,
    second: relations.EventId,
    coordinate: u8,
};

pub const ClaimSlot = struct {
    index: u8,
    batch_ordinal: u8,
    first: relations.EventId,
    second: relations.EventId,
};

/// Exact physical placement authenticated by H-004 and H-006. The fixed-size
/// value is cheap to compare and requires no allocation to construct or hash.
pub const LayoutIdentity = struct {
    semantic_digest: Digest,
    compatibility_identity: compat.Identity,
    materializer_policy_version: u16,
    gate: types.ValueId,
    materializer_policy: materializer.Policy,
    main_columns: [compat.N_MAIN_COLUMNS]MainColumn,
    interaction_columns: [relations.N_INTERACTION_COLUMNS]InteractionColumn,
    claim_slots: [relations.N_SUMS]ClaimSlot,

    pub fn init(
        binding: *const compat.OwnedBinding,
        relation_plan: *const relations.Plan,
    ) LayoutError!LayoutIdentity {
        try binding.identity.validate();
        if (!std.meta.eql(binding.identity, compat.Identity.canonical()) or
            binding.materializer_policy_version != materializer.policy_version or
            binding.policy.maximum_constraint_degree !=
                compat.MAXIMUM_CONSTRAINT_DEGREE or
            binding.policy.row_mask_degree != 0)
        {
            return error.ComponentIdentityMismatch;
        }
        if (binding.entries.len != compat.N_MATERIALIZATIONS)
            return error.BindingEntryCountMismatch;

        try relation_plan.validateIdentityShape();
        if (!std.meta.eql(
            relation_plan.compatibility_identity,
            binding.identity,
        ) or
            relation_plan.materializer_policy_version !=
                binding.materializer_policy_version or
            !std.mem.eql(
                u8,
                &relation_plan.program_digest,
                &binding.program_digest,
            ) or
            relation_plan.gate != binding.gate or
            !std.meta.eql(relation_plan.materializer_policy, binding.policy))
        {
            return error.ComponentIdentityMismatch;
        }

        var main_columns: [compat.N_MAIN_COLUMNS]MainColumn = undefined;
        for (&main_columns, 0..) |*destination, index| {
            destination.* = switch (try compat.column(index)) {
                .enabler => .enabler,
                .input => |lane| .{ .input = lane },
                .materialization => |placement| blk: {
                    const ordinal: usize = placement.ordinal;
                    const entry = binding.entries[ordinal];
                    if (!std.meta.eql(entry.materialization, placement))
                        return error.LayoutColumnMismatch;
                    break :blk .{ .materialization = .{
                        .placement = placement,
                        .plan_materialization = entry.plan_materialization,
                        .value = entry.value,
                    } };
                },
                .wide => .wide,
                .io => .io,
            };
        }

        var interaction_columns: [relations.N_INTERACTION_COLUMNS]InteractionColumn =
            undefined;
        var seen_interactions = [_]bool{false} ** relations.N_INTERACTION_COLUMNS;
        for (relation_plan.batches) |batch| {
            for (0..4) |coordinate| {
                const index = @as(usize, batch.interaction_column_start) + coordinate;
                if (index >= interaction_columns.len or seen_interactions[index])
                    return error.LayoutInteractionMismatch;
                seen_interactions[index] = true;
                interaction_columns[index] = .{
                    .index = @intCast(index),
                    .batch_ordinal = batch.ordinal,
                    .first = batch.first,
                    .second = batch.second,
                    .coordinate = @intCast(coordinate),
                };
            }
        }
        for (seen_interactions) |seen| {
            if (!seen) return error.LayoutInteractionMismatch;
        }

        var claim_slots: [relations.N_SUMS]ClaimSlot = undefined;
        for (&claim_slots, relation_plan.batches, 0..) |*slot, batch, index| {
            slot.* = .{
                .index = @intCast(index),
                .batch_ordinal = batch.ordinal,
                .first = batch.first,
                .second = batch.second,
            };
        }

        const result = LayoutIdentity{
            .semantic_digest = binding.program_digest,
            .compatibility_identity = binding.identity,
            .materializer_policy_version = binding.materializer_policy_version,
            .gate = binding.gate,
            .materializer_policy = binding.policy,
            .main_columns = main_columns,
            .interaction_columns = interaction_columns,
            .claim_slots = claim_slots,
        };
        try result.validate();
        return result;
    }

    /// Checks the complete canonical geometry and all physical role mappings.
    /// Logical value mappings remain variable but must be a one-to-one H-003
    /// plan mapping; `init` obtains them only from an authenticated H-004 bind.
    pub fn validate(self: *const LayoutIdentity) LayoutError!void {
        try self.compatibility_identity.validate();
        if (!std.meta.eql(
            self.compatibility_identity,
            compat.Identity.canonical(),
        ) or
            self.materializer_policy_version != materializer.policy_version or
            self.materializer_policy.maximum_constraint_degree !=
                compat.MAXIMUM_CONSTRAINT_DEGREE or
            self.materializer_policy.row_mask_degree != 0)
        {
            return error.ComponentIdentityMismatch;
        }

        var seen_plan_ids = [_]bool{false} ** compat.N_MATERIALIZATIONS;
        for (self.main_columns, 0..) |actual, index| {
            const expected = try compat.column(index);
            switch (expected) {
                .enabler => switch (actual) {
                    .enabler => {},
                    else => return error.LayoutColumnMismatch,
                },
                .input => |expected_lane| switch (actual) {
                    .input => |lane| if (lane != expected_lane)
                        return error.LayoutColumnMismatch,
                    else => return error.LayoutColumnMismatch,
                },
                .materialization => |expected_placement| switch (actual) {
                    .materialization => |entry| {
                        if (!std.meta.eql(entry.placement, expected_placement))
                            return error.LayoutColumnMismatch;
                        const plan_index = types.idIndex(entry.plan_materialization);
                        if (plan_index >= seen_plan_ids.len)
                            return error.MaterializationMappingOutOfRange;
                        if (seen_plan_ids[plan_index])
                            return error.DuplicateMaterializationMapping;
                        seen_plan_ids[plan_index] = true;
                        const first_materialization = compat.TEMPORARY_START;
                        for (self.main_columns[first_materialization..index]) |prior| {
                            switch (prior) {
                                .materialization => |prior_entry| {
                                    if (prior_entry.value == entry.value)
                                        return error.DuplicateMaterializationMapping;
                                },
                                else => unreachable,
                            }
                        }
                    },
                    else => return error.LayoutColumnMismatch,
                },
                .wide => switch (actual) {
                    .wide => {},
                    else => return error.LayoutColumnMismatch,
                },
                .io => switch (actual) {
                    .io => {},
                    else => return error.LayoutColumnMismatch,
                },
            }
        }
        for (seen_plan_ids) |seen| {
            if (!seen) return error.MaterializationMappingOutOfRange;
        }

        for (self.interaction_columns, 0..) |actual, index| {
            const batch_ordinal: u8 = @intCast(index / 4);
            const expected_first: relations.EventId = if (batch_ordinal == 0)
                .input
            else
                .wide_output;
            const expected_second: relations.EventId = if (batch_ordinal == 0)
                .narrow_output
            else
                .io;
            if (actual.index != @as(u8, @intCast(index)) or
                actual.batch_ordinal != batch_ordinal or
                actual.first != expected_first or
                actual.second != expected_second or
                actual.coordinate != @as(u8, @intCast(index % 4)))
            {
                return error.LayoutInteractionMismatch;
            }
        }

        for (self.claim_slots, 0..) |actual, index| {
            const batch_ordinal: u8 = @intCast(index);
            const expected_first: relations.EventId = if (batch_ordinal == 0)
                .input
            else
                .wide_output;
            const expected_second: relations.EventId = if (batch_ordinal == 0)
                .narrow_output
            else
                .io;
            if (actual.index != @as(u8, @intCast(index)) or
                actual.batch_ordinal != batch_ordinal or
                actual.first != expected_first or
                actual.second != expected_second)
            {
                return error.LayoutClaimMismatch;
            }
        }
    }

    pub fn digestValue(self: *const LayoutIdentity) LayoutError!Digest {
        try self.validate();
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(LAYOUT_DIGEST_DOMAIN_SEPARATOR);
        hashInt(&hash, u16, LAYOUT_DIGEST_FORMAT_VERSION);
        hash.update(&self.semantic_digest);

        hashCompatIdentity(&hash, self.compatibility_identity);
        hashInt(&hash, u16, self.materializer_policy_version);
        hashInt(&hash, u32, @intFromEnum(self.gate));
        hashInt(
            &hash,
            u64,
            self.materializer_policy.maximum_constraint_degree,
        );
        hashInt(&hash, u64, self.materializer_policy.row_mask_degree);

        hashInt(&hash, u16, @intCast(self.main_columns.len));
        for (self.main_columns, 0..) |column, index| {
            hashInt(&hash, u16, @intCast(index));
            switch (column) {
                .enabler => hashInt(&hash, u8, 0),
                .input => |lane| {
                    hashInt(&hash, u8, 1);
                    hashInt(&hash, u8, lane);
                },
                .materialization => |entry| {
                    hashInt(&hash, u8, 2);
                    hashPlacement(&hash, entry.placement);
                    hashInt(
                        &hash,
                        u32,
                        @intFromEnum(entry.plan_materialization),
                    );
                    hashInt(&hash, u32, @intFromEnum(entry.value));
                },
                .wide => hashInt(&hash, u8, 3),
                .io => hashInt(&hash, u8, 4),
            }
        }

        hashInt(&hash, u16, @intCast(self.interaction_columns.len));
        for (self.interaction_columns) |column| {
            hashInt(&hash, u8, column.index);
            hashInt(&hash, u8, column.batch_ordinal);
            hashInt(&hash, u8, @intFromEnum(column.first));
            hashInt(&hash, u8, @intFromEnum(column.second));
            hashInt(&hash, u8, column.coordinate);
        }

        hashInt(&hash, u16, @intCast(self.claim_slots.len));
        for (self.claim_slots) |slot| {
            hashInt(&hash, u8, slot.index);
            hashInt(&hash, u8, slot.batch_ordinal);
            hashInt(&hash, u8, @intFromEnum(slot.first));
            hashInt(&hash, u8, @intFromEnum(slot.second));
        }
        return hash.finalResult();
    }
};

/// Canonical H-006 relation-program identity. The preimage covers every event
/// and batch field and binds them to both the semantic and physical identities.
pub fn relationDigest(
    plan: *const relations.Plan,
    layout_digest: Digest,
) relations.Error!Digest {
    try plan.validateIdentityShape();

    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(relations.RELATION_DIGEST_DOMAIN_SEPARATOR);
    hashInt(&hash, u16, relations.RELATION_DIGEST_FORMAT_VERSION);
    hash.update(&plan.program_digest);
    hash.update(&layout_digest);

    hashInt(&hash, u16, plan.identity.format_version);
    hashInt(&hash, u32, @intFromEnum(plan.identity.policy));
    hashInt(&hash, u16, plan.identity.policy_version);
    hashInt(&hash, u8, plan.identity.events);
    hashInt(&hash, u8, plan.identity.batches);
    hashInt(&hash, u8, plan.identity.sums);
    hashInt(&hash, u8, plan.identity.interaction_columns);

    hashCompatIdentity(&hash, plan.compatibility_identity);
    hashInt(&hash, u16, plan.materializer_policy_version);
    hashInt(&hash, u32, @intFromEnum(plan.gate));
    hashInt(
        &hash,
        u64,
        plan.materializer_policy.maximum_constraint_degree,
    );
    hashInt(&hash, u64, plan.materializer_policy.row_mask_degree);

    hashInt(&hash, u8, @intCast(relations.N_EVENTS));
    for (plan.events) |event| {
        hashInt(&hash, u8, @intFromEnum(event.id));
        hashInt(&hash, u8, event.ordinal);
        hashInt(&hash, u16, @intFromEnum(event.schema));
        hashInt(&hash, u16, event.schema_version);
        hashInt(&hash, u8, @intFromEnum(event.domain));
        hashInt(&hash, u8, @intFromEnum(event.role));
        if (event.access_ordinal) |access_ordinal| {
            hashInt(&hash, u8, 1);
            hashInt(&hash, u8, access_ordinal);
        } else {
            hashInt(&hash, u8, 0);
        }
        hashInt(&hash, u8, event.relation_arity);
        hashInt(&hash, u8, event.semantic_width);
        hashInt(&hash, u8, @intFromEnum(event.numerator));
        hashInt(&hash, u8, @intFromEnum(event.projection));
    }

    hashInt(&hash, u8, @intCast(relations.N_BATCHES));
    for (plan.batches) |batch| {
        hashInt(&hash, u8, batch.ordinal);
        hashInt(&hash, u8, @intFromEnum(batch.first));
        hashInt(&hash, u8, @intFromEnum(batch.second));
        hashInt(&hash, u8, batch.interaction_column_start);
    }
    return hash.finalResult();
}

/// Self-authenticating composition of the four proof-facing identities.
pub const ProgramIdentity = struct {
    const CodecMethods = codec.Methods(@This());
    semantic_digest: @FieldType(codec.ProgramIdentity, "semantic_digest"),
    layout_digest: @FieldType(codec.ProgramIdentity, "layout_digest"),
    executor_digest: @FieldType(codec.ProgramIdentity, "executor_digest"),
    relation_digest: @FieldType(codec.ProgramIdentity, "relation_digest"),
    combined_digest: @FieldType(codec.ProgramIdentity, "combined_digest"),

    pub const canonical = CodecMethods.canonical;

    pub const isCanonical = CodecMethods.isCanonical;

    pub fn fromAuthenticated(
        binding: *const compat.OwnedBinding,
        executor: *const witness.Executor,
        relation_plan: *const relations.Plan,
    ) IdentityError!ProgramIdentity {
        const layout = try LayoutIdentity.init(binding, relation_plan);
        const layout_digest = try layout.digestValue();
        const executor_identity = try executor.identitySnapshot();
        if (!executorMatchesBinding(executor_identity, binding))
            return error.ComponentIdentityMismatch;
        const executor_digest = try executor.identityDigest();
        const relation_digest = try relationDigest(relation_plan, layout_digest);
        return sealDigests(
            binding.program_digest,
            layout_digest,
            executor_digest,
            relation_digest,
        );
    }

    /// Low-level fixed composition used by decoders and sensitivity tests.
    /// Callers that possess components should prefer `fromAuthenticated`.
    pub const sealDigests = CodecMethods.sealDigests;

    pub const validate = CodecMethods.validate;

    /// Canonical bytes hashed by the combined identity. These bytes are the
    /// backend-neutral equality contract; they contain no backend metadata.
    pub const preimageBytes = CodecMethods.preimageBytes;

    /// Self-authenticating transport form: canonical preimage followed by its
    /// combined SHA-256 digest.
    pub const receiptBytes = CodecMethods.receiptBytes;

    pub const fromReceiptBytes = CodecMethods.fromReceiptBytes;
};

fn executorMatchesBinding(
    executor_identity: witness.Identity,
    binding: *const compat.OwnedBinding,
) bool {
    if (!std.meta.eql(executor_identity.compatibility, binding.identity) or
        executor_identity.materializer_policy_version !=
            binding.materializer_policy_version or
        !std.mem.eql(
            u8,
            &executor_identity.program_digest,
            &binding.program_digest,
        ) or
        executor_identity.gate != binding.gate or
        !std.meta.eql(executor_identity.policy, binding.policy) or
        binding.entries.len != compat.N_MATERIALIZATIONS)
    {
        return false;
    }
    for (
        binding.entries,
        executor_identity.plan_materializations,
        executor_identity.values,
    ) |entry, plan_materialization, value| {
        if (entry.plan_materialization != plan_materialization or
            entry.value != value)
        {
            return false;
        }
    }
    return true;
}

fn hashCompatIdentity(hash: anytype, identity: compat.Identity) void {
    hashInt(hash, u16, identity.format_version);
    hashInt(hash, u32, @intFromEnum(identity.policy));
    hashInt(hash, u16, identity.policy_version);
    hashInt(hash, u8, identity.maximum_constraint_degree);
    hashInt(hash, u16, identity.width);
    hashInt(hash, u16, identity.materializations);
    hashInt(hash, u16, identity.main_columns);
}

fn hashPlacement(hash: anytype, placement: compat.Materialization) void {
    hashInt(hash, u16, placement.ordinal);
    hashInt(hash, u16, placement.column);
    hashInt(hash, u16, placement.constraint);
    hashInt(hash, u8, @intFromEnum(placement.phase));
    if (placement.round == compat.NO_ROUND) {
        hashInt(hash, u8, 0);
    } else {
        hashInt(hash, u8, 1);
        hashInt(hash, u8, placement.round);
    }
    hashInt(hash, u8, placement.lane);
    hashInt(hash, u8, @intFromEnum(placement.role));
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

comptime {
    if (compat.N_MAIN_COLUMNS != 445 or
        compat.N_MATERIALIZATIONS != 426 or
        relations.N_EVENTS != 4 or
        relations.N_BATCHES != 2 or
        relations.N_INTERACTION_COLUMNS != 8 or
        relations.N_SUMS != 2)
    {
        @compileError(
            "Poseidon2 program-identity v1 geometry drifted; review and bump the format",
        );
    }
    if (CANONICAL_PREIMAGE_LEN != 182 or RECEIPT_BYTES_LEN != 214)
        @compileError("Poseidon2 program-identity v1 byte encoding drifted");
}
