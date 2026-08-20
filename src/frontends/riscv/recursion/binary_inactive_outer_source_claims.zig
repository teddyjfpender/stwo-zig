//! Internal shard of binary_inactive_outer_source.zig; use the public facade.

pub const std = @import("std");

pub const stwo_core = @import("stwo_core");

pub const M31 = stwo_core.fields.m31.M31;

pub const QM31 = stwo_core.fields.qm31.QM31;

pub const leaf_authority = @import("segment_leaf_authority.zig");

pub const segment_source = @import("segment_public_outer_source.zig");

pub const air = @import("air/mod.zig");

pub const adapter = air.universal_typed_component;

pub const binding = air.universal_relation_binding;

pub const framework = air.framework_interaction;

pub const manifest_mod = air.universal_adapter_manifest;

pub const relation_interaction = air.relation_interaction;

pub const roster = air.universal_roster;

pub const schedule = air.verifier_schedule;

pub const universal = air.universal_challenges;

pub const universal_manifest = air.universal_manifest;

pub const claim_input_air = air.vm_public_claim_input;

pub const claim_input_witness = air.vm_public_claim_input_witness;

pub const claim_hash_air = air.vm_public_claim_hash;

pub const claim_hash_witness = air.vm_public_claim_hash_witness;

pub const io_hash_air = air.vm_public_io_hash;

pub const io_hash_witness = air.vm_public_io_hash_witness;

pub const claim_semantics_air = air.vm_public_claim_semantics_input;

pub const claim_semantics_witness = air.vm_public_claim_semantics_input_witness;

pub const public_logup_air = air.vm_public_logup_input;

pub const public_logup_witness = air.vm_public_logup_input_witness;

pub const public_logup_control_air = air.vm_public_logup_control.Air;

pub const control_witness = air.control_slice_witness;

pub const prepared_init = @import("binary_inactive_outer_source_prepared_init.zig");

pub const domain_audit = @import("binary_inactive_outer_source_domain_audit.zig");

pub const FORMAT_VERSION: u16 = 1;

pub const FIRST_ROW: usize = @intFromEnum(roster.Component.vm_public_claim_input);

pub const LAST_INACTIVE_ROW: usize = @intFromEnum(
    roster.Component.vm_public_logup_input,
);

pub const CONTROL_ROW: usize = @intFromEnum(
    roster.Component.vm_public_logup_control,
);

pub const ROW_COUNT: usize = CONTROL_ROW - FIRST_ROW + 1;

pub const INACTIVE_ROW_COUNT: usize = LAST_INACTIVE_ROW - FIRST_ROW + 1;

/// One retained logical-row allocation per family.  Hash witnesses allocate
/// zero Poseidon calls in binary mode; the allocator is never entered for the
/// empty call slices.
pub const COLD_PREPARED_RETAINED_ALLOCATIONS: usize = 10;

pub const COLD_PREPARE_HEAP_ALLOCATIONS: usize = 11;

pub const HOT_TREE_HEAP_ALLOCATIONS = [manifest_mod.TREE_COUNT]usize{ 1, 1, 13 };

pub const HOT_ALL_TREES_HEAP_ALLOCATIONS: usize = 15;

pub const HOT_PAIR_AUTHENTICATIONS_PER_TREE: usize = 0;

pub const POSEIDON_CALLS_PER_BINARY_NODE: usize = 0;

pub const Error = error{
    ArithmeticOverflow,
    AuthorityMismatch,
    DestinationAlias,
    DestinationColumnCountMismatch,
    DestinationLogSizeMismatch,
    InactiveClaimNonZero,
    ManifestGeometryMismatch,
    PreparedAuthorityMismatch,
};

pub const ClaimInputRelation = binding.Binding(claim_input_air);

pub const ClaimHashRelation = binding.Binding(claim_hash_air);

pub const IoHashRelation = binding.Binding(io_hash_air);

pub const ClaimSemanticsRelation = binding.Binding(claim_semantics_air);

pub const PublicLogupRelation = binding.Binding(public_logup_air);

pub const PublicLogupControlRelation = binding.Binding(public_logup_control_air);

pub const ClaimInputFramework = framework.Runtime(ClaimInputRelation.Runtime);

pub const ClaimHashFramework = framework.Runtime(ClaimHashRelation.Runtime);

pub const IoHashFramework = framework.Runtime(IoHashRelation.Runtime);

pub const ClaimSemanticsFramework = framework.Runtime(ClaimSemanticsRelation.Runtime);

pub const PublicLogupFramework = framework.Runtime(PublicLogupRelation.Runtime);

pub const PublicLogupControlFramework = framework.Runtime(
    PublicLogupControlRelation.Runtime,
);

pub const ClaimInputAdapter = adapter.Component(claim_input_air, ClaimInputRelation);

pub const ClaimHashAdapter = adapter.Component(claim_hash_air, ClaimHashRelation);

pub const IoHashAdapter = adapter.Component(io_hash_air, IoHashRelation);

pub const ClaimSemanticsAdapter = adapter.Component(
    claim_semantics_air,
    ClaimSemanticsRelation,
);

pub const PublicLogupAdapter = adapter.Component(public_logup_air, PublicLogupRelation);

pub const PublicLogupControlAdapter = adapter.Component(
    public_logup_control_air,
    PublicLogupControlRelation,
);

pub const LogSizes = [ROW_COUNT]u32;

pub const DomainAudits = [ROW_COUNT]relation_interaction.DomainAudit;

pub const Parameters = struct {
    claim_input: [ClaimInputAdapter.PARAMETER_COLUMN_COUNT]M31,
    claim_hash: [ClaimHashAdapter.PARAMETER_COLUMN_COUNT]M31,
    io_hash: [IoHashAdapter.PARAMETER_COLUMN_COUNT]M31,
    claim_semantics: [ClaimSemanticsAdapter.PARAMETER_COLUMN_COUNT]M31,
    public_logup: [PublicLogupAdapter.PARAMETER_COLUMN_COUNT]M31,
    public_logup_control: [PublicLogupControlAdapter.PARAMETER_COLUMN_COUNT]M31,

    pub fn binaryNode() Parameters {
        const segment = segment_source.Parameters.segmentLeaf();
        var result = Parameters{
            .claim_input = segment.claim_input,
            .claim_hash = segment.claim_hash,
            .io_hash = segment.io_hash,
            .claim_semantics = segment.claim_semantics,
            .public_logup = segment.public_logup,
            .public_logup_control = segment.public_logup_control,
        };
        result.claim_input[0] = M31.zero();
        result.claim_hash[0] = M31.zero();
        result.io_hash[0] = M31.zero();
        result.claim_semantics[0] = M31.zero();
        result.public_logup[0] = M31.zero();
        result.public_logup_control = control_witness.ProofKind.binary_node
            .selectors()[0..2].*;
        return result;
    }
};

pub const Claims = struct {
    claim_input: QM31,
    claim_hash: QM31,
    io_hash: QM31,
    claim_semantics: QM31,
    public_logup: QM31,
    public_logup_control: QM31,

    pub fn asArray(self: Claims) [ROW_COUNT]QM31 {
        return .{
            self.claim_input,
            self.claim_hash,
            self.io_hash,
            self.claim_semantics,
            self.public_logup,
            self.public_logup_control,
        };
    }

    pub fn validateInactive(self: Claims) Error!void {
        for (self.asArray()[0..INACTIVE_ROW_COUNT]) |claim|
            if (!claim.isZero()) return error.InactiveClaimNonZero;
    }

    pub fn bindInto(
        self: Claims,
        claims: *manifest_mod.ClaimVector,
    ) !void {
        inline for (self.asArray(), 0..) |value, index| {
            const row: roster.Component = @enumFromInt(FIRST_ROW + index);
            try claims.bind(row, value);
        }
    }
};

pub const Components = struct {
    claim_input: ClaimInputAdapter,
    claim_hash: ClaimHashAdapter,
    io_hash: IoHashAdapter,
    claim_semantics: ClaimSemanticsAdapter,
    public_logup: PublicLogupAdapter,
    public_logup_control: PublicLogupControlAdapter,

    pub fn appendToGate(
        self: *const Components,
        manifest: *const manifest_mod.Manifest,
        gate: *manifest_mod.ProofGate,
    ) !void {
        try gate.append(manifest, try self.claim_input.binding(manifest));
        try gate.append(manifest, try self.claim_hash.binding(manifest));
        try gate.append(manifest, try self.io_hash.binding(manifest));
        try gate.append(manifest, try self.claim_semantics.binding(manifest));
        try gate.append(manifest, try self.public_logup.binding(manifest));
        try gate.append(manifest, try self.public_logup_control.binding(manifest));
    }
};
