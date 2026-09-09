//! Typed authority for omitting the native narrow-memory Poseidon2 provider.
//!
//! This module does not activate a proof route. It admits the ordinary full
//! Ethereum SegmentV2 statement first, then derives one versioned physical
//! projection with exactly the native Poseidon2 infrastructure descriptor
//! removed. Only APIs that explicitly accept `ProjectionV1` may use that
//! geometry; the projected core is never passed through ordinary StatementV2
//! admission, whose complete native layout intentionally requires the provider.

const std = @import("std");
const Blake2sChannel = @import("stwo_core").channel.blake2s.Blake2sChannel;
const M31 = @import("stwo_core").fields.m31.M31;
const poseidon_channel = @import("../../recursion/poseidon2_channel.zig");
const statement = @import("../../air/statement.zig");
const statement_v2 = @import("../../air/statement_v2.zig");
const ethereum_statement = @import("../../air/guest_precompile/ethereum_statement.zig");
const ethereum_admission = @import("../../air/guest_precompile/ethereum_proof_admission.zig");
const lookup_physical_v2 = @import("../../air/lang/lookup_physical_manifest_v2.zig");
const poseidon2_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const statement_geometry = @import("../statement_geometry.zig");
const statement_validation = @import("../statement_validation.zig");
const aggregation_hash = @import("../../aggregation/hash.zig");
const provider_authority = @import("authority.zig");

pub const format_version: u32 = 1;
pub const ACTIVATES_PRODUCTION_PROOF = false;
pub const Digest = aggregation_hash.Digest;

/// Geometry exposed to omission-aware generators. There is deliberately no
/// Poseidon field that can accidentally route the full provider generator.
pub const ProjectedGeometryV1 = struct {
    program_log_size: u32,
    merkle_log_size: u32,
    clock_update_log: u32,
    merkle_infra_index: u32,
    clock_infra_index: u32,
};

pub const ProjectionV1 = struct {
    format: u32,
    full_statement_authority: poseidon_channel.Digest,
    extension_statement_identity: Digest,
    lookup_manifest_identity: lookup_physical_v2.Digest,
    lookup_statement_identity: lookup_physical_v2.Digest,
    lookup_activation_identity: lookup_physical_v2.Digest,
    provider_plan_identity: Digest,
    call_list_commitment: Digest,
    omitted_infra_index: u32,
    omitted_descriptor: statement.InfraComponentDesc,
    projected_native: statement_v2.RiscVStatementV2,
    projected_geometry: ProjectedGeometryV1,
    identity: Digest,

    pub fn init(
        full_native: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
        policy: statement_validation.AdmissionPolicy,
        manifest: *const lookup_physical_v2.Manifest,
        authenticated_lookup: *const lookup_physical_v2.AuthenticatedStatement,
        plan: *const provider_authority.ProviderShardPlanV1,
        calls: []const poseidon2_air.Call,
        full_geometry: statement_geometry.Geometry,
    ) !ProjectionV1 {
        try ethereum_admission.validateV2(full_native, extension, policy);
        return initAfterAdmission(
            full_native,
            extension,
            manifest,
            authenticated_lookup,
            plan,
            calls,
            null,
            full_geometry,
        );
    }

    /// Identity-neutral sibling of `init`. The expensive
    /// `ProviderShardPlanV1.validate(calls)` corpus rehash is replaced by an
    /// O(1) pointer-closed readmission of an already minted authority; the
    /// cheap `ethereum_admission.validateV2` boundary is unchanged, and every
    /// projected field and identity is computed by the same code.
    pub fn initValidated(
        full_native: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
        policy: statement_validation.AdmissionPolicy,
        manifest: *const lookup_physical_v2.Manifest,
        authenticated_lookup: *const lookup_physical_v2.AuthenticatedStatement,
        plan: *const provider_authority.ProviderShardPlanV1,
        calls: []const poseidon2_air.Call,
        validated: *const provider_authority.OwnedValidatedPlanCallAuthorityV1,
        full_geometry: statement_geometry.Geometry,
    ) !ProjectionV1 {
        try ethereum_admission.validateV2(full_native, extension, policy);
        return initAfterAdmission(
            full_native,
            extension,
            manifest,
            authenticated_lookup,
            plan,
            calls,
            validated,
            full_geometry,
        );
    }

    /// Candidate-only heterogeneous-retirement sibling. The caller supplies
    /// the exact supplement recomputed from its typed profile; the common
    /// validator still authenticates the full V2 boundary and proves that the
    /// supplement closes the base retirement and memory coefficients before
    /// any provider projection is constructed.
    pub fn initWithRetirementSupplementV2(
        full_native: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
        policy: statement_validation.AdmissionPolicy,
        supplement: statement_validation.RetirementSupplementV2,
        manifest: *const lookup_physical_v2.Manifest,
        authenticated_lookup: *const lookup_physical_v2.AuthenticatedStatement,
        plan: *const provider_authority.ProviderShardPlanV1,
        calls: []const poseidon2_air.Call,
        full_geometry: statement_geometry.Geometry,
    ) !ProjectionV1 {
        try extension.validateV2(full_native);
        try statement_validation.validateV2WithRetirementSupplementV2(
            full_native,
            policy,
            supplement,
        );
        return initAfterAdmission(
            full_native,
            extension,
            manifest,
            authenticated_lookup,
            plan,
            calls,
            null,
            full_geometry,
        );
    }

    /// Identity-neutral validated sibling of the candidate-only supplement
    /// route above.
    pub fn initWithRetirementSupplementV2Validated(
        full_native: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
        policy: statement_validation.AdmissionPolicy,
        supplement: statement_validation.RetirementSupplementV2,
        manifest: *const lookup_physical_v2.Manifest,
        authenticated_lookup: *const lookup_physical_v2.AuthenticatedStatement,
        plan: *const provider_authority.ProviderShardPlanV1,
        calls: []const poseidon2_air.Call,
        validated: *const provider_authority.OwnedValidatedPlanCallAuthorityV1,
        full_geometry: statement_geometry.Geometry,
    ) !ProjectionV1 {
        try extension.validateV2(full_native);
        try statement_validation.validateV2WithRetirementSupplementV2(
            full_native,
            policy,
            supplement,
        );
        return initAfterAdmission(
            full_native,
            extension,
            manifest,
            authenticated_lookup,
            plan,
            calls,
            validated,
            full_geometry,
        );
    }

    fn initAfterAdmission(
        full_native: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
        manifest: *const lookup_physical_v2.Manifest,
        authenticated_lookup: *const lookup_physical_v2.AuthenticatedStatement,
        plan: *const provider_authority.ProviderShardPlanV1,
        calls: []const poseidon2_air.Call,
        validated: ?*const provider_authority.OwnedValidatedPlanCallAuthorityV1,
        full_geometry: statement_geometry.Geometry,
    ) !ProjectionV1 {
        try authenticated_lookup.validateAgainst(&full_native.core, manifest);
        if (validated) |token|
            try token.validateBorrowed(plan, calls)
        else
            try plan.validate(calls);

        const omitted_index = try findExactProvider(full_native, plan, calls);
        const projected_core = try projectCore(&full_native.core, omitted_index);
        const projected_native = try statement_v2.RiscVStatementV2.init(
            projected_core,
            full_native.public_data,
        );
        // The selected lookup authority is opcode-scoped. Revalidating it here
        // proves that removing the infrastructure provider cannot alter opcode
        // physical selection or activation.
        try authenticated_lookup.validateAgainst(&projected_native.core, manifest);

        var result = ProjectionV1{
            .format = format_version,
            .full_statement_authority = full_native.authority_id,
            .extension_statement_identity = try extensionIdentity(full_native, extension),
            .lookup_manifest_identity = manifest.identity,
            .lookup_statement_identity = authenticated_lookup.statement_identity,
            .lookup_activation_identity = authenticated_lookup.activation_identity,
            .provider_plan_identity = plan.identity,
            .call_list_commitment = plan.call_list_commitment,
            .omitted_infra_index = @intCast(omitted_index),
            .omitted_descriptor = full_native.core.infra_descs[omitted_index],
            .projected_native = projected_native,
            .projected_geometry = try projectGeometry(full_geometry, omitted_index),
            .identity = undefined,
        };
        result.identity = projectionIdentity(&result);
        try result.validateAgainstAfterAdmission(
            full_native,
            extension,
            manifest,
            authenticated_lookup,
            plan,
            calls,
            validated,
            full_geometry,
        );
        return result;
    }

    pub fn validateAgainst(
        self: *const ProjectionV1,
        full_native: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
        policy: statement_validation.AdmissionPolicy,
        manifest: *const lookup_physical_v2.Manifest,
        authenticated_lookup: *const lookup_physical_v2.AuthenticatedStatement,
        plan: *const provider_authority.ProviderShardPlanV1,
        calls: []const poseidon2_air.Call,
        full_geometry: statement_geometry.Geometry,
    ) !void {
        try ethereum_admission.validateV2(full_native, extension, policy);
        return self.validateAgainstAfterAdmission(
            full_native,
            extension,
            manifest,
            authenticated_lookup,
            plan,
            calls,
            null,
            full_geometry,
        );
    }

    /// Identity-neutral sibling of `validateAgainst`: same admission, same
    /// comparisons, same errors, with the corpus rehash replaced by an O(1)
    /// pointer-closed readmission.
    pub fn validateAgainstValidated(
        self: *const ProjectionV1,
        full_native: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
        policy: statement_validation.AdmissionPolicy,
        manifest: *const lookup_physical_v2.Manifest,
        authenticated_lookup: *const lookup_physical_v2.AuthenticatedStatement,
        plan: *const provider_authority.ProviderShardPlanV1,
        calls: []const poseidon2_air.Call,
        validated: *const provider_authority.OwnedValidatedPlanCallAuthorityV1,
        full_geometry: statement_geometry.Geometry,
    ) !void {
        try ethereum_admission.validateV2(full_native, extension, policy);
        return self.validateAgainstAfterAdmission(
            full_native,
            extension,
            manifest,
            authenticated_lookup,
            plan,
            calls,
            validated,
            full_geometry,
        );
    }

    /// Revalidates a candidate projection under the exact heterogeneous
    /// retirement supplement. This is additive; the ordinary Ethereum entry
    /// point above retains its byte-for-byte admission route.
    pub fn validateAgainstWithRetirementSupplementV2(
        self: *const ProjectionV1,
        full_native: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
        policy: statement_validation.AdmissionPolicy,
        supplement: statement_validation.RetirementSupplementV2,
        manifest: *const lookup_physical_v2.Manifest,
        authenticated_lookup: *const lookup_physical_v2.AuthenticatedStatement,
        plan: *const provider_authority.ProviderShardPlanV1,
        calls: []const poseidon2_air.Call,
        full_geometry: statement_geometry.Geometry,
    ) !void {
        try extension.validateV2(full_native);
        try statement_validation.validateV2WithRetirementSupplementV2(
            full_native,
            policy,
            supplement,
        );
        return self.validateAgainstAfterAdmission(
            full_native,
            extension,
            manifest,
            authenticated_lookup,
            plan,
            calls,
            null,
            full_geometry,
        );
    }

    /// Identity-neutral validated sibling of the candidate-only supplement
    /// revalidation above.
    pub fn validateAgainstWithRetirementSupplementV2Validated(
        self: *const ProjectionV1,
        full_native: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
        policy: statement_validation.AdmissionPolicy,
        supplement: statement_validation.RetirementSupplementV2,
        manifest: *const lookup_physical_v2.Manifest,
        authenticated_lookup: *const lookup_physical_v2.AuthenticatedStatement,
        plan: *const provider_authority.ProviderShardPlanV1,
        calls: []const poseidon2_air.Call,
        validated: *const provider_authority.OwnedValidatedPlanCallAuthorityV1,
        full_geometry: statement_geometry.Geometry,
    ) !void {
        try extension.validateV2(full_native);
        try statement_validation.validateV2WithRetirementSupplementV2(
            full_native,
            policy,
            supplement,
        );
        return self.validateAgainstAfterAdmission(
            full_native,
            extension,
            manifest,
            authenticated_lookup,
            plan,
            calls,
            validated,
            full_geometry,
        );
    }

    fn validateAgainstAfterAdmission(
        self: *const ProjectionV1,
        full_native: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
        manifest: *const lookup_physical_v2.Manifest,
        authenticated_lookup: *const lookup_physical_v2.AuthenticatedStatement,
        plan: *const provider_authority.ProviderShardPlanV1,
        calls: []const poseidon2_air.Call,
        validated: ?*const provider_authority.OwnedValidatedPlanCallAuthorityV1,
        full_geometry: statement_geometry.Geometry,
    ) !void {
        try authenticated_lookup.validateAgainst(&full_native.core, manifest);
        if (validated) |token|
            try token.validateBorrowed(plan, calls)
        else
            try plan.validate(calls);
        if (!std.meta.eql(full_geometry, try deriveFullGeometry(full_native)))
            return error.ProviderGeometryMismatch;
        if (self.format != format_version or
            !std.meta.eql(self.full_statement_authority, full_native.authority_id) or
            !aggregation_hash.eql(
                self.extension_statement_identity,
                try extensionIdentity(full_native, extension),
            ) or
            !std.mem.eql(u8, &self.lookup_manifest_identity, &manifest.identity) or
            !std.mem.eql(
                u8,
                &self.lookup_statement_identity,
                &authenticated_lookup.statement_identity,
            ) or
            !std.mem.eql(
                u8,
                &self.lookup_activation_identity,
                &authenticated_lookup.activation_identity,
            ) or
            !aggregation_hash.eql(self.provider_plan_identity, plan.identity) or
            !aggregation_hash.eql(self.call_list_commitment, plan.call_list_commitment))
        {
            return error.InvalidProviderOmissionAuthority;
        }

        const omitted_index = try findExactProvider(full_native, plan, calls);
        if (self.omitted_infra_index != @as(u32, @intCast(omitted_index)) or
            !std.meta.eql(
                self.omitted_descriptor,
                full_native.core.infra_descs[omitted_index],
            ))
        {
            return error.InvalidProviderOmissionAuthority;
        }
        const expected_core = try projectCore(&full_native.core, omitted_index);
        try validateProjectedCore(&self.projected_native, &expected_core);
        try authenticated_lookup.validateAgainst(&self.projected_native.core, manifest);
        const expected_geometry = try projectGeometry(full_geometry, omitted_index);
        if (!std.meta.eql(self.projected_geometry, expected_geometry) or
            !aggregation_hash.eql(self.identity, projectionIdentity(self)))
        {
            return error.InvalidProviderOmissionAuthority;
        }
    }

    /// Cheap internal custody check after `validateAgainst` has admitted the
    /// external plan and call authority in the same transaction. This never
    /// substitutes for full ingress validation.
    pub fn validateSealAndFull(
        self: *const ProjectionV1,
        full_native: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
    ) !void {
        try extension.validateV2(full_native);
        try self.projected_native.validate();
        if (self.format != format_version or
            !std.meta.eql(self.full_statement_authority, full_native.authority_id) or
            !aggregation_hash.eql(
                self.extension_statement_identity,
                try extensionIdentity(full_native, extension),
            ) or !aggregation_hash.eql(self.identity, projectionIdentity(self)))
        {
            return error.InvalidProviderOmissionAuthority;
        }
    }

    /// Transactionally replaces the workspace's already-admitted full core
    /// with the exact projection. The caller retains `full_native` by value for
    /// public admission, transcript binding, and the eventual fresh verifier.
    pub fn installProjectedCore(
        self: *const ProjectionV1,
        current_core: *statement.RiscVStatement,
        full_native: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
    ) !void {
        try self.validateSealAndFull(full_native, extension);
        const current_native = try statement_v2.RiscVStatementV2.init(
            current_core.*,
            full_native.public_data,
        );
        if (!std.meta.eql(current_native.authority_id, full_native.authority_id))
            return error.FullStatementWorkspaceMismatch;
        current_core.* = self.projected_native.core;
    }

    pub fn tree0ColumnsRemoved(self: *const ProjectionV1) u32 {
        _ = self;
        return statement.nPreprocessedColumnsForInfra(.poseidon2);
    }

    pub fn tree1ColumnsRemoved(self: *const ProjectionV1) u32 {
        return self.omitted_descriptor.n_columns;
    }

    pub fn tree2ColumnsRemoved(self: *const ProjectionV1) u32 {
        _ = self;
        return statement.nInteractionColsForInfra(.poseidon2);
    }
};

/// Cold reconstruction of the full native geometry from the admitted public
/// statement. This is the verifier-side counterpart of the prover's
/// witness-derived `Geometry`: it accepts exactly one program, Merkle,
/// Poseidon, and clock descriptor in canonical relative order.
pub fn deriveFullGeometry(
    full_native: *const statement_v2.RiscVStatementV2,
) !statement_geometry.Geometry {
    try full_native.validate();
    const core = &full_native.core;
    const program_index = try uniqueInfraIndex(core, .program);
    const merkle_index = try uniqueInfraIndex(core, .merkle);
    const poseidon_index = try uniqueInfraIndex(core, .poseidon2);
    const clock_index = try uniqueInfraIndex(core, .clock_update);
    if (program_index >= merkle_index or merkle_index + 1 != poseidon_index or
        poseidon_index + 1 != clock_index)
    {
        return error.ProviderOrderMismatch;
    }
    const program = core.infra_descs[program_index];
    const merkle = core.infra_descs[merkle_index];
    const poseidon = core.infra_descs[poseidon_index];
    const clock = core.infra_descs[clock_index];
    if (poseidon.n_columns != poseidon2_air.N_MAIN_COLUMNS)
        return error.ProviderGeometryMismatch;
    return .{
        .program_log_size = program.log_size,
        .merkle_log_size = merkle.log_size,
        .poseidon_log_size = poseidon.log_size,
        .clock_update_log = clock.log_size,
        .merkle_infra_index = merkle_index,
        .poseidon_infra_index = poseidon_index,
        .clock_infra_index = clock_index,
    };
}

fn uniqueInfraIndex(
    core: *const statement.RiscVStatement,
    kind: statement.InfraKind,
) !usize {
    var result: ?usize = null;
    for (core.infra_descs[0..@intCast(core.n_infra)], 0..) |descriptor, index| {
        if (descriptor.kind != kind) continue;
        if (result != null) return error.DuplicateInfrastructureAuthority;
        result = index;
    }
    return result orelse error.MissingInfrastructureAuthority;
}

fn findExactProvider(
    full_native: *const statement_v2.RiscVStatementV2,
    plan: *const provider_authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
) !usize {
    const rows = std.math.cast(u32, calls.len) orelse
        return error.ProviderCallCountOutOfRange;
    if (plan.total_call_count != calls.len or rows == 0)
        return error.ProviderCallCountMismatch;
    const expected_log = @max(
        provider_authority.minimum_shard_log_size,
        std.math.log2_int_ceil(u32, rows),
    );
    var found: ?usize = null;
    for (full_native.core.infra_descs[0..@intCast(full_native.core.n_infra)], 0..) |
        descriptor,
        index,
    | {
        if (descriptor.kind != .poseidon2) continue;
        if (found != null) return error.MultipleNativePoseidonProviders;
        if (descriptor.n_rows != rows or descriptor.log_size != expected_log or
            descriptor.n_columns != poseidon2_air.N_MAIN_COLUMNS)
        {
            return error.ProviderGeometryMismatch;
        }
        if (index == 0 or index + 1 >= @as(usize, @intCast(full_native.core.n_infra)) or
            full_native.core.infra_descs[index - 1].kind != .merkle or
            full_native.core.infra_descs[index + 1].kind != .clock_update)
        {
            return error.ProviderOrderMismatch;
        }
        found = index;
    }
    return found orelse error.MissingNativePoseidonProvider;
}

fn projectCore(
    full: *const statement.RiscVStatement,
    omitted_index: usize,
) !statement.RiscVStatement {
    if (full.n_infra == 0 or omitted_index >= @as(usize, @intCast(full.n_infra)))
        return error.InvalidProviderOmissionAuthority;
    var projected = full.*;
    var index = omitted_index;
    while (index + 1 < @as(usize, @intCast(full.n_infra))) : (index += 1)
        projected.infra_descs[index] = full.infra_descs[index + 1];
    projected.n_infra -= 1;
    return projected;
}

fn projectGeometry(
    full: statement_geometry.Geometry,
    omitted_index: usize,
) !ProjectedGeometryV1 {
    if (full.poseidon_infra_index != omitted_index or
        full.merkle_infra_index >= omitted_index or
        full.clock_infra_index <= omitted_index)
    {
        return error.ProviderGeometryMismatch;
    }
    return .{
        .program_log_size = full.program_log_size,
        .merkle_log_size = full.merkle_log_size,
        .clock_update_log = full.clock_update_log,
        .merkle_infra_index = @intCast(full.merkle_infra_index),
        .clock_infra_index = @intCast(full.clock_infra_index - 1),
    };
}

fn validateProjectedCore(
    actual: *const statement_v2.RiscVStatementV2,
    expected_core: *const statement.RiscVStatement,
) !void {
    try actual.validate();
    const expected = try statement_v2.RiscVStatementV2.init(
        expected_core.*,
        actual.public_data,
    );
    if (!std.meta.eql(actual.authority_id, expected.authority_id) or
        actual.core.n_components != expected.core.n_components or
        actual.core.n_infra != expected.core.n_infra or
        actual.core.initial_pc != expected.core.initial_pc or
        actual.core.final_pc != expected.core.final_pc or
        actual.core.total_steps != expected.core.total_steps or
        !componentDescriptorsEql(&actual.core, &expected.core) or
        !infraDescriptorsEql(&actual.core, &expected.core) or
        !m31SlicesEql(actual.public_data.words(), expected.public_data.words()))
    {
        return error.InvalidProjectedStatement;
    }
}

fn m31SlicesEql(actual: []const M31, expected: []const M31) bool {
    if (actual.len != expected.len) return false;
    for (actual, expected) |lhs, rhs| {
        if (!lhs.eql(rhs)) return false;
    }
    return true;
}

fn componentDescriptorsEql(
    actual: *const statement.RiscVStatement,
    expected: *const statement.RiscVStatement,
) bool {
    if (actual.n_components != expected.n_components) return false;
    for (
        actual.component_descs[0..@intCast(actual.n_components)],
        expected.component_descs[0..@intCast(expected.n_components)],
    ) |actual_descriptor, expected_descriptor| {
        if (!std.meta.eql(actual_descriptor, expected_descriptor)) return false;
    }
    return true;
}

fn infraDescriptorsEql(
    actual: *const statement.RiscVStatement,
    expected: *const statement.RiscVStatement,
) bool {
    if (actual.n_infra != expected.n_infra) return false;
    for (
        actual.infra_descs[0..@intCast(actual.n_infra)],
        expected.infra_descs[0..@intCast(expected.n_infra)],
    ) |actual_descriptor, expected_descriptor| {
        if (!std.meta.eql(actual_descriptor, expected_descriptor)) return false;
    }
    return true;
}

fn extensionIdentity(
    full_native: *const statement_v2.RiscVStatementV2,
    extension: *const ethereum_statement.Statement,
) !Digest {
    var channel = Blake2sChannel{};
    try extension.mixIntoV2(full_native, &channel);
    return channel.digestBytes();
}

pub fn projectionIdentity(value: *const ProjectionV1) Digest {
    var sink = aggregation_hash.HashSink.init(projection_domain);
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    for (value.full_statement_authority) |word|
        aggregation_hash.writeU32(&sink, word) catch unreachable;
    sink.writeAll(&value.extension_statement_identity) catch unreachable;
    sink.writeAll(&value.lookup_manifest_identity) catch unreachable;
    sink.writeAll(&value.lookup_statement_identity) catch unreachable;
    sink.writeAll(&value.lookup_activation_identity) catch unreachable;
    sink.writeAll(&value.provider_plan_identity) catch unreachable;
    sink.writeAll(&value.call_list_commitment) catch unreachable;
    aggregation_hash.writeU32(&sink, value.omitted_infra_index) catch unreachable;
    aggregation_hash.writeU32(
        &sink,
        @intFromEnum(value.omitted_descriptor.kind),
    ) catch unreachable;
    aggregation_hash.writeU32(&sink, value.omitted_descriptor.log_size) catch unreachable;
    aggregation_hash.writeU32(&sink, value.omitted_descriptor.n_rows) catch unreachable;
    aggregation_hash.writeU32(&sink, value.omitted_descriptor.n_columns) catch unreachable;
    for (value.projected_native.authority_id) |word|
        aggregation_hash.writeU32(&sink, word) catch unreachable;
    aggregation_hash.writeU32(&sink, value.projected_geometry.program_log_size) catch unreachable;
    aggregation_hash.writeU32(&sink, value.projected_geometry.merkle_log_size) catch unreachable;
    aggregation_hash.writeU32(&sink, value.projected_geometry.clock_update_log) catch unreachable;
    aggregation_hash.writeU32(&sink, value.projected_geometry.merkle_infra_index) catch unreachable;
    aggregation_hash.writeU32(&sink, value.projected_geometry.clock_infra_index) catch unreachable;
    return sink.finalize();
}

const projection_domain =
    "stwo-zig/riscv/ethereum/native-poseidon-provider-omission/v1\x00";

comptime {
    if (ACTIVATES_PRODUCTION_PROOF)
        @compileError("native provider omission requires fresh joint closure activation");
    if (poseidon2_air.N_MAIN_COLUMNS != 445 or
        poseidon2_air.N_INTERACTION_COLUMNS != 8)
    {
        @compileError("native narrow-memory Poseidon provider geometry drifted");
    }
}
