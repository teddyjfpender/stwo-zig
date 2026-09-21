//! Structural authority for the reuse-only Ethereum h1 component cohort.
//!
//! Four reviewed wrapper AIR kinds occupy eleven wrapper placements: three
//! concatenated routers and eight parameter-distinct hash instances.  The
//! twelfth placement is the existing shared native Poseidon2 provider.  This
//! module binds ranges, instance parameters, and provider-call custody before
//! any interaction challenge or expensive secure-parent proof is attempted.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const ingress_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_ingress_v1.zig");
const manifest_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_manifest_v1.zig");
const materializer_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_materializer_v1.zig");

const recursion = frontend.recursion;
const source_air = recursion.air.ethereum_leaf_link_source_v1;
const link_program = recursion.ethereum_leaf_link_program_v1;
const child_program = recursion.ethereum_leaf_child_field_program_v1;
const statement_v2 = frontend.air.statement_v2;
const m31 = @import("stwo_core").fields.m31;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const WRAPPER_AIR_KIND_COUNT: u8 = 4;
pub const PHYSICAL_PLACEMENT_COUNT: u8 = 12;
pub const HASH_INSTANCE_COUNT: usize = 8;
pub const SHARED_PROVIDER_COUNT: u8 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const DOMAIN =
    "stwo-zig/typed-air/ethereum-poseidon-h1-cohort/v1\x00";

pub const ChildSlotV1 = enum(u8) { left = 0, right = 1 };
pub const HashRoleV1 = enum(u8) {
    metadata = 0,
    verified_link = 1,
    child_authority = 2,
    child_receipt = 3,
};

pub const ConcatenatedRangeV1 = struct {
    left_start: u32,
    left_count: u32,
    right_start: u32,
    right_count: u32,
    total_count: u32,

    pub fn validate(self: ConcatenatedRangeV1) !void {
        if (self.left_start != 0 or self.left_count == 0 or
            self.right_start != self.left_count or self.right_count == 0 or
            self.total_count != try add(self.left_count, self.right_count))
        {
            return error.InvalidEthereumPoseidonH1Cohort;
        }
    }
};

pub const HashInstanceV1 = struct {
    placement: manifest_mod.ComponentKey,
    child: ChildSlotV1,
    role: HashRoleV1,
    active_rows: u32,
    provider_call_start: u32,
    provider_call_count: u32,
    parameters: [5]u32,

    pub fn validate(self: HashInstanceV1) !void {
        if (self.active_rows == 0 or
            self.provider_call_count != self.active_rows or
            self.parameters[0] != 1 or
            self.parameters[3] != source_air.VERIFIER_ID)
        {
            return error.InvalidEthereumPoseidonH1Cohort;
        }
        for (self.parameters) |word| if (word >= m31.Modulus)
            return error.InvalidEthereumPoseidonH1Cohort;
        const expected = hashParameters(self.role);
        if (!std.meta.eql(self.parameters, expected))
            return error.InvalidEthereumPoseidonH1Cohort;
    }
};

pub const CohortV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    wrapper_air_kind_count: u8 = WRAPPER_AIR_KIND_COUNT,
    physical_placement_count: u8 = PHYSICAL_PLACEMENT_COUNT,
    shared_provider_count: u8 = SHARED_PROVIDER_COUNT,
    reserved: [2]u8 = .{ 0, 0 },
    plan_identity_sha256: [32]u8,
    manifest_seal: [32]u8,
    ingress_authority_sha256: [32]u8,
    air_contract_sha256: [32]u8,
    link_source: ConcatenatedRangeV1,
    link_projection: ConcatenatedRangeV1,
    child_field_router: ConcatenatedRangeV1,
    hashes: [HASH_INSTANCE_COUNT]HashInstanceV1,
    provider_active_rows: u32,
    provider_semantic_digest: [32]u8,
    identity_sha256: [32]u8,

    pub fn init(
        plan: *const materializer_mod.PlanV1,
        custody: *const ingress_mod.CustodyV1,
    ) !CohortV1 {
        try plan.validateAgainst(custody);
        const source_count: u32 = @intCast(link_program.SOURCE_ROW_COUNT);
        const projection_count: u32 = @intCast(
            link_program.PROJECTION_ROW_COUNT,
        );
        const source_range = try range(source_count, source_count);
        const projection_range = try range(
            projection_count,
            projection_count,
        );
        const router_range = try range(
            custody.children[0].child_router_row_count,
            custody.children[1].child_router_row_count,
        );
        var hashes: [HASH_INSTANCE_COUNT]HashInstanceV1 = undefined;
        const roles = [_]HashRoleV1{
            .metadata,
            .verified_link,
            .child_authority,
            .child_receipt,
            .metadata,
            .verified_link,
            .child_authority,
            .child_receipt,
        };
        var provider_at: u32 = 0;
        for (&hashes, roles, 0..) |*instance, role, ordinal| {
            const row = manifest_mod.keyIndex(.left_metadata_hash) + ordinal;
            const active = plan.active_rows[row];
            instance.* = .{
                .placement = @enumFromInt(row),
                .child = if (ordinal < 4) .left else .right,
                .role = role,
                .active_rows = active,
                .provider_call_start = provider_at,
                .provider_call_count = active,
                .parameters = hashParameters(role),
            };
            provider_at = try add(provider_at, active);
        }
        const provider_placement = try plan.manifest.placement(.poseidon2);
        var result = CohortV1{
            .plan_identity_sha256 = plan.identity_sha256,
            .manifest_seal = plan.manifest.seal,
            .ingress_authority_sha256 = custody.identity_sha256,
            .air_contract_sha256 = custody.air_contract.identity_sha256,
            .link_source = source_range,
            .link_projection = projection_range,
            .child_field_router = router_range,
            .hashes = hashes,
            .provider_active_rows = provider_at,
            .provider_semantic_digest = provider_placement.geometry.semantic_digest,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = cohortIdentity(&result);
        try result.validateAgainst(plan, custody);
        return result;
    }

    pub fn validate(self: *const CohortV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or
            self.wrapper_air_kind_count != WRAPPER_AIR_KIND_COUNT or
            self.physical_placement_count != PHYSICAL_PLACEMENT_COUNT or
            self.shared_provider_count != SHARED_PROVIDER_COUNT or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            std.mem.allEqual(u8, &self.plan_identity_sha256, 0) or
            std.mem.allEqual(u8, &self.manifest_seal, 0) or
            std.mem.allEqual(u8, &self.ingress_authority_sha256, 0) or
            std.mem.allEqual(u8, &self.air_contract_sha256, 0))
        {
            return error.InvalidEthereumPoseidonH1Cohort;
        }
        try self.link_source.validate();
        try self.link_projection.validate();
        try self.child_field_router.validate();
        var provider_at: u32 = 0;
        for (self.hashes, 0..) |instance, ordinal| {
            try instance.validate();
            if (manifest_mod.keyIndex(instance.placement) !=
                manifest_mod.keyIndex(.left_metadata_hash) + ordinal or
                instance.child != (if (ordinal < 4)
                    ChildSlotV1.left
                else
                    ChildSlotV1.right) or
                @intFromEnum(instance.role) != ordinal % 4 or
                instance.provider_call_start != provider_at)
            {
                return error.InvalidEthereumPoseidonH1Cohort;
            }
            provider_at = try add(provider_at, instance.provider_call_count);
        }
        if (provider_at != self.provider_active_rows or
            std.mem.allEqual(u8, &self.provider_semantic_digest, 0) or
            !std.mem.eql(u8, &self.identity_sha256, &cohortIdentity(self)))
        {
            return error.InvalidEthereumPoseidonH1Cohort;
        }
    }

    pub fn validateAgainst(
        self: *const CohortV1,
        plan: *const materializer_mod.PlanV1,
        custody: *const ingress_mod.CustodyV1,
    ) !void {
        try self.validate();
        try plan.validateAgainst(custody);
        const expected = try buildUnchecked(plan, custody);
        if (!std.meta.eql(self.*, expected))
            return error.EthereumPoseidonH1CohortMismatch;
    }

    pub fn validateMaterialized(
        self: *const CohortV1,
        materialized: *const materializer_mod.MaterializedV1,
        custody: *const ingress_mod.CustodyV1,
    ) !void {
        try self.validateAgainst(&materialized.plan, custody);
        if (materialized.source_rows.len != self.link_source.total_count or
            materialized.projection_rows.len !=
                self.link_projection.total_count or
            materialized.child_router_rows.len !=
                self.child_field_router.total_count or
            materialized.poseidon_calls.len != self.provider_active_rows or
            std.mem.allEqual(u8, &materialized.identity_sha256, 0))
        {
            return error.EthereumPoseidonH1CohortMismatch;
        }
    }

    pub fn requireProduction(self: *const CohortV1) !void {
        try self.validate();
        if (!PRODUCTION_ACTIVATION)
            return error.EthereumPoseidonH1CohortUnavailable;
    }
};

fn buildUnchecked(
    plan: *const materializer_mod.PlanV1,
    custody: *const ingress_mod.CustodyV1,
) !CohortV1 {
    const source_count: u32 = @intCast(link_program.SOURCE_ROW_COUNT);
    const projection_count: u32 = @intCast(link_program.PROJECTION_ROW_COUNT);
    var hashes: [HASH_INSTANCE_COUNT]HashInstanceV1 = undefined;
    const roles = [_]HashRoleV1{
        .metadata,
        .verified_link,
        .child_authority,
        .child_receipt,
        .metadata,
        .verified_link,
        .child_authority,
        .child_receipt,
    };
    var provider_at: u32 = 0;
    for (&hashes, roles, 0..) |*instance, role, ordinal| {
        const row = manifest_mod.keyIndex(.left_metadata_hash) + ordinal;
        const active = plan.active_rows[row];
        instance.* = .{
            .placement = @enumFromInt(row),
            .child = if (ordinal < 4) .left else .right,
            .role = role,
            .active_rows = active,
            .provider_call_start = provider_at,
            .provider_call_count = active,
            .parameters = hashParameters(role),
        };
        provider_at = try add(provider_at, active);
    }
    const provider_placement = try plan.manifest.placement(.poseidon2);
    var result = CohortV1{
        .plan_identity_sha256 = plan.identity_sha256,
        .manifest_seal = plan.manifest.seal,
        .ingress_authority_sha256 = custody.identity_sha256,
        .air_contract_sha256 = custody.air_contract.identity_sha256,
        .link_source = try range(source_count, source_count),
        .link_projection = try range(projection_count, projection_count),
        .child_field_router = try range(
            custody.children[0].child_router_row_count,
            custody.children[1].child_router_row_count,
        ),
        .hashes = hashes,
        .provider_active_rows = provider_at,
        .provider_semantic_digest = provider_placement.geometry.semantic_digest,
        .identity_sha256 = undefined,
    };
    result.identity_sha256 = cohortIdentity(&result);
    return result;
}

fn range(left: u32, right: u32) !ConcatenatedRangeV1 {
    const result = ConcatenatedRangeV1{
        .left_start = 0,
        .left_count = left,
        .right_start = left,
        .right_count = right,
        .total_count = try add(left, right),
    };
    try result.validate();
    return result;
}

fn hashParameters(role: HashRoleV1) [5]u32 {
    const domain: u32 = switch (role) {
        .metadata => recursion.segment_leaf_local_authority_v3.METADATA_ID_DOMAIN,
        .verified_link => recursion.segment_leaf_local_verified_link_v3.IDENTITY_DOMAIN,
        .child_authority => statement_v2.AUTHORITY_ID_DOMAIN,
        .child_receipt => statement_v2.RECEIPT_ID_DOMAIN,
    };
    const scope: u32 = switch (role) {
        .metadata => source_air.METADATA_SCOPE,
        .verified_link => source_air.LINK_SCOPE,
        .child_authority => child_program.AUTHORITY_PREIMAGE_SCOPE,
        .child_receipt => child_program.RECEIPT_PREIMAGE_SCOPE,
    };
    const digest_kind: u32 = switch (role) {
        .metadata => source_air.METADATA_DIGEST_KIND,
        .verified_link => source_air.LINK_DIGEST_KIND,
        .child_authority => source_air.LOCAL_AUTHORITY_DIGEST_KIND,
        .child_receipt => source_air.LOCAL_RECEIPT_DIGEST_KIND,
    };
    return .{ 1, domain, scope, source_air.VERIFIER_ID, digest_kind };
}

fn cohortIdentity(value: *const CohortV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromBool(value.production_activation));
    hashInt(&hash, u8, value.wrapper_air_kind_count);
    hashInt(&hash, u8, value.physical_placement_count);
    hashInt(&hash, u8, value.shared_provider_count);
    hash.update(&value.reserved);
    hash.update(&value.plan_identity_sha256);
    hash.update(&value.manifest_seal);
    hash.update(&value.ingress_authority_sha256);
    hash.update(&value.air_contract_sha256);
    inline for (.{
        value.link_source,
        value.link_projection,
        value.child_field_router,
    }) |item| hashRange(&hash, item);
    for (value.hashes) |instance| {
        hashInt(&hash, u8, manifest_mod.keyIndex(instance.placement));
        hashInt(&hash, u8, @intFromEnum(instance.child));
        hashInt(&hash, u8, @intFromEnum(instance.role));
        hashInt(&hash, u32, instance.active_rows);
        hashInt(&hash, u32, instance.provider_call_start);
        hashInt(&hash, u32, instance.provider_call_count);
        for (instance.parameters) |word| hashInt(&hash, u32, word);
    }
    hashInt(&hash, u32, value.provider_active_rows);
    hash.update(&value.provider_semantic_digest);
    return hash.finalResult();
}

fn hashRange(hash: *Sha256, value: ConcatenatedRangeV1) void {
    hashInt(hash, u32, value.left_start);
    hashInt(hash, u32, value.left_count);
    hashInt(hash, u32, value.right_start);
    hashInt(hash, u32, value.right_count);
    hashInt(hash, u32, value.total_count);
}

fn add(left: anytype, right: anytype) !u32 {
    return std.math.add(u32, @intCast(left), @intCast(right)) catch
        error.ArithmeticOverflow;
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

pub const testing = struct {
    pub fn reseal(value: *CohortV1) void {
        value.identity_sha256 = cohortIdentity(value);
    }
};

comptime {
    if (WRAPPER_AIR_KIND_COUNT != ingress_mod.AIR_COMPONENT_COUNT or
        PHYSICAL_PLACEMENT_COUNT != manifest_mod.COMPONENT_COUNT or
        HASH_INSTANCE_COUNT != manifest_mod.HASH_PLACEMENT_COUNT or
        SHARED_PROVIDER_COUNT != 1 or PRODUCTION_ACTIVATION)
    {
        @compileError("Ethereum Poseidon h1 cohort contract drifted");
    }
}
