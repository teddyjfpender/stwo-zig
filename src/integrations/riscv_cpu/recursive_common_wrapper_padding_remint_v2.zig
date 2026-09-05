//! Two-phase production padding target and cold-remint authority.
//!
//! Phase one accepts exactly one role-specific, process-local cold geometry
//! capability for each schema-4 wrapper role. It derives the pointwise target
//! over the 36 semantic rows and a single role-neutral padding/table-layout
//! identity. It does not mint a registry or padding parity.
//!
//! Phase two accepts a second, independently cold-validated geometry for each
//! role. Every remint must preserve its source active-row vector while proving
//! the common padded trace layout. Only that final set is allowed through this
//! module's registry and `PaddingParityV1` constructor. No freshness capability
//! has a codec, and no bootstrap/common-fold geometry is accepted by name.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const registry_mod = @import("recursive_circuit_registry_v1.zig");

const air = frontend.recursion.air;
const roster = air.universal_roster;
const universal = air.universal_challenges;
const universal_manifest = air.universal_manifest;
const Manifest = air.universal_adapter_manifest.Manifest;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const ROLE_COUNT: usize = registry_mod.ROLE_COUNT;
pub const COMPONENT_COUNT: usize = roster.COMPONENT_COUNT;
pub const MAX_COMPONENT_COUNT: usize = registry_mod.MAX_COMPONENT_COUNT;

pub const Role = registry_mod.CircuitRoleV1;
pub const Geometry = registry_mod.AuthenticatedGeometryV1;
pub const Registry = registry_mod.RecursiveCircuitRegistryV1;
pub const PaddingParity = registry_mod.PaddingParityV1;
pub const LogVectorV2 = [MAX_COMPONENT_COUNT]u8;

const TARGET_DOMAIN =
    "stwo-zig/recursive-production-padding-target/v2\x00";
const LAYOUT_DOMAIN =
    "stwo-zig/recursive-production-padding-table-layout/v2\x00";
const FINAL_DOMAIN =
    "stwo-zig/recursive-production-padding-remint-final/v2\x00";

pub const Error = registry_mod.Error || universal_manifest.Error || error{
    ColdGeometryClone,
    ColdGeometryRoleMismatch,
    ColdGeometrySourceContractMismatch,
    FinalGeometryDidNotRemint,
    FinalGeometryLayoutMismatch,
    FinalGeometryProofLayoutMismatch,
    FinalSemanticActiveLogMismatch,
    InvalidFinalRemintAuthority,
    InvalidPaddingTarget,
    PaddingTargetManifestMismatch,
    PaddingTargetRosterMismatch,
};

/// Pointer-free target receipt. It binds the exact three cold source
/// geometries, but it is not itself a verifier capability and has no codec.
pub const PaddingTargetV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    role_count: u8 = ROLE_COUNT,
    component_count: u16 = COMPONENT_COUNT,
    target_trace_log_size: u8,
    reserved: [3]u8 = .{ 0, 0, 0 },
    active_component_log_sizes: [ROLE_COUNT]LogVectorV2,
    target_padded_log_sizes: LogVectorV2,
    active_geometry_authority_identities: [ROLE_COUNT][32]u8,
    active_circuit_identities: [ROLE_COUNT][32]u8,
    active_program_identities: [ROLE_COUNT][32]u8,
    active_profile_identities: [ROLE_COUNT][32]u8,
    active_proof_shape_identities: [ROLE_COUNT][32]u8,
    active_preprocessed_roots: [ROLE_COUNT][8]u32,
    pcs: registry_mod.PcsConfigV1,
    output_abi: registry_mod.OutputAbiV1,
    roster_identity_sha256: [32]u8,
    target_manifest_seal: [32]u8,
    padding_table_layout_identity_sha256: [32]u8,
    identity_sha256: [32]u8,

    /// `active_sources` is an ordered heterogeneous tuple `(real, empty,
    /// common)`. Each pointee must expose the nonserializable cold-source
    /// contract documented by `assertColdSourceContract`.
    pub fn derive(active_sources: anytype) !PaddingTargetV2 {
        const active = try openColdGeometries(active_sources);
        return deriveTargetCore(active);
    }

    pub fn validateAgainst(
        self: *const PaddingTargetV2,
        active_sources: anytype,
    ) !void {
        try self.validateSelf();
        const active = try openColdGeometries(active_sources);
        const expected = try deriveTargetCore(active);
        if (!std.meta.eql(self.*, expected))
            return error.InvalidPaddingTarget;
    }

    /// Validates one independently cold-reminted role geometry against this
    /// target.  This is deliberately weaker than final registry admission:
    /// it proves the role retained its semantic active rows and used the
    /// common padded layout, but cannot mint registry/parity authority until
    /// the other two role geometries are also cold-owned.
    pub fn validateRemintedGeometry(
        self: *const PaddingTargetV2,
        role: Role,
        geometry: *const Geometry,
    ) !void {
        try self.validateSelf();
        try geometry.validate();
        const ordinal = @intFromEnum(role);
        if (ordinal >= ROLE_COUNT or geometry.role != role or
            geometry.component_count != COMPONENT_COUNT or
            geometry.trace_log_size != self.target_trace_log_size or
            !std.mem.eql(
                u8,
                &geometry.active_component_log_sizes,
                &self.active_component_log_sizes[ordinal],
            )) return error.FinalSemanticActiveLogMismatch;
        if (!std.mem.eql(
            u8,
            geometry.padded_component_log_sizes[0..COMPONENT_COUNT],
            self.target_padded_log_sizes[0..COMPONENT_COUNT],
        ) or !std.mem.eql(
            u8,
            &geometry.padding_layout_identity_sha256,
            &self.padding_table_layout_identity_sha256,
        )) return error.FinalGeometryLayoutMismatch;
        if (!std.mem.eql(
            u8,
            &geometry.proof_shape.table_layout_identity_sha256,
            &self.padding_table_layout_identity_sha256,
        ) or !std.meta.eql(geometry.pcs, self.pcs) or
            !std.meta.eql(geometry.output_abi, self.output_abi))
        {
            return error.FinalGeometryProofLayoutMismatch;
        }
        const manifest = try targetManifest(self.target_padded_log_sizes);
        try validateGeometryTraceLayout(geometry, &manifest);
    }

    pub fn validateSelf(self: *const PaddingTargetV2) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or self.role_count != ROLE_COUNT or
            self.component_count != COMPONENT_COUNT or
            self.target_trace_log_size == 0 or
            self.target_trace_log_size >= 31 or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            !std.mem.allEqual(
                u8,
                self.target_padded_log_sizes[COMPONENT_COUNT..],
                0,
            )) return error.InvalidPaddingTarget;
        try self.pcs.validate();
        if (!std.meta.eql(
            self.pcs,
            registry_mod.PcsConfigV1.secureTemporalParent(),
        )) return error.InvalidPaddingTarget;
        try self.output_abi.validate();
        if (!std.meta.eql(
            self.output_abi,
            registry_mod.OutputAbiV1.fieldNodePublicV2(),
        )) return error.InvalidPaddingTarget;

        const roster_identity = universal.registryOrderDigest();
        if (!std.mem.eql(
            u8,
            &self.roster_identity_sha256,
            &roster_identity,
        )) return error.PaddingTargetRosterMismatch;
        var observed_trace_log: u8 = 0;
        for (0..COMPONENT_COUNT) |component| {
            const target = self.target_padded_log_sizes[component];
            if (target == 0 or target >= 31)
                return error.InvalidPaddingTarget;
            observed_trace_log = @max(observed_trace_log, target);
            for (self.active_component_log_sizes) |active| {
                if (active[component] == 0 or active[component] > target)
                    return error.InvalidPaddingTarget;
            }
        }
        if (observed_trace_log != self.target_trace_log_size)
            return error.InvalidPaddingTarget;
        for (self.active_component_log_sizes) |active| if (!std.mem.allEqual(
            u8,
            active[COMPONENT_COUNT..],
            0,
        )) return error.InvalidPaddingTarget;
        try validateDistinctSourceIdentities(
            self.active_geometry_authority_identities,
            self.active_circuit_identities,
            self.active_preprocessed_roots,
        );
        inline for (.{
            self.active_geometry_authority_identities,
            self.active_circuit_identities,
            self.active_program_identities,
            self.active_profile_identities,
            self.active_proof_shape_identities,
        }) |identities| for (identities) |identity_value| if (std.mem.allEqual(
            u8,
            &identity_value,
            0,
        )) return error.InvalidPaddingTarget;

        const manifest = try targetManifest(self.target_padded_log_sizes);
        if (!std.mem.eql(
            u8,
            &self.target_manifest_seal,
            &manifest.seal,
        )) return error.PaddingTargetManifestMismatch;
        const expected_layout = layoutIdentity(self, &manifest);
        if (std.mem.allEqual(
            u8,
            &self.padding_table_layout_identity_sha256,
            0,
        ) or !std.mem.eql(
            u8,
            &self.padding_table_layout_identity_sha256,
            &expected_layout,
        ) or !std.mem.eql(
            u8,
            &self.identity_sha256,
            &targetIdentity(self),
        )) return error.InvalidPaddingTarget;
    }
};

/// Process-local final set. Registry/parity are minted only after all six cold
/// sources have been revalidated and each final proof shape closes the target
/// manifest. This type deliberately has no encoder.
pub const FinalRemintAuthorityV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    role_count: u8 = ROLE_COUNT,
    target: PaddingTargetV2,
    final_geometries: [ROLE_COUNT]Geometry,
    registry: Registry,
    parity: PaddingParity,
    identity_sha256: [32]u8,

    pub fn mint(
        target: *const PaddingTargetV2,
        active_sources: anytype,
        final_sources: anytype,
    ) !FinalRemintAuthorityV2 {
        const active = try openColdGeometries(active_sources);
        const final = try openColdGeometries(final_sources);
        return mintCore(target, active, final);
    }

    pub fn validateAgainst(
        self: *const FinalRemintAuthorityV2,
        active_sources: anytype,
        final_sources: anytype,
    ) !void {
        const active = try openColdGeometries(active_sources);
        const final = try openColdGeometries(final_sources);
        const expected = try mintCore(&self.target, active, final);
        if (!std.meta.eql(self.*, expected))
            return error.InvalidFinalRemintAuthority;
    }

    pub fn validateSelf(self: *const FinalRemintAuthorityV2) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or self.role_count != ROLE_COUNT)
        {
            return error.InvalidFinalRemintAuthority;
        }
        try self.target.validateSelf();
        try self.registry.validate();
        try self.parity.validate(&self.registry, &self.final_geometries);
        for (&self.final_geometries, 0..) |*geometry, ordinal| {
            try geometry.validate();
            if (@intFromEnum(geometry.role) != ordinal)
                return error.InvalidFinalRemintAuthority;
            const entry = try self.registry.entry(geometry.role);
            const expected_entry = try registry_mod.RegistryEntryV1
                .fromGeometry(geometry);
            if (!std.meta.eql(entry.*, expected_entry))
                return error.InvalidFinalRemintAuthority;
        }
        if (!std.mem.eql(
            u8,
            &self.identity_sha256,
            &finalIdentity(self),
        )) return error.InvalidFinalRemintAuthority;
    }
};

fn deriveTargetCore(
    active: [ROLE_COUNT]Geometry,
) !PaddingTargetV2 {
    try validateColdGeometrySet(active);
    const first = &active[0];
    var target = [_]u8{0} ** MAX_COMPONENT_COUNT;
    for (0..COMPONENT_COUNT) |component| {
        for (active) |geometry| target[component] = @max(
            target[component],
            geometry.active_component_log_sizes[component],
        );
    }
    var trace_log_size: u8 = 0;
    for (target[0..COMPONENT_COUNT]) |log_size|
        trace_log_size = @max(trace_log_size, log_size);
    const manifest = try targetManifest(target);

    var result = PaddingTargetV2{
        .target_trace_log_size = trace_log_size,
        .active_component_log_sizes = .{
            active[0].active_component_log_sizes,
            active[1].active_component_log_sizes,
            active[2].active_component_log_sizes,
        },
        .target_padded_log_sizes = target,
        .active_geometry_authority_identities = .{
            active[0].authority_identity_sha256,
            active[1].authority_identity_sha256,
            active[2].authority_identity_sha256,
        },
        .active_circuit_identities = .{
            active[0].circuit_identity_sha256,
            active[1].circuit_identity_sha256,
            active[2].circuit_identity_sha256,
        },
        .active_program_identities = .{
            active[0].program_identity_sha256,
            active[1].program_identity_sha256,
            active[2].program_identity_sha256,
        },
        .active_profile_identities = .{
            active[0].profile_identity_sha256,
            active[1].profile_identity_sha256,
            active[2].profile_identity_sha256,
        },
        .active_proof_shape_identities = .{
            active[0].proof_shape.identity_sha256,
            active[1].proof_shape.identity_sha256,
            active[2].proof_shape.identity_sha256,
        },
        .active_preprocessed_roots = .{
            active[0].preprocessed_root,
            active[1].preprocessed_root,
            active[2].preprocessed_root,
        },
        .pcs = first.pcs,
        .output_abi = first.output_abi,
        .roster_identity_sha256 = universal.registryOrderDigest(),
        .target_manifest_seal = manifest.seal,
        .padding_table_layout_identity_sha256 = undefined,
        .identity_sha256 = undefined,
    };
    result.padding_table_layout_identity_sha256 = layoutIdentity(
        &result,
        &manifest,
    );
    result.identity_sha256 = targetIdentity(&result);
    try result.validateSelf();
    return result;
}

fn mintCore(
    target: *const PaddingTargetV2,
    active: [ROLE_COUNT]Geometry,
    final: [ROLE_COUNT]Geometry,
) !FinalRemintAuthorityV2 {
    const expected_target = try deriveTargetCore(active);
    if (!std.meta.eql(target.*, expected_target))
        return error.InvalidPaddingTarget;
    const manifest = try targetManifest(target.target_padded_log_sizes);
    for (&final, 0..) |*geometry, ordinal| {
        try validateFinalGeometry(
            target,
            &active[ordinal],
            geometry,
            &manifest,
        );
    }
    var entries: [ROLE_COUNT]registry_mod.RegistryEntryV1 = undefined;
    for (&final, &entries) |*geometry, *entry|
        entry.* = try registry_mod.RegistryEntryV1.fromGeometry(geometry);
    const registry = try Registry.seal(entries);
    const parity = try PaddingParity.derive(&registry, final);
    var result = FinalRemintAuthorityV2{
        .target = target.*,
        .final_geometries = final,
        .registry = registry,
        .parity = parity,
        .identity_sha256 = undefined,
    };
    result.identity_sha256 = finalIdentity(&result);
    try result.validateSelf();
    return result;
}

fn validateColdGeometrySet(
    geometries: [ROLE_COUNT]Geometry,
) !void {
    const first = &geometries[0];
    for (&geometries, 0..) |*geometry, ordinal| {
        try geometry.validate();
        if (@intFromEnum(geometry.role) != ordinal or
            geometry.component_count != COMPONENT_COUNT or
            geometry.proof_shape.claimed_sum_count != COMPONENT_COUNT or
            !std.meta.eql(geometry.pcs, first.pcs) or
            !std.meta.eql(geometry.output_abi, first.output_abi))
        {
            return error.ColdGeometryRoleMismatch;
        }
    }
    try validateDistinctSourceIdentities(.{
        geometries[0].authority_identity_sha256,
        geometries[1].authority_identity_sha256,
        geometries[2].authority_identity_sha256,
    }, .{
        geometries[0].circuit_identity_sha256,
        geometries[1].circuit_identity_sha256,
        geometries[2].circuit_identity_sha256,
    }, .{
        geometries[0].preprocessed_root,
        geometries[1].preprocessed_root,
        geometries[2].preprocessed_root,
    });
    const target = try targetManifestLogsFromActive(geometries);
    const manifest = try targetManifest(target);
    const expected_counts = [_]u32{
        manifest.total_preprocessed_columns,
        manifest.total_main_columns,
        manifest.total_interaction_columns,
    };
    for (geometries) |geometry| {
        for (expected_counts, 0..) |expected, tree| {
            if (geometry.proof_shape.tree_column_counts[tree] !=
                (std.math.cast(u16, expected) orelse
                    return error.PaddingTargetManifestMismatch))
            {
                return error.PaddingTargetManifestMismatch;
            }
        }
    }
}

fn validateFinalGeometry(
    target: *const PaddingTargetV2,
    active: *const Geometry,
    final: *const Geometry,
    manifest: *const Manifest,
) !void {
    try target.validateRemintedGeometry(active.role, final);
    if (std.mem.eql(
        u8,
        &final.authority_identity_sha256,
        &active.authority_identity_sha256,
    )) return error.FinalGeometryDidNotRemint;
    // Keep the explicit shared-manifest check at the final three-role mint
    // boundary as defense in depth against a future target implementation
    // accidentally using a different manifest constructor.
    try validateGeometryTraceLayout(final, manifest);
}

fn validateGeometryTraceLayout(
    geometry: *const Geometry,
    manifest: *const Manifest,
) !void {
    try manifest.validate();
    const blowup = geometry.pcs.fri_log_blowup_factor;
    const expected_counts = [_]u32{
        manifest.total_preprocessed_columns,
        manifest.total_main_columns,
        manifest.total_interaction_columns,
    };
    for (expected_counts, 0..) |expected_count, tree| {
        if (geometry.proof_shape.tree_column_counts[tree] !=
            (std.math.cast(u16, expected_count) orelse
                return error.FinalGeometryProofLayoutMismatch))
        {
            return error.FinalGeometryProofLayoutMismatch;
        }
    }
    for (std.enums.values(roster.Component)) |component| {
        const placement = try manifest.placement(component);
        const base_log = std.math.cast(u8, placement.geometry.log_size) orelse
            return error.FinalGeometryProofLayoutMismatch;
        const extended_log = std.math.cast(
            u8,
            std.math.add(u32, base_log, blowup) catch
                return error.FinalGeometryProofLayoutMismatch,
        ) orelse return error.FinalGeometryProofLayoutMismatch;
        const counts = [_]u16{
            placement.geometry.preprocessed_columns,
            placement.geometry.main_columns,
            placement.geometry.interaction_columns,
        };
        const offsets = [_]u32{
            placement.preprocessed_offset,
            placement.main_offset,
            placement.interaction_offset,
        };
        for (counts, offsets, 0..) |count, offset, tree| {
            const start: usize = @intCast(offset);
            const end = std.math.add(usize, start, @as(usize, count)) catch
                return error.FinalGeometryProofLayoutMismatch;
            if (!std.mem.allEqual(
                u8,
                geometry.proof_shape.tree_column_log_sizes[tree][start..end],
                extended_log,
            )) return error.FinalGeometryProofLayoutMismatch;
            if (tree == 0 and !std.mem.allEqual(
                u8,
                geometry.preprocessed_column_log_sizes[start..end],
                base_log,
            )) return error.FinalGeometryProofLayoutMismatch;
        }
    }
}

fn targetManifestLogsFromActive(
    active: [ROLE_COUNT]Geometry,
) !LogVectorV2 {
    var result = [_]u8{0} ** MAX_COMPONENT_COUNT;
    for (0..COMPONENT_COUNT) |component| {
        for (active) |geometry| {
            result[component] = @max(
                result[component],
                geometry.active_component_log_sizes[component],
            );
        }
    }
    return result;
}

fn targetManifest(logs: LogVectorV2) !Manifest {
    var exact: universal_manifest.LogSizes = undefined;
    for (&exact, logs[0..COMPONENT_COUNT]) |*destination, source|
        destination.* = source;
    const result = try universal_manifest.build(exact);
    try result.validate();
    if (result.roster_count != COMPONENT_COUNT)
        return error.PaddingTargetManifestMismatch;
    return result;
}

fn openColdGeometries(sources: anytype) ![ROLE_COUNT]Geometry {
    assertSourceTuple(@TypeOf(sources));
    var result: [ROLE_COUNT]Geometry = undefined;
    var owner_addresses: [ROLE_COUNT]usize = undefined;
    inline for (sources, 0..) |source, ordinal| {
        const SourcePointer = @TypeOf(source);
        const Source = @typeInfo(SourcePointer).pointer.child;
        const expected_role: Role = @enumFromInt(ordinal);
        assertColdSourceContract(Source, expected_role);
        try source.validateColdGeometry();
        const geometry = source.geometryForPaddingTarget();
        try geometry.validate();
        if (geometry.role != expected_role)
            return error.ColdGeometryRoleMismatch;
        result[ordinal] = geometry.*;
        owner_addresses[ordinal] = @intFromPtr(source);
    }
    for (owner_addresses, 0..) |left, left_index| for (
        owner_addresses[left_index + 1 ..],
    ) |right| if (left == right) return error.ColdGeometryClone;
    return result;
}

fn assertSourceTuple(comptime Sources: type) void {
    const info = @typeInfo(Sources);
    switch (info) {
        .@"struct" => |structure| {
            if (!structure.is_tuple or structure.fields.len != ROLE_COUNT)
                @compileError(
                    "cold padding sources must be an ordered (real, empty, common) tuple",
                );
            inline for (structure.fields) |field| switch (@typeInfo(field.type)) {
                .pointer => {},
                else => @compileError("cold padding sources must be pointers"),
            };
        },
        else => @compileError(
            "cold padding sources must be an ordered (real, empty, common) tuple",
        ),
    }
}

fn assertColdSourceContract(comptime Source: type, comptime role: Role) void {
    if (!@hasDecl(Source, "ROLE"))
        @compileError("cold padding source must expose exact ROLE");
    if (Source.ROLE != role)
        @compileError("cold padding source ROLE does not match tuple ordinal");
    if (!@hasDecl(Source, "validateColdGeometry") or
        !@hasDecl(Source, "geometryForPaddingTarget"))
    {
        @compileError(
            "cold padding source must expose exact ROLE, validateColdGeometry, and geometryForPaddingTarget",
        );
    }
}

fn validateDistinctSourceIdentities(
    authority_identities: [ROLE_COUNT][32]u8,
    circuit_identities: [ROLE_COUNT][32]u8,
    roots: [ROLE_COUNT][8]u32,
) Error!void {
    for (0..ROLE_COUNT) |left| for (left + 1..ROLE_COUNT) |right| {
        if (std.mem.eql(
            u8,
            &authority_identities[left],
            &authority_identities[right],
        ) or std.mem.eql(
            u8,
            &circuit_identities[left],
            &circuit_identities[right],
        ) or std.meta.eql(roots[left], roots[right])) {
            return error.ColdGeometryClone;
        }
    };
}

fn layoutIdentity(
    target: *const PaddingTargetV2,
    manifest: *const Manifest,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(LAYOUT_DOMAIN);
    hashInt(&hash, u16, target.format_version);
    hashInt(&hash, u16, target.schema_version);
    hashInt(&hash, u16, target.component_count);
    hash.update(&target.roster_identity_sha256);
    hash.update(&target.target_padded_log_sizes);
    hash.update(&target.pcs.identity_sha256);
    hash.update(&target.output_abi.identity_sha256);
    hash.update(&manifest.seal);
    hashInt(&hash, u32, manifest.total_preprocessed_columns);
    hashInt(&hash, u32, manifest.total_main_columns);
    hashInt(&hash, u32, manifest.total_interaction_columns);
    hashInt(&hash, u32, manifest.total_constraints);
    return hash.finalResult();
}

fn targetIdentity(target: *const PaddingTargetV2) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(TARGET_DOMAIN);
    hashInt(&hash, u16, target.format_version);
    hashInt(&hash, u16, target.schema_version);
    hashInt(&hash, u8, @intFromBool(target.production_activation));
    hashInt(&hash, u8, target.role_count);
    hashInt(&hash, u16, target.component_count);
    hashInt(&hash, u8, target.target_trace_log_size);
    hash.update(&target.reserved);
    for (target.active_component_log_sizes) |logs| hash.update(&logs);
    hash.update(&target.target_padded_log_sizes);
    inline for (.{
        target.active_geometry_authority_identities,
        target.active_circuit_identities,
        target.active_program_identities,
        target.active_profile_identities,
        target.active_proof_shape_identities,
    }) |identities| for (identities) |identity_value|
        hash.update(&identity_value);
    for (target.active_preprocessed_roots) |root|
        for (root) |word| hashInt(&hash, u32, word);
    hash.update(&target.pcs.identity_sha256);
    hash.update(&target.output_abi.identity_sha256);
    hash.update(&target.roster_identity_sha256);
    hash.update(&target.target_manifest_seal);
    hash.update(&target.padding_table_layout_identity_sha256);
    return hash.finalResult();
}

fn finalIdentity(value: *const FinalRemintAuthorityV2) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(FINAL_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromBool(value.production_activation));
    hashInt(&hash, u8, value.role_count);
    hash.update(&value.target.identity_sha256);
    for (value.final_geometries) |geometry|
        hash.update(&geometry.authority_identity_sha256);
    hash.update(&value.registry.identity_sha256);
    hash.update(&value.parity.identity_sha256);
    return hash.finalResult();
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or ROLE_COUNT != 3 or
        COMPONENT_COUNT != 36 or PRODUCTION_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or
        @hasDecl(PaddingTargetV2, "encode") or
        @hasDecl(FinalRemintAuthorityV2, "encode"))
    {
        @compileError("production padding remint contract drifted");
    }
}
