//! Tree-2 generation for the base trace plus combined Ethereum components.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const stage_profile = @import("stwo_prover_api").stage_profile;
const work_pool = @import("stwo_prover_engine").work_pool;
const keccak_component = @import("../../air/guest_precompile/keccakf_component.zig");
const keccak_interaction = @import("../../air/guest_precompile/keccakf_interaction.zig");
const keccak_table_interaction = @import("../../air/guest_precompile/keccakf_table_interaction.zig");
const keccak_tables = @import("../../air/guest_precompile/keccakf_tables.zig");
const secp_bundle = @import("../../air/guest_precompile/secp256k1_component_bundle.zig");
const secp_component = @import("../../air/guest_precompile/secp256k1_component.zig");
const secp_config = @import("../../air/guest_precompile/secp256k1_component_config.zig");
const secp_interaction = @import("../../air/guest_precompile/secp256k1_component_interaction.zig");
const opcode_interaction = @import("../../air/lookups/opcode_interaction.zig");
const lookup_physical_v2 = @import("../../air/lang/lookup_physical_manifest_v2.zig");
const base_statement = @import("../../air/statement.zig");
const commitment_witness = @import("../commitment_witness.zig");
const lookup_sources = @import("../lookup_sources.zig");
const proof_workspace = @import("../proof_workspace.zig");
const statement_geometry = @import("../statement_geometry.zig");
const external_tree = @import("external_profile_tree.zig");
const ethereum_transcript = @import("ethereum_transcript.zig");
const ethereum_types = @import("ethereum_types.zig");
const ethereum_witness = @import("ethereum_witness.zig");
const native_provider_omit = @import("../memory_provider_shards/native_provider_omit_v1.zig");

const BaseClaim = base_statement.RiscVInteractionClaim;

pub fn generateAndCommit(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *proof_workspace.ProofWorkspace,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    base_witness: *const commitment_witness.CommitmentWitness,
    geometry: statement_geometry.Geometry,
    lookup_source: *const lookup_sources.Result,
    prefix: *const ethereum_transcript.Prefix,
    extension: *const ethereum_witness.Witness,
    pool: *work_pool.WorkPool,
    base_claim: *BaseClaim,
) !ethereum_types.ExtensionClaim {
    return generateAndCommitInternal(
        Engine,
        allocator,
        workspace,
        scheme,
        channel,
        recorder,
        base_witness,
        geometry,
        lookup_source,
        prefix,
        extension,
        pool,
        base_claim,
        null,
        null,
        NoAdditional{},
    );
}

pub fn generateAndCommitAuthenticatedLookupV2(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *proof_workspace.ProofWorkspace,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    base_witness: *const commitment_witness.CommitmentWitness,
    geometry: statement_geometry.Geometry,
    lookup_source: *const lookup_sources.Result,
    prefix: *const ethereum_transcript.Prefix,
    extension: *const ethereum_witness.Witness,
    pool: *work_pool.WorkPool,
    base_claim: *BaseClaim,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
) !ethereum_types.ExtensionClaim {
    try authenticated.validateAgainst(&workspace.statement, manifest);
    return generateAndCommitInternal(
        Engine,
        allocator,
        workspace,
        scheme,
        channel,
        recorder,
        base_witness,
        geometry,
        lookup_source,
        prefix,
        extension,
        pool,
        base_claim,
        .{ .manifest = manifest, .authenticated = authenticated },
        null,
        NoAdditional{},
    );
}

/// Ordinary full-core Tree-2 sibling with append-only external columns and
/// claim mixing. The canonical base and fourteen Ethereum claims remain the
/// prefix; the caller's mixer runs exactly once afterward.
pub fn generateAndCommitAuthenticatedLookupV2WithExternal(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *proof_workspace.ProofWorkspace,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    base_witness: *const commitment_witness.CommitmentWitness,
    geometry: statement_geometry.Geometry,
    lookup_source: *const lookup_sources.Result,
    prefix: *const ethereum_transcript.Prefix,
    extension: *const ethereum_witness.Witness,
    pool: *work_pool.WorkPool,
    base_claim: *BaseClaim,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    external_columns: []const external_tree.OwnedColumn,
    additional_mix_context: anytype,
    comptime mixAdditionalClaim: anytype,
) !ethereum_types.ExtensionClaim {
    try authenticated.validateAgainst(&workspace.statement, manifest);
    const Additional = AdditionalExtension(
        @TypeOf(additional_mix_context),
        mixAdditionalClaim,
    );
    return generateAndCommitInternal(
        Engine,
        allocator,
        workspace,
        scheme,
        channel,
        recorder,
        base_witness,
        geometry,
        lookup_source,
        prefix,
        extension,
        pool,
        base_claim,
        .{ .manifest = manifest, .authenticated = authenticated },
        null,
        Additional{
            .columns = external_columns,
            .mix_context = additional_mix_context,
        },
    );
}

pub fn generateAndCommitWithoutNativePoseidonAuthenticatedLookupV2(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *proof_workspace.ProofWorkspace,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    base_witness: *const commitment_witness.CommitmentWitness,
    geometry: statement_geometry.Geometry,
    lookup_source: *const lookup_sources.Result,
    prefix: *const ethereum_transcript.Prefix,
    extension: *const ethereum_witness.Witness,
    pool: *work_pool.WorkPool,
    base_claim: *BaseClaim,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    projection: *const native_provider_omit.ProjectionV1,
) !ethereum_types.ExtensionClaim {
    try authenticated.validateAgainst(&workspace.statement, manifest);
    return generateAndCommitInternal(
        Engine,
        allocator,
        workspace,
        scheme,
        channel,
        recorder,
        base_witness,
        geometry,
        lookup_source,
        prefix,
        extension,
        pool,
        base_claim,
        .{ .manifest = manifest, .authenticated = authenticated },
        projection,
        NoAdditional{},
    );
}

/// Candidate-only Tree-2 sibling. The ordinary fourteen interactions are
/// generated first and retain their exact transcript order. Caller-owned
/// interaction columns then move into the same commitment, and one typed
/// additive claim mixer runs strictly after the canonical Ethereum claim.
pub fn generateAndCommitWithoutNativePoseidonAuthenticatedLookupV2WithExternal(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *proof_workspace.ProofWorkspace,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    base_witness: *const commitment_witness.CommitmentWitness,
    geometry: statement_geometry.Geometry,
    lookup_source: *const lookup_sources.Result,
    prefix: *const ethereum_transcript.Prefix,
    extension: *const ethereum_witness.Witness,
    pool: *work_pool.WorkPool,
    base_claim: *BaseClaim,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    projection: *const native_provider_omit.ProjectionV1,
    external_columns: []const external_tree.OwnedColumn,
    additional_mix_context: anytype,
    comptime mixAdditionalClaim: anytype,
) !ethereum_types.ExtensionClaim {
    try authenticated.validateAgainst(&workspace.statement, manifest);
    const Additional = AdditionalExtension(
        @TypeOf(additional_mix_context),
        mixAdditionalClaim,
    );
    return generateAndCommitInternal(
        Engine,
        allocator,
        workspace,
        scheme,
        channel,
        recorder,
        base_witness,
        geometry,
        lookup_source,
        prefix,
        extension,
        pool,
        base_claim,
        .{ .manifest = manifest, .authenticated = authenticated },
        projection,
        Additional{
            .columns = external_columns,
            .mix_context = additional_mix_context,
        },
    );
}

const LookupV2Context = struct {
    manifest: *const lookup_physical_v2.Manifest,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
};

fn generateAndCommitInternal(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *proof_workspace.ProofWorkspace,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    base_witness: *const commitment_witness.CommitmentWitness,
    geometry: statement_geometry.Geometry,
    lookup_source: *const lookup_sources.Result,
    prefix: *const ethereum_transcript.Prefix,
    extension: *const ethereum_witness.Witness,
    pool: *work_pool.WorkPool,
    base_claim: *BaseClaim,
    lookup_v2: ?LookupV2Context,
    projection: ?*const native_provider_omit.ProjectionV1,
    additional: anytype,
) !ethereum_types.ExtensionClaim {
    var k0 = try keccak_interaction.generate(
        allocator,
        &extension.keccak_shard,
        &prefix.relations.keccak,
        pool,
    );
    defer k0.deinit(allocator);
    var k1 = try keccak_table_interaction.generate(
        allocator,
        .chi,
        &extension.keccak_counters,
        &prefix.relations.keccak,
        pool,
    );
    defer k1.deinit(allocator);
    var k2 = try keccak_table_interaction.generate(
        allocator,
        .xor5,
        &extension.keccak_counters,
        &prefix.relations.keccak,
        pool,
    );
    defer k2.deinit(allocator);

    var s0 = try secp_interaction.generate(secp_bundle.ProductBase, allocator, &extension.secp.product_base, &prefix.relations.secp, pool);
    defer s0.deinit(allocator);
    var s1 = try secp_interaction.generate(secp_bundle.ProductScalar, allocator, &extension.secp.product_scalar, &prefix.relations.secp, pool);
    defer s1.deinit(allocator);
    var s2 = try secp_interaction.generate(secp_bundle.LinearBase, allocator, &extension.secp.linear_base, &prefix.relations.secp, pool);
    defer s2.deinit(allocator);
    var s3 = try secp_interaction.generate(secp_bundle.LinearScalar, allocator, &extension.secp.linear_scalar, &prefix.relations.secp, pool);
    defer s3.deinit(allocator);
    var s4 = try secp_interaction.generate(secp_config.Point, allocator, &extension.secp.point, &prefix.relations.secp, pool);
    defer s4.deinit(allocator);
    var s5 = try secp_interaction.generate(secp_config.Split, allocator, &extension.secp.split, &prefix.relations.secp, pool);
    defer s5.deinit(allocator);
    var s6 = try secp_interaction.generate(secp_config.ScalarProgram, allocator, &extension.secp.scalar, &prefix.relations.secp, pool);
    defer s6.deinit(allocator);
    var s7 = try secp_interaction.generate(secp_config.Table, allocator, &extension.secp.table, &prefix.relations.secp, pool);
    defer s7.deinit(allocator);
    var s8 = try secp_interaction.generate(secp_config.Recovery, allocator, &extension.secp.recovery, &prefix.relations.secp, pool);
    defer s8.deinit(allocator);
    var s9 = try secp_interaction.generate(secp_config.ByteTable, allocator, &extension.secp.byte, &prefix.relations.secp, pool);
    defer s9.deinit(allocator);
    var s10 = try secp_interaction.generate(secp_config.RecoveryCaller, allocator, &extension.recovery_caller, &prefix.relations.secp, pool);
    defer s10.deinit(allocator);

    const signer_empty = extension.secp_tape.recoveries.items.len == 0;
    const claim = ethereum_types.ExtensionClaim{
        .keccak_shard = try keccak_component.Claim.canonical(&extension.keccak_shard, k0.claims),
        .keccak_chi_table = k1.claim,
        .keccak_xor5_table = k2.claim,
        .product_base = try secp_component.Claim(secp_bundle.ProductBase).canonicalLogical(&extension.secp.product_base, logicalRows(&extension.secp.product_base, signer_empty), s0.claims),
        .product_scalar = try secp_component.Claim(secp_bundle.ProductScalar).canonicalLogical(&extension.secp.product_scalar, logicalRows(&extension.secp.product_scalar, signer_empty), s1.claims),
        .linear_base = try secp_component.Claim(secp_bundle.LinearBase).canonicalLogical(&extension.secp.linear_base, logicalRows(&extension.secp.linear_base, signer_empty), s2.claims),
        .linear_scalar = try secp_component.Claim(secp_bundle.LinearScalar).canonicalLogical(&extension.secp.linear_scalar, logicalRows(&extension.secp.linear_scalar, signer_empty), s3.claims),
        .point = try secp_component.Claim(secp_config.Point).canonicalLogical(&extension.secp.point, logicalRows(&extension.secp.point, signer_empty), s4.claims),
        .split = try secp_component.Claim(secp_config.Split).canonicalLogical(&extension.secp.split, logicalRows(&extension.secp.split, signer_empty), s5.claims),
        .scalar = try secp_component.Claim(secp_config.ScalarProgram).canonicalLogical(&extension.secp.scalar, logicalRows(&extension.secp.scalar, signer_empty), s6.claims),
        .table = try secp_component.Claim(secp_config.Table).canonicalLogical(&extension.secp.table, logicalRows(&extension.secp.table, signer_empty), s7.claims),
        .recovery = try secp_component.Claim(secp_config.Recovery).canonicalLogical(&extension.secp.recovery, logicalRows(&extension.secp.recovery, signer_empty), s8.claims),
        .byte = try secp_component.Claim(secp_config.ByteTable).canonical(&extension.secp.byte, s9.claims),
        .recovery_caller = try secp_component.Claim(secp_config.RecoveryCaller).canonicalLogical(&extension.recovery_caller, logicalRows(&extension.recovery_caller, signer_empty), s10.claims),
    };

    var columns: std.ArrayList(external_tree.OwnedColumn) = .empty;
    defer columns.deinit(allocator);
    try appendColumns(allocator, &columns, extension.keccak_shard.log_size, &k0.columns);
    try appendColumns(allocator, &columns, keccak_tables.logSize(.chi), &k1.columns);
    try appendColumns(allocator, &columns, keccak_tables.logSize(.xor5), &k2.columns);
    inline for (.{
        .{ extension.secp.product_base.log_size, &s0.columns },
        .{ extension.secp.product_scalar.log_size, &s1.columns },
        .{ extension.secp.linear_base.log_size, &s2.columns },
        .{ extension.secp.linear_scalar.log_size, &s3.columns },
        .{ extension.secp.point.log_size, &s4.columns },
        .{ extension.secp.split.log_size, &s5.columns },
        .{ extension.secp.scalar.log_size, &s6.columns },
        .{ extension.secp.table.log_size, &s7.columns },
        .{ extension.secp.recovery.log_size, &s8.columns },
        .{ extension.secp.byte.log_size, &s9.columns },
        .{ extension.recovery_caller.log_size, &s10.columns },
    }) |entry| try appendColumns(allocator, &columns, entry[0], entry[1]);
    try additional.appendColumns(allocator, &columns);

    if (lookup_v2) |authority| {
        const Context = MixContextV2WithAdditional(@TypeOf(additional));
        const mix_context = Context{
            .core = &workspace.statement,
            .extension = &claim,
            .manifest = authority.manifest,
            .authenticated = authority.authenticated,
            .additional = &additional,
        };
        if (projection) |omission| {
            try external_tree.commitInteractionWithoutNativePoseidonAuthenticatedLookupV2(
                Engine,
                allocator,
                workspace,
                scheme,
                channel,
                recorder,
                base_witness,
                omission.projected_geometry,
                lookup_source,
                &prefix.relations.base,
                prefix.interaction_pow,
                base_claim,
                columns.items,
                authority.manifest,
                authority.authenticated,
                &mix_context,
                mixClaimV2WithAdditional,
            );
        } else {
            try external_tree.commitInteractionAuthenticatedLookupV2(
                Engine,
                allocator,
                workspace,
                scheme,
                channel,
                recorder,
                base_witness,
                geometry,
                lookup_source,
                &prefix.relations.base,
                prefix.interaction_pow,
                base_claim,
                columns.items,
                authority.manifest,
                authority.authenticated,
                &mix_context,
                mixClaimV2WithAdditional,
            );
        }
    } else {
        if (comptime @TypeOf(additional) != NoAdditional)
            return error.MissingAuthenticatedLookupAuthority;
        if (projection != null) return error.MissingAuthenticatedLookupAuthority;
        const mix_context = MixContext{
            .core = &workspace.statement,
            .extension = &claim,
        };
        try external_tree.commitInteraction(
            Engine,
            allocator,
            workspace,
            scheme,
            channel,
            recorder,
            base_witness,
            geometry,
            lookup_source,
            &prefix.relations.base,
            prefix.interaction_pow,
            base_claim,
            columns.items,
            &mix_context,
            mixClaim,
        );
    }
    return claim;
}

fn logicalRows(trace: anytype, empty: bool) u32 {
    return if (empty) 0 else @intCast(trace.n_rows);
}

pub fn logSizes(
    allocator: std.mem.Allocator,
    core: *const base_statement.RiscVStatement,
    extension: *const @import("../../air/guest_precompile/ethereum_statement.zig").Statement,
) ![]u32 {
    var total: usize = @intCast(core.nInteractionColumns());
    for (extension.components) |descriptor| total = std.math.add(
        usize,
        total,
        @as(usize, @intCast(descriptor.interaction_columns)),
    ) catch return error.InvalidTraceShape;
    const result = try allocator.alloc(u32, total);
    var cursor: usize = 0;
    for (core.component_descs[0..core.n_components]) |descriptor| {
        const count = opcode_interaction.nColumns(descriptor.family);
        @memset(result[cursor..][0..count], descriptor.log_size);
        cursor += count;
    }
    for (core.infra_descs[0..core.n_infra]) |descriptor| {
        const count = base_statement.nInteractionColsForInfra(descriptor.kind);
        @memset(result[cursor..][0..count], descriptor.log_size);
        cursor += count;
    }
    for (extension.components) |descriptor| {
        @memset(result[cursor..][0..descriptor.interaction_columns], descriptor.log_size);
        cursor += descriptor.interaction_columns;
    }
    if (cursor != result.len) return error.InvalidTraceShape;
    return result;
}

pub fn logSizesAuthenticatedLookupV2(
    allocator: std.mem.Allocator,
    core: *const base_statement.RiscVStatement,
    extension: *const @import("../../air/guest_precompile/ethereum_statement.zig").Statement,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
) ![]u32 {
    var total = try authenticated.totalInteractionColumns(core, manifest);
    for (extension.components) |descriptor| total = std.math.add(
        usize,
        total,
        @as(usize, @intCast(descriptor.interaction_columns)),
    ) catch return error.InvalidTraceShape;
    const result = try allocator.alloc(u32, total);
    var cursor: usize = 0;
    for (core.component_descs[0..core.n_components]) |descriptor| {
        const entry = manifest.entryForFamily(descriptor.family);
        const count: usize = @intCast(entry.interaction_column_count);
        @memset(result[cursor..][0..count], descriptor.log_size);
        cursor += count;
    }
    for (core.infra_descs[0..core.n_infra]) |descriptor| {
        const count = base_statement.nInteractionColsForInfra(descriptor.kind);
        @memset(result[cursor..][0..count], descriptor.log_size);
        cursor += count;
    }
    for (extension.components) |descriptor| {
        @memset(result[cursor..][0..descriptor.interaction_columns], descriptor.log_size);
        cursor += descriptor.interaction_columns;
    }
    if (cursor != result.len) return error.InvalidTraceShape;
    return result;
}

const MixContext = struct {
    core: *const base_statement.RiscVStatement,
    extension: *const ethereum_types.ExtensionClaim,
};

const MixContextV2 = struct {
    core: *const base_statement.RiscVStatement,
    extension: *const ethereum_types.ExtensionClaim,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
};

fn MixContextV2WithAdditional(comptime Additional: type) type {
    return struct {
        core: *const base_statement.RiscVStatement,
        extension: *const ethereum_types.ExtensionClaim,
        manifest: *const lookup_physical_v2.Manifest,
        authenticated: *const lookup_physical_v2.AuthenticatedStatement,
        additional: *const Additional,
    };
}

fn mixClaim(context: *const MixContext, channel: anytype, base: *const BaseClaim) !void {
    try ethereum_transcript.mixInteractionClaim(
        channel,
        context.core,
        base,
        context.extension,
    );
}

fn mixClaimV2(
    context: *const MixContextV2,
    channel: anytype,
    base: *const BaseClaim,
) !void {
    try ethereum_transcript.mixInteractionClaimV2(
        channel,
        context.core,
        context.manifest,
        context.authenticated,
        base,
        context.extension,
    );
}

fn mixClaimV2WithAdditional(
    context: anytype,
    channel: anytype,
    base: *const BaseClaim,
) !void {
    try ethereum_transcript.mixInteractionClaimV2(
        channel,
        context.core,
        context.manifest,
        context.authenticated,
        base,
        context.extension,
    );
    try context.additional.mix(channel, base, context.extension);
}

const NoAdditional = struct {
    fn appendColumns(
        _: NoAdditional,
        _: std.mem.Allocator,
        _: *std.ArrayList(external_tree.OwnedColumn),
    ) !void {}

    fn mix(
        _: NoAdditional,
        _: anytype,
        _: *const BaseClaim,
        _: *const ethereum_types.ExtensionClaim,
    ) !void {}
};

fn AdditionalExtension(
    comptime MixContextType: type,
    comptime mixAdditionalClaim: anytype,
) type {
    return struct {
        columns: []const external_tree.OwnedColumn,
        mix_context: MixContextType,

        fn appendColumns(
            self: @This(),
            allocator: std.mem.Allocator,
            destination: *std.ArrayList(external_tree.OwnedColumn),
        ) !void {
            try destination.appendSlice(allocator, self.columns);
        }

        fn mix(
            self: @This(),
            channel: anytype,
            base: *const BaseClaim,
            extension: *const ethereum_types.ExtensionClaim,
        ) !void {
            try mixAdditionalClaim(
                self.mix_context,
                channel,
                base,
                extension,
            );
        }
    };
}

fn appendColumns(
    allocator: std.mem.Allocator,
    destination: *std.ArrayList(external_tree.OwnedColumn),
    log_size: u32,
    columns: anytype,
) !void {
    try destination.ensureUnusedCapacity(allocator, columns.len);
    for (columns) |*values| destination.appendAssumeCapacity(.{
        .log_size = log_size,
        .values = values,
    });
}
