//! Pointer-free verifier context for the fourteen Ethereum leaf components.
//!
//! The native verifier constructs this value only after the full dynamic
//! base-plus-fourteen-component AIR/PCS proof succeeds. It retains the actual
//! verifier placements and all
//! transcript relation draws, then independently re-derives canonical
//! placement and claim seals before recursive witness construction.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;

const base_relations = @import("../air/relation_challenges.zig");
const base_statement = @import("../air/statement.zig");
const statement_v2 = @import("../air/statement_v2.zig");
const lookup_physical_v2 = @import("../air/lang/lookup_physical_manifest_v2.zig");
const ethereum_statement = @import("../air/guest_precompile/ethereum_statement.zig");
const keccak_component = @import("../air/guest_precompile/keccakf_component.zig");
const keccak_table_component = @import("../air/guest_precompile/keccakf_table_component.zig");
const secp_bundle = @import("../air/guest_precompile/secp256k1_component_bundle.zig");
const secp_config = @import("../air/guest_precompile/secp256k1_component_config.zig");
const vm_leaf_context = @import("vm_leaf_context.zig");
const vm_leaf_context_v2 = @import("vm_leaf_context_v2.zig");
const ethereum_assembly = @import("../prover/guest_precompile/ethereum_assembly.zig");
const ethereum_transcript = @import("../prover/guest_precompile/ethereum_transcript.zig");
const ethereum_types = @import("../prover/guest_precompile/ethereum_types.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const SCHEMA_VERSION: u16 = 1;
pub const EXTENSION_COMPONENT_COUNT: usize = ethereum_statement.component_count;
pub const EXTENSION_RELATION_DRAW_COUNT: usize = 26;
pub const RELATION_DRAW_COUNT: usize = base_relations.DRAW_COUNT +
    EXTENSION_RELATION_DRAW_COUNT;
pub const CONTEXT_DOMAIN =
    "stwo-zig/riscv/recursion/ethereum-leaf-context/v1\x00";
const COMPONENT_SEMANTIC_DOMAIN =
    "stwo-zig/riscv/recursion/ethereum-component-semantic/v1\x00";
const BATCH_SUMS_DOMAIN =
    "stwo-zig/riscv/recursion/ethereum-component-batch-sums/v1\x00";
const STATEMENT_DOMAIN =
    "stwo-zig/riscv/recursion/ethereum-extension-statement/v1\x00";
const CLAIM_DOMAIN =
    "stwo-zig/riscv/recursion/ethereum-extension-claim/v1\x00";

pub const ComponentAuthorityV1 = struct {
    kind: ethereum_statement.Kind,
    log_size: u32,
    n_rows: u32,
    preprocessed_offset: u32,
    preprocessed_columns: u32,
    main_offset: u32,
    main_columns: u32,
    interaction_offset: u32,
    interaction_columns: u32,
    direct_constraint_count: u32,
    interaction_batch_count: u32,
    semantic_digest: [32]u8,
    component_sum: QM31,
    detailed_batch_sums_sha256: [32]u8,
};

pub const ContextV1 = struct {
    schema_version: u16 = SCHEMA_VERSION,
    base_component_count: u32,
    full_component_count: u32,
    base_preprocessed_columns: u32,
    base_main_columns: u32,
    base_interaction_columns: u32,
    statement_sha256: [32]u8,
    claim_sha256: [32]u8,
    components: [EXTENSION_COMPONENT_COUNT]ComponentAuthorityV1,
    relation_draws: [RELATION_DRAW_COUNT]QM31,
    identity_digest: [32]u8,

    pub fn initVerified(
        native: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
        claim: *const ethereum_types.ExtensionClaim,
        transcript_relations: *const ethereum_transcript.Relations,
        assembly: *const ethereum_assembly.Assembly(.verifier),
        base_component_count: usize,
    ) !ContextV1 {
        return initVerifiedAtBaseInteractionColumns(
            native,
            extension,
            claim,
            transcript_relations,
            assembly,
            base_component_count,
            native.core.nInteractionColumns(),
        );
    }

    /// SegmentV2 derives the base Tree-2 boundary from the authenticated
    /// physical lookup authority. Callers cannot inject an interaction offset.
    pub fn initVerifiedAuthenticatedLookupV2(
        native: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
        claim: *const ethereum_types.ExtensionClaim,
        transcript_relations: *const ethereum_transcript.Relations,
        assembly: *const ethereum_assembly.Assembly(.verifier),
        base_component_count: usize,
        manifest: *const lookup_physical_v2.Manifest,
        authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    ) !ContextV1 {
        const base_interaction_columns = try authenticated.totalInteractionColumns(
            &native.core,
            manifest,
        );
        return initVerifiedAtBaseInteractionColumns(
            native,
            extension,
            claim,
            transcript_relations,
            assembly,
            base_component_count,
            base_interaction_columns,
        );
    }

    /// SegmentV2 constructor deriving base placement from ContextV2.
    pub fn initVerifiedWithVmContextV2(
        native: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
        claim: *const ethereum_types.ExtensionClaim,
        transcript_relations: *const ethereum_transcript.Relations,
        assembly: *const ethereum_assembly.Assembly(.verifier),
        base: *const vm_leaf_context_v2.ContextV2,
    ) !ContextV1 {
        try base.validate();
        return initVerifiedAtBaseInteractionColumns(
            native,
            extension,
            claim,
            transcript_relations,
            assembly,
            @intCast(base.profile.physical_component_count),
            @intCast(base.profile.interaction_column_count),
        );
    }

    fn initVerifiedAtBaseInteractionColumns(
        native: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
        claim: *const ethereum_types.ExtensionClaim,
        transcript_relations: *const ethereum_transcript.Relations,
        assembly: *const ethereum_assembly.Assembly(.verifier),
        base_component_count: usize,
        base_interaction_columns: usize,
    ) !ContextV1 {
        try extension.validateV2(native);
        try claim.validate(extension);
        const core = &native.core;
        const expected_base_count = try physicalBaseComponentCount(core);
        const expected_full_count = std.math.add(
            usize,
            expected_base_count,
            EXTENSION_COMPONENT_COUNT,
        ) catch return error.EthereumContextOverflow;
        if (base_component_count != expected_base_count or
            assembly.active().len != expected_full_count)
        {
            return error.InvalidEthereumComponentCount;
        }
        const placements = assembly.extensionPlacements();
        var result = ContextV1{
            .base_component_count = try castOffset(base_component_count),
            .full_component_count = try castOffset(expected_full_count),
            .base_preprocessed_columns = core.nPreprocessedColumns(),
            .base_main_columns = core.nMainColumns(),
            .base_interaction_columns = try castOffset(base_interaction_columns),
            .statement_sha256 = statementSha256(extension),
            .claim_sha256 = claimSha256(claim),
            .components = try componentAuthorities(extension, claim, placements),
            .relation_draws = undefined,
            .identity_digest = undefined,
        };
        try writeRelationDraws(transcript_relations, &result.relation_draws);
        try result.validateShapeAtBaseInteractionColumns(
            native,
            extension,
            claim,
            base_interaction_columns,
        );
        result.identity_digest = result.computeIdentityDigest();
        return result;
    }

    pub fn validateAgainst(
        self: *const ContextV1,
        native: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
        claim: *const ethereum_types.ExtensionClaim,
        base: *const vm_leaf_context.Context,
    ) !void {
        return self.validateAgainstAtBaseInteractionColumns(
            native,
            extension,
            claim,
            base,
            native.core.nInteractionColumns(),
        );
    }

    /// Revalidates a SegmentV2 context against its exact typed physical
    /// lookup authority before any recursive witness consumes the sidecar.
    pub fn validateAgainstAuthenticatedLookupV2(
        self: *const ContextV1,
        native: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
        claim: *const ethereum_types.ExtensionClaim,
        base: *const vm_leaf_context.Context,
        manifest: *const lookup_physical_v2.Manifest,
        authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    ) !void {
        const base_interaction_columns = try authenticated.totalInteractionColumns(
            &native.core,
            manifest,
        );
        return self.validateAgainstAtBaseInteractionColumns(
            native,
            extension,
            claim,
            base,
            base_interaction_columns,
        );
    }

    /// Revalidates the pointer-free Ethereum authority when the base verifier
    /// uses a nonstandard public-boundary authority but retains the canonical
    /// authenticated physical-V2 component placement. No VM context or public
    /// sums are inferred here; the caller must validate those independently.
    pub fn validateAgainstAuthenticatedLookupV2Authority(
        self: *const ContextV1,
        native: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
        claim: *const ethereum_types.ExtensionClaim,
        transcript_relations: *const ethereum_transcript.Relations,
        manifest: *const lookup_physical_v2.Manifest,
        authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    ) !void {
        try authenticated.validateAgainst(&native.core, manifest);
        const base_interaction_columns = try authenticated.totalInteractionColumns(
            &native.core,
            manifest,
        );
        try self.validateShapeAtBaseInteractionColumns(
            native,
            extension,
            claim,
            base_interaction_columns,
        );
        var expected_draws: [RELATION_DRAW_COUNT]QM31 = undefined;
        try writeRelationDraws(transcript_relations, &expected_draws);
        const expected_identity = self.computeIdentityDigest();
        if (!std.meta.eql(self.relation_draws, expected_draws) or
            !std.mem.eql(u8, &self.identity_digest, &expected_identity))
        {
            return error.EthereumContextMismatch;
        }
    }

    /// Revalidates Ethereum placement against the retained SegmentV2 profile.
    pub fn validateAgainstVmContextV2(
        self: *const ContextV1,
        native: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
        claim: *const ethereum_types.ExtensionClaim,
        base: *const vm_leaf_context_v2.ContextV2,
    ) !void {
        try base.validate();
        try self.validateShapeAtBaseInteractionColumns(
            native,
            extension,
            claim,
            @intCast(base.profile.interaction_column_count),
        );
        const expected_identity = self.computeIdentityDigest();
        if (base.profile.physical_component_count != self.base_component_count or
            !std.meta.eql(
                self.relation_draws[0..base_relations.DRAW_COUNT].*,
                base.relation_draws,
            ) or
            !std.mem.eql(u8, &self.identity_digest, &expected_identity))
        {
            return error.EthereumContextMismatch;
        }
    }

    fn validateAgainstAtBaseInteractionColumns(
        self: *const ContextV1,
        native: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
        claim: *const ethereum_types.ExtensionClaim,
        base: *const vm_leaf_context.Context,
        base_interaction_columns: usize,
    ) !void {
        try base.validate();
        try self.validateShapeAtBaseInteractionColumns(
            native,
            extension,
            claim,
            base_interaction_columns,
        );
        const expected_identity = self.computeIdentityDigest();
        if (base.profile.component_count != self.base_component_count or
            !std.meta.eql(
                self.relation_draws[0..base_relations.DRAW_COUNT].*,
                base.relation_draws,
            ) or
            !std.mem.eql(
                u8,
                &self.identity_digest,
                &expected_identity,
            ))
        {
            return error.EthereumContextMismatch;
        }
    }

    pub fn relations(
        self: *const ContextV1,
        base: *const vm_leaf_context.Context,
    ) !ethereum_transcript.Relations {
        try base.validate();
        if (!std.meta.eql(
            self.relation_draws[0..base_relations.DRAW_COUNT].*,
            base.relation_draws,
        )) return error.EthereumContextMismatch;
        const draws = self.relation_draws[base_relations.DRAW_COUNT..];
        const base_value = base_relations.Relations.fromDrawSequence(
            &base.relation_draws,
        );
        return .{
            .base = base_value,
            .keccak = .{
                .base = base_value,
                .io = .init(draws[0], draws[1]),
                .chi = .init(draws[2], draws[3]),
                .xor5 = .init(draws[4], draws[5]),
            },
            .secp = .{
                .base = base_value,
                .product = .init(draws[6], draws[7]),
                .linear = .init(draws[8], draws[9]),
                .point = .init(draws[10], draws[11]),
                .split = .init(draws[12], draws[13]),
                .table = .init(draws[14], draws[15]),
                .program = .init(draws[16], draws[17]),
                .table_root = .init(draws[18], draws[19]),
                .ecdsa = .init(draws[20], draws[21]),
                .byte = .init(draws[22], draws[23]),
                .recovery = .init(draws[24], draws[25]),
            },
        };
    }

    fn validateShapeAtBaseInteractionColumns(
        self: *const ContextV1,
        native: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
        claim: *const ethereum_types.ExtensionClaim,
        base_interaction_columns: usize,
    ) !void {
        const core = &native.core;
        const expected_base_count = try castOffset(
            try physicalBaseComponentCount(core),
        );
        const expected_full_count = std.math.add(
            u32,
            expected_base_count,
            EXTENSION_COMPONENT_COUNT,
        ) catch return error.EthereumContextOverflow;
        if (self.schema_version != SCHEMA_VERSION or
            self.base_component_count != expected_base_count or
            self.full_component_count != expected_full_count or
            self.base_preprocessed_columns != core.nPreprocessedColumns() or
            self.base_main_columns != core.nMainColumns() or
            self.base_interaction_columns !=
                try castOffset(base_interaction_columns))
        {
            return error.EthereumContextMismatch;
        }
        try extension.validateV2(native);
        try claim.validate(extension);
        const placements = try canonicalPlacements(
            core,
            extension,
            base_interaction_columns,
        );
        const expected = try componentAuthorities(extension, claim, placements);
        const expected_statement_sha256 = statementSha256(extension);
        const expected_claim_sha256 = claimSha256(claim);
        if (!std.mem.eql(u8, &self.statement_sha256, &expected_statement_sha256) or
            !std.mem.eql(u8, &self.claim_sha256, &expected_claim_sha256) or
            !std.meta.eql(self.components, expected))
            return error.EthereumContextMismatch;
        for (self.relation_draws) |draw| try validateQm31(draw);
    }

    fn computeIdentityDigest(self: *const ContextV1) [32]u8 {
        var hash = Sha256.init(.{});
        hash.update(CONTEXT_DOMAIN);
        hashInt(&hash, u16, self.schema_version);
        hashInt(&hash, u32, self.base_component_count);
        hashInt(&hash, u32, self.full_component_count);
        hashInt(&hash, u32, self.base_preprocessed_columns);
        hashInt(&hash, u32, self.base_main_columns);
        hashInt(&hash, u32, self.base_interaction_columns);
        hash.update(&self.statement_sha256);
        hash.update(&self.claim_sha256);
        hashInt(&hash, u32, self.components.len);
        for (self.components) |component| hashComponent(&hash, component);
        hashInt(&hash, u32, self.relation_draws.len);
        for (self.relation_draws) |draw| hashQm31(&hash, draw);
        return hash.finalResult();
    }
};

/// Canonical byte identity of the complete verifier-visible Ethereum
/// extension statement. This intentionally includes call counts and admission
/// bounds even when two count choices happen to select the same padded trace
/// geometry.
pub fn statementSha256(statement: *const ethereum_statement.Statement) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(STATEMENT_DOMAIN);
    hashInt(&hash, u16, statement.version);
    hashInt(&hash, u8, @intFromEnum(statement.profile_id));
    hashInt(&hash, u16, statement.abi_version);
    hash.update(&statement.semantic_digest);
    hashInt(&hash, u32, statement.counts.keccak_calls);
    hashInt(&hash, u32, statement.counts.signer_calls);
    hashInt(&hash, u32, statement.counts.external_retirements);
    hashInt(&hash, u32, statement.components.len);
    for (statement.components) |descriptor| {
        hashInt(&hash, u8, @intFromEnum(descriptor.kind));
        hashInt(&hash, u32, descriptor.log_size);
        hashInt(&hash, u32, descriptor.n_rows);
        hashInt(&hash, u32, descriptor.preprocessed_columns);
        hashInt(&hash, u32, descriptor.main_columns);
        hashInt(&hash, u32, descriptor.interaction_columns);
    }
    hashInt(&hash, u64, statement.admission.extra_memory_terms);
    hashInt(&hash, u64, statement.admission.memory_relation_terms);
    hashInt(&hash, u32, statement.admission.base_fixed_table_bounds.len);
    for (statement.admission.base_fixed_table_bounds) |bound|
        hashInt(&hash, u64, bound);
    hashInt(&hash, u32, statement.admission.extended_fixed_table_bounds.len);
    for (statement.admission.extended_fixed_table_bounds) |bound|
        hashInt(&hash, u64, bound);
    return hash.finalResult();
}

/// Canonical byte identity of every Ethereum extension interaction claim,
/// including component-local metadata and every detailed LogUp batch sum.
pub fn claimSha256(claim: *const ethereum_types.ExtensionClaim) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(CLAIM_DOMAIN);
    hashInt(&hash, u32, claim.keccak_shard.log_size);
    hashInt(&hash, u32, claim.keccak_shard.n_rows);
    hashInt(&hash, u32, claim.keccak_shard.first_call_index);
    hashInt(&hash, u32, claim.keccak_shard.call_count);
    hashClaimSums(
        &hash,
        &claim.keccak_shard.batch_sums,
        claim.keccak_shard.component_sum,
    );
    hashQm31(&hash, claim.keccak_chi_table);
    hashQm31(&hash, claim.keccak_xor5_table);
    inline for (.{
        claim.product_base,
        claim.product_scalar,
        claim.linear_base,
        claim.linear_scalar,
        claim.point,
        claim.split,
        claim.scalar,
        claim.table,
        claim.recovery,
        claim.byte,
        claim.recovery_caller,
    }) |component_claim| {
        hashInt(&hash, u32, component_claim.log_size);
        hashInt(&hash, u32, component_claim.n_rows);
        hashClaimSums(
            &hash,
            &component_claim.batch_sums,
            component_claim.component_sum,
        );
    }
    return hash.finalResult();
}

fn hashClaimSums(hash: *Sha256, values: []const QM31, total: QM31) void {
    hashInt(hash, u32, @as(u32, @intCast(values.len)));
    for (values) |value| hashQm31(hash, value);
    hashQm31(hash, total);
}

fn canonicalPlacements(
    core: *const base_statement.RiscVStatement,
    extension: *const ethereum_statement.Statement,
    base_interaction_columns: usize,
) ![EXTENSION_COMPONENT_COUNT]ethereum_assembly.PlacementDescriptor {
    var result: [EXTENSION_COMPONENT_COUNT]ethereum_assembly.PlacementDescriptor = undefined;
    var pp: usize = core.nPreprocessedColumns();
    var main: usize = core.nMainColumns();
    var interaction = base_interaction_columns;
    for (&result, extension.components) |*placement, descriptor| {
        placement.* = .{
            .preprocessed_offset = pp,
            .main_offset = main,
            .interaction_offset = interaction,
        };
        pp = try add(pp, descriptor.preprocessed_columns);
        main = try add(main, descriptor.main_columns);
        interaction = try add(interaction, descriptor.interaction_columns);
    }
    return result;
}

fn componentAuthorities(
    extension: *const ethereum_statement.Statement,
    claim: *const ethereum_types.ExtensionClaim,
    placements: [EXTENSION_COMPONENT_COUNT]ethereum_assembly.PlacementDescriptor,
) ![EXTENSION_COMPONENT_COUNT]ComponentAuthorityV1 {
    var result: [EXTENSION_COMPONENT_COUNT]ComponentAuthorityV1 = undefined;
    result[0] = try componentAuthority(
        extension.components[0],
        placements[0],
        keccak_component.direct_constraint_count,
        claim.keccak_shard.batch_sums.len,
        claim.keccak_shard.component_sum,
        &claim.keccak_shard.batch_sums,
    );
    const chi = [_]QM31{claim.keccak_chi_table};
    result[1] = try componentAuthority(
        extension.components[1],
        placements[1],
        keccak_table_component.constraint_count,
        1,
        claim.keccak_chi_table,
        &chi,
    );
    const xor5 = [_]QM31{claim.keccak_xor5_table};
    result[2] = try componentAuthority(
        extension.components[2],
        placements[2],
        keccak_table_component.constraint_count,
        1,
        claim.keccak_xor5_table,
        &xor5,
    );
    inline for (.{
        .{ secp_bundle.ProductBase, claim.product_base },
        .{ secp_bundle.ProductScalar, claim.product_scalar },
        .{ secp_bundle.LinearBase, claim.linear_base },
        .{ secp_bundle.LinearScalar, claim.linear_scalar },
        .{ secp_config.Point, claim.point },
        .{ secp_config.Split, claim.split },
        .{ secp_config.ScalarProgram, claim.scalar },
        .{ secp_config.Table, claim.table },
        .{ secp_config.Recovery, claim.recovery },
        .{ secp_config.ByteTable, claim.byte },
        .{ secp_config.RecoveryCaller, claim.recovery_caller },
    }, 3..) |entry, index| {
        const Config = entry[0];
        const component_claim = entry[1];
        result[index] = try componentAuthority(
            extension.components[index],
            placements[index],
            Config.direct_constraint_count,
            Config.batch_count,
            component_claim.component_sum,
            &component_claim.batch_sums,
        );
    }
    return result;
}

fn componentAuthority(
    descriptor: ethereum_statement.Descriptor,
    placement: ethereum_assembly.PlacementDescriptor,
    direct_constraint_count: usize,
    interaction_batch_count: usize,
    component_sum: QM31,
    detailed: []const QM31,
) !ComponentAuthorityV1 {
    if (detailed.len != interaction_batch_count)
        return error.EthereumContextMismatch;
    const direct = std.math.cast(u32, direct_constraint_count) orelse
        return error.EthereumContextOverflow;
    const batches = std.math.cast(u32, interaction_batch_count) orelse
        return error.EthereumContextOverflow;
    const result = ComponentAuthorityV1{
        .kind = descriptor.kind,
        .log_size = descriptor.log_size,
        .n_rows = descriptor.n_rows,
        .preprocessed_offset = try castOffset(placement.preprocessed_offset),
        .preprocessed_columns = descriptor.preprocessed_columns,
        .main_offset = try castOffset(placement.main_offset),
        .main_columns = descriptor.main_columns,
        .interaction_offset = try castOffset(placement.interaction_offset),
        .interaction_columns = descriptor.interaction_columns,
        .direct_constraint_count = direct,
        .interaction_batch_count = batches,
        .semantic_digest = componentSemanticDigest(descriptor, direct, batches),
        .component_sum = component_sum,
        .detailed_batch_sums_sha256 = batchSumsDigest(descriptor.kind, detailed),
    };
    try validateQm31(result.component_sum);
    for (detailed) |sum| try validateQm31(sum);
    return result;
}

fn writeRelationDraws(
    relations: *const ethereum_transcript.Relations,
    destination: *[RELATION_DRAW_COUNT]QM31,
) !void {
    try relations.base.writeDraws(destination[0..base_relations.DRAW_COUNT]);
    var at: usize = base_relations.DRAW_COUNT;
    inline for (.{
        relations.keccak.io,
        relations.keccak.chi,
        relations.keccak.xor5,
        relations.secp.product,
        relations.secp.linear,
        relations.secp.point,
        relations.secp.split,
        relations.secp.table,
        relations.secp.program,
        relations.secp.table_root,
        relations.secp.ecdsa,
        relations.secp.byte,
        relations.secp.recovery,
    }) |relation| {
        destination[at] = relation.z;
        destination[at + 1] = relation.alpha;
        at += 2;
    }
    std.debug.assert(at == destination.len);
}

fn componentSemanticDigest(
    descriptor: ethereum_statement.Descriptor,
    direct: u32,
    batches: u32,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(COMPONENT_SEMANTIC_DOMAIN);
    hash.update(&@import("../isa/execution_profile.zig").ethereum_semantic_digest);
    hashInt(&hash, u8, @intFromEnum(descriptor.kind));
    hashInt(&hash, u32, descriptor.preprocessed_columns);
    hashInt(&hash, u32, descriptor.main_columns);
    hashInt(&hash, u32, descriptor.interaction_columns);
    hashInt(&hash, u32, direct);
    hashInt(&hash, u32, batches);
    return hash.finalResult();
}

fn batchSumsDigest(
    kind: ethereum_statement.Kind,
    values: []const QM31,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(BATCH_SUMS_DOMAIN);
    hashInt(&hash, u8, @intFromEnum(kind));
    hashInt(&hash, u32, @as(u32, @intCast(values.len)));
    for (values) |value| hashQm31(&hash, value);
    return hash.finalResult();
}

fn hashComponent(hash: *Sha256, value: ComponentAuthorityV1) void {
    hashInt(hash, u8, @intFromEnum(value.kind));
    inline for (.{
        value.log_size,
        value.n_rows,
        value.preprocessed_offset,
        value.preprocessed_columns,
        value.main_offset,
        value.main_columns,
        value.interaction_offset,
        value.interaction_columns,
        value.direct_constraint_count,
        value.interaction_batch_count,
    }) |field| hashInt(hash, u32, field);
    hash.update(&value.semantic_digest);
    hashQm31(hash, value.component_sum);
    hash.update(&value.detailed_batch_sums_sha256);
}

fn hashQm31(hash: *Sha256, value: QM31) void {
    for (value.toM31Array()) |limb| hashInt(hash, u32, limb.toU32());
}

fn validateQm31(value: QM31) !void {
    for (value.toM31Array()) |limb|
        if (limb.toU32() >= @import("stwo_core").fields.m31.Modulus)
            return error.InvalidEthereumRelationDraw;
}

fn add(left: usize, right: u32) !usize {
    return std.math.add(usize, left, right) catch
        error.EthereumContextOverflow;
}

fn physicalBaseComponentCount(
    core: *const base_statement.RiscVStatement,
) !usize {
    const opcode = std.math.mul(
        usize,
        @intCast(core.n_components),
        2,
    ) catch return error.EthereumContextOverflow;
    return std.math.add(
        usize,
        opcode,
        @intCast(core.n_infra),
    ) catch error.EthereumContextOverflow;
}

fn castOffset(value: usize) !u32 {
    return std.math.cast(u32, value) orelse error.EthereumContextOverflow;
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (EXTENSION_COMPONENT_COUNT != 14 or RELATION_DRAW_COUNT != 50) {
        @compileError("Ethereum recursive leaf context authority drifted");
    }
}

test "Ethereum leaf context preserves legacy placement and authenticates V2" {
    const allocator = std.testing.allocator;
    const public_data_v2 = @import("../air/public_data_v2.zig");
    const public_support = @import("../air/public_data_v2_test_support.zig");
    const context_support = @import("ethereum_leaf_context_v1_test_support.zig");
    var fixture = try public_support.Fixture.init();
    const source = fixture.leftSource();
    const words = try public_support.encode(allocator, &source);
    defer allocator.free(words);
    const public_data = try public_data_v2.PublicDataV2.authenticate(words);
    const projected = try statement_v2.canonicalCorePublicData(&public_data);
    var core = context_support.retainedSegmentZeroCore();
    core.initial_pc = projected.initial_pc;
    core.final_pc = projected.final_pc;
    core.total_steps = projected.clock;
    core.public_data = projected;
    const native = try statement_v2.RiscVStatementV2.init(core, public_data);
    const extension = try ethereum_statement.Statement.canonicalV2(
        &native,
        0,
        0,
        context_support.emptySecpShapes(),
    );
    const claim = context_support.zeroExtensionClaim(&extension);
    try claim.validate(&extension);
    const relations = std.mem.zeroes(ethereum_transcript.Relations);
    const base_count = try physicalBaseComponentCount(&native.core);
    const BaseComponent = @import("stwo_core").air.components.Component;
    const base = try allocator.alloc(BaseComponent, base_count);
    defer allocator.free(base);

    const legacy_assembly = try ethereum_assembly.Assembly(.verifier).create(
        allocator,
        &native.core,
        &extension,
        &relations,
        base,
        &claim,
    );
    defer legacy_assembly.destroy(allocator);
    const legacy = try ContextV1.initVerified(
        &native,
        &extension,
        &claim,
        &relations,
        legacy_assembly,
        base_count,
    );
    try std.testing.expectEqual(@as(u32, 372), legacy.base_interaction_columns);
    try std.testing.expectEqual(
        @as(u32, 372),
        legacy.components[0].interaction_offset,
    );

    var manifest = lookup_physical_v2.Manifest.native();
    var authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
        &native.core,
        &manifest,
    );
    const selected = try authenticated.totalInteractionColumns(
        &native.core,
        &manifest,
    );
    try std.testing.expectEqual(@as(usize, 352), selected);
    const v2_assembly = try ethereum_assembly.Assembly(.verifier)
        .createAuthenticatedLookupV2(
        allocator,
        &native,
        &extension,
        &relations,
        base,
        &claim,
        &manifest,
        &authenticated,
    );
    defer v2_assembly.destroy(allocator);
    const v2 = try ContextV1.initVerifiedAuthenticatedLookupV2(
        &native,
        &extension,
        &claim,
        &relations,
        v2_assembly,
        base_count,
        &manifest,
        &authenticated,
    );
    try std.testing.expectEqual(@as(u32, 352), v2.base_interaction_columns);
    try std.testing.expectEqual(
        @as(u32, 352),
        v2.components[0].interaction_offset,
    );
    const v2_identity = v2.computeIdentityDigest();
    try std.testing.expect(std.mem.eql(
        u8,
        &v2.identity_digest,
        &v2_identity,
    ));
    try std.testing.expect(!std.mem.eql(
        u8,
        &legacy.identity_digest,
        &v2.identity_digest,
    ));

    var mutated_context = v2;
    mutated_context.components[0].interaction_offset += 1;
    try std.testing.expectError(
        error.EthereumContextMismatch,
        mutated_context.validateShapeAtBaseInteractionColumns(
            &native,
            &extension,
            &claim,
            selected,
        ),
    );
    authenticated.opcode_interaction_columns += 4;
    try std.testing.expectError(
        error.InvalidStatementGeometry,
        ContextV1.initVerifiedAuthenticatedLookupV2(
            &native,
            &extension,
            &claim,
            &relations,
            v2_assembly,
            base_count,
            &manifest,
            &authenticated,
        ),
    );
    authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
        &native.core,
        &manifest,
    );
    manifest.identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidManifestIdentity,
        ContextV1.initVerifiedAuthenticatedLookupV2(
            &native,
            &extension,
            &claim,
            &relations,
            v2_assembly,
            base_count,
            &manifest,
            &authenticated,
        ),
    );
}
