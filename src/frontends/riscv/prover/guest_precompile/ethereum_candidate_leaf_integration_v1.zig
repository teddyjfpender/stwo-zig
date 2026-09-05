//! Genuine component boundary for the combined Ethereum candidate leaf.
//!
//! The ordinary provider-omitted Ethereum proof remains unchanged. This
//! sibling appends the bulk-memcpy caller/word and U256-SWAP caller/word AIRs
//! after the projected core and all fourteen Ethereum components. All four
//! components share the base relation draw, receive independent call-bus
//! challenges, and contribute to the same global cancellation residual.
//! Nothing in this module activates a production profile or publishes a leaf.

const std = @import("std");

const core_components = @import("stwo_core").air.components;
const verifier_types = @import("stwo_core").verifier_types;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const prover_component = @import("stwo_prover_engine").air.component_prover;

const base_statement = @import("../../air/statement.zig");
const statement_v2 = @import("../../air/statement_v2.zig");
const lookup_physical_v2 = @import("../../air/lang/lookup_physical_manifest_v2.zig");
const ethereum_statement = @import("../../air/guest_precompile/ethereum_statement.zig");
const bulk_contract = @import("../../air/guest_precompile/bulk_memcpy_component_v1.zig");
const bulk_interaction = @import("../../air/guest_precompile/bulk_memcpy_interaction_v1.zig");
const bulk_relations = @import("../../air/guest_precompile/bulk_memcpy_relations_v1.zig");
const bulk_stark = @import("../../air/guest_precompile/bulk_memcpy_stark_component_v1.zig");
const bulk_trace = @import("../../air/guest_precompile/bulk_memcpy_trace_v1.zig");
const swap_contract = @import("../../air/guest_precompile/stack_swap_component_v1.zig");
const swap_interaction = @import("../../air/guest_precompile/stack_swap_interaction_v1.zig");
const swap_relations = @import("../../air/guest_precompile/stack_swap_relations_v1.zig");
const swap_stark = @import("../../air/guest_precompile/stack_swap_stark_component_v1.zig");
const swap_trace = @import("../../air/guest_precompile/stack_swap_trace_v1.zig");
const base_logup = @import("../../air/logup.zig");
const public_logup = @import("../../air/public_logup.zig");
const native_provider_omit = @import("../memory_provider_shards/native_provider_omit_v1.zig");
const provider_authority = @import("../memory_provider_shards/authority.zig");
const statement_geometry = @import("../statement_geometry.zig");
const ethereum_assembly = @import("ethereum_assembly.zig");
const ethereum_cancellation = @import("ethereum_cancellation.zig");
const ethereum_transcript = @import("ethereum_transcript.zig");
const ethereum_types = @import("ethereum_types.zig");
const external_tree = @import("external_profile_tree.zig");
const candidate_admission = @import("ethereum_candidate_leaf_admission_v1.zig");
const profile_mod = @import("ethereum_candidate_leaf_profile_v1.zig");

pub const production_active = false;
pub const appended_component_count: usize = profile_mod.component_count;
pub const max_component_handles = ethereum_assembly.max_handles +
    appended_component_count;
pub const ordinary_composition_bound_delta: u8 = 1;

const candidate_composition_geometry =
    core_components.CompositionGeometryOverrideV1{
        .max_constraint_log_degree_bound_delta = ordinary_composition_bound_delta,
        .composition_log_split = profile_mod.composition_log_split,
    };

const BulkCallerComponent = bulk_stark.ComponentWithCompositionLogSplit(
    bulk_contract.Caller,
    profile_mod.composition_log_split,
);
const BulkWordComponent = bulk_stark.ComponentWithCompositionLogSplit(
    bulk_contract.Word,
    profile_mod.composition_log_split,
);
const SwapCallerComponent = swap_stark.ComponentWithCompositionLogSplit(
    swap_contract.Caller,
    profile_mod.composition_log_split,
);
const SwapWordComponent = swap_stark.ComponentWithCompositionLogSplit(
    swap_contract.Word,
    profile_mod.composition_log_split,
);

/// One shared base relation draw followed by independent candidate call buses.
pub const Relations = struct {
    ethereum: ethereum_transcript.Relations,
    bulk_memcpy: bulk_relations.Relations,
    stack_swap: swap_relations.Relations,

    pub fn draw(allocator: std.mem.Allocator, channel: anytype) !Relations {
        const ethereum = try ethereum_transcript.Relations.draw(allocator, channel);
        const extension = try channel.drawSecureFelts(allocator, 4);
        defer allocator.free(extension);
        if (extension.len != 4) return error.InvalidChallengeDraw;
        return .{
            .ethereum = ethereum,
            .bulk_memcpy = .{
                .base = ethereum.base,
                .call = .init(extension[0], extension[1]),
            },
            .stack_swap = .{
                .base = ethereum.base,
                .call = .init(extension[2], extension[3]),
            },
        };
    }

    pub fn validate(self: Relations) !void {
        if (!std.meta.eql(self.ethereum.base, self.bulk_memcpy.base) or
            !std.meta.eql(self.ethereum.base, self.stack_swap.base))
        {
            return error.EthereumCandidateLeafBaseRelationMismatch;
        }
    }
};

pub const Prefix = struct {
    interaction_pow: u64,
    relations: Relations,
};

/// The normal base/Ethereum main statement is mixed first. The two candidate
/// call buses are drawn only after the ordinary 38 base+Ethereum challenges.
pub fn proveToRelations(
    allocator: std.mem.Allocator,
    channel: anytype,
    core: *const base_statement.RiscVStatement,
    extension: anytype,
) !Prefix {
    const ordinary = try ethereum_transcript.proveToRelationsWithExtension(
        allocator,
        channel,
        core,
        extension,
    );
    return appendCandidateRelations(allocator, channel, ordinary);
}

/// Appends exactly four candidate call-bus challenges after an already-drawn
/// canonical Ethereum/provider prefix. Provider-omission adapters use this to
/// retain their existing Stage-A frame and root ordering.
pub fn appendCandidateRelations(
    allocator: std.mem.Allocator,
    channel: anytype,
    ordinary: ethereum_transcript.Prefix,
) !Prefix {
    return .{
        .interaction_pow = ordinary.interaction_pow,
        .relations = try drawCandidateCallRelations(
            allocator,
            channel,
            ordinary.relations,
        ),
    };
}

pub fn verifyToRelations(
    allocator: std.mem.Allocator,
    channel: anytype,
    core: *const base_statement.RiscVStatement,
    nonce: u64,
    extension: anytype,
) !Relations {
    const ordinary = try ethereum_transcript.verifyToRelationsWithExtension(
        allocator,
        channel,
        core,
        nonce,
        extension,
    );
    return appendCandidateRelationsAfterVerify(allocator, channel, ordinary);
}

pub fn appendCandidateRelationsAfterVerify(
    allocator: std.mem.Allocator,
    channel: anytype,
    ordinary: ethereum_transcript.Relations,
) !Relations {
    return drawCandidateCallRelations(allocator, channel, ordinary);
}

fn drawCandidateCallRelations(
    allocator: std.mem.Allocator,
    channel: anytype,
    ethereum: ethereum_transcript.Relations,
) !Relations {
    const extension = try channel.drawSecureFelts(allocator, 4);
    defer allocator.free(extension);
    if (extension.len != 4) return error.InvalidChallengeDraw;
    const result = Relations{
        .ethereum = ethereum,
        .bulk_memcpy = .{
            .base = ethereum.base,
            .call = .init(extension[0], extension[1]),
        },
        .stack_swap = .{
            .base = ethereum.base,
            .call = .init(extension[2], extension[3]),
        },
    };
    try result.validate();
    return result;
}

/// Verifier-visible claims for the four appended components.
pub const Claims = struct {
    bulk_memcpy_caller: bulk_contract.CallerClaim,
    bulk_memcpy_words: bulk_contract.WordClaim,
    stack_swap_caller: swap_contract.CallerClaim,
    stack_swap_words: swap_contract.WordClaim,

    pub fn validate(self: Claims, profile: *const profile_mod.Profile) !void {
        try self.bulk_memcpy_caller.validate();
        try self.bulk_memcpy_words.validate();
        try self.stack_swap_caller.validate();
        try self.stack_swap_words.validate();
        try validateClaimGeometry(
            self.bulk_memcpy_caller,
            profile.components[0],
        );
        try validateClaimGeometry(
            self.bulk_memcpy_words,
            profile.components[1],
        );
        try validateClaimGeometry(
            self.stack_swap_caller,
            profile.components[2],
        );
        try validateClaimGeometry(
            self.stack_swap_words,
            profile.components[3],
        );
        if (!bulkCallRelationSum(self).isZero())
            return error.EthereumCandidateLeafBulkCallRelationUnclosed;
        if (!swapCallRelationSum(self).isZero())
            return error.EthereumCandidateLeafSwapCallRelationUnclosed;
    }

    pub fn componentSum(self: Claims) QM31 {
        return self.bulk_memcpy_caller.component_sum
            .add(self.bulk_memcpy_words.component_sum)
            .add(self.stack_swap_caller.component_sum)
            .add(self.stack_swap_words.component_sum);
    }
};

pub fn bulkCallRelationSum(claims: Claims) QM31 {
    return claims.bulk_memcpy_caller.batch_sums[bulk_contract.Caller.batch_count - 1]
        .add(claims.bulk_memcpy_words.batch_sums[bulk_contract.Word.batch_count - 1]);
}

pub fn swapCallRelationSum(claims: Claims) QM31 {
    return claims.stack_swap_caller.batch_sums[swap_contract.Caller.batch_count - 1]
        .add(claims.stack_swap_words.batch_sums[swap_contract.Word.batch_count - 1]);
}

/// Stable borrowed arrays for appending candidate columns to Trees 0/1/2.
pub const TraceBlocks = struct {
    bulk_caller_preprocessed: [bulk_trace.preprocessed_column_count][]const M31,
    bulk_word_preprocessed: [bulk_trace.preprocessed_column_count][]const M31,
    swap_caller_preprocessed: [swap_trace.preprocessed_column_count][]const M31,
    swap_word_preprocessed: [swap_trace.preprocessed_column_count][]const M31,
    bulk_caller_main: [bulk_contract.Caller.main_column_count][]const M31,
    bulk_word_main: [bulk_contract.Word.main_column_count][]const M31,
    swap_caller_main: [swap_contract.Caller.main_column_count][]const M31,
    swap_word_main: [swap_contract.Word.main_column_count][]const M31,
    bulk_caller_interaction: [bulk_contract.Caller.interaction_column_count][]const M31,
    bulk_word_interaction: [bulk_contract.Word.interaction_column_count][]const M31,
    swap_caller_interaction: [swap_contract.Caller.interaction_column_count][]const M31,
    swap_word_interaction: [swap_contract.Word.interaction_column_count][]const M31,
    log_sizes: [appended_component_count]u32,

    pub fn init(
        bulk: *const bulk_trace.Bundle,
        bulk_caller_interaction: *const bulk_interaction.Result(bulk_contract.Caller),
        bulk_word_interaction: *const bulk_interaction.Result(bulk_contract.Word),
        swap: *const swap_trace.Bundle,
        swap_caller_interaction: *const swap_interaction.Result(swap_contract.Caller),
        swap_word_interaction: *const swap_interaction.Result(swap_contract.Word),
    ) TraceBlocks {
        var result: TraceBlocks = undefined;
        fillPreprocessed(&result.bulk_caller_preprocessed, &bulk.caller);
        fillPreprocessed(&result.bulk_word_preprocessed, &bulk.words);
        fillPreprocessed(&result.swap_caller_preprocessed, &swap.caller);
        fillPreprocessed(&result.swap_word_preprocessed, &swap.words);
        fillMain(&result.bulk_caller_main, &bulk.caller);
        fillMain(&result.bulk_word_main, &bulk.words);
        fillMain(&result.swap_caller_main, &swap.caller);
        fillMain(&result.swap_word_main, &swap.words);
        fillInteraction(&result.bulk_caller_interaction, bulk_caller_interaction);
        fillInteraction(&result.bulk_word_interaction, bulk_word_interaction);
        fillInteraction(&result.swap_caller_interaction, swap_caller_interaction);
        fillInteraction(&result.swap_word_interaction, swap_word_interaction);
        result.log_sizes = .{
            bulk.caller.log_size,
            bulk.words.log_size,
            swap.caller.log_size,
            swap.words.log_size,
        };
        return result;
    }

    pub fn validateAgainst(
        self: *const TraceBlocks,
        profile: *const profile_mod.Profile,
    ) !void {
        inline for (self.log_sizes, profile.components) |actual, descriptor|
            if (actual != descriptor.log_size)
                return error.EthereumCandidateLeafTraceGeometryMismatch;
        inline for (.{
            self.bulk_caller_preprocessed,
            self.bulk_word_preprocessed,
            self.swap_caller_preprocessed,
            self.swap_word_preprocessed,
            self.bulk_caller_main,
            self.bulk_word_main,
            self.swap_caller_main,
            self.swap_word_main,
            self.bulk_caller_interaction,
            self.bulk_word_interaction,
            self.swap_caller_interaction,
            self.swap_word_interaction,
        }, .{
            self.log_sizes[0], self.log_sizes[1], self.log_sizes[2], self.log_sizes[3],
            self.log_sizes[0], self.log_sizes[1], self.log_sizes[2], self.log_sizes[3],
            self.log_sizes[0], self.log_sizes[1], self.log_sizes[2], self.log_sizes[3],
        }) |columns, log_size| try validateColumnLengths(columns, log_size);
    }

    pub fn tree0(self: *const TraceBlocks) [appended_component_count]external_tree.BorrowedBlock {
        return .{
            block(self.log_sizes[0], &self.bulk_caller_preprocessed),
            block(self.log_sizes[1], &self.bulk_word_preprocessed),
            block(self.log_sizes[2], &self.swap_caller_preprocessed),
            block(self.log_sizes[3], &self.swap_word_preprocessed),
        };
    }

    pub fn tree1(self: *const TraceBlocks) [appended_component_count]external_tree.BorrowedBlock {
        return .{
            block(self.log_sizes[0], &self.bulk_caller_main),
            block(self.log_sizes[1], &self.bulk_word_main),
            block(self.log_sizes[2], &self.swap_caller_main),
            block(self.log_sizes[3], &self.swap_word_main),
        };
    }

    pub fn tree2(self: *const TraceBlocks) [appended_component_count]external_tree.BorrowedBlock {
        return .{
            block(self.log_sizes[0], &self.bulk_caller_interaction),
            block(self.log_sizes[1], &self.bulk_word_interaction),
            block(self.log_sizes[2], &self.swap_caller_interaction),
            block(self.log_sizes[3], &self.swap_word_interaction),
        };
    }
};

pub fn Assembly(comptime direction: ethereum_assembly.Direction) type {
    const Handle = if (direction == .prover)
        prover_component.ComponentProver
    else
        core_components.Component;
    const EthereumAssembly = ethereum_assembly.Assembly(direction);
    return struct {
        const Self = @This();

        ethereum: *EthereumAssembly,
        bulk_memcpy_caller: BulkCallerComponent,
        bulk_memcpy_words: BulkWordComponent,
        stack_swap_caller: SwapCallerComponent,
        stack_swap_words: SwapWordComponent,
        handles: [max_component_handles]Handle,
        len: usize,

        pub fn createWithoutNativePoseidonAuthenticatedLookupV2(
            allocator: std.mem.Allocator,
            projection: *const native_provider_omit.ProjectionV1,
            full_native: *const statement_v2.RiscVStatementV2,
            extension: *const ethereum_statement.Statement,
            relations: *const Relations,
            base: []const Handle,
            ethereum_claim: *const ethereum_types.ExtensionClaim,
            candidate_claims: Claims,
            manifest: *const lookup_physical_v2.Manifest,
            authenticated: *const lookup_physical_v2.AuthenticatedStatement,
            profile: *const profile_mod.Profile,
        ) !*Self {
            try relations.validate();
            try projection.validateSealAndFull(full_native, extension);
            const core = &projection.projected_native.core;
            const base_interaction_columns = std.math.cast(
                u32,
                try authenticated.totalInteractionColumns(core, manifest),
            ) orelse return error.EthereumCandidateLeafGeometryOverflow;
            try profile.validate(core, extension, base_interaction_columns);
            try candidate_claims.validate(profile);

            const self = try allocator.create(Self);
            errdefer allocator.destroy(self);
            self.ethereum = try EthereumAssembly
                .createWithoutNativePoseidonAuthenticatedLookupV2(
                allocator,
                projection,
                full_native,
                extension,
                &relations.ethereum,
                base,
                ethereum_claim,
                manifest,
                authenticated,
            );
            errdefer self.ethereum.destroy(allocator);

            self.bulk_memcpy_caller = try .init(
                candidate_claims.bulk_memcpy_caller,
                placementBulk(profile.placements.bulk_memcpy_caller),
                &relations.bulk_memcpy,
            );
            self.bulk_memcpy_words = try .init(
                candidate_claims.bulk_memcpy_words,
                placementBulk(profile.placements.bulk_memcpy_words),
                &relations.bulk_memcpy,
            );
            const swap_inputs = swap_contract.Inputs{
                .relations = &relations.stack_swap,
                .authority = &profile.authority.stack_swap.stack_swap,
            };
            self.stack_swap_caller = try .init(
                candidate_claims.stack_swap_caller,
                placementSwap(profile.placements.stack_swap_caller),
                swap_inputs,
            );
            self.stack_swap_words = try .init(
                candidate_claims.stack_swap_words,
                placementSwap(profile.placements.stack_swap_words),
                swap_inputs,
            );

            const ordinary = self.ethereum.active();
            if (ordinary.len + appended_component_count > self.handles.len)
                return error.TooManyComponentHandles;
            for (ordinary, 0..) |handle, index| {
                self.handles[index] = if (direction == .prover)
                    try liftOrdinaryProverComponent(handle)
                else
                    try liftOrdinaryVerifierComponent(handle);
            }
            var cursor = ordinary.len;
            inline for (.{
                &self.bulk_memcpy_caller,
                &self.bulk_memcpy_words,
                &self.stack_swap_caller,
                &self.stack_swap_words,
            }) |component| {
                const handle = if (direction == .prover)
                    component.asProverComponent()
                else
                    component.asVerifierComponent();
                if (handle.compositionLogSplit() !=
                    profile_mod.composition_log_split)
                {
                    return error.EthereumCandidateLeafCompositionGeometryMismatch;
                }
                self.handles[cursor] = handle;
                cursor += 1;
            }
            self.len = cursor;
            return self;
        }

        pub fn active(self: *const Self) []const Handle {
            return self.handles[0..self.len];
        }

        pub fn destroy(self: *Self, allocator: std.mem.Allocator) void {
            self.ethereum.destroy(allocator);
            allocator.destroy(self);
        }
    };
}

/// Candidate-only lift for an ordinary prover handle. The handle value is
/// copied, so its context, vtable, and prepared/domain/work callbacks retain
/// the exact original owner and operation ordering. Backend composition is
/// intentionally declined by the generic override because a capability bound
/// to the original context would bypass its q1-to-q2 polynomial extension.
pub fn liftOrdinaryProverComponent(
    handle: prover_component.ComponentProver,
) !prover_component.ComponentProver {
    if (handle.compositionLogSplit() != verifier_types.COMPOSITION_LOG_SPLIT)
        return error.EthereumCandidateLeafOrdinaryCompositionGeometryMismatch;
    const result = try handle.withCompositionGeometryOverrideV1(
        candidate_composition_geometry,
    );
    if (result.maxConstraintLogDegreeBound() !=
        handle.maxConstraintLogDegreeBound() +
            @as(u32, ordinary_composition_bound_delta) or
        result.compositionLogSplit() != profile_mod.composition_log_split)
    {
        return error.EthereumCandidateLeafCompositionGeometryMismatch;
    }
    return result;
}

/// Verifier counterpart of `liftOrdinaryProverComponent`.
pub fn liftOrdinaryVerifierComponent(
    handle: core_components.Component,
) !core_components.Component {
    if (handle.compositionLogSplit() != verifier_types.COMPOSITION_LOG_SPLIT)
        return error.EthereumCandidateLeafOrdinaryCompositionGeometryMismatch;
    const result = try handle.withCompositionGeometryOverrideV1(
        candidate_composition_geometry,
    );
    if (result.maxConstraintLogDegreeBound() !=
        handle.maxConstraintLogDegreeBound() +
            @as(u32, ordinary_composition_bound_delta) or
        result.compositionLogSplit() != profile_mod.composition_log_split)
    {
        return error.EthereumCandidateLeafCompositionGeometryMismatch;
    }
    return result;
}

/// Mixes the complete field-native profile before Tree 0.
pub fn mixPreTree0Authority(
    channel: anytype,
    core: *const base_statement.RiscVStatement,
    extension: *const ethereum_statement.Statement,
    base_interaction_columns: u32,
    profile: *const profile_mod.Profile,
) !void {
    try profile.mixInto(core, extension, base_interaction_columns, channel);
}

/// Mixes the ordinary authenticated base and Ethereum claims followed by all
/// candidate component and batch claims in placement order.
pub fn mixInteractionClaimV2(
    channel: anytype,
    core: *const base_statement.RiscVStatement,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    base: *const base_statement.RiscVInteractionClaim,
    ethereum: *const ethereum_types.ExtensionClaim,
    profile: *const profile_mod.Profile,
    claims: Claims,
) !void {
    try claims.validate(profile);
    try ethereum_transcript.mixInteractionClaimV2(
        channel,
        core,
        manifest,
        authenticated,
        base,
        ethereum,
    );
    try mixCandidateClaim(channel, profile, claims);
}

/// Mixes only the four appended candidate claims. Tree-2 generators use this
/// after the canonical authenticated base + fourteen-component Ethereum claim
/// has already been mixed by the unchanged external-profile path.
pub fn mixCandidateClaim(
    channel: anytype,
    profile: *const profile_mod.Profile,
    claims: Claims,
) !void {
    try claims.validate(profile);
    channel.mixU32s(&.{
        0x4757_5453, // STWG
        0x3143_4c43, // CLC1
        appended_component_count,
    });
    mixOneClaim(channel, claims.bulk_memcpy_caller);
    mixOneClaim(channel, claims.bulk_memcpy_words);
    mixOneClaim(channel, claims.stack_swap_caller);
    mixOneClaim(channel, claims.stack_swap_words);
}

/// Exact provider-omission residual extended by all four candidate sums. The
/// two internal call buses must already close; provider proofs may cancel only
/// the physical narrow-memory Poseidon residual, never a candidate call bus.
pub fn residualWithoutNativePoseidonV2(
    projection: *const native_provider_omit.ProjectionV1,
    full_native: *const statement_v2.RiscVStatementV2,
    extension_statement: *const ethereum_statement.Statement,
    policy: @import("../statement_validation.zig").AdmissionPolicy,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    plan: *const provider_authority.ProviderShardPlanV1,
    calls: []const @import("../../air/memory_commitment/poseidon2_air.zig").Call,
    full_geometry: statement_geometry.Geometry,
    relations: *const Relations,
    base: *const base_statement.RiscVInteractionClaim,
    ethereum: *const ethereum_types.ExtensionClaim,
    profile: *const profile_mod.Profile,
    candidate: Claims,
) !QM31 {
    try relations.validate();
    const base_interaction_columns = std.math.cast(
        u32,
        try authenticated.totalInteractionColumns(
            &projection.projected_native.core,
            manifest,
        ),
    ) orelse return error.EthereumCandidateLeafGeometryOverflow;
    const admission = try candidate_admission.validateProjectedV2(
        full_native,
        &projection.projected_native.core,
        extension_statement,
        base_interaction_columns,
        profile,
        policy,
    );
    try candidate.validate(profile);
    const ordinary = try ethereum_cancellation
        .residualWithoutNativePoseidonWithRetirementSupplementV2(
        projection,
        full_native,
        extension_statement,
        policy,
        admission.retirementSupplementV2(),
        manifest,
        authenticated,
        plan,
        calls,
        full_geometry,
        &relations.ethereum,
        base,
        ethereum,
    );
    return ordinary.add(candidate.componentSum());
}

/// Complete-execution cancellation helper for tests and future non-omitted
/// candidate proofs. The provider-omitted path above returns a residual.
pub fn verifyGlobalCancellation(
    core: *const base_statement.RiscVStatement,
    relations: *const Relations,
    base: anytype,
    ethereum: *const ethereum_types.ExtensionClaim,
    profile: *const profile_mod.Profile,
    candidate: Claims,
) !void {
    try relations.validate();
    try candidate.validate(profile);
    const boundary = try public_logup.sum(&core.public_data, &relations.ethereum.base);
    try base_logup.verifyGlobalCancellation(
        &.{ base.total(), ethereum.componentSum(), candidate.componentSum() },
        boundary,
    );
}

fn fillPreprocessed(out: anytype, trace: anytype) void {
    for (out, 0..) |*column, index| column.* = trace.preprocessedColumn(index);
}

fn validateClaimGeometry(claim: anytype, descriptor: anytype) !void {
    if (claim.n_rows != descriptor.n_rows or
        claim.log_size != descriptor.log_size)
    {
        return error.EthereumCandidateLeafClaimGeometryMismatch;
    }
}

fn mixOneClaim(channel: anytype, claim: anytype) void {
    channel.mixU32s(&.{ claim.log_size, claim.n_rows });
    channel.mixFelts(&claim.batch_sums);
    channel.mixFelts(&.{claim.component_sum});
}

fn fillMain(out: anytype, trace: anytype) void {
    for (out, 0..) |*column, index| column.* = trace.mainColumn(index);
}

fn fillInteraction(out: anytype, interaction: anytype) void {
    for (out, interaction.columns) |*column, values| column.* = values;
}

fn validateColumnLengths(columns: anytype, log_size: u32) !void {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidTraceShape;
    const expected = @as(usize, 1) << @intCast(log_size);
    for (columns) |column| if (column.len != expected)
        return error.InvalidTraceShape;
}

fn block(log_size: u32, columns: []const []const M31) external_tree.BorrowedBlock {
    return .{ .log_size = log_size, .columns = columns };
}

fn placementBulk(value: profile_mod.Placement) bulk_stark.Placement {
    return .{
        .preprocessed_offset = value.preprocessed_offset,
        .main_offset = value.main_offset,
        .interaction_offset = value.interaction_offset,
    };
}

fn placementSwap(value: profile_mod.Placement) swap_stark.Placement {
    return .{
        .preprocessed_offset = value.preprocessed_offset,
        .main_offset = value.main_offset,
        .interaction_offset = value.interaction_offset,
    };
}

comptime {
    if (production_active or profile_mod.production_active or
        appended_component_count != 4 or
        bulk_stark.production_active or swap_stark.production_active)
    {
        @compileError("combined Ethereum candidate leaf integration became active");
    }
}
