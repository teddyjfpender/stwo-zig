//! Candidate-only Tree 0/1/2 materialization for the combined Ethereum leaf.
//!
//! The canonical projected core and fourteen Ethereum components always remain
//! the prefix. Bulk-memcpy caller/word and U256-SWAP caller/word blocks append
//! in the verifier-visible profile order. Fixed-table registration and claim
//! mixing share the canonical base tables/transcript; no standalone residual
//! is treated as a closed VM proof.

const std = @import("std");

const M31 = @import("stwo_core").fields.m31.M31;
const prover_pcs = @import("stwo_prover_engine").pcs;
const stage_profile = @import("stwo_prover_api").stage_profile;
const work_pool = @import("stwo_prover_engine").work_pool;

const lookup_physical_v2 = @import("../../air/lang/lookup_physical_manifest_v2.zig");
const base_statement = @import("../../air/statement.zig");
const statement_v2 = @import("../../air/statement_v2.zig");
const bulk_contract = @import("../../air/guest_precompile/bulk_memcpy_component_v1.zig");
const bulk_interaction = @import("../../air/guest_precompile/bulk_memcpy_interaction_v1.zig");
const bulk_trace_mod = @import("../../air/guest_precompile/bulk_memcpy_trace_v1.zig");
const ethereum_statement = @import("../../air/guest_precompile/ethereum_statement.zig");
const swap_contract = @import("../../air/guest_precompile/stack_swap_component_v1.zig");
const swap_interaction = @import("../../air/guest_precompile/stack_swap_interaction_v1.zig");
const swap_trace_mod = @import("../../air/guest_precompile/stack_swap_trace_v1.zig");
const swap_word_contract =
    @import("../../air/guest_precompile/stack_swap_word_candidate_v1.zig");
const state_chain = @import("../../runner/state_chain.zig");
const trace_mod = @import("../../runner/trace.zig");
const bulk_tape_mod = @import("../../runner/guest_precompile/bulk_memcpy_session_tape_v1.zig");
const keccak_calls_mod = @import("../../runner/guest_precompile/keccakf_call_buffer.zig");
const recovery_calls_mod = @import("../../runner/guest_precompile/secp256k1_recover_call_buffer.zig");
const swap_tape_mod = @import("../../runner/guest_precompile/stack_swap_session_tape_v1.zig");
const commitment_witness = @import("../commitment_witness.zig");
const lookup_sources = @import("../lookup_sources.zig");
const native_provider_omit = @import("../memory_provider_shards/native_provider_omit_v1.zig");
const proof_workspace = @import("../proof_workspace.zig");
const statement_geometry = @import("../statement_geometry.zig");
const external_tree = @import("external_profile_tree.zig");
const ethereum_interaction = @import("ethereum_interaction.zig");
const ethereum_main = @import("ethereum_main.zig");
const ethereum_preprocessed = @import("ethereum_preprocessed.zig");
const ethereum_transcript = @import("ethereum_transcript.zig");
const ethereum_types = @import("ethereum_types.zig");
const ethereum_witness = @import("ethereum_witness.zig");
const admission_mod = @import("ethereum_candidate_leaf_admission_v1.zig");
const integration = @import("ethereum_candidate_leaf_integration_v1.zig");
const lookup_registration = @import("ethereum_candidate_leaf_lookup_registration_v1.zig");
const profile_mod = @import("ethereum_candidate_leaf_profile_v1.zig");

pub const production_active = false;
pub const candidate_interaction_column_count: usize =
    bulk_contract.Caller.interaction_column_count +
    bulk_contract.Word.interaction_column_count +
    swap_contract.Caller.interaction_column_count +
    swap_contract.Word.interaction_column_count;

/// Live, transaction-local tapes and their independently reconstructed traces.
/// Every Tree entrypoint revalidates this boundary before moving any columns.
pub const CandidateWitness = struct {
    bulk_memcpy_tape: *const bulk_tape_mod.Frozen,
    stack_swap_tape: *const swap_tape_mod.Frozen,
    bulk_memcpy_trace: *const bulk_trace_mod.Bundle,
    stack_swap_trace: *const swap_trace_mod.Bundle,

    pub fn validate(
        self: CandidateWitness,
        profile: *const profile_mod.Profile,
    ) !void {
        try self.bulk_memcpy_trace.validateAgainst(self.bulk_memcpy_tape);
        try self.stack_swap_trace.validateAgainst(self.stack_swap_tape);
        const registration = lookup_registration.Context{
            .profile = profile,
            .bulk_memcpy = self.bulk_memcpy_tape,
            .stack_swap = self.stack_swap_tape,
        };
        try registration.validate();
        inline for (.{
            .{ self.bulk_memcpy_trace.caller.log_size, self.bulk_memcpy_trace.caller.logical_rows },
            .{ self.bulk_memcpy_trace.words.log_size, self.bulk_memcpy_trace.words.logical_rows },
            .{ self.stack_swap_trace.caller.log_size, self.stack_swap_trace.caller.logical_rows },
            .{ self.stack_swap_trace.words.log_size, self.stack_swap_trace.words.logical_rows },
        }, profile.components) |actual, descriptor| {
            if (actual[0] != descriptor.log_size or
                actual[1] != descriptor.n_rows)
            {
                return error.EthereumCandidateLeafTraceGeometryMismatch;
            }
        }
    }
};

pub const InteractionClaims = struct {
    ethereum: ethereum_types.ExtensionClaim,
    candidate: integration.Claims,

    pub fn validate(
        self: InteractionClaims,
        extension: *const ethereum_statement.Statement,
        profile: *const profile_mod.Profile,
    ) !void {
        try self.ethereum.validate(extension);
        try self.candidate.validate(profile);
    }
};

/// Mixes the complete field-native candidate authority before generating the
/// immutable Tree-0 values, then appends the four fixed-column blocks.
pub fn mixAndGenerateTree0(
    allocator: std.mem.Allocator,
    channel: anytype,
    projection: *const native_provider_omit.ProjectionV1,
    full_native: *const statement_v2.RiscVStatementV2,
    extension: *const ethereum_statement.Statement,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    profile: *const profile_mod.Profile,
    candidate: CandidateWitness,
) ![]prover_pcs.ColumnEvaluation {
    try validateAndMixTree0Authority(
        channel,
        projection,
        full_native,
        extension,
        manifest,
        authenticated,
        profile,
    );
    try candidate.validate(profile);
    var storage = CandidateBlocks.init(candidate);
    const blocks = storage.tree0();
    return ethereum_preprocessed.generateWithoutNativePoseidonV2WithExternalBlocks(
        allocator,
        projection,
        full_native,
        extension,
        &blocks,
    );
}

/// Cold-verifier reconstruction of the exact candidate Tree-0 values.
///
/// Unlike the prover entrypoint above, this path owns no execution tape and
/// trusts no witness-supplied selector. All twelve appended columns are
/// derived solely from the already-admitted profile row counts and log sizes.
/// The profile and its recomputed Admission are mixed in the identical order
/// before the caller commits the returned columns to the verifier scheme.
pub fn mixAndGenerateTree0ForVerifier(
    allocator: std.mem.Allocator,
    channel: anytype,
    projection: *const native_provider_omit.ProjectionV1,
    full_native: *const statement_v2.RiscVStatementV2,
    extension: *const ethereum_statement.Statement,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    profile: *const profile_mod.Profile,
) ![]prover_pcs.ColumnEvaluation {
    try validateAndMixTree0Authority(
        channel,
        projection,
        full_native,
        extension,
        manifest,
        authenticated,
        profile,
    );
    var storage = try VerifierPreprocessed.init(allocator, profile);
    defer storage.deinit(allocator);
    const blocks = storage.blocks();
    return ethereum_preprocessed.generateWithoutNativePoseidonV2WithExternalBlocks(
        allocator,
        projection,
        full_native,
        extension,
        &blocks,
    );
}

fn validateAndMixTree0Authority(
    channel: anytype,
    projection: *const native_provider_omit.ProjectionV1,
    full_native: *const statement_v2.RiscVStatementV2,
    extension: *const ethereum_statement.Statement,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    profile: *const profile_mod.Profile,
) !void {
    try projection.validateSealAndFull(full_native, extension);
    try authenticated.validateAgainst(&projection.projected_native.core, manifest);
    const base_interaction_columns: u32 = @intCast(
        try authenticated.totalInteractionColumns(
            &projection.projected_native.core,
            manifest,
        ),
    );
    try profile.validate(
        &projection.projected_native.core,
        extension,
        base_interaction_columns,
    );
    try integration.mixPreTree0Authority(
        channel,
        &projection.projected_native.core,
        extension,
        base_interaction_columns,
        profile,
    );
    const admission = try admission_mod.validateProjectedV2(
        full_native,
        &projection.projected_native.core,
        extension,
        base_interaction_columns,
        profile,
        .proof,
    );
    admission.mixInto(channel);
}

/// Commits Tree 1 with both candidate traces and their range-table requests.
/// Memory/program/state tuples remain on the canonical base relation and are
/// therefore not registered as a candidate-local table.
pub fn commitTree1(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *proof_workspace.ProofWorkspace,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    exec_trace: *const trace_mod.Trace,
    base_witness: *const commitment_witness.CommitmentWitness,
    full_geometry: statement_geometry.Geometry,
    opt_chain: ?*const state_chain.StateChainTracker,
    extension: *const ethereum_witness.Witness,
    keccak_calls: []const keccak_calls_mod.Record,
    recovery_calls: []const recovery_calls_mod.Record,
    full_native: *const statement_v2.RiscVStatementV2,
    extension_statement: *const ethereum_statement.Statement,
    projection: *const native_provider_omit.ProjectionV1,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    profile: *const profile_mod.Profile,
    candidate: CandidateWitness,
) !external_tree.MainRetained {
    try projection.validateSealAndFull(full_native, extension_statement);
    try authenticated.validateAgainst(&projection.projected_native.core, manifest);
    const base_interaction_columns: u32 = @intCast(
        try authenticated.totalInteractionColumns(
            &projection.projected_native.core,
            manifest,
        ),
    );
    try profile.validate(
        &projection.projected_native.core,
        extension_statement,
        base_interaction_columns,
    );
    try candidate.validate(profile);
    var storage = CandidateBlocks.init(candidate);
    const blocks = storage.tree1();
    const registration = lookup_registration.Context{
        .profile = profile,
        .bulk_memcpy = candidate.bulk_memcpy_tape,
        .stack_swap = candidate.stack_swap_tape,
    };
    return ethereum_main.commitWithoutNativePoseidonWithExternalBlocks(
        Engine,
        allocator,
        workspace,
        scheme,
        channel,
        recorder,
        exec_trace,
        base_witness,
        full_geometry,
        opt_chain,
        extension,
        keccak_calls,
        recovery_calls,
        projection,
        &blocks,
        registration.registration(),
    );
}

/// Generates all four candidate LogUp traces under the shared base relation,
/// commits them after the canonical Ethereum interaction columns, and mixes
/// their claims after the ordinary authenticated V2 interaction claim.
pub fn generateAndCommitTree2(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *proof_workspace.ProofWorkspace,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    base_witness: *const commitment_witness.CommitmentWitness,
    full_geometry: statement_geometry.Geometry,
    lookup_source: *const lookup_sources.Result,
    prefix: *const integration.Prefix,
    extension: *const ethereum_witness.Witness,
    pool: *work_pool.WorkPool,
    base_claim: *base_statement.RiscVInteractionClaim,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    full_native: *const statement_v2.RiscVStatementV2,
    extension_statement: *const ethereum_statement.Statement,
    projection: *const native_provider_omit.ProjectionV1,
    profile: *const profile_mod.Profile,
    candidate: CandidateWitness,
) !InteractionClaims {
    try projection.validateSealAndFull(full_native, extension_statement);
    try authenticated.validateAgainst(&projection.projected_native.core, manifest);
    const base_interaction_columns: u32 = @intCast(
        try authenticated.totalInteractionColumns(
            &projection.projected_native.core,
            manifest,
        ),
    );
    try profile.validate(
        &projection.projected_native.core,
        extension_statement,
        base_interaction_columns,
    );
    try prefix.relations.validate();
    try candidate.validate(profile);

    var bulk_caller = try bulk_interaction.generate(
        bulk_contract.Caller,
        allocator,
        &candidate.bulk_memcpy_trace.caller,
        &prefix.relations.bulk_memcpy,
        pool,
    );
    defer bulk_caller.deinit(allocator);
    var bulk_words = try bulk_interaction.generate(
        bulk_contract.Word,
        allocator,
        &candidate.bulk_memcpy_trace.words,
        &prefix.relations.bulk_memcpy,
        pool,
    );
    defer bulk_words.deinit(allocator);
    const swap_inputs = swap_contract.Inputs{
        .relations = &prefix.relations.stack_swap,
        .authority = &profile.authority.stack_swap.stack_swap,
    };
    var swap_caller = try swap_interaction.generate(
        swap_contract.Caller,
        allocator,
        &candidate.stack_swap_trace.caller,
        swap_inputs,
        pool,
    );
    defer swap_caller.deinit(allocator);
    var swap_words = try swap_interaction.generate(
        swap_contract.Word,
        allocator,
        &candidate.stack_swap_trace.words,
        swap_inputs,
        pool,
    );
    defer swap_words.deinit(allocator);

    const claims = integration.Claims{
        .bulk_memcpy_caller = try bulk_contract.CallerClaim.canonical(
            candidate.bulk_memcpy_trace.caller.log_size,
            candidate.bulk_memcpy_trace.caller.logical_rows,
            bulk_caller.claims,
        ),
        .bulk_memcpy_words = try bulk_contract.WordClaim.canonical(
            candidate.bulk_memcpy_trace.words.log_size,
            candidate.bulk_memcpy_trace.words.logical_rows,
            bulk_words.claims,
        ),
        .stack_swap_caller = try swap_contract.CallerClaim.canonical(
            candidate.stack_swap_trace.caller.log_size,
            candidate.stack_swap_trace.caller.logical_rows,
            swap_caller.claims,
        ),
        .stack_swap_words = try swap_contract.WordClaim.canonical(
            candidate.stack_swap_trace.words.log_size,
            candidate.stack_swap_trace.words.logical_rows,
            swap_words.claims,
        ),
    };
    try claims.validate(profile);

    var columns: [candidate_interaction_column_count]external_tree.OwnedColumn =
        undefined;
    var cursor: usize = 0;
    appendOwned(
        &columns,
        &cursor,
        candidate.bulk_memcpy_trace.caller.log_size,
        &bulk_caller.columns,
    );
    appendOwned(
        &columns,
        &cursor,
        candidate.bulk_memcpy_trace.words.log_size,
        &bulk_words.columns,
    );
    appendOwned(
        &columns,
        &cursor,
        candidate.stack_swap_trace.caller.log_size,
        &swap_caller.columns,
    );
    appendOwned(
        &columns,
        &cursor,
        candidate.stack_swap_trace.words.log_size,
        &swap_words.columns,
    );
    if (cursor != columns.len) return error.InvalidTraceShape;

    const ordinary_prefix = ethereum_transcript.Prefix{
        .interaction_pow = prefix.interaction_pow,
        .relations = prefix.relations.ethereum,
    };
    const ethereum_claim = try ethereum_interaction
        .generateAndCommitWithoutNativePoseidonAuthenticatedLookupV2WithExternal(
        Engine,
        allocator,
        workspace,
        scheme,
        channel,
        recorder,
        base_witness,
        full_geometry,
        lookup_source,
        &ordinary_prefix,
        extension,
        pool,
        base_claim,
        manifest,
        authenticated,
        projection,
        columns[0..],
        CandidateMixContext{ .profile = profile, .claims = claims },
        mixCandidateClaim,
    );
    const result = InteractionClaims{
        .ethereum = ethereum_claim,
        .candidate = claims,
    };
    try result.validate(extension_statement, profile);
    return result;
}

pub const TreeLogSizes = struct {
    tree0: []u32,
    tree1: []u32,
    tree2: []u32,

    pub fn deinit(self: *TreeLogSizes, allocator: std.mem.Allocator) void {
        allocator.free(self.tree2);
        allocator.free(self.tree1);
        allocator.free(self.tree0);
        self.* = undefined;
    }
};

/// Verifier and prover derive all three append-only tree shapes from the same
/// field-native profile. No witness column is trusted to supply a log size.
pub fn logSizes(
    allocator: std.mem.Allocator,
    core: *const base_statement.RiscVStatement,
    extension: *const ethereum_statement.Statement,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    profile: *const profile_mod.Profile,
) !TreeLogSizes {
    try authenticated.validateAgainst(core, manifest);
    const base_interaction_columns: u32 = @intCast(
        try authenticated.totalInteractionColumns(core, manifest),
    );
    try profile.validate(core, extension, base_interaction_columns);

    const tree0_prefix = try ethereum_preprocessed.logSizes(
        allocator,
        core,
        extension,
    );
    defer allocator.free(tree0_prefix);
    const tree1_prefix = try ethereum_main.logSizes(allocator, core, extension);
    defer allocator.free(tree1_prefix);
    const tree2_prefix = try ethereum_interaction.logSizesAuthenticatedLookupV2(
        allocator,
        core,
        extension,
        manifest,
        authenticated,
    );
    defer allocator.free(tree2_prefix);

    var result = TreeLogSizes{
        .tree0 = try appendProfileLogs(
            allocator,
            tree0_prefix,
            profile,
            .preprocessed,
        ),
        .tree1 = undefined,
        .tree2 = undefined,
    };
    errdefer allocator.free(result.tree0);
    result.tree1 = try appendProfileLogs(
        allocator,
        tree1_prefix,
        profile,
        .main,
    );
    errdefer allocator.free(result.tree1);
    result.tree2 = try appendProfileLogs(
        allocator,
        tree2_prefix,
        profile,
        .interaction,
    );
    return result;
}

const CandidateMixContext = struct {
    profile: *const profile_mod.Profile,
    claims: integration.Claims,
};

fn mixCandidateClaim(
    context: CandidateMixContext,
    channel: anytype,
    _: *const base_statement.RiscVInteractionClaim,
    _: *const ethereum_types.ExtensionClaim,
) !void {
    try integration.mixCandidateClaim(channel, context.profile, context.claims);
}

const CandidateBlocks = struct {
    bulk_caller_preprocessed: [bulk_trace_mod.preprocessed_column_count][]const M31,
    bulk_word_preprocessed: [bulk_trace_mod.preprocessed_column_count][]const M31,
    swap_caller_preprocessed: [swap_trace_mod.preprocessed_column_count][]const M31,
    swap_word_preprocessed: [swap_trace_mod.preprocessed_column_count][]const M31,
    bulk_caller_main: [bulk_contract.Caller.main_column_count][]const M31,
    bulk_word_main: [bulk_contract.Word.main_column_count][]const M31,
    swap_caller_main: [swap_contract.Caller.main_column_count][]const M31,
    swap_word_main: [swap_contract.Word.main_column_count][]const M31,
    log_sizes: [profile_mod.component_count]u32,

    fn init(candidate: CandidateWitness) CandidateBlocks {
        var result: CandidateBlocks = undefined;
        fillPreprocessed(
            &result.bulk_caller_preprocessed,
            &candidate.bulk_memcpy_trace.caller,
        );
        fillPreprocessed(
            &result.bulk_word_preprocessed,
            &candidate.bulk_memcpy_trace.words,
        );
        fillPreprocessed(
            &result.swap_caller_preprocessed,
            &candidate.stack_swap_trace.caller,
        );
        fillPreprocessed(
            &result.swap_word_preprocessed,
            &candidate.stack_swap_trace.words,
        );
        fillMain(&result.bulk_caller_main, &candidate.bulk_memcpy_trace.caller);
        fillMain(&result.bulk_word_main, &candidate.bulk_memcpy_trace.words);
        fillMain(&result.swap_caller_main, &candidate.stack_swap_trace.caller);
        fillMain(&result.swap_word_main, &candidate.stack_swap_trace.words);
        result.log_sizes = .{
            candidate.bulk_memcpy_trace.caller.log_size,
            candidate.bulk_memcpy_trace.words.log_size,
            candidate.stack_swap_trace.caller.log_size,
            candidate.stack_swap_trace.words.log_size,
        };
        return result;
    }

    fn tree0(self: *const CandidateBlocks) [profile_mod.component_count]external_tree.BorrowedBlock {
        return .{
            block(self.log_sizes[0], &self.bulk_caller_preprocessed),
            block(self.log_sizes[1], &self.bulk_word_preprocessed),
            block(self.log_sizes[2], &self.swap_caller_preprocessed),
            block(self.log_sizes[3], &self.swap_word_preprocessed),
        };
    }

    fn tree1(self: *const CandidateBlocks) [profile_mod.component_count]external_tree.BorrowedBlock {
        return .{
            block(self.log_sizes[0], &self.bulk_caller_main),
            block(self.log_sizes[1], &self.bulk_word_main),
            block(self.log_sizes[2], &self.swap_caller_main),
            block(self.log_sizes[3], &self.swap_word_main),
        };
    }
};

const VerifierPreprocessed = struct {
    storage: [profile_mod.component_count][]M31,
    columns: [profile_mod.component_count][bulk_trace_mod.preprocessed_column_count][]const M31,
    log_sizes: [profile_mod.component_count]u32,

    fn init(
        allocator: std.mem.Allocator,
        profile: *const profile_mod.Profile,
    ) !VerifierPreprocessed {
        comptime if (bulk_trace_mod.preprocessed_column_count !=
            swap_trace_mod.preprocessed_column_count)
        {
            @compileError("candidate preprocessed widths diverged");
        };
        var result: VerifierPreprocessed = undefined;
        var initialized: usize = 0;
        errdefer for (result.storage[0..initialized]) |values|
            allocator.free(values);

        for (profile.components, 0..) |descriptor, component| {
            if (descriptor.preprocessed_columns !=
                bulk_trace_mod.preprocessed_column_count or
                descriptor.log_size >= @bitSizeOf(usize))
            {
                return error.InvalidTraceShape;
            }
            const size = @as(usize, 1) << @intCast(descriptor.log_size);
            const cell_count = std.math.mul(
                usize,
                size,
                bulk_trace_mod.preprocessed_column_count,
            ) catch return error.InvalidTraceShape;
            result.storage[component] = try allocator.alloc(M31, cell_count);
            initialized += 1;
            @memset(result.storage[component], M31.zero());
            for (&result.columns[component], 0..) |*column, index|
                column.* = result.storage[component][index * size ..][0..size];
            result.log_sizes[component] = descriptor.log_size;
            fillCanonicalPreprocessed(
                &result.columns[component],
                descriptor,
            );
        }
        return result;
    }

    fn deinit(
        self: *VerifierPreprocessed,
        allocator: std.mem.Allocator,
    ) void {
        for (self.storage) |values| allocator.free(values);
        self.* = undefined;
    }

    fn blocks(
        self: *const VerifierPreprocessed,
    ) [profile_mod.component_count]external_tree.BorrowedBlock {
        return .{
            block(self.log_sizes[0], &self.columns[0]),
            block(self.log_sizes[1], &self.columns[1]),
            block(self.log_sizes[2], &self.columns[2]),
            block(self.log_sizes[3], &self.columns[3]),
        };
    }
};

fn fillCanonicalPreprocessed(
    columns: *[bulk_trace_mod.preprocessed_column_count][]const M31,
    descriptor: profile_mod.ComponentDescriptor,
) void {
    const size = @as(usize, 1) << @intCast(descriptor.log_size);
    switch (descriptor.kind) {
        .bulk_memcpy_caller, .bulk_memcpy_words => {
            @constCast(columns[bulk_trace_mod.domain_first_column])[
                bulk_trace_mod.committedRow(0, descriptor.log_size)
            ] = M31.one();
            @constCast(columns[bulk_trace_mod.domain_last_column])[
                bulk_trace_mod.committedRow(size - 1, descriptor.log_size)
            ] = M31.one();
            for (0..descriptor.n_rows) |logical|
                @constCast(columns[bulk_trace_mod.active_prefix_column])[
                    bulk_trace_mod.committedRow(logical, descriptor.log_size)
                ] = M31.one();
        },
        .stack_swap_caller, .stack_swap_words => {
            @constCast(columns[swap_trace_mod.domain_first_column])[
                swap_trace_mod.committedRow(0, descriptor.log_size)
            ] = M31.one();
            for (0..size) |logical| {
                const physical = swap_trace_mod.committedRow(
                    logical,
                    descriptor.log_size,
                );
                if (logical < descriptor.n_rows)
                    @constCast(columns[swap_trace_mod.active_prefix_column])[
                        physical
                    ] = M31.one();
                if (logical % swap_word_contract.lane_count ==
                    swap_word_contract.lane_count - 1)
                    @constCast(columns[swap_trace_mod.lane_last_column])[
                        physical
                    ] = M31.one();
            }
        },
    }
}

const ColumnFamily = enum { preprocessed, main, interaction };

fn appendProfileLogs(
    allocator: std.mem.Allocator,
    prefix: []const u32,
    profile: *const profile_mod.Profile,
    family: ColumnFamily,
) ![]u32 {
    var additional: usize = 0;
    for (profile.components) |descriptor| additional = std.math.add(
        usize,
        additional,
        switch (family) {
            .preprocessed => descriptor.preprocessed_columns,
            .main => descriptor.main_columns,
            .interaction => descriptor.interaction_columns,
        },
    ) catch return error.InvalidTraceShape;
    const result = try allocator.alloc(u32, prefix.len + additional);
    @memcpy(result[0..prefix.len], prefix);
    var cursor = prefix.len;
    for (profile.components) |descriptor| {
        const count: usize = switch (family) {
            .preprocessed => descriptor.preprocessed_columns,
            .main => descriptor.main_columns,
            .interaction => descriptor.interaction_columns,
        };
        @memset(result[cursor..][0..count], descriptor.log_size);
        cursor += count;
    }
    if (cursor != result.len) return error.InvalidTraceShape;
    return result;
}

fn appendOwned(
    destination: *[candidate_interaction_column_count]external_tree.OwnedColumn,
    cursor: *usize,
    log_size: u32,
    columns: anytype,
) void {
    for (columns) |*values| {
        destination[cursor.*] = .{ .log_size = log_size, .values = values };
        cursor.* += 1;
    }
}

fn fillPreprocessed(destination: anytype, trace: anytype) void {
    for (destination, 0..) |*column, index|
        column.* = trace.preprocessedColumn(index);
}

fn fillMain(destination: anytype, trace: anytype) void {
    for (destination, 0..) |*column, index|
        column.* = trace.mainColumn(index);
}

fn block(log_size: u32, columns: []const []const M31) external_tree.BorrowedBlock {
    return .{ .log_size = log_size, .columns = columns };
}

comptime {
    if (production_active or profile_mod.production_active or
        integration.production_active or lookup_registration.production_active or
        candidate_interaction_column_count != 128)
    {
        @compileError("combined Ethereum candidate Tree materializer became active");
    }
}
