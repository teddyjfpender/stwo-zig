//! Proof-independent Ethereum SegmentV2 geometry and provider-call authority.
//!
//! These helpers rebuild the fully admitted pre-Engine statement, expose the
//! exact three-tree geometry, and detach the ordered native Poseidon call list.
//! They never initialize a commitment scheme or mint proof authority.

const std = @import("std");
const prover_engine = @import("stwo_prover_engine");
const residency_estimate = prover_engine.pcs.residency_estimate;
const lookup_physical_v2 = @import("../../air/lang/lookup_physical_manifest_v2.zig");
const public_data_v2 = @import("../../air/public_data_v2.zig");
const statement_v2 = @import("../../air/statement_v2.zig");
const proof_admission = @import("../../air/guest_precompile/ethereum_proof_admission.zig");
const statement_mod = @import("../../air/guest_precompile/ethereum_statement.zig");
const poseidon2_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const candidate = @import("../../air/lang/typed_poseidon2_degree_bounded_candidate.zig");
const candidate_residency = @import("../../air/lang/typed_poseidon2_degree_bounded_residency.zig");
const keccak_calls_mod = @import("../../runner/guest_precompile/keccakf_call_buffer.zig");
const keccak_rows_mod = @import("../../runner/guest_precompile/keccakf_v1.zig");
const recovery_calls_mod = @import("../../runner/guest_precompile/secp256k1_recover_call_buffer.zig");
const recovery_rows_mod = @import("../../runner/guest_precompile/secp256k1_recover_v1.zig");
const runner_result = @import("../../runner/result.zig");
const commitment_witness = @import("../commitment_witness.zig");
const proof_workspace = @import("../proof_workspace.zig");
const statement_geometry = @import("../statement_geometry.zig");
const base_types = @import("../types.zig");
const ethereum_interaction = @import("ethereum_interaction.zig");
const ethereum_main = @import("ethereum_main.zig");
const ethereum_preprocessed = @import("ethereum_preprocessed.zig");
const ethereum_witness = @import("ethereum_witness.zig");
const inventory_v1 = @import("ethereum_segment_geometry_inventory_v1.zig");

pub const PoseidonCandidateProfile = candidate.Profile;
pub const PoseidonCandidateGeometry = candidate.Geometry;
pub const PoseidonCandidateResidencyEstimate = candidate_residency.Estimate;

/// Matches the commitment scheme's current default. Changing this product
/// policy requires a proof-byte identity regression before it is activated.
pub const tree1_coefficient_retention_policy: residency_estimate.RetentionPolicy = .always;

/// Diagnostic-only, proof-independent geometry for one fully authenticated
/// Ethereum SegmentV2 execution. This value is minted before `Engine.init` and
/// owns only compact log-size arrays and cold-reconstructed candidate
/// authorities; it never contains a commitment scheme or proof material.
pub const GeometrySnapshot = struct {
    allocator: std.mem.Allocator,
    tree0_log_sizes: []u32,
    tree1_non_candidate_log_sizes: []u32,
    tree2_log_sizes: []u32,
    legacy_poseidon: LegacyPoseidonSpan,
    degree5: CandidateEstimate,
    degree6: CandidateEstimate,

    pub fn deinit(self: *GeometrySnapshot) void {
        self.allocator.free(self.tree2_log_sizes);
        self.allocator.free(self.tree1_non_candidate_log_sizes);
        self.allocator.free(self.tree0_log_sizes);
        self.* = undefined;
    }
};

/// Exact, allocator-owned narrow-memory Poseidon call authority extracted from
/// the same fully admitted SegmentV2 witness used by the Ethereum prover.
pub const ProviderCallAuthorityV1 = struct {
    allocator: std.mem.Allocator,
    calls: []poseidon2_air.Call,
    public_data_wire_id: public_data_v2.Digest,

    pub fn deinit(self: *ProviderCallAuthorityV1) void {
        self.allocator.free(self.calls);
        self.* = undefined;
    }
};

pub const LegacyPoseidonSpan = struct {
    infra_index: u32,
    main_column_offset: u32,
    main_column_count: u32,
    log_size: u32,
    n_rows: u32,
};

pub const CandidateEstimate = struct {
    profile: candidate.Profile,
    candidate_identity: [32]u8,
    direct_program_digest: [32]u8,
    geometry: candidate.Geometry,
    residency: candidate_residency.Estimate,
};

pub const inventory_format_version = inventory_v1.format_version;
pub const ProgramInventoryV1 = inventory_v1.ProgramInventoryV1;
pub const SparseBoundaryInventoryV1 = inventory_v1.SparseBoundaryInventoryV1;
pub const ExecutionInventoryV1 = inventory_v1.ExecutionInventoryV1;

pub const CountedGeometryV1 = struct {
    inventory: ExecutionInventoryV1,
    geometry: GeometrySnapshot,

    pub fn deinit(self: *CountedGeometryV1) void {
        self.geometry.deinit();
        self.* = undefined;
    }
};

/// Rejects a Tree1 whose allocation-free PCS residency lower bound already
/// exceeds the caller's finite proof budget. Fitting is planning telemetry,
/// not an allocation guarantee, because Merkle nodes, twiddles, witness data,
/// and allocator overhead are intentionally outside this lower bound.
pub fn requireTree1Residency(
    column_log_sizes: []const u32,
    log_blowup_factor: u32,
    host_byte_budget: usize,
) residency_estimate.Error!residency_estimate.Estimate {
    const estimate = try residency_estimate.estimate(
        column_log_sizes,
        log_blowup_factor,
        tree1_coefficient_retention_policy,
    );
    const budget = std.math.cast(u64, host_byte_budget) orelse
        return error.ResidencyEstimateOverflow;
    try estimate.requireWithin(budget);
    return estimate;
}

/// Count-only sibling of `inspectPreEngineGeometry`. The caller supplies one
/// program inventory minted from the continuous session's first segment. Each
/// invocation rebinds the exact program image, validates the local execution
/// clocks and external tapes, counts entry/exit sparse frontiers, and derives
/// the same statement descriptors and tree log arrays as the full witness
/// route. It deliberately does not construct public-data roots, Merkle rows,
/// Poseidon calls, a provider plan, or any proof authority.
pub fn inspectPreEngineGeometryFromCountedInventoryV1(
    allocator: std.mem.Allocator,
    log_blowup_factor: u32,
    result: *const runner_result.SegmentResult,
    program: ProgramInventoryV1,
    keccak_calls: *const keccak_calls_mod.Frozen,
    keccak_rows: *const keccak_rows_mod.FrozenExecutionRows,
    recovery_calls: *const recovery_calls_mod.Frozen,
    recovery_rows: *const recovery_rows_mod.FrozenExecutionRows,
) !CountedGeometryV1 {
    if (result.execution_trace.step_count == 0)
        return base_types.ProverError.EmptyTrace;
    const local_cycles = std.math.cast(u32, result.cycle_count) orelse
        return base_types.ProverError.InvalidStatement;
    _ = try validateClockAuthority(
        &result.execution_trace,
        keccak_calls.len(),
        keccak_rows.rows().len,
        recovery_calls.len(),
        recovery_rows.rows().len,
        local_cycles,
    );
    const inventory = try inventory_v1.buildExecutionInventoryV1(
        allocator,
        result,
        program,
        std.math.cast(u32, keccak_calls.len()) orelse
            return error.InvalidExecutionInventory,
        std.math.cast(u32, recovery_calls.len()) orelse
            return error.InvalidExecutionInventory,
    );
    var core = try inventory_v1.countedCoreStatement(result, inventory);
    var extension_witness = try ethereum_witness.Witness.init(
        allocator,
        keccak_calls.records(),
        keccak_rows.rows(),
        recovery_calls.records(),
        recovery_rows.rows(),
        local_cycles,
    );
    defer extension_witness.deinit();
    // Tree geometry depends only on the canonical component descriptors. The
    // retained V3 source/journal authority separately authenticates the V2
    // public boundary; this count-only path must not rebuild those roots.
    const extension = try statement_mod.Statement.canonical(
        &core,
        inventory.keccak_calls,
        inventory.signer_calls,
        extension_witness.shapes(),
    );

    const tree0 = try ethereum_preprocessed.logSizes(allocator, &core, &extension);
    errdefer allocator.free(tree0);
    const tree1 = try ethereum_main.logSizes(allocator, &core, &extension);
    defer allocator.free(tree1);
    var manifest = lookup_physical_v2.Manifest.native();
    const authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
        &core,
        &manifest,
    );
    const tree2 = try ethereum_interaction.logSizesAuthenticatedLookupV2(
        allocator,
        &core,
        &extension,
        &manifest,
        &authenticated,
    );
    errdefer allocator.free(tree2);
    const removed = try removeLegacyPoseidonColumnsInternal(allocator, &core, tree1);
    errdefer allocator.free(removed.log_sizes);
    if (removed.span.n_rows != inventory.provider_call_count)
        return error.InvalidExecutionInventory;
    const degree5 = try candidateEstimateInternal(
        allocator,
        .degree5,
        removed.span.log_size,
        log_blowup_factor,
        tree0,
        removed.log_sizes,
        tree2,
    );
    const degree6 = try candidateEstimateInternal(
        allocator,
        .degree6,
        removed.span.log_size,
        log_blowup_factor,
        tree0,
        removed.log_sizes,
        tree2,
    );
    return .{
        .inventory = inventory,
        .geometry = .{
            .allocator = allocator,
            .tree0_log_sizes = tree0,
            .tree1_non_candidate_log_sizes = removed.log_sizes,
            .tree2_log_sizes = tree2,
            .legacy_poseidon = removed.span,
            .degree5 = degree5,
            .degree6 = degree6,
        },
    };
}

/// Reconstructs the exact pre-Engine statement and all three commitment-tree
/// log-size arrays for one retained Ethereum SegmentV2 execution. The legacy
/// narrow-memory Poseidon provider is removed from Tree1 by its typed infra
/// descriptor, never by a caller-supplied offset. Both lower-width candidates
/// are cold-built and estimated under coefficient retention `.never`.
pub fn inspectPreEngineGeometry(
    allocator: std.mem.Allocator,
    log_blowup_factor: u32,
    result: *const runner_result.SegmentResult,
    keccak_calls: *const keccak_calls_mod.Frozen,
    keccak_rows: *const keccak_rows_mod.FrozenExecutionRows,
    recovery_calls: *const recovery_calls_mod.Frozen,
    recovery_rows: *const recovery_rows_mod.FrozenExecutionRows,
    public_data: public_data_v2.PublicDataV2,
) !GeometrySnapshot {
    if (result.execution_trace.step_count == 0)
        return base_types.ProverError.EmptyTrace;

    const workspace = try proof_workspace.ProofWorkspace.create(allocator);
    defer workspace.destroy(allocator);
    const core_public = statement_v2.canonicalCorePublicData(&public_data) catch
        return base_types.ProverError.InvalidStatement;
    const external_count = try validateClockAuthority(
        &result.execution_trace,
        keccak_calls.len(),
        keccak_rows.rows().len,
        recovery_calls.len(),
        recovery_rows.rows().len,
        core_public.clock,
    );
    var base_witness = try commitment_witness.CommitmentWitness
        .buildExternalProfileV2(
        allocator,
        .rv32im_zkvm_ethereum_v1,
        .{
            result.execution_trace.rows.items,
            keccak_rows.rows(),
            recovery_rows.rows(),
        },
        &result.rw_memory,
        &public_data,
    );
    defer base_witness.deinit(allocator);
    const built = try statement_geometry.buildExternalV2(
        allocator,
        workspace,
        &result.execution_trace,
        &base_witness,
        &result.state_chain_tracker,
        public_data,
        external_count,
        .proof,
    );
    const native_statement = built.statement;
    const core = &workspace.statement;
    try native_statement.validateSegmentResult(result);

    var witness = try ethereum_witness.Witness.init(
        allocator,
        keccak_calls.records(),
        keccak_rows.rows(),
        recovery_calls.records(),
        recovery_rows.rows(),
        core_public.clock,
    );
    defer witness.deinit();
    const extension = try statement_mod.Statement.canonicalV2(
        &native_statement,
        @intCast(keccak_calls.len()),
        @intCast(recovery_calls.len()),
        witness.shapes(),
    );
    try proof_admission.validateV2(&native_statement, &extension, .proof);

    const tree0 = try ethereum_preprocessed.logSizes(
        allocator,
        core,
        &extension,
    );
    errdefer allocator.free(tree0);
    const tree1 = try ethereum_main.logSizes(allocator, core, &extension);
    defer allocator.free(tree1);
    var manifest = lookup_physical_v2.Manifest.native();
    const authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
        core,
        &manifest,
    );
    const tree2 = try ethereum_interaction.logSizesAuthenticatedLookupV2(
        allocator,
        core,
        &extension,
        &manifest,
        &authenticated,
    );
    errdefer allocator.free(tree2);

    const removed = try removeLegacyPoseidonColumnsInternal(allocator, core, tree1);
    errdefer allocator.free(removed.log_sizes);
    const degree5 = try candidateEstimateInternal(
        allocator,
        .degree5,
        removed.span.log_size,
        log_blowup_factor,
        tree0,
        removed.log_sizes,
        tree2,
    );
    const degree6 = try candidateEstimateInternal(
        allocator,
        .degree6,
        removed.span.log_size,
        log_blowup_factor,
        tree0,
        removed.log_sizes,
        tree2,
    );
    return .{
        .allocator = allocator,
        .tree0_log_sizes = tree0,
        .tree1_non_candidate_log_sizes = removed.log_sizes,
        .tree2_log_sizes = tree2,
        .legacy_poseidon = removed.span,
        .degree5 = degree5,
        .degree6 = degree6,
    };
}

/// Rebuilds only the proof-admitted base commitment witness, detaches its
/// ordered Poseidon call list, and tears down every other witness allocation
/// before returning.
pub fn buildProviderCallAuthorityV1(
    allocator: std.mem.Allocator,
    result: *const runner_result.SegmentResult,
    keccak_calls: *const keccak_calls_mod.Frozen,
    keccak_rows: *const keccak_rows_mod.FrozenExecutionRows,
    recovery_calls: *const recovery_calls_mod.Frozen,
    recovery_rows: *const recovery_rows_mod.FrozenExecutionRows,
    public_data: public_data_v2.PublicDataV2,
) !ProviderCallAuthorityV1 {
    if (result.execution_trace.step_count == 0)
        return base_types.ProverError.EmptyTrace;

    const workspace = try proof_workspace.ProofWorkspace.create(allocator);
    defer workspace.destroy(allocator);
    const core_public = statement_v2.canonicalCorePublicData(&public_data) catch
        return base_types.ProverError.InvalidStatement;
    const external_count = try validateClockAuthority(
        &result.execution_trace,
        keccak_calls.len(),
        keccak_rows.rows().len,
        recovery_calls.len(),
        recovery_rows.rows().len,
        core_public.clock,
    );
    var base_witness = try commitment_witness.CommitmentWitness
        .buildExternalProfileV2(
        allocator,
        .rv32im_zkvm_ethereum_v1,
        .{
            result.execution_trace.rows.items,
            keccak_rows.rows(),
            recovery_rows.rows(),
        },
        &result.rw_memory,
        &public_data,
    );
    defer base_witness.deinit(allocator);
    const built = try statement_geometry.buildExternalV2(
        allocator,
        workspace,
        &result.execution_trace,
        &base_witness,
        &result.state_chain_tracker,
        public_data,
        external_count,
        .proof,
    );
    try built.statement.validateSegmentResult(result);

    var extension_witness = try ethereum_witness.Witness.init(
        allocator,
        keccak_calls.records(),
        keccak_rows.rows(),
        recovery_calls.records(),
        recovery_rows.rows(),
        core_public.clock,
    );
    defer extension_witness.deinit();
    const extension = try statement_mod.Statement.canonicalV2(
        &built.statement,
        @intCast(keccak_calls.len()),
        @intCast(recovery_calls.len()),
        extension_witness.shapes(),
    );
    try proof_admission.validateV2(&built.statement, &extension, .proof);

    const calls = try base_witness.poseidon_calls.toOwnedSlice(allocator);
    base_witness.poseidon_calls = .{};
    if (calls.len == 0) {
        allocator.free(calls);
        return error.EmptyProviderCallAuthority;
    }
    return .{
        .allocator = allocator,
        .calls = calls,
        .public_data_wire_id = public_data.wireId(),
    };
}

pub const RemovedPoseidonColumns = struct {
    log_sizes: []u32,
    span: LegacyPoseidonSpan,
};

fn removeLegacyPoseidonColumnsInternal(
    allocator: std.mem.Allocator,
    core: *const @import("../../air/statement.zig").RiscVStatement,
    tree1_log_sizes: []const u32,
) !RemovedPoseidonColumns {
    const base_main_column_count: usize = @intCast(core.nMainColumns());
    if (tree1_log_sizes.len != base_main_column_count and
        tree1_log_sizes.len < base_main_column_count)
    {
        return error.InvalidTraceShape;
    }
    var offset: usize = core.nOpcodeMainColumns();
    var matched: ?LegacyPoseidonSpan = null;
    for (core.infra_descs[0..core.n_infra], 0..) |descriptor, infra_index| {
        const count: usize = @intCast(descriptor.n_columns);
        const end = std.math.add(usize, offset, count) catch
            return error.InvalidTraceShape;
        if (end > tree1_log_sizes.len) return error.InvalidTraceShape;
        if (descriptor.kind == .poseidon2) {
            if (matched != null or
                descriptor.n_columns != poseidon2_air.N_MAIN_COLUMNS)
            {
                return error.InvalidTraceShape;
            }
            for (tree1_log_sizes[offset..end]) |log_size| {
                if (log_size != descriptor.log_size)
                    return error.InvalidTraceShape;
            }
            matched = .{
                .infra_index = @intCast(infra_index),
                .main_column_offset = @intCast(offset),
                .main_column_count = descriptor.n_columns,
                .log_size = descriptor.log_size,
                .n_rows = descriptor.n_rows,
            };
        }
        offset = end;
    }
    if (offset != base_main_column_count) return error.InvalidTraceShape;
    const span = matched orelse return error.InvalidTraceShape;
    const count: usize = @intCast(span.main_column_count);
    const start: usize = @intCast(span.main_column_offset);
    const end = std.math.add(usize, start, count) catch
        return error.InvalidTraceShape;
    const output_len = std.math.sub(usize, tree1_log_sizes.len, count) catch
        return error.InvalidTraceShape;
    if (output_len == 0) return error.InvalidTraceShape;
    const output = try allocator.alloc(u32, output_len);
    @memcpy(output[0..start], tree1_log_sizes[0..start]);
    @memcpy(output[start..], tree1_log_sizes[end..]);
    return .{ .log_sizes = output, .span = span };
}

fn candidateEstimateInternal(
    allocator: std.mem.Allocator,
    profile: candidate.Profile,
    trace_log_size: u32,
    log_blowup_factor: u32,
    tree0_log_sizes: []const u32,
    tree1_non_candidate_log_sizes: []const u32,
    tree2_log_sizes: []const u32,
) !CandidateEstimate {
    var authority = try candidate.Candidate.init(allocator, profile);
    defer authority.deinit();
    try authority.validate();
    return .{
        .profile = profile,
        .candidate_identity = authority.identity,
        .direct_program_digest = authority.direct_program_digest,
        .geometry = authority.geometry,
        .residency = try candidate_residency.estimate(.{
            .profile = profile,
            .trace_log_size = trace_log_size,
            .log_blowup_factor = log_blowup_factor,
            .retention_policy = .never,
            .tree0_log_sizes = tree0_log_sizes,
            .tree1_non_candidate_log_sizes = tree1_non_candidate_log_sizes,
            .tree2_log_sizes = tree2_log_sizes,
        }),
    };
}

fn validateClockAuthority(
    trace: *const @import("../../runner/trace.zig").Trace,
    keccak_calls: usize,
    keccak_rows: usize,
    recovery_calls: usize,
    recovery_rows: usize,
    public_clock: u32,
) !u32 {
    if (keccak_calls != keccak_rows or recovery_calls != recovery_rows)
        return base_types.ProverError.InvalidStatement;
    const external = std.math.add(usize, keccak_calls, recovery_calls) catch
        return base_types.ProverError.InvalidStatement;
    const total = std.math.add(usize, trace.step_count, external) catch
        return base_types.ProverError.InvalidStatement;
    if (std.math.cast(u32, total) != public_clock or
        trace.recordedExternalSteps() != external)
    {
        return base_types.ProverError.InvalidStatement;
    }
    trace.validateClockRange(0, public_clock, external) catch
        return base_types.ProverError.InvalidStatement;
    return std.math.cast(u32, external) orelse
        return base_types.ProverError.InvalidStatement;
}

pub const testing = struct {
    pub fn removeLegacyPoseidonColumns(
        allocator: std.mem.Allocator,
        core: *const @import("../../air/statement.zig").RiscVStatement,
        tree1_log_sizes: []const u32,
    ) !RemovedPoseidonColumns {
        return removeLegacyPoseidonColumnsInternal(
            allocator,
            core,
            tree1_log_sizes,
        );
    }

    pub fn candidateEstimate(
        allocator: std.mem.Allocator,
        profile: candidate.Profile,
        trace_log_size: u32,
        log_blowup_factor: u32,
        tree0_log_sizes: []const u32,
        tree1_non_candidate_log_sizes: []const u32,
        tree2_log_sizes: []const u32,
    ) !CandidateEstimate {
        return candidateEstimateInternal(
            allocator,
            profile,
            trace_log_size,
            log_blowup_factor,
            tree0_log_sizes,
            tree1_non_candidate_log_sizes,
            tree2_log_sizes,
        );
    }
};
