const std = @import("std");
const stwo_core = @import("stwo_core");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");
const postcard = @import("interop_postcard");
const prover_engine = @import("stwo_prover_engine");
const prover_pcs = prover_engine.pcs;
const prover_work_pool = prover_engine.work_pool;
const contract = @import("recursive_binary_outer_contract.zig");
const verified_publication = @import("recursive_binary_verified_publication.zig");
const verified_artifact_v3 = @import("recursive_binary_v3_verified_artifact.zig");
const segment_publication = @import("recursive_segment_v2_verified_publication.zig");
const segment_artifact = @import("recursive_segment_v2_verified_artifact.zig");

const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const recursion = frontend.recursion;
const air = recursion.air;
const manifest_mod = air.universal_adapter_manifest;
const poseidon2_channel = recursion.poseidon2_channel;
const Engine = recursion.engine.ProverEngineForBackend(CpuBackend);
const VerifierScheme = stwo_core.pcs.verifier.CommitmentSchemeVerifier(
    recursion.engine.Hasher,
    recursion.engine.MerkleChannel,
);
const COMPLETE_ROW_COUNT = contract.COMPLETE_ROW_COUNT;
const OuterProofCapture = stwo_core.pcs.verifier.VerifiedProofCapture(
    recursion.engine.Hasher,
);
const VerifiedBinaryClosurePublicationV2 = contract.VerifiedBinaryClosurePublicationV2;
const VerifiedBinaryArtifactV3 = contract.VerifiedBinaryArtifactV3;
const TemporalVerifierSuccessBindingV1 = contract.TemporalVerifierSuccessBindingV1;
const TemporalVerifierSuccessEvidenceStorageV1 = contract.TemporalVerifierSuccessEvidenceStorageV1;
const TemporalVerifierSuccessEvidenceV1 = contract.TemporalVerifierSuccessEvidenceV1;
const Receipt = contract.Receipt;

pub fn canonicalProofIdentity(
    proof: recursion.engine.Proof,
) !verified_publication.CanonicalProofIdentityV1 {
    var counter = ProofLengthWriter{};
    try postcard.serializeProof(
        recursion.engine.Hasher,
        &counter,
        proof,
    );
    var identity_stream = try verified_publication
        .CanonicalProofIdentityStreamV1.init(counter.byte_count);
    try postcard.serializeProof(
        recursion.engine.Hasher,
        &identity_stream,
        proof,
    );
    return identity_stream.finalize();
}

const ProofLengthWriter = struct {
    byte_count: usize = 0,

    pub fn write(self: *ProofLengthWriter, bytes: []const u8) !usize {
        self.byte_count = try std.math.add(
            usize,
            self.byte_count,
            bytes.len,
        );
        return bytes.len;
    }

    pub fn writeAll(self: *ProofLengthWriter, bytes: []const u8) !void {
        _ = try self.write(bytes);
    }

    pub fn writeByte(self: *ProofLengthWriter, byte: u8) !void {
        const bytes = [_]u8{byte};
        _ = try self.write(&bytes);
    }
};

/// Current honest entrypoint. Both source authorities are revalidated first;
/// the capability error is returned before any transcript, scheme, tree, or
/// output publication exists. `capture_out` is untouched on every error.
pub const ProofExecutionPool = struct {
    pool: prover_work_pool.WorkPool = undefined,
    binding: prover_work_pool.ScopedPoolBinding = undefined,
    requested_worker_count: usize = 1,
    pool_initialized: bool = false,
    binding_initialized: bool = false,

    pub fn initInPlace(
        self: *ProofExecutionPool,
        allocator: std.mem.Allocator,
        worker_count: usize,
    ) !void {
        self.* = .{};
        _ = try prover_work_pool.WorkerBudget.init(worker_count);
        self.requested_worker_count = worker_count;
        if (worker_count == 1) return;
        try self.pool.initInPlaceWithOptions(.{
            .worker_count = worker_count,
            .stack_size = prover_work_pool.WORKER_STACK_SIZE,
            .backing_allocator = allocator,
        });
        self.pool_initialized = true;
        errdefer {
            self.pool.deinit();
            self.pool_initialized = false;
        }
        self.binding = try prover_work_pool.ScopedPoolBinding.init(&self.pool);
        self.binding_initialized = true;
    }

    pub fn visibleWorkerCount(self: *ProofExecutionPool) !usize {
        if (self.requested_worker_count == 1) {
            if (self.pool_initialized or self.binding_initialized)
                return error.WorkerPoolMismatch;
            return 1;
        }
        if (!self.pool_initialized or !self.binding_initialized)
            return error.WorkerPoolMismatch;
        const visible = prover_work_pool.getGlobalPool() orelse
            return error.WorkerPoolMismatch;
        if (visible != &self.pool or
            visible.workerCount() != self.requested_worker_count)
        {
            return error.WorkerPoolMismatch;
        }
        return visible.workerCount();
    }

    pub fn deinit(self: *ProofExecutionPool) void {
        if (self.binding_initialized) {
            self.binding.deinit();
            self.binding_initialized = false;
        }
        if (self.pool_initialized) {
            self.pool.deinit();
            self.pool_initialized = false;
        }
    }
};

pub fn assertCohortContract(comptime Cohort: type) void {
    inline for (.{
        "AuthorityInputs",
        "GeneratedInteractionsV1",
        "init",
        "deinit",
        "validate",
        "manifest",
        "mixAuthority",
        "fillPreprocessedInto",
        "fillMainInto",
        "fillInteractionInto",
        "validateGenerated",
        "auditGlobalClosure",
        "auditGlobalClosureV2",
        "claimVector",
        "rebuildGeneratedInteractions",
        "initComponents",
        "publicationAuthority",
        "recursiveStatementWords",
    }) |name| if (!@hasDecl(Cohort, name))
        @compileError("binary outer Cohort contract is incomplete: missing " ++ name);
}

pub fn assertNativeCohortContract(comptime Cohort: type) void {
    inline for (.{
        "AuthorityInputs",
        "GeneratedInteractionsV1",
        "AuditedInteractionsV2",
        "VerifiedPublicationV1",
        "VerifiedArtifactV1",
        "PAIR_AUTHENTICATION_POSEIDON_PERMUTATIONS",
        "init",
        "deinit",
        "validate",
        "manifest",
        "mixAuthority",
        "fillPreprocessedInto",
        "fillMainInto",
        "fillInteractionInto",
        "validateGenerated",
        "auditGlobalClosure",
        "auditGlobalClosureV2",
        "claimVector",
        "rebuildGeneratedInteractions",
        "initComponents",
        "validateAuditedInteractions",
        "verifierSuccessBinding",
        "publishSuccessfulVerifier",
    }) |name| if (!@hasDecl(Cohort, name))
        @compileError(
            "native outer Cohort contract is incomplete: missing " ++ name,
        );
}

pub fn assertManifestContract(comptime ManifestContract: type) void {
    inline for (.{
        "Manifest",
        "Placement",
        "Geometry",
        "ProofGate",
        "TREE_COUNT",
        "PREPROCESSED_TREE_INDEX",
        "MAIN_TREE_INDEX",
        "INTERACTION_TREE_INDEX",
        "COMPONENT_COUNT",
    }) |name| if (!@hasDecl(ManifestContract, name))
        @compileError(
            "binary outer manifest contract is incomplete: missing " ++ name,
        );

    if (ManifestContract.TREE_COUNT != 3 or
        ManifestContract.COMPONENT_COUNT != COMPLETE_ROW_COUNT or
        ManifestContract.PREPROCESSED_TREE_INDEX ==
            ManifestContract.MAIN_TREE_INDEX or
        ManifestContract.PREPROCESSED_TREE_INDEX ==
            ManifestContract.INTERACTION_TREE_INDEX or
        ManifestContract.MAIN_TREE_INDEX ==
            ManifestContract.INTERACTION_TREE_INDEX)
    {
        @compileError("binary outer manifest tree contract drifted");
    }
}

pub fn moveOwnedForVerifier(
    comptime T: type,
    value: *T,
    owned: *bool,
) T {
    std.debug.assert(owned.*);
    const moved = value.*;
    value.* = undefined;
    owned.* = false;
    return moved;
}

pub fn rejectTransactionOutputAlias(
    capture_out: *OuterProofCapture,
    publication_out: *VerifiedBinaryClosurePublicationV2,
) !void {
    if (memoryOverlaps(
        std.mem.asBytes(capture_out),
        std.mem.asBytes(publication_out),
    )) return error.TransactionOutputAlias;
}

pub fn rejectNativeTransactionOutputAlias(
    comptime Publication: type,
    capture_out: *OuterProofCapture,
    publication_out: *Publication,
) !void {
    if (memoryOverlaps(
        std.mem.asBytes(capture_out),
        std.mem.asBytes(publication_out),
    )) return error.TransactionOutputAlias;
}

pub fn rejectNativeArtifactTransactionOutputAlias(
    comptime Publication: type,
    comptime Artifact: type,
    capture_out: *OuterProofCapture,
    publication_out: *Publication,
    artifact_out: *Artifact,
) !void {
    try rejectNativeTransactionOutputAlias(
        Publication,
        capture_out,
        publication_out,
    );
    if (memoryOverlaps(
        std.mem.asBytes(capture_out),
        std.mem.asBytes(artifact_out),
    ) or memoryOverlaps(
        std.mem.asBytes(publication_out),
        std.mem.asBytes(artifact_out),
    )) return error.TransactionOutputAlias;
}

pub fn rejectV3TransactionOutputAlias(
    capture_out: *OuterProofCapture,
    publication_out: *VerifiedBinaryClosurePublicationV2,
    artifact_out: *VerifiedBinaryArtifactV3,
) !void {
    try rejectTransactionOutputAlias(capture_out, publication_out);
    if (memoryOverlaps(
        std.mem.asBytes(capture_out),
        std.mem.asBytes(artifact_out),
    ) or memoryOverlaps(
        std.mem.asBytes(publication_out),
        std.mem.asBytes(artifact_out),
    )) return error.TransactionOutputAlias;
}

fn memoryOverlaps(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}

pub fn nativeDigestCanonicalNonzero(value: poseidon2_channel.Digest) bool {
    var any = false;
    for (value) |word| {
        if (word >= m31.Modulus) return false;
        any = any or word != 0;
    }
    return any;
}

pub fn temporalVerifierEvidenceIdentity(
    evidence: *const TemporalVerifierSuccessEvidenceStorageV1,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/temporal-verifier-success-evidence/v1\x00");
    evidenceHashInt(&hash, u16, evidence.format_version);
    evidenceHashInt(&hash, u8, @intFromBool(evidence.verified));
    hash.update(&evidence.padding);
    const binding = evidence.binding;
    evidenceHashInt(&hash, u32, binding.canonical_proof_byte_count);
    for (binding.proof_id) |word| evidenceHashInt(&hash, u32, word);
    hash.update(&binding.canonical_proof_sha_id);
    for (binding.capture_id) |word| evidenceHashInt(&hash, u32, word);
    for (binding.transcript_id) |word| evidenceHashInt(&hash, u32, word);
    hash.update(&binding.cohort_authority_sha_id);
    hash.update(&binding.manifest_sha_id);
    hash.update(&binding.claims_sha_id);
    hash.update(&binding.generated_interactions_sha_id);
    hash.update(&binding.audit_sha_id);
    hash.update(&binding.closure_receipt_sha_id);
    return hash.finalResult();
}

fn evidenceHashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: anytype,
) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

pub fn commitVerifierTreeForManifest(
    comptime manifest_contract: type,
    allocator: std.mem.Allocator,
    scheme: *VerifierScheme,
    manifest: *const manifest_contract.Manifest,
    tree: usize,
    commitment: recursion.engine.Hasher.Hash,
    channel: *Engine.Channel,
) !void {
    const logs = try allocator.alloc(
        u32,
        treeColumnCount(manifest_contract, manifest, tree),
    );
    defer allocator.free(logs);
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const placement = manifest.placements[row].?;
        const offset = treeOffset(manifest_contract, placement, tree);
        const count = treeGeometryColumns(
            manifest_contract,
            placement.geometry,
            tree,
        );
        @memset(logs[offset..][0..count], placement.geometry.log_size);
    }
    try scheme.commit(allocator, commitment, logs, channel);
}

pub fn TreeStorageForManifest(comptime manifest_contract: type) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        evaluations: []prover_pcs.ColumnEvaluation,
        columns: [][]M31,
        storage: []M31,
        backing: [][]M31,

        pub fn init(
            allocator: std.mem.Allocator,
            manifest: *const manifest_contract.Manifest,
            tree: usize,
        ) !Self {
            const count = treeColumnCount(manifest_contract, manifest, tree);
            const evaluations = try allocator.alloc(
                prover_pcs.ColumnEvaluation,
                count,
            );
            errdefer allocator.free(evaluations);
            for (manifest.roster_rows[0..manifest.roster_count]) |row| {
                const placement = manifest.placements[row].?;
                const offset = treeOffset(manifest_contract, placement, tree);
                const local_count = treeGeometryColumns(
                    manifest_contract,
                    placement.geometry,
                    tree,
                );
                for (evaluations[offset..][0..local_count]) |*evaluation|
                    evaluation.log_size = placement.geometry.log_size;
            }
            var cells: usize = 0;
            for (evaluations) |evaluation|
                cells = std.math.add(
                    usize,
                    cells,
                    @as(usize, 1) << @intCast(evaluation.log_size),
                ) catch return error.ArithmeticOverflow;
            const storage = try allocator.alloc(M31, cells);
            errdefer allocator.free(storage);
            @memset(storage, M31.zero());
            var cursor: usize = 0;
            for (evaluations) |*evaluation| {
                const rows = @as(usize, 1) << @intCast(evaluation.log_size);
                evaluation.values = storage[cursor..][0..rows];
                cursor += rows;
            }
            const columns = try allocator.alloc([]M31, count);
            errdefer allocator.free(columns);
            for (evaluations, columns) |evaluation, *column|
                column.* = @constCast(evaluation.values);
            const backing = try allocator.alloc([]M31, 1);
            errdefer allocator.free(backing);
            backing[0] = storage;
            return .{
                .allocator = allocator,
                .evaluations = evaluations,
                .columns = columns,
                .storage = storage,
                .backing = backing,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.evaluations.len != 0) self.allocator.free(self.evaluations);
            if (self.columns.len != 0) self.allocator.free(self.columns);
            if (self.backing.len != 0) self.allocator.free(self.backing);
            if (self.storage.len != 0) self.allocator.free(self.storage);
            self.* = undefined;
        }

        pub fn commit(
            self: *Self,
            scheme: *Engine.Scheme,
            channel: *Engine.Channel,
        ) !void {
            const evaluations = self.evaluations;
            const backing = self.backing;
            self.evaluations = &.{};
            self.backing = &.{};
            self.storage = &.{};
            try Engine.commitWithBacking(
                scheme,
                self.allocator,
                evaluations,
                backing,
                null,
                channel,
            );
        }
    };
}

pub fn treeColumnCount(
    comptime manifest_contract: type,
    manifest: *const manifest_contract.Manifest,
    tree: usize,
) usize {
    return switch (tree) {
        manifest_contract.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
        manifest_contract.MAIN_TREE_INDEX => manifest.total_main_columns,
        manifest_contract.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
        else => unreachable,
    };
}

pub fn treeOffset(
    comptime manifest_contract: type,
    placement: manifest_contract.Placement,
    tree: usize,
) usize {
    return switch (tree) {
        manifest_contract.PREPROCESSED_TREE_INDEX => placement.preprocessed_offset,
        manifest_contract.MAIN_TREE_INDEX => placement.main_offset,
        manifest_contract.INTERACTION_TREE_INDEX => placement.interaction_offset,
        else => unreachable,
    };
}

pub fn treeGeometryColumns(
    comptime manifest_contract: type,
    geometry: manifest_contract.Geometry,
    tree: usize,
) usize {
    return switch (tree) {
        manifest_contract.PREPROCESSED_TREE_INDEX => geometry.preprocessed_columns,
        manifest_contract.MAIN_TREE_INDEX => geometry.main_columns,
        manifest_contract.INTERACTION_TREE_INDEX => geometry.interaction_columns,
        else => unreachable,
    };
}
