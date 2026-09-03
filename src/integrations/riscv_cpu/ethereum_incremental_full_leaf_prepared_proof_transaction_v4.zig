//! One-pass process-local preparation for a full Ethereum V4 leaf proof.
//!
//! The legacy producer prepares a native statement, Ethereum witness,
//! extension, and profile before proving, while the current orchestration
//! entry point reconstructs the statement geometry and Ethereum witness a
//! second time.  This owner is the additive handoff for removing that work:
//! it retains exactly one populated `ProofWorkspace`, one full incremental
//! witness, one Ethereum witness, and their statement/extension/profile.
//!
//! This file deliberately does not alter the default producer. The additive
//! prepared orchestration entry borrows `proofView()`; the existing entry
//! point and canonical proof bytes remain unchanged.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_v4 = @import("ethereum_incremental_boundary_artifact_v4.zig");
const boundary_v4 = @import("ethereum_incremental_boundary_authority_v4.zig");
const full_leaf = @import("ethereum_incremental_full_leaf_proof_v4.zig");
const profile_mod = @import("ethereum_incremental_full_leaf_profile_v4.zig");
const prepared_program_mod =
    @import("ethereum_incremental_prepared_program_commitment_v1.zig");

const ethereum_statement = frontend.air.guest_precompile.ethereum_statement;
const public_data = frontend.air.public_data;
const public_data_v2 = frontend.air.public_data_v2;
const statement_geometry = frontend.testing.statement_geometry;
const statement_v2 = frontend.air.statement_v2;
const proof_workspace = frontend.testing.proof_workspace;
const minimal = frontend.runner.minimal_trace;
const memory_state = frontend.runner.memory_state;
const ethereum_witness = frontend.prover_mod.guest_precompile.ethereum_witness;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 1;
pub const SERIALIZABLE = false;
pub const DIGEST_IS_ADMISSION = false;
pub const DEFAULT_PRODUCER_CHANGED = false;
pub const PREPARED_ORCHESTRATION_AVAILABLE = true;

const TOKEN_DOMAIN =
    "stwo-zig/ethereum-incremental-full-leaf-prepared-proof-transaction/v4\x00";
const PROVIDER_CALL_SOURCE_DOMAIN =
    "stwo-zig/ethereum-incremental-full-leaf-provider-call-source/v2\x00";

/// Exact constructor-call inventory. These are calls to typed authority
/// owners, not estimates inferred from timings. The transport remint count is
/// pinned to zero: the profile must be minted from the already-owned cold
/// reconstruction and boundary witness.
pub const ConstructionReceiptV1 = struct {
    cold_reconstructions: u32,
    boundary_witness_builds: u32,
    full_witness_builds: u32,
    workspace_builds: u32,
    statement_geometry_builds: u32,
    ethereum_witness_builds: u32,
    extension_builds: u32,
    profile_mints_from_cold: u32,
    profile_mints_from_transport: u32,

    pub fn onePass() ConstructionReceiptV1 {
        return .{
            .cold_reconstructions = 1,
            .boundary_witness_builds = 1,
            .full_witness_builds = 1,
            .workspace_builds = 1,
            .statement_geometry_builds = 1,
            .ethereum_witness_builds = 1,
            .extension_builds = 1,
            .profile_mints_from_cold = 1,
            .profile_mints_from_transport = 0,
        };
    }

    pub fn validate(self: ConstructionReceiptV1) !void {
        if (!std.meta.eql(self, onePass()))
            return error.InvalidIncrementalPreparedConstructionReceiptV4;
    }
};

pub const CounterSnapshotV1 = struct {
    construction: ConstructionReceiptV1,
    phase_timing: PhaseTimingV1,
    prepared_program_work: ?frontend.testing.commitment_witness
        .PreparedProgramWorkReceiptV1,
    owner_validations: u64,
    proof_view_borrows: u64,
};

pub const PhaseTimingV1 = struct {
    witness_prepare_ns: u64,
    statement_profile_prepare_ns: u64,

    pub fn validate(self: PhaseTimingV1) !void {
        if (self.witness_prepare_ns == 0 or
            self.statement_profile_prepare_ns == 0)
        {
            return error.InvalidIncrementalPreparedPhaseTimingV4;
        }
    }
};

/// Mutable diagnostics stay behind the process-local owner and never enter a
/// transcript or codec.
pub const CountersV1 = struct {
    owner_validations: std.atomic.Value(u64) = .init(0),
    proof_view_borrows: std.atomic.Value(u64) = .init(0),

    pub fn recordValidation(self: *const CountersV1) void {
        const mutable = @constCast(self);
        _ = mutable.owner_validations.fetchAdd(1, .monotonic);
    }

    pub fn recordBorrow(self: *const CountersV1) void {
        const mutable = @constCast(self);
        _ = mutable.proof_view_borrows.fetchAdd(1, .monotonic);
    }

    pub fn snapshot(
        self: *const CountersV1,
        construction: ConstructionReceiptV1,
        phase_timing: PhaseTimingV1,
        prepared_program_work: ?frontend.testing.commitment_witness
            .PreparedProgramWorkReceiptV1,
    ) CounterSnapshotV1 {
        return .{
            .construction = construction,
            .phase_timing = phase_timing,
            .prepared_program_work = prepared_program_work,
            .owner_validations = self.owner_validations.load(.acquire),
            .proof_view_borrows = self.proof_view_borrows.load(.acquire),
        };
    }
};

/// Borrowed inputs after compact replay. All owners must outlive the prepared
/// transaction. No digest-only or reconstructed substitute is accepted.
pub const InputsV4 = struct {
    replay: *const minimal.EthereumReplayResultV1,
    memory_snapshot: *const memory_state.Snapshot,
    program_source_identity_sha256: [32]u8,
    completion: public_data.Completion,
    boundary_artifact: *const artifact_v4.OwnedArtifactV4,
    public_wire: *const public_data_v2.PublicDataV2,
    role_aware_public: *const public_data.PublicData,
    public_authority: boundary_v4.SegmentPublicAuthorityV4,
    /// Optional only so the legacy constructor remains byte- and API-stable.
    /// `initOwnedWithPreparedProgram` requires this exact live owner, while
    /// `initOwned` rejects it and retains the reconstructing path.
    prepared_program: ?*const prepared_program_mod.PreparedProgramCommitmentV1 = null,

    pub fn validateBorrowed(self: InputsV4) !void {
        try self.public_wire.validate();
        try self.role_aware_public.validate();
        try self.public_authority.validate();
        try self.boundary_artifact.validateCanonical(
            artifact_v4.default_limits,
        );
        if (self.prepared_program) |prepared_program| {
            const borrowed = try prepared_program.borrow();
            if (!std.mem.eql(
                u8,
                &borrowed.inventory.program_source_identity_sha256,
                &self.program_source_identity_sha256,
            ) or !std.meta.eql(
                borrowed.layout.*,
                self.memory_snapshot.layout,
            ) or borrowed.declared_rows.len !=
                self.memory_snapshot.program_words.len)
            {
                return error.InvalidIncrementalPreparedProgramBindingV4;
            }
            for (
                borrowed.declared_rows,
                self.memory_snapshot.program_words,
            ) |expected, actual| {
                if (!std.meta.eql(expected, actual))
                    return error.InvalidIncrementalPreparedProgramBindingV4;
            }
        }
        if (self.replay.execution_trace.step_count == 0 or
            std.mem.allEqual(u8, &self.program_source_identity_sha256, 0) or
            self.public_authority.public_data != self.role_aware_public or
            !std.meta.eql(
                self.role_aware_public.completion,
                @as(?public_data.Completion, self.completion),
            ) or !std.meta.eql(
            self.public_wire.wireId(),
            self.boundary_artifact.segment_public_wire_id,
        )) {
            return error.InvalidIncrementalPreparedInputsV4;
        }
    }
};

/// Pointer snapshot sealed only for in-process ownership closure. Its digest
/// is not stable across processes and is explicitly not proof admission.
pub const LivePointerSnapshotV1 = struct {
    owner_anchor_ptr: usize,
    replay_ptr: usize,
    memory_snapshot_ptr: usize,
    boundary_artifact_ptr: usize,
    public_wire_ptr: usize,
    role_public_ptr: usize,
    workspace_ptr: usize,
    prepared_witness_ptr: usize,
    ethereum_witness_ptr: usize,
    statement_ptr: usize,
    extension_ptr: usize,
    profile_ptr: usize,
    trace_rows_ptr: usize,
    trace_rows_len: usize,
    keccak_records_ptr: usize,
    keccak_records_len: usize,
    recovery_records_ptr: usize,
    recovery_records_len: usize,
    public_wire_id: public_data_v2.Digest,
    boundary_content_sha256: [32]u8,
    statement_authority_id: [8]u32,
    profile_identity_sha256: [32]u8,
    program_source_identity_sha256: [32]u8,
    prepared_program_owner_ptr: usize,
    prepared_program_token_ptr: usize,
    prepared_program_identity_sha256: [32]u8,

    pub fn validate(self: LivePointerSnapshotV1) !void {
        inline for (.{
            self.owner_anchor_ptr,
            self.replay_ptr,
            self.memory_snapshot_ptr,
            self.boundary_artifact_ptr,
            self.public_wire_ptr,
            self.role_public_ptr,
            self.workspace_ptr,
            self.prepared_witness_ptr,
            self.ethereum_witness_ptr,
            self.statement_ptr,
            self.extension_ptr,
            self.profile_ptr,
            self.trace_rows_ptr,
            self.trace_rows_len,
        }) |value| if (value == 0)
            return error.InvalidIncrementalPreparedPointerSnapshotV4;
        const has_prepared_program = self.prepared_program_owner_ptr != 0 or
            self.prepared_program_token_ptr != 0 or
            !std.mem.allEqual(
                u8,
                &self.prepared_program_identity_sha256,
                0,
            );
        if ((has_prepared_program and
            (self.prepared_program_owner_ptr == 0 or
                self.prepared_program_token_ptr == 0 or
                std.mem.allEqual(
                    u8,
                    &self.prepared_program_identity_sha256,
                    0,
                ))) or
            (self.keccak_records_len != 0 and self.keccak_records_ptr == 0) or
            (self.recovery_records_len != 0 and
                self.recovery_records_ptr == 0) or
            allZeroFields(self.public_wire_id) or
            std.mem.allEqual(u8, &self.boundary_content_sha256, 0) or
            allZeroFields(self.statement_authority_id) or
            std.mem.allEqual(u8, &self.profile_identity_sha256, 0) or
            std.mem.allEqual(u8, &self.program_source_identity_sha256, 0))
        {
            return error.InvalidIncrementalPreparedPointerSnapshotV4;
        }
    }
};

pub const ProcessTokenV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    snapshot: LivePointerSnapshotV1,
    seal_sha256: [32]u8,

    pub fn init(snapshot: LivePointerSnapshotV1) !ProcessTokenV1 {
        try snapshot.validate();
        const result = ProcessTokenV1{
            .snapshot = snapshot,
            .seal_sha256 = snapshotIdentity(snapshot),
        };
        try result.validateAgainst(snapshot);
        return result;
    }

    pub fn validateAgainst(
        self: *const ProcessTokenV1,
        snapshot: LivePointerSnapshotV1,
    ) !void {
        try snapshot.validate();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.meta.eql(self.snapshot, snapshot) or
            !std.mem.eql(u8, &self.seal_sha256, &snapshotIdentity(snapshot)))
        {
            return error.InvalidIncrementalPreparedProcessTokenV4;
        }
    }
};

const StorageV4 = struct {
    allocator: std.mem.Allocator,
    inputs: InputsV4,
    prepared_witness: full_leaf.PreparedWitnessV4,
    workspace: *proof_workspace.ProofWorkspace,
    geometry: statement_geometry.V2Geometry,
    ethereum_witness: ethereum_witness.Witness,
    extension: ethereum_statement.Statement,
    profile: profile_mod.AuthorityV4,
    construction: ConstructionReceiptV1,
    phase_timing: PhaseTimingV1,
    prepared_program_binding: ?PreparedProgramBindingV1,
    counters: CountersV1,
    token: ProcessTokenV1,
};

const PreparedProgramBindingV1 = struct {
    owner: *const prepared_program_mod.PreparedProgramCommitmentV1,
    token: *const prepared_program_mod.TokenV1,
    inventory_identity_sha256: [32]u8,

    fn init(
        owner: *const prepared_program_mod.PreparedProgramCommitmentV1,
    ) !PreparedProgramBindingV1 {
        const borrowed = try owner.borrow();
        return .{
            .owner = owner,
            .token = borrowed.token,
            .inventory_identity_sha256 = borrowed.inventory.identity_sha256,
        };
    }

    fn validate(self: PreparedProgramBindingV1) !void {
        const borrowed = try self.owner.borrow();
        if (self.token != borrowed.token or
            !std.mem.eql(
                u8,
                &self.inventory_identity_sha256,
                &borrowed.inventory.identity_sha256,
            ))
        {
            return error.InvalidIncrementalPreparedProgramBindingV4;
        }
    }
};

/// Exact borrowed surface for the additive prepared orchestration entry.
/// Every pointer is owned by or transitively retained through one heap-stable
/// `PreparedProofTransactionV4` storage block.
pub const ProofViewV4 = struct {
    replay: *const minimal.EthereumReplayResultV1,
    workspace: *proof_workspace.ProofWorkspace,
    geometry: *const statement_geometry.V2Geometry,
    prepared_witness: *const full_leaf.PreparedWitnessV4,
    ethereum_witness: *const ethereum_witness.Witness,
    extension: *const ethereum_statement.Statement,
    profile: *const profile_mod.AuthorityV4,
    role_aware_public: *const public_data.PublicData,
    boundary_artifact: *const artifact_v4.OwnedArtifactV4,
    public_wire: *const public_data_v2.PublicDataV2,
    public_authority: boundary_v4.SegmentPublicAuthorityV4,
};

/// Borrowed exact ordered Poseidon-call source for candidate provider
/// autoresearch. The calls remain owned by this prepared transaction; the
/// source identity binds the already-cold-admitted boundary, public wire, and
/// full-leaf profile, but is not a serializable proof admission token.
pub const ProviderCallViewV1 = struct {
    calls: []const poseidon2_air.Call,
    calls_owner_ptr: usize,
    source_identity_sha256: [32]u8,
    program_source_identity_sha256: [32]u8,
    inventory: ProviderCallInventoryV1,
    boundary_content_sha256: [32]u8,
    profile_identity_sha256: [32]u8,
    segment_public_wire_id: public_data_v2.Digest,

    pub fn validateAgainst(
        self: ProviderCallViewV1,
        owner: *const PreparedProofTransactionV4,
    ) !void {
        try owner.validateBorrowed();
        const storage = owner.storage;
        const expected_calls = storage.prepared_witness.full.base.poseidonCalls();
        const expected_inventory = try providerCallInventory(storage);
        if (self.calls.len == 0 or
            self.calls.ptr != expected_calls.ptr or
            self.calls.len != expected_calls.len or
            self.calls_owner_ptr != @intFromPtr(&storage.prepared_witness) or
            !std.mem.eql(
                u8,
                &self.program_source_identity_sha256,
                &storage.inputs.program_source_identity_sha256,
            ) or !std.meta.eql(self.inventory, expected_inventory) or
            !std.mem.eql(
                u8,
                &self.boundary_content_sha256,
                &storage.inputs.boundary_artifact.content_sha256,
            ) or !std.mem.eql(
            u8,
            &self.profile_identity_sha256,
            &storage.profile.identity_sha256,
        ) or !std.meta.eql(
            self.segment_public_wire_id,
            storage.inputs.public_wire.wireId(),
        ) or !std.mem.eql(
            u8,
            &self.source_identity_sha256,
            &providerCallSourceIdentity(storage, expected_inventory),
        )) return error.InvalidIncrementalPreparedProviderCallViewV4;
    }
};

/// Exact process-local decomposition of the native Poseidon provider table.
/// `CommitmentWitness` fixes its order as program-tree calls followed by the
/// incremental-memory transition calls. This value does not authorize either
/// source by digest; it is re-derived from their retained owners on every
/// `ProviderCallViewV1` validation.
pub const ProviderCallInventoryV1 = struct {
    program_base: u32,
    program_end: u32,
    declared_program_word_count: u64,
    committed_program_word_count: u64,
    program_leaf_count: u64,
    program_call_count: u64,
    program_commitment_root: u32,
    incremental_memory_call_count: u64,
    total_call_count: u64,
};

pub const PreparedProofTransactionV4 = struct {
    storage: *StorageV4,

    const Self = @This();

    pub fn initOwned(
        allocator: std.mem.Allocator,
        inputs: InputsV4,
    ) !Self {
        if (inputs.prepared_program != null)
            return error.PreparedProgramRequiresExplicitConstructorV4;
        return initOwnedInternal(false, allocator, inputs);
    }

    /// Explicit prepared-program entry. This has no reconstructing fallback:
    /// the caller must retain the exact P2 owner until this transaction is
    /// deinitialized, and every borrow revalidates its process-local token.
    pub fn initOwnedWithPreparedProgram(
        allocator: std.mem.Allocator,
        inputs: InputsV4,
    ) !Self {
        if (inputs.prepared_program == null)
            return error.MissingPreparedProgramCommitmentV4;
        return initOwnedInternal(true, allocator, inputs);
    }

    fn initOwnedInternal(
        comptime use_prepared_program: bool,
        allocator: std.mem.Allocator,
        inputs: InputsV4,
    ) !Self {
        try inputs.validateBorrowed();
        const prepared_program_binding: ?PreparedProgramBindingV1 =
            if (use_prepared_program)
                try PreparedProgramBindingV1.init(inputs.prepared_program.?)
            else
                null;

        var witness_timer = try std.time.Timer.start();
        var prepared = if (use_prepared_program) blk: {
            const prepared_program = try inputs.prepared_program.?.borrow();
            break :blk try full_leaf
                .prepareFullWitnessFromColdArtifactPreparedProgram(
                allocator,
                .{
                    inputs.replay.execution_trace.rows.items,
                    inputs.replay.keccakf_execution_rows.rows(),
                    inputs.replay.signer_recovery_execution_rows.rows(),
                },
                inputs.memory_snapshot,
                inputs.completion,
                prepared_program,
                inputs.boundary_artifact,
                inputs.public_wire,
                inputs.public_authority,
                artifact_v4.default_limits,
            );
        } else try full_leaf.prepareFullWitnessFromColdArtifact(
            allocator,
            .{
                inputs.replay.execution_trace.rows.items,
                inputs.replay.keccakf_execution_rows.rows(),
                inputs.replay.signer_recovery_execution_rows.rows(),
            },
            inputs.memory_snapshot,
            inputs.completion,
            inputs.boundary_artifact,
            inputs.public_wire,
            inputs.public_authority,
            artifact_v4.default_limits,
        );
        const witness_prepare_ns = witness_timer.read();
        var prepared_owned = true;
        errdefer if (prepared_owned) prepared.deinit(allocator);

        var profile_timer = try std.time.Timer.start();
        const workspace = try proof_workspace.ProofWorkspace.create(allocator);
        var workspace_owned = true;
        errdefer if (workspace_owned) workspace.destroy(allocator);

        const external_count = std.math.add(
            usize,
            inputs.replay.keccakf_calls.records().len,
            inputs.replay.signer_recovery_calls.records().len,
        ) catch return error.IncrementalPreparedResourceOverflowV4;
        const external_retirements = std.math.cast(u32, external_count) orelse
            return error.IncrementalPreparedResourceOverflowV4;
        const geometry = try statement_geometry.buildExternalV2(
            allocator,
            workspace,
            &inputs.replay.execution_trace,
            &prepared.full.base,
            &inputs.replay.state_chain_tracker,
            inputs.public_wire.*,
            external_retirements,
            .proof,
        );
        try geometry.statement.validate();
        const core_public = try statement_v2.canonicalCorePublicData(
            &geometry.statement.public_data,
        );

        var external = try ethereum_witness.Witness.init(
            allocator,
            inputs.replay.keccakf_calls.records(),
            inputs.replay.keccakf_execution_rows.rows(),
            inputs.replay.signer_recovery_calls.records(),
            inputs.replay.signer_recovery_execution_rows.rows(),
            core_public.clock,
        );
        var external_owned = true;
        errdefer if (external_owned) external.deinit();
        const extension = try ethereum_statement.Statement.canonicalV2(
            &geometry.statement,
            std.math.cast(
                u32,
                inputs.replay.keccakf_calls.records().len,
            ) orelse return error.IncrementalPreparedResourceOverflowV4,
            std.math.cast(
                u32,
                inputs.replay.signer_recovery_calls.records().len,
            ) orelse return error.IncrementalPreparedResourceOverflowV4,
            external.shapes(),
        );
        const profile = try prepared.mintProfile(
            inputs.boundary_artifact,
            inputs.public_authority,
            &geometry.statement,
            &extension,
        );
        const statement_profile_prepare_ns = profile_timer.read();

        const storage = try allocator.create(StorageV4);
        var storage_owned = false;
        errdefer if (storage_owned) {
            storage.ethereum_witness.deinit();
            storage.workspace.destroy(allocator);
            storage.prepared_witness.deinit(allocator);
            allocator.destroy(storage);
        } else allocator.destroy(storage);
        storage.* = .{
            .allocator = allocator,
            .inputs = inputs,
            .prepared_witness = prepared,
            .workspace = workspace,
            .geometry = geometry,
            .ethereum_witness = external,
            .extension = extension,
            .profile = profile,
            .construction = ConstructionReceiptV1.onePass(),
            .phase_timing = .{
                .witness_prepare_ns = witness_prepare_ns,
                .statement_profile_prepare_ns = statement_profile_prepare_ns,
            },
            .prepared_program_binding = prepared_program_binding,
            .counters = .{},
            .token = undefined,
        };
        prepared_owned = false;
        workspace_owned = false;
        external_owned = false;
        storage_owned = true;
        storage.token = try ProcessTokenV1.init(snapshotFor(storage));
        var result = Self{ .storage = storage };
        try result.validateBorrowed();
        storage_owned = false;
        return result;
    }

    pub fn deinit(self: *Self) void {
        const storage = self.storage;
        const allocator = storage.allocator;
        storage.ethereum_witness.deinit();
        storage.workspace.destroy(allocator);
        storage.prepared_witness.deinit(allocator);
        allocator.destroy(storage);
        self.* = undefined;
    }

    /// Revalidates pointer/value closure without reconstructing a statement,
    /// witness, extension, boundary, or profile.
    pub fn validateBorrowed(self: *const Self) !void {
        const storage = self.storage;
        try storage.construction.validate();
        try storage.phase_timing.validate();
        const program_work = storage.prepared_witness.full.base
            .preparedProgramWorkReceipt();
        if (storage.prepared_program_binding) |binding| {
            try binding.validate();
            if (storage.inputs.prepared_program != binding.owner or
                program_work == null)
            {
                return error.InvalidIncrementalPreparedProgramBindingV4;
            }
            try program_work.?.validate();
        } else if (storage.inputs.prepared_program != null or
            program_work != null)
        {
            return error.InvalidIncrementalPreparedProgramBindingV4;
        }
        try storage.token.validateAgainst(snapshotFor(storage));
        if (storage.inputs.public_authority.public_data !=
            storage.inputs.role_aware_public or
            !std.meta.eql(
                storage.geometry.statement.core,
                storage.workspace.statement,
            ) or !std.meta.eql(
            storage.geometry.statement.public_data.wireId(),
            storage.inputs.public_wire.wireId(),
        ) or !std.meta.eql(
            storage.profile.ethereum,
            storage.extension,
        )) {
            return error.InvalidIncrementalPreparedProofTransactionV4;
        }
        const roots = storage.prepared_witness.full.boundary.roots();
        if (roots.entry != storage.profile.continuation_roots.entry or
            roots.exit != storage.profile.continuation_roots.exit or
            storage.prepared_witness.full.boundary.bridgeRows().len !=
                @as(usize, storage.profile.bridge_geometry.n_rows))
        {
            return error.InvalidIncrementalPreparedProofTransactionV4;
        }
        try storage.profile.validateAgainstStatement(
            &storage.geometry.statement,
            &storage.extension,
            storage.inputs.role_aware_public,
        );
        storage.counters.recordValidation();
    }

    pub fn proofView(self: *const Self) !ProofViewV4 {
        try self.validateBorrowed();
        const storage = self.storage;
        storage.counters.recordBorrow();
        return .{
            .replay = storage.inputs.replay,
            .workspace = storage.workspace,
            .geometry = &storage.geometry,
            .prepared_witness = &storage.prepared_witness,
            .ethereum_witness = &storage.ethereum_witness,
            .extension = &storage.extension,
            .profile = &storage.profile,
            .role_aware_public = storage.inputs.role_aware_public,
            .boundary_artifact = storage.inputs.boundary_artifact,
            .public_wire = storage.inputs.public_wire,
            .public_authority = storage.inputs.public_authority,
        };
    }

    pub fn providerCallView(self: *const Self) !ProviderCallViewV1 {
        try self.validateBorrowed();
        const storage = self.storage;
        const calls = storage.prepared_witness.full.base.poseidonCalls();
        if (calls.len == 0)
            return error.MissingIncrementalPreparedProviderCallsV4;
        const inventory = try providerCallInventory(storage);
        storage.counters.recordBorrow();
        const result = ProviderCallViewV1{
            .calls = calls,
            .calls_owner_ptr = @intFromPtr(&storage.prepared_witness),
            .source_identity_sha256 = providerCallSourceIdentity(
                storage,
                inventory,
            ),
            .program_source_identity_sha256 = storage.inputs.program_source_identity_sha256,
            .inventory = inventory,
            .boundary_content_sha256 = storage.inputs.boundary_artifact.content_sha256,
            .profile_identity_sha256 = storage.profile.identity_sha256,
            .segment_public_wire_id = storage.inputs.public_wire.wireId(),
        };
        try result.validateAgainst(self);
        return result;
    }

    /// Proves directly from the retained workspace/witness transaction. This
    /// is the sole prepared entry and therefore cannot silently fall back to
    /// the reconstructing orchestration API.
    pub fn proveWithEngineUsingChannel(
        self: *const Self,
        comptime Engine: type,
        allocator: std.mem.Allocator,
        recorder: ?*@import("stwo_prover_api").stage_profile.Recorder,
        channel: *Engine.Channel,
        execution: frontend.testing
            .incremental_ethereum_orchestration_v4_internal.ExecutionOptions,
    ) !frontend.testing.incremental_ethereum_orchestration_v4_internal
        .ProveOutputV4(Engine) {
        const view = try self.proofView();
        const orchestration = frontend.testing
            .incremental_ethereum_orchestration_v4_internal;
        return orchestration.provePreparedWithEngineUsingChannel(
            Engine,
            allocator,
            try view.profile.pcsConfig(),
            &view.replay.execution_trace,
            &view.replay.state_chain_tracker,
            &view.prepared_witness.full,
            &view.geometry.statement,
            view.role_aware_public,
            &view.replay.keccakf_calls,
            &view.replay.keccakf_execution_rows,
            &view.replay.signer_recovery_calls,
            &view.replay.signer_recovery_execution_rows,
            .{
                .workspace = view.workspace,
                .geometry = view.geometry,
                .ethereum_witness = view.ethereum_witness,
                .extension = view.extension,
            },
            view.profile,
            recorder,
            channel,
            execution,
        );
    }

    pub fn counterSnapshot(self: *const Self) CounterSnapshotV1 {
        return self.storage.counters.snapshot(
            self.storage.construction,
            self.storage.phase_timing,
            self.storage.prepared_witness.full.base
                .preparedProgramWorkReceipt(),
        );
    }

    pub fn phaseTiming(self: *const Self) PhaseTimingV1 {
        return self.storage.phase_timing;
    }
};

fn snapshotFor(storage: *const StorageV4) LivePointerSnapshotV1 {
    const replay = storage.inputs.replay;
    const keccak = replay.keccakf_calls.records();
    const recovery = replay.signer_recovery_calls.records();
    const prepared_binding = storage.prepared_program_binding;
    return .{
        .owner_anchor_ptr = @intFromPtr(storage),
        .replay_ptr = @intFromPtr(replay),
        .memory_snapshot_ptr = @intFromPtr(storage.inputs.memory_snapshot),
        .boundary_artifact_ptr = @intFromPtr(storage.inputs.boundary_artifact),
        .public_wire_ptr = @intFromPtr(storage.inputs.public_wire),
        .role_public_ptr = @intFromPtr(storage.inputs.role_aware_public),
        .workspace_ptr = @intFromPtr(storage.workspace),
        .prepared_witness_ptr = @intFromPtr(&storage.prepared_witness),
        .ethereum_witness_ptr = @intFromPtr(&storage.ethereum_witness),
        .statement_ptr = @intFromPtr(&storage.geometry.statement),
        .extension_ptr = @intFromPtr(&storage.extension),
        .profile_ptr = @intFromPtr(&storage.profile),
        .trace_rows_ptr = @intFromPtr(replay.execution_trace.rows.items.ptr),
        .trace_rows_len = replay.execution_trace.rows.items.len,
        .keccak_records_ptr = if (keccak.len == 0) 0 else @intFromPtr(keccak.ptr),
        .keccak_records_len = keccak.len,
        .recovery_records_ptr = if (recovery.len == 0)
            0
        else
            @intFromPtr(recovery.ptr),
        .recovery_records_len = recovery.len,
        .public_wire_id = storage.inputs.public_wire.wireId(),
        .boundary_content_sha256 = storage.inputs.boundary_artifact.content_sha256,
        .statement_authority_id = storage.geometry.statement.authority_id,
        .profile_identity_sha256 = storage.profile.identity_sha256,
        .program_source_identity_sha256 = storage.inputs.program_source_identity_sha256,
        .prepared_program_owner_ptr = if (prepared_binding) |binding|
            @intFromPtr(binding.owner)
        else
            0,
        .prepared_program_token_ptr = if (prepared_binding) |binding|
            @intFromPtr(binding.token)
        else
            0,
        .prepared_program_identity_sha256 = if (prepared_binding) |binding|
            binding.inventory_identity_sha256
        else
            .{0} ** 32,
    };
}

fn snapshotIdentity(value: LivePointerSnapshotV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(TOKEN_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    inline for (std.meta.fields(LivePointerSnapshotV1)) |field| {
        const item = @field(value, field.name);
        if (comptime field.type == [32]u8) {
            hash.update(&item);
        } else if (comptime field.type == [8]u32) {
            for (item) |word| hashInt(&hash, u32, word);
        } else {
            hashInt(&hash, field.type, item);
        }
    }
    return hash.finalResult();
}

fn providerCallInventory(
    storage: *const StorageV4,
) !ProviderCallInventoryV1 {
    const base = &storage.prepared_witness.full.base;
    const program = &base.program;
    const declared_words = std.math.cast(
        u64,
        storage.inputs.memory_snapshot.program_words.len,
    ) orelse return error.IncrementalPreparedResourceOverflowV4;
    const committed_words = std.math.cast(u64, program.rows.len) orelse
        return error.IncrementalPreparedResourceOverflowV4;
    const program_leaves = std.math.cast(u64, program.tree.leaf_count) orelse
        return error.IncrementalPreparedResourceOverflowV4;
    const expected_leaves = std.math.mul(u64, committed_words, 4) catch
        return error.IncrementalPreparedResourceOverflowV4;
    const program_calls = std.math.cast(u64, program.tree.node_count) orelse
        return error.IncrementalPreparedResourceOverflowV4;
    const incremental_calls = std.math.cast(
        u64,
        storage.prepared_witness.full.boundary.transition.poseidon_calls.len,
    ) orelse return error.IncrementalPreparedResourceOverflowV4;
    const total_calls = std.math.add(
        u64,
        program_calls,
        incremental_calls,
    ) catch return error.IncrementalPreparedResourceOverflowV4;
    const base_call_count = std.math.cast(
        u64,
        base.poseidonCalls().len,
    ) orelse return error.IncrementalPreparedResourceOverflowV4;
    if (program_leaves != expected_leaves or
        total_calls != base_call_count)
    {
        return error.InvalidIncrementalPreparedProviderCallViewV4;
    }
    return .{
        .program_base = storage.inputs.memory_snapshot.layout.program_base,
        .program_end = storage.inputs.memory_snapshot.layout.program_end,
        .declared_program_word_count = declared_words,
        .committed_program_word_count = committed_words,
        .program_leaf_count = program_leaves,
        .program_call_count = program_calls,
        .program_commitment_root = program.tree.root,
        .incremental_memory_call_count = incremental_calls,
        .total_call_count = total_calls,
    };
}

fn providerCallSourceIdentity(
    storage: *const StorageV4,
    inventory: ProviderCallInventoryV1,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(PROVIDER_CALL_SOURCE_DOMAIN);
    hash.update(&storage.inputs.program_source_identity_sha256);
    hashInt(&hash, u32, inventory.program_base);
    hashInt(&hash, u32, inventory.program_end);
    hashInt(&hash, u64, inventory.declared_program_word_count);
    hashInt(&hash, u64, inventory.committed_program_word_count);
    hashInt(&hash, u64, inventory.program_leaf_count);
    hashInt(&hash, u64, inventory.program_call_count);
    hashInt(&hash, u32, inventory.program_commitment_root);
    hashInt(&hash, u64, inventory.incremental_memory_call_count);
    hashInt(&hash, u64, inventory.total_call_count);
    hash.update(&storage.inputs.boundary_artifact.content_sha256);
    hash.update(&storage.profile.identity_sha256);
    for (storage.inputs.public_wire.wireId()) |word|
        hashInt(&hash, u32, word);
    return hash.finalResult();
}

fn allZeroFields(value: [8]u32) bool {
    for (value) |word| if (word != 0) return false;
    return true;
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 1 or SERIALIZABLE or
        DIGEST_IS_ADMISSION or DEFAULT_PRODUCER_CHANGED or
        !PREPARED_ORCHESTRATION_AVAILABLE or
        !@hasDecl(PreparedProofTransactionV4, "initOwnedWithPreparedProgram") or
        @hasDecl(PreparedProofTransactionV4, "encode") or
        @hasDecl(PreparedProofTransactionV4, "decode") or
        @hasDecl(ProcessTokenV1, "encode") or
        @hasDecl(ProcessTokenV1, "decode"))
    {
        @compileError("prepared full-leaf transaction contract drifted");
    }
}
