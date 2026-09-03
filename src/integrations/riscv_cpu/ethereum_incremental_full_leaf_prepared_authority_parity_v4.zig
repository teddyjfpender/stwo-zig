//! Diagnostic equivalence between one-pass and legacy Stage101 preparation.
//!
//! The prepared transaction and the legacy producer must derive identical
//! statement geometry, Ethereum witness shape, extension, and profile from
//! the same cold authorities. This owner reconstructs the legacy branch only
//! when explicitly requested and returns a process-local comparison receipt.
//! Neither the receipt nor its hashes are proof admission.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const prepared_mod =
    @import("ethereum_incremental_full_leaf_prepared_proof_transaction_v4.zig");
const profile_mod = @import("ethereum_incremental_full_leaf_profile_v4.zig");

const ethereum_statement = frontend.air.guest_precompile.ethereum_statement;
const statement_geometry = frontend.testing.statement_geometry;
const statement_v2 = frontend.air.statement_v2;
const proof_workspace = frontend.testing.proof_workspace;
const ethereum_witness = frontend.prover_mod.guest_precompile.ethereum_witness;

pub const ENV_NAME = "STWO_ZIG_STAGE101_PREPARED_AUTHORITY_PARITY";
pub const SCHEMA_VERSION: u16 = 1;
pub const DIGEST_IS_ADMISSION = false;

pub const AuthoritySnapshotV1 = struct {
    core_trace_sha256: [32]u8,
    statement_authority_id: [8]u32,
    workspace_statement_authority_id: [8]u32,
    public_wire_id: [8]u32,
    witness_shapes_sha256: [32]u8,
    extension_identity_sha256: [32]u8,
    base_geometry_identity_sha256: [32]u8,
    bridge_geometry_identity_sha256: [32]u8,
    public_boundary_identity_sha256: [32]u8,
    profile_identity_sha256: [32]u8,
    keccak_calls: u32,
    signer_calls: u32,
    external_retirements: u32,

    pub fn validate(self: AuthoritySnapshotV1) !void {
        if (allZero(u8, &self.core_trace_sha256) or
            allZero(u32, &self.statement_authority_id) or
            allZero(u32, &self.workspace_statement_authority_id) or
            allZero(u32, &self.public_wire_id) or
            allZero(u8, &self.witness_shapes_sha256) or
            allZero(u8, &self.extension_identity_sha256) or
            allZero(u8, &self.base_geometry_identity_sha256) or
            allZero(u8, &self.bridge_geometry_identity_sha256) or
            allZero(u8, &self.public_boundary_identity_sha256) or
            allZero(u8, &self.profile_identity_sha256) or
            self.external_retirements != self.keccak_calls + self.signer_calls)
        {
            return error.InvalidStage101PreparedAuthoritySnapshotV4;
        }
    }
};

pub const MismatchFieldV1 = enum {
    core_trace,
    statement,
    workspace_statement,
    public_wire,
    ethereum_witness,
    extension,
    base_geometry,
    bridge_geometry,
    public_boundary,
    profile,
    call_counts,
};

pub const MismatchV1 = struct {
    field: MismatchFieldV1,
    prepared: AuthoritySnapshotV1,
    legacy: AuthoritySnapshotV1,
};

pub const ReceiptV1 = struct {
    schema_version: u16 = SCHEMA_VERSION,
    exact_authority_count: u16 = 11,
    snapshot: AuthoritySnapshotV1,

    pub fn validate(self: ReceiptV1) !void {
        try self.snapshot.validate();
        if (self.schema_version != SCHEMA_VERSION or
            self.exact_authority_count != 11)
        {
            return error.InvalidStage101PreparedAuthorityParityReceiptV4;
        }
    }
};

pub const ResultV1 = union(enum) {
    exact: ReceiptV1,
    mismatch: MismatchV1,
};

pub fn enabled() bool {
    return std.process.hasEnvVarConstant(ENV_NAME);
}

pub fn compareSnapshots(
    prepared: AuthoritySnapshotV1,
    legacy: AuthoritySnapshotV1,
) !ResultV1 {
    try prepared.validate();
    try legacy.validate();
    if (firstMismatch(prepared, legacy)) |field| return .{ .mismatch = .{
        .field = field,
        .prepared = prepared,
        .legacy = legacy,
    } };
    const receipt = ReceiptV1{ .snapshot = prepared };
    try receipt.validate();
    return .{ .exact = receipt };
}

/// Reconstructs the old preparation branch from the same live/cold owners.
/// Direct value comparisons precede identity comparisons so a collision or a
/// stale identity cannot promote a non-equivalent witness.
pub fn comparePreparedAgainstLegacy(
    allocator: std.mem.Allocator,
    view: prepared_mod.ProofViewV4,
) !ResultV1 {
    const replay = view.replay;
    const external_count = std.math.add(
        usize,
        replay.keccakf_calls.records().len,
        replay.signer_recovery_calls.records().len,
    ) catch return error.Stage101PreparedParityResourceOverflowV4;
    const external_retirements = std.math.cast(u32, external_count) orelse
        return error.Stage101PreparedParityResourceOverflowV4;

    const workspace = try proof_workspace.ProofWorkspace.create(allocator);
    defer workspace.destroy(allocator);
    const geometry = try statement_geometry.buildExternalV2(
        allocator,
        workspace,
        &replay.execution_trace,
        &view.prepared_witness.full.base,
        &replay.state_chain_tracker,
        view.public_wire.*,
        external_retirements,
        .proof,
    );
    const core_public = try statement_v2.canonicalCorePublicData(
        &geometry.statement.public_data,
    );
    var witness = try ethereum_witness.Witness.init(
        allocator,
        replay.keccakf_calls.records(),
        replay.keccakf_execution_rows.rows(),
        replay.signer_recovery_calls.records(),
        replay.signer_recovery_execution_rows.rows(),
        core_public.clock,
    );
    defer witness.deinit();
    const extension = try ethereum_statement.Statement.canonicalV2(
        &geometry.statement,
        @intCast(replay.keccakf_calls.records().len),
        @intCast(replay.signer_recovery_calls.records().len),
        witness.shapes(),
    );
    const profile = try view.prepared_witness.mintProfile(
        view.boundary_artifact,
        view.public_authority,
        &geometry.statement,
        &extension,
    );
    try profile.validateAgainstInputs(
        allocator,
        view.boundary_artifact,
        view.public_wire,
        view.public_authority,
        &geometry.statement,
        &extension,
        @import("ethereum_incremental_boundary_artifact_v4.zig").default_limits,
    );

    const prepared_snapshot = snapshot(
        view,
        view.ethereum_witness.shapes(),
        view.extension,
        view.profile,
    );
    const legacy_snapshot = snapshot(
        view,
        witness.shapes(),
        &extension,
        &profile,
    );
    if (!std.meta.eql(view.geometry.base, geometry.base))
        return mismatch(.base_geometry, prepared_snapshot, legacy_snapshot);
    if (!std.meta.eql(view.geometry.statement, geometry.statement))
        return mismatch(.statement, prepared_snapshot, legacy_snapshot);
    if (!std.meta.eql(view.workspace.statement, workspace.statement))
        return mismatch(.workspace_statement, prepared_snapshot, legacy_snapshot);
    if (!std.meta.eql(view.ethereum_witness.shapes(), witness.shapes()))
        return mismatch(.ethereum_witness, prepared_snapshot, legacy_snapshot);
    if (!std.meta.eql(view.extension.*, extension))
        return mismatch(.extension, prepared_snapshot, legacy_snapshot);
    if (!std.meta.eql(view.profile.*, profile))
        return mismatch(.profile, prepared_snapshot, legacy_snapshot);
    return compareSnapshots(prepared_snapshot, legacy_snapshot);
}

fn snapshot(
    view: prepared_mod.ProofViewV4,
    shapes: ethereum_statement.SecpShapes,
    extension: *const ethereum_statement.Statement,
    profile: *const profile_mod.AuthorityV4,
) AuthoritySnapshotV1 {
    return .{
        .core_trace_sha256 = traceIdentity(&view.replay.execution_trace),
        .statement_authority_id = view.geometry.statement.authority_id,
        // The V2 authority is the canonical identity of this exact embedded
        // core statement. A direct whole-value workspace comparison precedes
        // this snapshot comparison.
        .workspace_statement_authority_id = view.geometry.statement.authority_id,
        .public_wire_id = view.public_wire.wireId(),
        .witness_shapes_sha256 = shapesIdentity(shapes),
        .extension_identity_sha256 = profile.ethereum_identity_sha256,
        .base_geometry_identity_sha256 = profile.base_geometry.identity_sha256,
        .bridge_geometry_identity_sha256 = profile.bridge_geometry.identity_sha256,
        .public_boundary_identity_sha256 = profile.public_boundary_identity_sha256,
        .profile_identity_sha256 = profile.identity_sha256,
        .keccak_calls = extension.counts.keccak_calls,
        .signer_calls = extension.counts.signer_calls,
        .external_retirements = extension.counts.external_retirements,
    };
}

fn firstMismatch(
    prepared: AuthoritySnapshotV1,
    legacy: AuthoritySnapshotV1,
) ?MismatchFieldV1 {
    if (!std.mem.eql(u8, &prepared.core_trace_sha256, &legacy.core_trace_sha256))
        return .core_trace;
    if (!std.mem.eql(u32, &prepared.statement_authority_id, &legacy.statement_authority_id))
        return .statement;
    if (!std.mem.eql(u32, &prepared.workspace_statement_authority_id, &legacy.workspace_statement_authority_id))
        return .workspace_statement;
    if (!std.mem.eql(u32, &prepared.public_wire_id, &legacy.public_wire_id))
        return .public_wire;
    if (!std.mem.eql(u8, &prepared.witness_shapes_sha256, &legacy.witness_shapes_sha256))
        return .ethereum_witness;
    if (!std.mem.eql(u8, &prepared.extension_identity_sha256, &legacy.extension_identity_sha256))
        return .extension;
    if (!std.mem.eql(u8, &prepared.base_geometry_identity_sha256, &legacy.base_geometry_identity_sha256))
        return .base_geometry;
    if (!std.mem.eql(u8, &prepared.bridge_geometry_identity_sha256, &legacy.bridge_geometry_identity_sha256))
        return .bridge_geometry;
    if (!std.mem.eql(u8, &prepared.public_boundary_identity_sha256, &legacy.public_boundary_identity_sha256))
        return .public_boundary;
    if (!std.mem.eql(u8, &prepared.profile_identity_sha256, &legacy.profile_identity_sha256))
        return .profile;
    if (prepared.keccak_calls != legacy.keccak_calls or
        prepared.signer_calls != legacy.signer_calls or
        prepared.external_retirements != legacy.external_retirements)
    {
        return .call_counts;
    }
    return null;
}

fn mismatch(
    field: MismatchFieldV1,
    prepared: AuthoritySnapshotV1,
    legacy: AuthoritySnapshotV1,
) ResultV1 {
    return .{ .mismatch = .{
        .field = field,
        .prepared = prepared,
        .legacy = legacy,
    } };
}

fn shapesIdentity(shapes: ethereum_statement.SecpShapes) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/stage101/ethereum-witness-shapes/v1\x00");
    inline for (std.meta.fields(ethereum_statement.SecpShapes)) |field| {
        const shape = @field(shapes, field.name);
        putInt(&hash, u32, shape.log_size);
        putInt(&hash, u32, shape.n_rows);
    }
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

fn traceIdentity(trace: *const frontend.runner.trace.Trace) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv/ethereum-replay-core-trace/v1\x00");
    putInt(&hash, u32, trace.initial_pc);
    putInt(&hash, u32, trace.final_pc);
    putInt(&hash, u64, trace.step_count);
    putInt(&hash, u32, trace.clock_origin);
    putInt(&hash, u32, trace.last_retirement_clock);
    putInt(&hash, u64, trace.recorded_external_steps);
    putInt(&hash, u32, @intCast(trace.rows.items.len));
    for (trace.rows.items) |row| {
        putInt(&hash, u32, row.clk);
        putInt(&hash, u32, row.pc);
        putInt(&hash, u8, @intFromEnum(row.opcode));
        putInt(&hash, u8, row.rd);
        putInt(&hash, u8, row.rs1);
        putInt(&hash, u8, row.rs2);
        putInt(&hash, u32, @bitCast(row.imm));
        inline for (.{
            row.rs1_val,       row.rs2_val,       row.rs1_prev_clk,
            row.rs2_prev_clk,  row.rd_prev_val,   row.rd_prev_clk,
            row.rd_val,        row.mem_addr,      row.mem_val,
            row.mem_prev_word, row.mem_next_word, row.mem_prev_clk,
        }) |value| putInt(&hash, u32, value);
        putInt(&hash, u8, @intFromBool(row.is_load));
        putInt(&hash, u8, @intFromBool(row.is_store));
        putInt(&hash, u8, @intFromBool(row.branch_taken));
        putInt(&hash, u32, row.next_pc);
        putInt(&hash, u32, row.inst_word);
    }
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

fn putInt(hash: anytype, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

fn allZero(comptime T: type, values: []const T) bool {
    for (values) |value| if (value != 0) return false;
    return true;
}
