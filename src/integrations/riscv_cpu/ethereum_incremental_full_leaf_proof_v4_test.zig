//! Genuine q193 full Ethereum + incremental-memory V4 proof transaction.
//!
//! One ordinary Ethereum session retires a successful recovery and one
//! Keccak-f call.  Its typed input contains an untouched zero word, forcing
//! the V4 policy-2 clock-zero exit row to participate in global memory
//! cancellation.  STWIMT04 is coldly reopened before proving, and proof
//! custody crosses an encode/destroy/decode boundary before fresh verification
//! returns the actual PCS/FRI capture.

const std = @import("std");
const stwo_core = @import("stwo_core");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");

const artifact_v2 = @import("ethereum_incremental_boundary_artifact_v2.zig");
const artifact_v4 = @import("ethereum_incremental_boundary_artifact_v4.zig");
const authority_v1 = @import("ethereum_incremental_boundary_authority_v1.zig");
const boundary_capture = @import("ethereum_incremental_boundary_capture_v2.zig");
const boundary_v4 = @import("ethereum_incremental_boundary_authority_v4.zig");
const full_leaf = @import("ethereum_incremental_full_leaf_proof_v4.zig");
const profile_mod = @import("ethereum_incremental_full_leaf_profile_v4.zig");
const proof_artifact =
    @import("ethereum_incremental_full_leaf_proof_artifact_v4.zig");

const M31 = stwo_core.fields.m31.M31;
const prover = frontend.prover_mod;
const runner = frontend.runner;
const public_data = frontend.air.public_data;
const recovery_abi = frontend.isa.ethereum_signer_recovery;
const channel = frontend.recursion.poseidon2_channel;
const protocol = frontend.recursion.protocol;
const segment_v2 = frontend.recursion.segment_statement_v2;
const span = frontend.recursion.span_statement;
const Engine = frontend.recursion.engine.ProverEngineForBackend(CpuBackend);

const input_bytes = [_]u8{ 0, 0, 0, 0 };
const input_address: u32 = 0x0010_0274;

const TestStage = enum {
    session_init,
    session_execute,
    execution_authority,
    program_commitment,
    statement,
    public_wire,
    role_public,
    boundary_artifact,
    full_witness,
    native_statement,
    ethereum_extension,
    profile,
    prove,
    artifact_encode,
    artifact_decode,
    fresh_verify,
    capture_validate,
    mutations,
};

test "full Ethereum incremental V4 proof coldly verifies q193 capture" {
    const allocator = std.testing.allocator;
    var stage: TestStage = .session_init;
    errdefer |err| std.debug.print(
        "incremental-ethereum-v4-leaf stage={s} cause={s}\n",
        .{ @tagName(stage), @errorName(err) },
    );
    var elf = ethereumWithUntouchedInput();
    var session = try runner.EthereumExecutionSession.init(
        allocator,
        &elf,
        .{
            .input = &input_bytes,
            .trace_retention = .segment_owned,
            .clock_frame = .global_continuous,
        },
    );
    defer session.deinit();
    stage = .session_execute;
    var configured = try session.startSegment(16);
    defer configured.deinit();
    const execution = &configured.base;
    try std.testing.expect(execution.isComplete());
    try std.testing.expectEqual(@as(usize, 1), configured.keccakf_calls.len());
    try std.testing.expectEqual(
        @as(usize, 1),
        configured.signer_recovery_calls.len(),
    );
    stage = .execution_authority;
    try requireUntouchedZeroInput(execution);

    stage = .program_commitment;
    var program = try frontend.air.program.commitment
        .buildDeclaredForProfileSources(
        allocator,
        .rv32im_zkvm_ethereum_v1,
        .{
            execution.execution_trace.rows.items,
            configured.keccakf_execution_rows.rows(),
            configured.signer_recovery_execution_rows.rows(),
        },
        execution.rw_memory.program_words,
        null,
    );
    defer program.deinit(allocator);
    stage = .statement;
    const entry_root = try snapshotRoot(
        allocator,
        execution.rw_memory.words,
        .entry,
    );
    const exit_root = try snapshotRoot(
        allocator,
        execution.rw_memory.words,
        .exit,
    );
    const entry_state = try machineState(
        execution.entry_cpu,
        scalarDigest(entry_root),
        digest("incremental-ethereum-v4-io-entry"),
    );
    const exit_state = try machineState(
        execution.exit_cpu,
        scalarDigest(exit_root),
        digest("incremental-ethereum-v4-io-exit"),
    );
    const job = try span.JobContext.init(
        try span.CompleteExecution.init(
            protocol.PROTOCOL_ID_WORDS,
            scalarDigest(program.tree.root),
            entry_state,
            exit_state,
            digest("incremental-ethereum-v4-input"),
            digest("incremental-ethereum-v4-output"),
            @intCast(execution.cycle_count),
        ),
        1,
    );
    const leaf = try leafStatement(job, execution, entry_state, exit_state);
    const source = try segment_v2.SourceV2.fromSegmentResult(
        digest("incremental-ethereum-v4-session"),
        leaf,
        execution,
    );
    stage = .public_wire;
    const canonical_words = try encodeSegment(allocator, &source);
    defer allocator.free(canonical_words);
    const public_wire = try frontend.air.public_data_v2.PublicDataV2
        .authenticate(canonical_words);
    const metadata = try public_wire.metadata();
    try std.testing.expectEqual(entry_root, metadata.entry_continuation_root);
    try std.testing.expectEqual(exit_root, metadata.exit_continuation_root);

    stage = .role_public;
    var role_public = try OwnedRolePublic.init(
        allocator,
        &public_wire,
        execution,
        &input_bytes,
    );
    defer role_public.deinit();
    const public_authority = boundary_v4.SegmentPublicAuthorityV4{
        .coordinate = .{
            .segment_index = metadata.segment_index,
            .segment_count = metadata.segment_count,
        },
        .segment_role = execution.segment_role,
        .layout = execution.rw_memory.layout,
        .public_data = &role_public.value,
        .continuation_roots = .{ .entry = entry_root, .exit = exit_root },
    };
    try public_authority.validate();

    stage = .boundary_artifact;
    var boundary_artifact = try buildBoundaryArtifact(
        allocator,
        &configured,
        &public_wire,
        public_authority,
        entry_root,
        exit_root,
    );
    defer boundary_artifact.deinit();
    const completion = role_public.value.completion orelse
        return error.MissingIncrementalEthereumCompletionV4;
    stage = .full_witness;
    var prepared = try full_leaf.prepareFullWitnessFromColdArtifact(
        allocator,
        .{
            execution.execution_trace.rows.items,
            configured.keccakf_execution_rows.rows(),
            configured.signer_recovery_execution_rows.rows(),
        },
        &execution.rw_memory,
        completion,
        &boundary_artifact,
        &public_wire,
        public_authority,
        artifact_v4.default_limits,
    );
    defer prepared.deinit(allocator);
    try requireUntouchedInputExitRow(&prepared, input_address);

    const external_count = std.math.add(
        usize,
        configured.keccakf_calls.len(),
        configured.signer_recovery_calls.len(),
    ) catch return error.InvalidIncrementalEthereumFixtureV4;
    stage = .native_statement;
    const native = try full_leaf.prepareStatement(
        allocator,
        &execution.execution_trace,
        &execution.state_chain_tracker,
        &prepared,
        public_wire,
        @intCast(external_count),
    );
    const core_public = try frontend.air.statement_v2
        .canonicalCorePublicData(&native.public_data);
    stage = .ethereum_extension;
    var ethereum_witness = try prover.guest_precompile.ethereum_witness.Witness
        .init(
        allocator,
        configured.keccakf_calls.records(),
        configured.keccakf_execution_rows.rows(),
        configured.signer_recovery_calls.records(),
        configured.signer_recovery_execution_rows.rows(),
        core_public.clock,
    );
    defer ethereum_witness.deinit();
    const extension = try frontend.air.guest_precompile.ethereum_statement
        .Statement.canonicalV2(
        &native,
        @intCast(configured.keccakf_calls.len()),
        @intCast(configured.signer_recovery_calls.len()),
        ethereum_witness.shapes(),
    );
    stage = .profile;
    const profile = try prepared.mintProfile(
        &boundary_artifact,
        public_authority,
        &native,
        &extension,
    );
    try profile.validateAgainstInputs(
        allocator,
        &boundary_artifact,
        &public_wire,
        public_authority,
        &native,
        &extension,
        artifact_v4.default_limits,
    );
    try profile.protocol.validate();
    try std.testing.expect(Engine.Hasher == frontend.recursion.engine.Hasher);
    try std.testing.expect(
        Engine.MerkleChannel == frontend.recursion.engine.MerkleChannel,
    );
    try std.testing.expect(Engine.Channel == channel.Channel);
    try std.testing.expectEqual(
        protocol.protocolId(),
        profile.protocol.protocol_id,
    );
    try std.testing.expectEqual(
        @as(usize, protocol.FRI_QUERY_COUNT),
        (try profile.pcsConfig()).fri_config.n_queries,
    );
    try std.testing.expectEqual(@as(usize, 14), extension.components.len);
    try std.testing.expectEqual(@as(u32, 193), profile.protocol.pcs.query_count);

    stage = .prove;
    var prove_channel = Engine.Channel{};
    var output = try full_leaf.proveWithEngineUsingChannel(
        Engine,
        allocator,
        &execution.execution_trace,
        &execution.state_chain_tracker,
        &prepared,
        &native,
        &role_public.value,
        &configured.keccakf_calls,
        &configured.keccakf_execution_rows,
        &configured.signer_recovery_calls,
        &configured.signer_recovery_execution_rows,
        &profile,
        null,
        &prove_channel,
        .{},
    );
    var output_live = true;
    defer if (output_live) output.deinit(allocator);
    try std.testing.expectEqualDeep(native, output.statement);
    try std.testing.expectEqualDeep(extension, output.extension);

    stage = .artifact_encode;
    const encoded = try proof_artifact.encodeAlloc(
        Engine,
        allocator,
        .{
            .statement = &output.statement,
            .role_aware_public = &role_public.value,
            .extension = &output.extension,
            .profile = &profile,
            .base_claim = output.claims.base,
            .extension_claim = &output.claims.ethereum,
            .bridge_claim = output.claims.bridge,
            .proof = &output.proof,
        },
        .{},
    );
    defer allocator.free(encoded);
    output.deinit(allocator);
    output_live = false;

    stage = .artifact_decode;
    const retained_view = try public_wire.authenticatedView();
    const retained_snapshots =
        frontend.air.public_data_v2.PublicDataV2.RetainedSnapshots{
            .entry = .{
                .id = retained_view.statement.entry_snapshot_id,
                .count = retained_view.statement.entry_snapshot_count,
                .root = retained_view.statement.entry_continuation_root,
            },
            .exit = .{
                .id = retained_view.statement.exit_snapshot_id,
                .count = retained_view.statement.exit_snapshot_count,
                .root = retained_view.statement.exit_continuation_root,
            },
        };
    var validation_counters = frontend.air.public_data_v2.PublicDataV2
        .ValidationCountersV2{};
    var decoded = try proof_artifact.decodeAllocWithRetainedLease(
        Engine,
        allocator,
        encoded,
        .{},
        retained_snapshots,
        &validation_counters,
    );
    var proof_moved = false;
    defer if (proof_moved)
        decoded.deinitAfterProofMoved(allocator)
    else
        decoded.deinit(allocator);
    try std.testing.expectEqualDeep(native.core, decoded.statement.core);
    try std.testing.expectEqualDeep(
        native.public_data.wireId(),
        decoded.statement.public_data.wireId(),
    );
    try std.testing.expectEqualDeep(
        native.authority_id,
        decoded.statement.authority_id,
    );
    try std.testing.expectEqualDeep(profile, decoded.profile);

    stage = .fresh_verify;
    var capture: full_leaf.FreshVerifiedCaptureV4(Engine) = undefined;
    var verify_channel = Engine.Channel{};
    proof_moved = true;
    try full_leaf.verifyWithEngineUsingChannelAndCaptureTakingLease(
        Engine,
        allocator,
        &decoded.statement,
        &decoded.extension,
        &decoded.role_aware_public.value,
        &decoded.profile,
        decoded.proof,
        decoded.base_claim,
        &decoded.extension_claim,
        decoded.bridge_claim,
        &decoded.statement_lease,
        &verify_channel,
        &capture,
    );
    defer capture.deinit(allocator);
    try std.testing.expect(decoded.statement_lease == null);
    stage = .capture_validate;
    try capture.validate();
    try std.testing.expectEqual(@as(usize, 4), capture.proof.commitments.len);
    try std.testing.expectEqual(
        @as(usize, 4),
        capture.proof.column_log_sizes.len,
    );
    try std.testing.expect(!allZero(capture.proof_capture_sha256));
    try std.testing.expect(!allZero(capture.identity_sha256));
    const validation_snapshot = validation_counters.snapshot();
    try std.testing.expectEqual(
        @as(u64, 1),
        validation_snapshot.retained_root_authentications,
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        validation_snapshot.legacy_full_authentications,
    );
    try std.testing.expect(validation_snapshot.cached_view_reuses > 10);

    stage = .mutations;
    const saved = capture.profile.identity_sha256[0];
    capture.profile.identity_sha256[0] ^= 1;
    try std.testing.expectError(
        error.InvalidIncrementalEthereumLeafAuthorityV4,
        capture.validate(),
    );
    capture.profile.identity_sha256[0] = saved;
    try capture.validate();

    capture.transcript_final_digest[0] ^= 1;
    try std.testing.expectError(
        error.InvalidIncrementalEthereumFreshCapture,
        capture.validate(),
    );
    capture.transcript_final_digest[0] ^= 1;
    try capture.validate();

    const changed = try allocator.dupe(u8, encoded);
    defer allocator.free(changed);
    changed[changed.len - 1] ^= 1;
    try std.testing.expectError(
        error.IncrementalFullLeafProofArtifactContentMismatchV4,
        proof_artifact.decodeAlloc(Engine, allocator, changed, .{}),
    );
    try std.testing.expect(!profile_mod.PRODUCTION_ACTIVE);
}

const OwnedRolePublic = struct {
    allocator: std.mem.Allocator,
    input_words: []u32,
    output_words: []public_data.OutputWord,
    value: public_data.PublicData,

    fn init(
        allocator: std.mem.Allocator,
        native: *const frontend.air.public_data_v2.PublicDataV2,
        execution: *const runner.SegmentResult,
        input: []const u8,
    ) !OwnedRolePublic {
        const input_words = try public_data.packInputWords(allocator, input);
        errdefer allocator.free(input_words);
        const output_words = try allocator.alloc(
            public_data.OutputWord,
            execution.output_words.len,
        );
        errdefer allocator.free(output_words);
        for (output_words, execution.output_words) |*destination, source|
            destination.* = .{
                .addr = source.addr,
                .value = source.value,
                .clock = source.clock,
            };
        var value = try frontend.air.statement_v2.canonicalCorePublicData(native);
        if (value.completion == null)
            value.completion = public_data.Completion.canonicalSelfLoop(
                value.final_pc,
            );
        value.io_entries = .{
            .input_start = execution.input_start,
            .input_len = @intCast(input.len),
            .input_words = input_words,
            .output_len = execution.output_len,
            .output_len_addr = execution.output_len_addr,
            .output_data_addr = execution.output_data_addr,
            .output_words = output_words,
        };
        try frontend.air.incremental_public_logup_v4.validateSharedAuthority(
            native,
            &value,
        );
        return .{
            .allocator = allocator,
            .input_words = input_words,
            .output_words = output_words,
            .value = value,
        };
    }

    fn deinit(self: *OwnedRolePublic) void {
        self.allocator.free(self.output_words);
        self.allocator.free(self.input_words);
        self.* = undefined;
    }
};

fn buildBoundaryArtifact(
    allocator: std.mem.Allocator,
    configured: *const runner.EthereumSegmentResult,
    public_wire: *const frontend.air.public_data_v2.PublicDataV2,
    public_authority: boundary_v4.SegmentPublicAuthorityV4,
    entry_root: u32,
    exit_root: u32,
) !artifact_v4.OwnedArtifactV4 {
    const execution = &configured.base;
    var capture = try boundary_capture.SessionCaptureV2.init(
        allocator,
        digestBytes("incremental-ethereum-v4-boundary-session"),
        execution.segment_index,
        &execution.rw_memory,
        entry_root,
    );
    defer capture.deinit();
    const addresses = try replayTouchedAddresses(allocator, configured);
    defer allocator.free(addresses);
    var transition = try capture.apply(
        execution.segment_index,
        &execution.rw_memory,
        addresses,
        entry_root,
        exit_root,
    );
    defer transition.deinit();
    const transition_bytes = try artifact_v2.encodeAlloc(
        allocator,
        &transition,
        artifact_v2.default_limits,
    );
    defer allocator.free(transition_bytes);
    const bytes = try artifact_v4.encodeAlloc(
        allocator,
        transition_bytes,
        public_wire,
        public_authority,
        artifact_v4.default_limits,
    );
    defer allocator.free(bytes);
    return artifact_v4.decodeAlloc(
        allocator,
        bytes,
        artifact_v4.default_limits,
    );
}

/// Reconstruct the same typed replay-touched inventory used by the retained
/// V4 observer. Public-role words are deliberately absent: SessionCaptureV2
/// adds that independently authenticated union itself.
fn replayTouchedAddresses(
    allocator: std.mem.Allocator,
    configured: *const runner.EthereumSegmentResult,
) ![]u32 {
    var unique = std.AutoHashMap(u32, void).init(allocator);
    defer unique.deinit();
    for (configured.base.execution_trace.rows.items) |row| {
        if (row.is_load or row.is_store)
            try unique.put(row.mem_addr & ~@as(u32, 3), {});
    }
    for (configured.keccakf_calls.records()) |record|
        try putWordRange(&unique, record.state_ptr, 0, record.input.len);
    for (configured.signer_recovery_calls.records()) |record| {
        try putWordRange(
            &unique,
            record.io_ptr,
            0,
            recovery_abi.input_word_count,
        );
        try putWordRange(
            &unique,
            record.io_ptr,
            recovery_abi.public_key_offset,
            recovery_abi.output_word_count,
        );
    }

    const result = try allocator.alloc(u32, unique.count());
    errdefer allocator.free(result);
    var iterator = unique.keyIterator();
    var at: usize = 0;
    while (iterator.next()) |address| : (at += 1) result[at] = address.*;
    if (at != result.len) return error.InvalidIncrementalEthereumFixtureV4;
    std.mem.sort(u32, result, {}, std.sort.asc(u32));
    return result;
}

fn putWordRange(
    addresses: *std.AutoHashMap(u32, void),
    base: u32,
    byte_offset: u32,
    count: usize,
) !void {
    const start = std.math.add(u32, base, byte_offset) catch
        return error.InvalidIncrementalEthereumFixtureV4;
    for (0..count) |index| {
        const word_offset = std.math.mul(
            u32,
            @intCast(index),
            @sizeOf(u32),
        ) catch return error.InvalidIncrementalEthereumFixtureV4;
        const address = std.math.add(u32, start, word_offset) catch
            return error.InvalidIncrementalEthereumFixtureV4;
        try addresses.put(address, {});
    }
}

const SnapshotSide = enum { entry, exit };

fn snapshotRoot(
    allocator: std.mem.Allocator,
    words: []const runner.memory_state.WordState,
    side: SnapshotSide,
) !u32 {
    var sparse: std.ArrayList(authority_v1.SparseWordV1) = .empty;
    defer sparse.deinit(allocator);
    for (words) |word| {
        const value = if (side == .entry)
            word.initial_word
        else
            word.final_word;
        if (value != 0) try sparse.append(allocator, .{
            .address = word.addr,
            .value = value,
        });
    }
    return artifact_v2.testing.fullRoot(allocator, sparse.items);
}

fn requireUntouchedZeroInput(execution: *const runner.SegmentResult) !void {
    for (execution.rw_memory.words) |word| {
        if (word.addr != input_address) continue;
        if (!word.role.is_public_input or word.initial_word != 0 or
            word.final_word != 0 or word.final_clock != 0)
        {
            return error.InvalidUntouchedInputFixtureV4;
        }
        return;
    }
    return error.MissingUntouchedInputFixtureV4;
}

fn requireUntouchedInputExitRow(
    prepared: *const full_leaf.PreparedWitnessV4,
    address: u32,
) !void {
    const rows = prepared.full.boundary.rows();
    var index: usize = 0;
    while (index + 1 < rows.len) : (index += 2) {
        const entry = rows[index];
        const exit = rows[index + 1];
        if (entry.addr != address) continue;
        if (exit.addr != address or entry.clock != 0 or exit.clock != 0 or
            !entry.multiplicity.isZero() or
            !exit.multiplicity.eql(M31.one().neg()))
        {
            return error.InvalidUntouchedInputBoundaryPolicyV4;
        }
        return;
    }
    return error.MissingUntouchedInputBoundaryPolicyV4;
}

fn leafStatement(
    job: span.JobContext,
    result: *const runner.SegmentResult,
    entry: span.MachineState,
    exit: span.MachineState,
) !span.SpanStatement {
    if (result.global_first_cycle == 0) return error.InvalidGlobalCycle;
    return span.SpanStatement.segmentLeaf(
        job,
        result.segment_index,
        try span.ExecutedSpan.init(
            result.segment_index,
            1,
            result.global_first_cycle - 1,
            @intCast(result.cycle_count),
            entry,
            exit,
            try span.EdgeClaim.present(digest("incremental-ethereum-v4-input")),
            try span.EdgeClaim.present(digest("incremental-ethereum-v4-output")),
        ),
    );
}

fn machineState(
    cpu: runner.Cpu,
    rw_memory: span.Digest,
    public_io_state: span.Digest,
) !span.MachineState {
    return span.MachineState.init(cpu.pc, cpu.regs, rw_memory, public_io_state);
}

fn encodeSegment(
    allocator: std.mem.Allocator,
    source: *const segment_v2.SourceV2,
) ![]M31 {
    const words = try allocator.alloc(M31, try source.canonicalWordCount());
    errdefer allocator.free(words);
    _ = try source.encodeCanonical(words);
    return words;
}

fn ethereumWithUntouchedInput() [frontend.testing.guest_precompile_test_elf.ethereum_elf_size]u8 {
    var elf = frontend.testing.guest_precompile_test_elf.buildEthereum();
    const strings_offset: usize = 480;
    const symbols_offset: usize = 560;
    const program_offset: usize = 640;
    const completion_offset = program_offset +
        (frontend.testing.guest_precompile_test_elf.ethereum_instructions.len - 1) *
            @sizeOf(u32);
    // ECALL is runner-admitted but deliberately absent from the proof opcode
    // manifest.  Use the canonical unretired self-loop completion shared by
    // the existing Ethereum q193 proof fixtures; both precompile calls remain
    // retired and committed before this boundary.
    std.mem.writeInt(
        u32,
        elf[completion_offset..][0..4],
        public_data.CANONICAL_SELF_LOOP_WORD,
        .little,
    );
    const prior_strings: usize = std.mem.readInt(u32, elf[308..312], .little);
    const extra = "__input_start\x00__input_end\x00";
    @memcpy(elf[strings_offset + prior_strings ..][0..extra.len], extra);
    std.mem.writeInt(
        u32,
        elf[308..312],
        @intCast(prior_strings + extra.len),
        .little,
    );
    std.mem.writeInt(u32, elf[268..272], 5 * 16, .little);
    writeSymbol(
        &elf,
        symbols_offset + 3 * 16,
        @intCast(prior_strings),
        input_address,
    );
    writeSymbol(
        &elf,
        symbols_offset + 4 * 16,
        @intCast(prior_strings + "__input_start\x00".len),
        input_address + input_bytes.len,
    );
    return elf;
}

fn writeSymbol(
    elf: []u8,
    offset: usize,
    name_offset: u32,
    value: u32,
) void {
    @memset(elf[offset..][0..16], 0);
    std.mem.writeInt(u32, elf[offset..][0..4], name_offset, .little);
    std.mem.writeInt(u32, elf[offset + 4 ..][0..4], value, .little);
}

fn digest(label: []const u8) span.Digest {
    return channel.hashBytes(label, 0x3446_4549); // "IEF4"
}

fn digestBytes(label: []const u8) [32]u8 {
    var result: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &result, .{});
    return result;
}

fn scalarDigest(value: u32) span.Digest {
    var result: span.Digest = .{0} ** channel.RATE;
    result[0] = value;
    return result;
}

fn allZero(value: [32]u8) bool {
    return std.mem.allEqual(u8, &value, 0);
}
