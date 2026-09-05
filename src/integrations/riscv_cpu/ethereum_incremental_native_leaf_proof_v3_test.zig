//! Terminal nonproduction proof transaction for one real incremental leaf.
//!
//! A real RV32 execution performs one memory access. STWIMT03 is coldly
//! reopened into a single FullWitnessV3, the exact q193 profile is minted,
//! and the resulting proof is encoded before every producer-owned proof/claim
//! allocation is destroyed. Only a cold artifact decode is then admitted to
//! the independent verifier, which must return an owned PCS/FRI capture.

const std = @import("std");
const stwo_core = @import("stwo_core");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");

const artifact_v2 = @import("ethereum_incremental_boundary_artifact_v2.zig");
const artifact_v3 = @import("ethereum_incremental_boundary_artifact_v3.zig");
const authority_v1 = @import("ethereum_incremental_boundary_authority_v1.zig");
const boundary_v3 = @import("ethereum_incremental_boundary_authority_v3.zig");
const profile_mod = @import("ethereum_incremental_native_leaf_profile_v3.zig");
const proof_v3 = @import("ethereum_incremental_native_leaf_proof_v3.zig");
const proof_artifact =
    @import("ethereum_incremental_native_leaf_proof_artifact_v3.zig");

const M31 = stwo_core.fields.m31.M31;
const prover = frontend.prover_mod;
const runner = frontend.runner;
const channel = frontend.recursion.poseidon2_channel;
const protocol = frontend.recursion.protocol;
const segment_v2 = frontend.recursion.segment_statement_v2;
const span = frontend.recursion.span_statement;
const Engine = prover.ProverEngineForBackend(CpuBackend);

test "incremental native V3 proof cold-decodes and freshly captures q193 PCS" {
    const allocator = std.testing.allocator;
    const elf = incrementalStoreElf();
    var session = try runner.Poseidon2ExecutionSession.init(allocator, &elf, .{
        .trace_retention = .segment_owned,
        .clock_frame = .global_continuous,
    });
    defer session.deinit();
    var execution_profile = try session.startSegment(16);
    defer execution_profile.deinit();
    const execution = &execution_profile.base;
    try std.testing.expect(execution.isComplete());

    var program = try frontend.air.program.commitment.buildDeclared(
        allocator,
        execution.execution_trace.rows.items,
        execution.rw_memory.program_words,
        null,
    );
    defer program.deinit(allocator);
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
    const initial_state = try machineState(
        execution.entry_cpu,
        scalarDigest(entry_root),
        digest("incremental-native-io-entry"),
    );
    const final_state = try machineState(
        execution.exit_cpu,
        scalarDigest(exit_root),
        digest("incremental-native-io-exit"),
    );
    const job = try span.JobContext.init(
        try span.CompleteExecution.init(
            protocol.PROTOCOL_ID_WORDS,
            scalarDigest(program.tree.root),
            initial_state,
            final_state,
            digest("incremental-native-input"),
            digest("incremental-native-output"),
            @intCast(execution.cycle_count),
        ),
        1,
    );
    const leaf = try leafStatement(
        job,
        execution,
        initial_state,
        final_state,
    );
    const source = try segment_v2.SourceV2.fromSegmentResult(
        digest("incremental-native-session"),
        leaf,
        execution,
    );
    const words = try encodeSegment(allocator, &source);
    defer allocator.free(words);
    const public_wire = try frontend.air.public_data_v2.PublicDataV2
        .authenticate(words);
    const metadata = try public_wire.metadata();
    try std.testing.expectEqual(entry_root, metadata.entry_continuation_root);
    try std.testing.expectEqual(exit_root, metadata.exit_continuation_root);

    var artifact = try buildBoundaryArtifact(
        allocator,
        execution,
        &public_wire,
    );
    defer artifact.deinit();
    const retained_public = try frontend.air.statement_v2
        .canonicalCorePublicData(&public_wire);
    const public_authority = boundary_v3.SegmentPublicAuthorityV3{
        .coordinate = .{
            .segment_index = metadata.segment_index,
            .segment_count = metadata.segment_count,
        },
        .segment_role = execution.segment_role,
        .layout = execution.rw_memory.layout,
        .public_data = &retained_public,
        .continuation_roots = .{
            .entry = entry_root,
            .exit = exit_root,
        },
    };
    try public_authority.validate();

    var full_witness = try proof_v3.buildFullWitnessFromColdArtifact(
        allocator,
        &execution.execution_trace,
        &execution.rw_memory,
        retained_public.completion orelse
            return error.MissingIncrementalNativeCompletion,
        &artifact,
        &public_wire,
        public_authority,
        artifact_v3.default_limits,
    );
    defer full_witness.deinit(allocator);
    const expected_statement = try proof_v3.prepareStatement(
        allocator,
        &execution.execution_trace,
        &execution.state_chain_tracker,
        &full_witness,
        public_wire,
    );
    const profile = try profile_mod.mint(
        allocator,
        &artifact,
        &public_wire,
        public_authority,
        &expected_statement,
        artifact_v3.default_limits,
    );
    try profile.validateAgainstInputs(
        allocator,
        &artifact,
        &public_wire,
        public_authority,
        &expected_statement,
        artifact_v3.default_limits,
    );
    try std.testing.expectEqual(@as(u32, 193), profile.protocol.pcs.query_count);

    var prove_channel = Engine.Channel{};
    var output = try proof_v3.proveWithEngineUsingChannel(
        Engine,
        allocator,
        &execution.execution_trace,
        &execution.state_chain_tracker,
        &full_witness,
        &expected_statement,
        &profile,
        null,
        &prove_channel,
        .{},
    );
    var output_live = true;
    defer if (output_live) output.deinit(allocator);
    try std.testing.expectEqualDeep(expected_statement, output.statement);
    const encoded = try proof_artifact.encodeAlloc(
        Engine,
        allocator,
        .{
            .statement = &output.statement,
            .profile = &profile,
            .base_claim = output.claims.base,
            .bridge_claim = output.claims.bridge,
            .proof = &output.proof,
        },
        .{},
    );
    defer allocator.free(encoded);

    // The proof artifact is now the only proof/claim owner across the cold
    // boundary. Producer allocations are destroyed before any decode occurs.
    output.deinit(allocator);
    output_live = false;
    var decoded = try proof_artifact.decodeAlloc(
        Engine,
        allocator,
        encoded,
        .{},
    );
    var decoded_proof_moved = false;
    defer if (decoded_proof_moved)
        decoded.deinitAfterProofMoved(allocator)
    else
        decoded.deinit(allocator);
    try std.testing.expectEqualDeep(expected_statement, decoded.statement);
    try std.testing.expectEqualDeep(profile, decoded.profile);

    var capture: proof_v3.FreshVerifiedCaptureV3(Engine) = undefined;
    var verify_channel = Engine.Channel{};
    decoded_proof_moved = true;
    try proof_v3.verifyWithEngineUsingChannelAndCapture(
        Engine,
        allocator,
        &decoded.statement,
        &decoded.profile,
        decoded.proof,
        decoded.base_claim,
        decoded.bridge_claim,
        &verify_channel,
        &capture,
    );
    defer capture.deinit(allocator);
    const pcs_config = try capture.profile.protocol.pcs.config();
    try capture.validateWithProfileHook(
        pcs_config,
        proof_v3.profileHook(Engine, &capture.profile),
    );
    try std.testing.expectEqual(
        @as(usize, 4),
        capture.proof.commitments.len,
    );
    try std.testing.expectEqual(
        @as(usize, 4),
        capture.proof.column_log_sizes.len,
    );
    try std.testing.expect(!allZero(capture.proof_capture_sha256));
    try std.testing.expect(!allZero(capture.identity_sha256));

    const saved_profile_identity = capture.profile.identity_sha256[0];
    capture.profile.identity_sha256[0] ^= 1;
    try std.testing.expectError(
        error.InvalidIncrementalNativeLeafAuthority,
        capture.validateWithProfileHook(
            pcs_config,
            proof_v3.profileHook(Engine, &capture.profile),
        ),
    );
    capture.profile.identity_sha256[0] = saved_profile_identity;
    try capture.validateWithProfileHook(
        pcs_config,
        proof_v3.profileHook(Engine, &capture.profile),
    );

    const changed = try allocator.dupe(u8, encoded);
    defer allocator.free(changed);
    changed[changed.len - 1] ^= 1;
    try std.testing.expectError(
        error.IncrementalNativeProofArtifactContentMismatch,
        proof_artifact.decodeAlloc(Engine, allocator, changed, .{}),
    );
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

fn buildBoundaryArtifact(
    allocator: std.mem.Allocator,
    execution: *const runner.SegmentResult,
    public_wire: *const frontend.air.public_data_v2.PublicDataV2,
) !artifact_v3.OwnedArtifactV3 {
    var initial: std.ArrayList(authority_v1.SparseWordV1) = .empty;
    defer initial.deinit(allocator);
    var touched: std.ArrayList(authority_v1.TouchedWordV1) = .empty;
    defer touched.deinit(allocator);
    for (execution.rw_memory.words) |word| {
        if (word.initial_word != 0) try initial.append(allocator, .{
            .address = word.addr,
            .value = word.initial_word,
        });
        if (word.final_clock != 0 or word.role.is_public_input or
            word.role.is_public_output or word.role.is_public_completion)
        {
            try touched.append(allocator, .{
                .address = word.addr,
                .old_word = word.initial_word,
                .new_word = word.final_word,
                .final_clock = word.final_clock,
            });
        }
    }
    if (touched.items.len == 0) return error.EmptyIncrementalNativeFixture;
    const metadata = try public_wire.metadata();
    const initial_root = try artifact_v2.testing.fullRoot(
        allocator,
        initial.items,
    );
    if (initial_root != metadata.entry_continuation_root)
        return error.IncrementalNativeFixtureRootMismatch;
    var session = try authority_v1.SessionTree.init(
        allocator,
        [_]u8{0x93} ** 32,
        metadata.segment_index,
        initial.items,
        initial_root,
    );
    defer session.deinit();
    var transition = try session.apply(metadata.segment_index, touched.items);
    defer transition.deinit();
    if (transition.exit_root != metadata.exit_continuation_root)
        return error.IncrementalNativeFixtureRootMismatch;
    const transition_bytes = try artifact_v2.encodeAlloc(
        allocator,
        &transition,
        artifact_v2.default_limits,
    );
    defer allocator.free(transition_bytes);
    const artifact_bytes = try artifact_v3.encodeAlloc(
        allocator,
        transition_bytes,
        public_wire,
        artifact_v3.default_limits,
    );
    defer allocator.free(artifact_bytes);
    return artifact_v3.decodeAlloc(
        allocator,
        artifact_bytes,
        artifact_v3.default_limits,
    );
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
            try span.EdgeClaim.present(digest("incremental-native-input")),
            try span.EdgeClaim.present(digest("incremental-native-output")),
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

/// Adds two ELF symbols to the repository fixture and changes its third NOP
/// into `SW x0, 0(x5)`. This keeps the real execution at three retired rows
/// while making the loaded writable segment an exact RW-memory authority.
fn incrementalStoreElf() [frontend.testing.guest_precompile_test_elf.elf_size]u8 {
    var elf = frontend.testing.guest_precompile_test_elf.build(
        false,
        .self_loop,
    );
    const strings_offset: usize = 480;
    const symbols_offset: usize = 560;
    const program_offset: usize = 640;
    const prior_strings: usize = std.mem.readInt(
        u32,
        elf[308..312],
        .little,
    );
    const extra = "__data_start\x00__data_len\x00";
    @memcpy(
        elf[strings_offset + prior_strings ..][0..extra.len],
        extra,
    );
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
        0x0010_0100,
    );
    writeSymbol(
        &elf,
        symbols_offset + 4 * 16,
        @intCast(prior_strings + "__data_start\x00".len),
        64,
    );
    std.mem.writeInt(u32, elf[program_offset + 8 ..][0..4], 0x0002_a023, .little);
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
    return channel.hashBytes(label, 0x3349_4e56); // "VNI3"
}

fn scalarDigest(value: u32) span.Digest {
    var result: span.Digest = .{0} ** channel.RATE;
    result[0] = value;
    return result;
}

fn allZero(value: [32]u8) bool {
    return std.mem.allEqual(u8, &value, 0);
}
