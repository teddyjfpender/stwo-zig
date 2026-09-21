//! Canonical native SegmentV2 producer destruction, fresh verification and owned leaf preparation.
const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const postcard = @import("interop_postcard");
const subject = @import("recursive_segment_v2_leaf_outer.zig");
const M31 = stwo_core.fields.m31.M31;
const prover = frontend.prover_mod;
const runner = frontend.runner;
const recursion = frontend.recursion;
const segment_v2 = recursion.segment_statement_v2;
const span = recursion.span_statement;
const protocol = recursion.protocol;
const channel = recursion.poseidon2_channel;
const schedule = recursion.air.verifier_schedule;
const Engine = subject.Engine;
pub const DEVELOPMENT_CONFIG = stwo_core.pcs.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 1,
        // A one-step fold needs more than the fixed verifier's 16-round
        // capacity for this real trace. Two-step folding is both admitted by
        // the native prover and representable by the recursive schedule.
        .fold_step = 2,
    },
};

pub fn prepare(
    allocator: std.mem.Allocator,
    result: *const runner.SegmentResult,
    statement: span.SpanStatement,
    keys: recursion.segment_leaf_authority_v2.VerifierKeyAuthorityV2,
) !subject.PreparedNativeV2LeafOuter {
    return prepareWithEngine(Engine, allocator, result, statement, keys);
}

/// The native producer may use Metal; canonical serialization, allocation
/// preflight and fresh native verification retain the shared CPU authority.
pub fn prepareWithEngine(
    comptime NativeEngine: type,
    allocator: std.mem.Allocator,
    result: *const runner.SegmentResult,
    statement: span.SpanStatement,
    keys: recursion.segment_leaf_authority_v2.VerifierKeyAuthorityV2,
) !subject.PreparedNativeV2LeafOuter {
    return prepareWithProfile(NativeEngine, allocator, result, statement, keys, .development_q1);
}

/// Exact native profile selection. The recursive wrapper and its own security
/// admission are separate; selecting protocol_v1 here does not upgrade them.
pub const NativeProfile = enum {
    development_q1,
    protocol_v1,

    pub fn pcsConfig(self: NativeProfile) stwo_core.pcs.PcsConfig {
        return switch (self) {
            .development_q1 => DEVELOPMENT_CONFIG,
            .protocol_v1 => protocol.PCS_CONFIG,
        };
    }
};

pub fn prepareWithProfile(
    comptime NativeEngine: type,
    allocator: std.mem.Allocator,
    result: *const runner.SegmentResult,
    statement: span.SpanStatement,
    keys: recursion.segment_leaf_authority_v2.VerifierKeyAuthorityV2,
    native_profile: NativeProfile,
) !subject.PreparedNativeV2LeafOuter {
    const pcs_config = native_profile.pcsConfig();
    var phase_timer = try std.time.Timer.start();
    const source = try segment_v2.SourceV2.fromSegmentResult(
        digest("recursive-v2-session"),
        statement,
        result,
    );
    const words = try encode(allocator, &source);
    defer allocator.free(words);
    const public_data = try frontend.air.public_data_v2.PublicDataV2.authenticate(
        words,
    );

    var native_memory = @import("stwo_prover_engine").tracked_smp_allocator.TrackedSmpAllocator{};
    defer std.debug.assert(native_memory.isEmpty());
    const native_allocator = native_memory.allocator();
    var output = try prover.proveRiscVSegmentV2WithEngine(
        NativeEngine,
        native_allocator,
        pcs_config,
        result,
        null,
        public_data,
    );
    var native_output_owned = true;
    defer if (native_output_owned) output.deinit(native_allocator);

    const prove_ns = phase_timer.lap();
    var proof_bytes: std.ArrayList(u8) = .empty;
    defer proof_bytes.deinit(allocator);
    try postcard.serializeProof(
        Engine.Hasher,
        proof_bytes.writer(allocator),
        output.proof,
    );
    // Same ownership handoff as the single-leaf route: the canonical wire
    // belongs to this ingress, while the claim is a copied array/scalar value.
    // Neither fresh decoding nor verification may observe the prover object.
    const native_statement = output.statement;
    if (native_statement.public_data.canonical_words.ptr != words.ptr or
        native_statement.public_data.canonical_words.len != words.len)
        return error.NativeStatementOwnerMismatch;
    const native_claim = try allocator.create(@TypeOf(output.interaction_claim.*));
    defer allocator.destroy(native_claim);
    @memcpy(std.mem.asBytes(native_claim), std.mem.asBytes(output.interaction_claim));
    output.deinit(native_allocator);
    native_output_owned = false;
    try native_memory.requireEmpty();
    std.debug.print(
        "SEGMENT_V2_NATIVE_MEMORY path=temporal segment={d} backend={s} scope=caller_allocator_payload excludes=size_routed_mmap_and_device producer_peak_bytes={d} producer_live_bytes_after_destroy={d} canonical_proof_bytes={d} before_fresh_decode=true\n",
        .{ result.segment_index, if (comptime NativeEngine == Engine) "cpu" else "metal", native_memory.peakBytes(), native_memory.snapshot().active_bytes, proof_bytes.items.len },
    );
    try recursion.proof_ingress.validateV2ForVerifierConfig(
        proof_bytes.items,
        &native_statement,
        pcs_config,
        proof_bytes.items.len,
    );
    var proof_stream = std.io.fixedBufferStream(proof_bytes.items);
    var decoded_proof = try postcard.deserializeProof(
        Engine.Hasher,
        allocator,
        proof_stream.reader(),
    );
    var decoded_proof_moved = false;
    defer if (!decoded_proof_moved) decoded_proof.deinit(allocator);
    if (proof_stream.pos != proof_bytes.items.len)
        return error.InvalidProofShape;

    const transport_ns = phase_timer.lap();
    var capture: subject.NativeCapture = undefined;
    var verifier_channel = Engine.Channel{};
    decoded_proof_moved = true;
    try prover.verifyRiscVSegmentV2WithEngineUsingChannelAndCapture(
        Engine,
        allocator,
        pcs_config,
        native_statement,
        decoded_proof,
        native_claim,
        &verifier_channel,
        &capture,
    );
    var capture_moved = false;
    defer if (!capture_moved) capture.deinit(allocator);
    try capture.validate();

    const verify_ns = phase_timer.lap();
    var profile = try recursion.captured_fri.Owned.init(
        allocator,
        recursion.captured_fri.ProfileConfig.fromPcs(pcs_config),
        &capture.proof,
    );
    defer profile.deinit();
    if (profile.trace_tree_heights.len != recursion.fixed_profile.TREE_COUNT)
        return error.InvalidProofShape;
    var tree_heights: [recursion.fixed_profile.TREE_COUNT]u32 = undefined;
    @memcpy(&tree_heights, profile.trace_tree_heights);
    const shape = try recursion.transcript_shape.derive(
        profile.circuit.profile(),
        tree_heights,
        .{
            .sampled_value_count = profile.sampled_value_count,
            .queried_values_per_query = profile.queried_values_per_query,
            .claimed_sum_count = profile.claimed_sum_count,
            .interaction_pow_bits = profile.interaction_pow_bits,
            .pcs_pow_bits = profile.pcs_pow_bits,
        },
    );
    var vm_plan = try schedule.Plan.initShape(
        allocator,
        try schedule.vmProgramSpec(0, 0),
        shape,
    );
    defer vm_plan.deinit();
    var recursion_plan = try schedule.Plan.initShape(
        allocator,
        schedule.RECURSION_PROGRAM_SPEC_V1,
        shape,
    );
    defer recursion_plan.deinit();

    var prepared = try subject.PreparedNativeV2LeafOuter.init(
        allocator,
        allocator,
        &capture,
        pcs_config,
        native_claim.interaction_pow,
        keys,
        recursion.air.universal_challenges.UniversalRelations.dummy(),
        .{ .vm = &vm_plan, .recursion = &recursion_plan },
    );
    capture_moved = true;
    errdefer prepared.deinit();
    try prepared.validate();
    std.debug.print("SEGMENT_V2_NATIVE_PROFILE profile={s} segment={d} queries={d} fold_step={d} pcs_pow_bits={d} interaction_pow_bits={d} prove_ns={d} transport_ns={d} verify_ns={d} recursive_prepare_ns={d} proof_bytes={d} transcript_calls={d} verifier_core_calls={d} outer_proof_created=false\n", .{
        @tagName(native_profile),                          result.segment_index,  pcs_config.fri_config.n_queries,
        pcs_config.fri_config.fold_step,                   pcs_config.pow_bits,   profile.interaction_pow_bits,
        prove_ns,                                          transport_ns,          verify_ns,
        phase_timer.read(),                                proof_bytes.items.len, prepared.transcript_execution.poseidonCalls().len,
        prepared.rows_18_34_core.core_poseidon_call_count,
    });
    return prepared;
}

pub fn leafStatement(
    job: span.JobContext,
    result: *const runner.SegmentResult,
    entry: span.MachineState,
    exit: span.MachineState,
    input: span.EdgeClaim,
    output: span.EdgeClaim,
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
            input,
            output,
        ),
    );
}

pub fn machineState(
    cpu: runner.Cpu,
    rw_memory: span.Digest,
    public_io_state: span.Digest,
) !span.MachineState {
    return span.MachineState.init(cpu.pc, cpu.regs, rw_memory, public_io_state);
}

pub fn encode(
    allocator: std.mem.Allocator,
    source: *const segment_v2.SourceV2,
) ![]M31 {
    const words = try allocator.alloc(M31, try source.canonicalWordCount());
    errdefer allocator.free(words);
    _ = try source.encodeCanonical(words);
    return words;
}

pub fn digest(label: []const u8) span.Digest {
    return channel.hashBytes(label, 0x5632_504f); // "V2PO"
}

pub fn scalarDigest(value: u32) span.Digest {
    var result: span.Digest = .{0} ** channel.RATE;
    result[0] = value;
    return result;
}
