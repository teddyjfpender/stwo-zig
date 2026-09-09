//! Two actual native proofs and detached outer candidates for one tiny complete
//! execution. Candidate publication is not detached verification or recursive
//! parent acceptance. The caller admits each key and freshly verifies both
//! directories before using them as parent inputs.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const frontend = @import("stwo_riscv_frontend");
const integration = @import("stwo_riscv_cpu_integration");
const recursion = frontend.recursion;
const span = recursion.span_statement;
const ingress = @import("recursive_segment_v2_leaf_outer_proof_test.zig");
const workload = @import("recursive_segment_v2_two_segment_test_support.zig");
const leaf = integration.recursive_segment_v2_leaf_outer;
const detached = integration.recursive_segment_v2_detached_proof;
const command = integration.recursive_segment_v2_detached_command;
const verifier = integration.recursive_segment_v2_detached_verifier;
const ProducerAllocator = integration.recursive_segment_v2_outer_engine.ProducerAllocator;

pub const Options = OptionsFor(2);

pub fn OptionsFor(comptime count: usize) type {
    return struct {
        initial_memory_word: u32 = 0,
        proof_profile: detached.Profile = .development_q3_v1,
        native_keys: recursion.segment_leaf_authority_v2.VerifierKeyAuthorityV2,
        /// Each directory must be new. Neither child may overwrite prior evidence.
        child_directories: [count][]const u8,
        /// Different actual child geometries may require different admitted keys.
        /// Null exports a candidate key, never an independently trusted key.
        admitted_outer_keys: [count]?*const verifier.KeyV1 = @splat(null),
    };
}

pub const ChildCandidate = struct {
    segment_index: u32,
    first_cycle: u64,
    retired_cycles: u64,
    completed: bool,
    hashes: command.CandidateHashesV1,
    expected_wire_sha256: [32]u8,
    circuit_identity: [32]u8,
    native_ingress_ns: u64,
    detached_prepare_ns: u64,
    detached_prove_ns: u64,
    transaction_ns: u64,
    /// Preparation/outer payloads passed through this caller allocator. The
    /// native producer has its own separately logged counter. Neither includes
    /// device caches or size-routed mmap allocations; measure process RSS outside.
    producer_peak_bytes: usize,
};

pub const Receipt = ReceiptFor(2);

pub fn ReceiptFor(comptime count: usize) type {
    return struct {
        children: [count]ChildCandidate,
        /// Canonical host admission only. No parent AIR/proof is constructed here.
        folded_statement: span.SpanStatement,
        address_count: usize,
        initial_memory_word: u32,
        transaction_ns: u64,
    };
}

/// Default entry points retain CPU outer proving. The explicit engine pair
/// selects native and recursive proving independently; fresh native verification
/// stays on CPU. The caller owns Metal initialization/shutdown policy.
/// No producer capture, native proof, cohort, trace or candidate buffer escapes.
pub fn producePair(
    comptime NativeEngine: type,
    allocator: std.mem.Allocator,
    address_count: usize,
    options: Options,
) !Receipt {
    return produceSegments(2, NativeEngine, allocator, address_count, options);
}

pub fn produceSegments(comptime count: usize, comptime NativeEngine: type, allocator: std.mem.Allocator, address_count: usize, options: OptionsFor(count)) !ReceiptFor(count) {
    return produceSegmentsWithEngines(count, NativeEngine, detached.CpuEngine, allocator, address_count, options);
}

pub fn produceSegmentsWithEngines(comptime count: usize, comptime NativeEngine: type, comptime OuterEngine: type, allocator: std.mem.Allocator, address_count: usize, options: OptionsFor(count)) !ReceiptFor(count) {
    for (options.child_directories, 0..) |directory, index| {
        if (directory.len == 0) return error.InvalidTwoSegmentCandidateDirectories;
        for (options.child_directories[0..index]) |previous|
            if (std.mem.eql(u8, directory, previous)) return error.InvalidTwoSegmentCandidateDirectories;
    }
    try options.native_keys.validate();
    inline for (.{ NativeEngine, OuterEngine }) |Engine| {
        if (@hasDecl(Engine.Backend, "admitHostProving"))
            try Engine.Backend.admitHostProving(.witness_generation);
    }
    var timer = try std.time.Timer.start();
    var segments = try @import("recursive_segment_v2_memory_workload_test_support.zig").materialize(count, allocator, address_count, options.initial_memory_word);
    var owned = true;
    defer if (owned) for (&segments) |*segment| segment.deinit();
    var results: [count]*const frontend.runner.SegmentResult = undefined;
    for (&segments, 0..) |*segment, index| results[index] = &segment.base;
    try workload.validateSegments(count, results, address_count, options.initial_memory_word);
    const statements = try workload.fixtureStatementsForSegments(count, allocator, results);
    const admission = try workload.admitSegments(count, results, ingress.digest("recursive-v2-session"), statements);
    var children: [count]ChildCandidate = undefined;
    for (results, statements, admission.sources, 0..) |result, statement, source, index| {
        children[index] = try produceChild(NativeEngine, OuterEngine, allocator, result, statement, source, options.native_keys, options.child_directories[index], options.admitted_outer_keys[index], options.proof_profile);
    }
    for (&segments) |*segment| segment.deinit();
    owned = false;
    return .{
        .children = children,
        .folded_statement = admission.folded,
        .address_count = address_count,
        .initial_memory_word = options.initial_memory_word,
        .transaction_ns = timer.read(),
    };
}

fn produceChild(
    comptime NativeEngine: type,
    comptime OuterEngine: type,
    allocator: std.mem.Allocator,
    result: *const frontend.runner.SegmentResult,
    statement: span.SpanStatement,
    source: recursion.segment_statement_v2.SourceV2,
    native_keys: recursion.segment_leaf_authority_v2.VerifierKeyAuthorityV2,
    directory_path: []const u8,
    admitted_key: ?*const verifier.KeyV1,
    proof_profile: detached.Profile,
) !ChildCandidate {
    var timer = try std.time.Timer.start();
    // Expected public input comes from independently checked execution/source
    // admission, not a claim recovered from the candidate outer proof.
    const words = try allocator.alloc(M31, try source.canonicalWordCount());
    defer allocator.free(words);
    _ = try source.encodeCanonical(words);
    const expected = try frontend.air.public_data_v2.PublicDataV2.authenticate(words);
    const expected_json = try command.encodeExpected(allocator, &expected);
    defer allocator.free(expected_json);
    var memory = ProducerAllocator{};
    defer std.debug.assert(memory.isEmpty());
    var candidate_receipt: ChildCandidate = undefined;
    {
        const producer_allocator = memory.allocator();
        const lifecycle_before = if (comptime NativeEngine != leaf.Engine) NativeEngine.Backend.runtimeLifecycleSnapshot() else {};
        const telemetry_before = if (comptime NativeEngine != leaf.Engine) try NativeEngine.Backend.telemetrySnapshot() else {};
        var native_timer = try std.time.Timer.start();
        var prepared = try ingress.prepareTemporalNativeLeafWithProfile(
            NativeEngine,
            producer_allocator,
            result,
            statement,
            native_keys,
            if (proof_profile == .recursive_q193_v1) .protocol_v1 else .development_q1,
        );
        defer prepared.deinit();
        const native_ingress_ns = native_timer.read();
        if (comptime NativeEngine != leaf.Engine) {
            const after = NativeEngine.Backend.runtimeLifecycleSnapshot();
            if (!after.initialized or !std.meta.eql(after.identity, lifecycle_before.identity) or
                after.initialization_count != lifecycle_before.initialization_count or
                after.shutdown_count != lifecycle_before.shutdown_count or after.active_call_leases != 0)
                return error.NativeMetalRuntimeChanged;
            const delta = (try NativeEngine.Backend.telemetrySnapshot()).delta(telemetry_before);
            try delta.requireMetalDispatch();
            if (delta.counters.metal_poseidon2_merkle_commits == 0)
                return error.NativeMetalPoseidonDispatchMissing;
            std.debug.print("SEGMENT_V2_TWO_CHILD_NATIVE_METAL segment={d} dispatches={d} poseidon_commits={d}\n", .{
                result.segment_index, delta.counters.metalDispatchTotal(), delta.counters.metal_poseidon2_merkle_commits,
            });
        }
        const captured_words = prepared.capture.public_data.data.words();
        if (captured_words.len != expected.words().len)
            return error.TwoSegmentExpectedStatementMismatch;
        for (captured_words, expected.words()) |actual, wanted|
            if (!actual.eql(wanted)) return error.TwoSegmentExpectedStatementMismatch;
        const outer_lifecycle = if (comptime OuterEngine != detached.CpuEngine) OuterEngine.Backend.runtimeLifecycleSnapshot() else {};
        const outer_before = if (comptime OuterEngine != detached.CpuEngine) try OuterEngine.Backend.telemetrySnapshot() else {};
        var candidate = try detached.produceWithEngine(OuterEngine, producer_allocator, &prepared, admitted_key, proof_profile);
        defer candidate.deinit();
        if (comptime OuterEngine != detached.CpuEngine) {
            const delta = (try OuterEngine.Backend.telemetrySnapshot()).delta(outer_before);
            try delta.requireMetalDispatch();
            if (delta.counters.metal_poseidon2_merkle_commits == 0) return error.RecursiveMetalPoseidonDispatchMissing;
            const after = OuterEngine.Backend.runtimeLifecycleSnapshot();
            if (!after.initialized or !std.meta.eql(after.identity, outer_lifecycle.identity) or
                after.initialization_count != outer_lifecycle.initialization_count or
                after.shutdown_count != outer_lifecycle.shutdown_count or after.active_call_leases != 0)
                return error.RecursiveMetalRuntimeChanged;
            std.debug.print("SEGMENT_V2_TWO_CHILD_RECURSIVE_METAL segment={d} dispatches={d} poseidon_commits={d} composition_dispatches={d} fri_circle_dispatches={d} fri_line_dispatches={d} cpu_fallbacks={d}\n", .{
                result.segment_index,                             delta.counters.metalDispatchTotal(),             delta.counters.metal_poseidon2_merkle_commits,
                delta.counters.metal_composition_eval_dispatches, delta.counters.metal_fri_circle_fold_dispatches, delta.counters.metal_fri_line_fold_dispatches,
                delta.counters.cpuFallbackTotal(),
            });
        }
        const hashes = try command.retainCandidate(
            allocator,
            directory_path,
            candidate.key_json,
            candidate.claims,
            candidate.proof_bytes,
        );
        var directory = try std.fs.cwd().openDir(directory_path, .{});
        defer directory.close();
        var expected_file = try directory.createFile("expected-wire.json", .{ .exclusive = true });
        defer expected_file.close();
        try expected_file.writeAll(expected_json);
        candidate_receipt = .{
            .segment_index = result.segment_index,
            .first_cycle = statement.body.executed.first_cycle,
            .retired_cycles = statement.body.executed.cycle_count,
            .completed = result.completion_reason != null,
            .hashes = hashes,
            .expected_wire_sha256 = command.hash(expected_json),
            .circuit_identity = candidate.circuit_identity,
            .native_ingress_ns = native_ingress_ns,
            .detached_prepare_ns = candidate.prepare_ns,
            .detached_prove_ns = candidate.prove_ns,
            .transaction_ns = 0,
            .producer_peak_bytes = 0,
        };
    }
    // Candidate buffers and each proof/preparation owner are gone before the
    // next child begins. The caller-owned array of execution witnesses remains
    // live until produceSegments returns; it is outside this payload counter.
    try memory.requireEmpty();
    candidate_receipt.producer_peak_bytes = memory.peakBytes();
    candidate_receipt.transaction_ns = timer.read();
    std.debug.print("SEGMENT_V2_TWO_CHILD_CANDIDATE segment={d} first_cycle={d} retired_cycles={d} completed={} directory={s} native_backend={s} recursive_backend={s} proof_bytes={d} native_ingress_ns={d} outer_prepare_ns={d} outer_prove_ns={d} transaction_ns={d} producer_peak_bytes={d} producer_live_bytes_after_destroy={d} status=unverified_candidate parent_proof_created=false\n", .{
        candidate_receipt.segment_index,                                    candidate_receipt.first_cycle,        candidate_receipt.retired_cycles,
        candidate_receipt.completed,                                        directory_path,                       if (comptime NativeEngine == leaf.Engine) "cpu" else "metal",
        if (comptime OuterEngine == detached.CpuEngine) "cpu" else "metal", candidate_receipt.hashes.proof_bytes, candidate_receipt.native_ingress_ns,
        candidate_receipt.detached_prepare_ns,                              candidate_receipt.detached_prove_ns,  candidate_receipt.transaction_ns,
        candidate_receipt.producer_peak_bytes,                              memory.snapshot().active_bytes,
    });
    return candidate_receipt;
}

/// First native segment of the same memory ladder, crossing the production
/// profile through serialization, producer destruction and fresh CPU capture.
/// No outer STARK is constructed: this measures the admitted native input and
/// recursive geometry before allocating a stronger wrapper.
pub fn checkNativeProfile(comptime NativeEngine: type, allocator: std.mem.Allocator, address_count: usize, profile: ingress.NativeProfile) !void {
    var segments = try @import("recursive_segment_v2_memory_workload_test_support.zig").materialize(2, allocator, address_count, 13);
    defer for (&segments) |*segment| segment.deinit();
    const results = [2]*const frontend.runner.SegmentResult{ &segments[0].base, &segments[1].base };
    try workload.validateSegments(2, results, address_count, 13);
    const statements = try workload.fixtureStatementsForSegments(2, allocator, results);
    const keys = try recursion.segment_leaf_authority_v2.VerifierKeyAuthorityV2.init(
        ingress.digest("recursive-v2-segment-vk"),
        ingress.digest("recursive-v2-parent-vk"),
    );
    var prepared = try ingress.prepareTemporalNativeLeafWithProfile(NativeEngine, allocator, results[0], statements[0], keys, profile);
    defer prepared.deinit();
    if (!std.meta.eql(prepared.pcs_config, profile.pcsConfig()) or
        prepared.captured_fri.interaction_pow_bits != recursion.protocol.INTERACTION_POW_BITS)
        return error.NativeSecurityProfileMismatch;
}
