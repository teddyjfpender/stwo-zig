//! Request-independent all-leaf omitted-provider geometry audit for matched A/B.
//!
//! The command cold reopens the completed baseline materialization and
//! candidate execution capture, reexecutes the baseline once at the shared
//! 2^20 segment boundary, and evaluates every leaf through the exact
//! count-only pre-Engine geometry inspector. It publishes one seal-last compact
//! audit and cannot mint requests, call custody, a provider plan, or a proof.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const authority =
    @import("ethereum_matched_ab_rematerialization_authority_v1.zig");
const candidate_receipt =
    @import("ethereum_candidate_combined_execution_capture_receipt_v1.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const journal_authority = @import("ethereum_block_leaf_journal.zig");
const support = @import("ethereum_block_leaf_support.zig");

const geometry_api = frontend.prover_mod.guest_precompile
    .ethereum_segment_orchestration;
const omitted_policy = frontend.prover_mod.guest_precompile
    .ethereum_matched_ab_omitted_provider_policy_v1;

pub const command_name = "ethereum-matched-ab-omitted-provider-geometry-audit-v2";
pub const minimum_hard_cap_seconds: u64 = 300;
pub const maximum_hard_cap_seconds: u64 = 3_600;
pub const maximum_candidate_result_bytes: usize = 16 * 1024 * 1024;
pub const maximum_executable_bytes: usize = 512 * 1024 * 1024;

const DigestText = struct {
    tree0: [64]u8,
    tree1: [64]u8,
    tree2: [64]u8,
};

pub fn run(allocator: std.mem.Allocator, arguments: []const []const u8) !void {
    var options = try Options.parseAndResolve(allocator, arguments);
    defer options.deinit(allocator);
    try audit(allocator, options);
}

fn audit(allocator: std.mem.Allocator, options: Options) !void {
    var hard_timer = try std.time.Timer.start();
    const materialization_bytes = try artifact_io.readFileBounded(
        allocator,
        options.baseline_materialization,
        contract.max_json_bytes,
    );
    defer allocator.free(materialization_bytes);
    var materialization = try contract.parseMaterializationResult(
        allocator,
        materialization_bytes,
    );
    defer materialization.deinit();
    const baseline = &materialization.value;
    if (baseline.segment_count != baseline.leaf_sources.len) {
        return error.InvalidMatchedAbBaselineMaterialization;
    }

    const source_bytes = try support.readIdentity(
        allocator,
        typedIdentity(baseline.source_request),
        contract.max_json_bytes,
    );
    defer allocator.free(source_bytes);
    var source = try contract.parseRecursiveSource(allocator, source_bytes);
    defer source.deinit();
    if (source.value.segment_count != baseline.segment_count or
        source.value.segment_step_budget != authority.segment_step_budget or
        !identityEql(source.value.input, baseline.input) or
        !identityEql(source.value.expected_output, baseline.expected_output))
    {
        return error.InvalidMatchedAbBaselineMaterialization;
    }

    const candidate_bytes = try artifact_io.readFileBounded(
        allocator,
        options.candidate_capture,
        maximum_candidate_result_bytes,
    );
    defer allocator.free(candidate_bytes);
    var candidate = try parseCandidateResult(allocator, candidate_bytes);
    defer candidate.deinit();
    try validateCandidateJoin(candidate.value, baseline);
    try reopenCandidateIdentity(allocator, candidate.value.manifest);
    try reopenCandidateIdentity(allocator, candidate.value.journal);

    const journal_bytes = try support.readIdentity(
        allocator,
        source.value.execution_journal,
        64 * 1024 * 1024,
    );
    defer allocator.free(journal_bytes);
    const journal_records = try journal_authority.validate(
        allocator,
        journal_bytes,
        source.value,
    );
    defer allocator.free(journal_records);
    if (journal_records.len != baseline.segment_count)
        return error.InvalidMatchedAbBaselineMaterialization;

    const elf = try support.readIdentity(
        allocator,
        source.value.elf,
        maximum_executable_bytes,
    );
    defer allocator.free(elf);
    const input = try support.readIdentity(
        allocator,
        source.value.input,
        512 * 1024 * 1024,
    );
    defer allocator.free(input);
    const expected_output = try support.readIdentity(
        allocator,
        source.value.expected_output,
        16 * 1024 * 1024,
    );
    defer allocator.free(expected_output);

    const producer_path = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(producer_path);
    const producer_bytes = try artifact_io.readFileBounded(
        allocator,
        producer_path,
        maximum_executable_bytes,
    );
    defer allocator.free(producer_bytes);
    const producer_sha = support.sha256(producer_bytes);
    const producer_sha_text = std.fmt.bytesToHex(producer_sha, .lower);
    const materialization_sha = support.sha256(materialization_bytes);
    const materialization_sha_text = std.fmt.bytesToHex(
        materialization_sha,
        .lower,
    );
    const candidate_sha = support.sha256(candidate_bytes);
    const candidate_sha_text = std.fmt.bytesToHex(candidate_sha, .lower);

    const count: usize = baseline.segment_count;
    const entries = try allocator.alloc(authority.GeometryEntryV2, count);
    defer allocator.free(entries);
    const digest_text = try allocator.alloc(DigestText, count);
    defer allocator.free(digest_text);
    const matched_execution = authority.MatchedExecutionAuthorityV1.canonical();
    try matched_execution.validate();
    const provider_resource = try authority.ProviderResourceEstimateV1.canonical();
    try provider_resource.validate();
    var program_inventory: ?geometry_api.ProgramInventoryV1 = null;
    var maximum_core_staged: u64 = 0;
    var maximum_provider_shards: u32 = 0;
    var total_provider_calls: u64 = 0;
    var session = try frontend.runner.EthereumExecutionSession.init(
        allocator,
        elf,
        .{
            .input = input,
            .stop_on_halt_flag = true,
            .strict_completion = true,
            .trace_retention = .segment_owned,
            .clock_frame = .leaf_local,
        },
    );
    defer session.deinit();
    var continuation: ?frontend.runner.result_mod.ContinuationToken = null;
    for (baseline.leaf_sources, 0..) |leaf, index| {
        try ensureWithinCap(&hard_timer, options.hard_cap_ns);
        var segment = if (index == 0)
            try session.startSegment(authority.segment_step_budget)
        else
            try session.resumeSegment(
                continuation orelse return error.MissingContinuation,
                authority.segment_step_budget,
            );
        defer segment.deinit();
        const expected_bytes = try support.readIdentity(
            allocator,
            leaf.authority,
            support.source_wire.encoded_size,
        );
        defer allocator.free(expected_bytes);
        const expected = try support.source_wire.decode(expected_bytes);
        if (expected.metadata.segment_index != index or
            expected.metadata.segment_count != baseline.segment_count or
            segment.base.segment_index != index or
            !std.meta.eql(expected.journal_record_sha256, journal_records[index]))
        {
            return error.ReexecutedSegmentMismatch;
        }
        const complete = segment.base.isComplete();
        if (complete != (index + 1 == baseline.segment_count))
            return error.ExecutionCompletionMismatch;
        if (complete) {
            const output = segment.base.output orelse return error.MissingOutput;
            if (!std.mem.eql(u8, output, expected_output))
                return error.PublicOutputMismatch;
        }

        try validateRetainedBoundaryWithoutRehashingRoots(
            &segment.base,
            &expected.metadata,
        );
        if (program_inventory == null) {
            program_inventory = try geometry_api.ProgramInventoryV1.create(
                allocator,
                segment.base.rw_memory.program_words,
            );
        }
        var counted = try geometry_api
            .inspectPreEngineGeometryFromCountedInventoryV1(
            allocator,
            authority.log_blowup_factor,
            &segment.base,
            program_inventory.?,
            &segment.keccakf_calls,
            &segment.keccakf_execution_rows,
            &segment.signer_recovery_calls,
            &segment.signer_recovery_execution_rows,
        );
        defer counted.deinit();
        const geometry = &counted.geometry;
        const estimate = try omitted_policy.estimateOmittedCoreV1(
            geometry,
            matched_execution,
        );
        try estimate.requireWithinMatchedBudget();
        const provider = try authority.ProviderShardShapeV2.canonical(
            counted.inventory.provider_call_count,
        );
        digest_text[index] = .{
            .tree0 = std.fmt.bytesToHex(
                authority.logSizesIdentity(geometry.tree0_log_sizes),
                .lower,
            ),
            .tree1 = std.fmt.bytesToHex(
                authority.logSizesIdentity(
                    geometry.tree1_non_candidate_log_sizes,
                ),
                .lower,
            ),
            .tree2 = std.fmt.bytesToHex(
                authority.logSizesIdentity(geometry.tree2_log_sizes),
                .lower,
            ),
        };
        entries[index] = .{
            .segment_index = @intCast(index),
            .source_segment = leaf.authority,
            .execution_inventory_identity = counted.inventory.identity,
            .tree0_log_sizes_sha256 = &digest_text[index].tree0,
            .tree1_non_provider_log_sizes_sha256 = &digest_text[index].tree1,
            .tree2_log_sizes_sha256 = &digest_text[index].tree2,
            .provider = provider,
            .omitted_core = estimate,
        };
        try entries[index].validate(index, matched_execution);
        maximum_core_staged = @max(
            maximum_core_staged,
            estimate.staged_peak_lower_bound_bytes,
        );
        maximum_provider_shards = @max(
            maximum_provider_shards,
            provider.shard_count,
        );
        total_provider_calls = std.math.add(
            u64,
            total_provider_calls,
            provider.call_count,
        ) catch return error.MatchedAbProviderCallCountOverflow;
        continuation = segment.base.continuation;
        if (!complete and continuation == null) return error.MissingContinuation;
    }
    try ensureWithinCap(&hard_timer, options.hard_cap_ns);

    const zero_sha = [_]u8{'0'} ** 64;
    const value = authority.GeometryAuditV2{
        .content_sha256 = &zero_sha,
        .schema = authority.geometry_v2_schema,
        .status = authority.geometry_v2_status,
        .production_active = false,
        .proof_or_fresh_verification = false,
        .segment_step_budget = authority.segment_step_budget,
        .host_byte_budget = authority.host_byte_budget,
        .omitted_core_retention_policy = "never",
        .provider_shard_log_size = authority.provider_shard_log_size,
        .provider_retention_policy = "always",
        .provider_call_commitment_deferred_to_leaf_producer = true,
        .provider_plan_deferred_to_leaf_producer = true,
        .fresh_closure_deferred_to_leaf_producer = true,
        .matched_execution = matched_execution,
        .provider_resource = provider_resource,
        .baseline_materialization = .{
            .bytes = materialization_bytes.len,
            .path = options.baseline_materialization,
            .sha256 = &materialization_sha_text,
        },
        .baseline_source_request = baseline.source_request,
        .candidate_capture = .{
            .bytes = candidate_bytes.len,
            .path = options.candidate_capture,
            .sha256 = &candidate_sha_text,
        },
        .input = baseline.input,
        .expected_output = baseline.expected_output,
        .producer_executable = .{
            .bytes = producer_bytes.len,
            .path = producer_path,
            .sha256 = &producer_sha_text,
        },
        .entries = entries,
        .total_provider_calls = total_provider_calls,
        .maximum_provider_shard_count = maximum_provider_shards,
        .maximum_omitted_core_staged_peak_lower_bound_bytes = maximum_core_staged,
    };
    const encoded = try authority.encodeGeometryAuditV2(allocator, value);
    defer allocator.free(encoded);
    try artifact_io.publishCreateOnlyDurable(options.audit, encoded);
    const reopened = try artifact_io.readFileBounded(
        allocator,
        options.audit,
        authority.maximum_authority_bytes,
    );
    defer allocator.free(reopened);
    if (!std.mem.eql(u8, reopened, encoded))
        return error.MatchedAbGeometryAuditPublicationMismatch;
    var parsed = try authority.parseGeometryAuditV2(allocator, reopened);
    parsed.deinit();
    try ensureWithinCap(&hard_timer, options.hard_cap_ns);
}

/// Rebind the live segment to the already-authenticated STWESG31 boundary
/// without recomputing either sparse Merkle root. Snapshot digest/count are
/// recomputed from every exact nonzero word; only an equal retained boundary
/// may lend its root. All remaining pointer-free MetadataV3 fields are compared
/// directly to the live runner state before geometry is counted.
fn validateRetainedBoundaryWithoutRehashingRoots(
    result: *const frontend.runner.result_mod.SegmentResult,
    expected: *const frontend.recursion.segment_leaf_local_authority_v3.MetadataV3,
) !void {
    try expected.validate();
    const global = try frontend.recursion.span_statement.SpanStatement
        .fromCanonicalWords(&expected.base_statement_words);
    const executed = switch (global.body) {
        .empty => return error.ReexecutedSegmentMismatch,
        .executed => |value| value,
    };
    const local_cycles = std.math.cast(u32, result.cycle_count) orelse
        return error.ReexecutedSegmentMismatch;
    const expected_global_first = std.math.add(
        u64,
        expected.global_cycle_start,
        1,
    ) catch return error.ReexecutedSegmentMismatch;
    const is_first = expected.segment_index == 0;
    const is_final = expected.segment_index + 1 == expected.segment_count;
    if (result.clock_frame != .leaf_local or
        result.segment_index != expected.segment_index or
        global.job.segment_count != expected.segment_count or
        result.global_first_cycle != expected_global_first or
        local_cycles != expected.local_cycle_count or
        result.segment_role.is_first != is_first or
        result.segment_role.is_last != is_final or
        (result.input != null) != is_first or
        (result.completion_reason != null) != is_final or
        (result.continuation == null) != is_final or
        result.entry_cpu.pc != executed.entry.pc or
        !std.mem.eql(u32, &result.entry_cpu.regs, &executed.entry.registers) or
        result.exit_cpu.pc != executed.exit.pc or
        !std.mem.eql(u32, &result.exit_cpu.regs, &executed.exit.registers) or
        result.execution_trace.initial_pc != result.entry_cpu.pc or
        result.execution_trace.final_pc != result.exit_cpu.pc)
    {
        return error.ReexecutedSegmentMismatch;
    }
    const external = result.execution_trace.recordedExternalSteps();
    const total = std.math.add(
        usize,
        result.execution_trace.step_count,
        external,
    ) catch return error.ReexecutedSegmentMismatch;
    if (total != local_cycles) return error.ReexecutedSegmentMismatch;
    result.execution_trace.validateClockRange(
        0,
        local_cycles,
        external,
    ) catch return error.ReexecutedSegmentMismatch;
    try frontend.recursion.segment_statement_v2.validateMemoryWords(
        result.rw_memory.words,
        result.segment_role,
        local_cycles,
    );
    try frontend.recursion.segment_statement_v2.validateClockBoundary(
        result.entry_access_clocks.register_clocks,
        result.entry_access_clocks.memory_clocks,
        0,
    );
    try frontend.recursion.segment_statement_v2.validateClockBoundary(
        result.exit_access_clocks.register_clocks,
        result.exit_access_clocks.memory_clocks,
        local_cycles,
    );

    const entry = try frontend.recursion.segment_statement_v2
        .snapshotIdentityReusingRoot(
        .{
            .id = expected.entry.snapshot_id,
            .count = expected.entry.snapshot_count,
            .root = expected.entry.continuation_root,
        },
        result.rw_memory.words,
        .initial_word,
    );
    const exit = try frontend.recursion.segment_statement_v2
        .snapshotIdentityReusingRoot(
        .{
            .id = expected.exit.snapshot_id,
            .count = expected.exit.snapshot_count,
            .root = expected.exit.continuation_root,
        },
        result.rw_memory.words,
        .final_word,
    );
    const entry_memory_clock_id = frontend.recursion.segment_statement_v2
        .memoryClockIdentity(result.entry_access_clocks.memory_clocks);
    const exit_memory_clock_id = frontend.recursion.segment_statement_v2
        .memoryClockIdentity(result.exit_access_clocks.memory_clocks);
    if (!std.meta.eql(entry.id, expected.entry.snapshot_id) or
        entry.count != expected.entry.snapshot_count or
        entry.root != expected.entry.continuation_root or
        !std.meta.eql(exit.id, expected.exit.snapshot_id) or
        exit.count != expected.exit.snapshot_count or
        exit.root != expected.exit.continuation_root or
        !std.meta.eql(
            result.entry_access_clocks.register_clocks,
            expected.entry.register_clocks,
        ) or !std.meta.eql(
        result.exit_access_clocks.register_clocks,
        expected.exit.register_clocks,
    ) or !std.meta.eql(entry_memory_clock_id, expected.entry.memory_clock_id) or
        !std.meta.eql(exit_memory_clock_id, expected.exit.memory_clock_id) or
        result.entry_access_clocks.memory_clocks.len !=
            expected.entry.memory_clock_count or
        result.exit_access_clocks.memory_clocks.len !=
            expected.exit.memory_clock_count)
    {
        return error.ReexecutedSegmentMismatch;
    }
    const completion = if (result.completion_reason) |reason|
        try frontend.recursion.segment_statement_v2.completionFromRunner(
            reason,
            result.completion_address,
            result.completion_value,
            result.completion_clock,
        )
    else
        null;
    if (!std.meta.eql(completion, expected.completion))
        return error.ReexecutedSegmentMismatch;
}

fn parseCandidateResult(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(candidate_receipt.ResultSealed) {
    _ = try candidate_receipt.validateSeal(bytes);
    var parsed = try std.json.parseFromSlice(
        candidate_receipt.ResultSealed,
        allocator,
        bytes,
        .{ .allocate = .alloc_always, .ignore_unknown_fields = false },
    );
    errdefer parsed.deinit();
    const canonical = try std.json.Stringify.valueAlloc(
        allocator,
        parsed.value,
        .{},
    );
    defer allocator.free(canonical);
    if (canonical.len + 1 != bytes.len or
        !std.mem.eql(u8, canonical, bytes[0..canonical.len]))
    {
        return error.InvalidCanonicalJson;
    }
    if (!std.mem.eql(u8, parsed.value.schema, candidate_receipt.schema) or
        !std.mem.eql(u8, parsed.value.status, "execution-captured-not-proved") or
        parsed.value.production_active or
        parsed.value.proof_or_fresh_verification or
        parsed.value.product_admissible or parsed.value.segment_count == 0 or
        parsed.value.segment_receipts.len != parsed.value.segment_count or
        parsed.value.segment_step_budget != authority.segment_step_budget)
    {
        return error.InvalidMatchedAbCandidateCapture;
    }
    return parsed;
}

fn validateCandidateJoin(
    candidate: candidate_receipt.ResultSealed,
    baseline: *const contract.MaterializationResult,
) !void {
    if (!candidateIdentityEql(candidate.input, baseline.input) or
        !candidateIdentityEql(candidate.expected_output, baseline.expected_output))
    {
        return error.MatchedAbSemanticInputOutputMismatch;
    }
}

fn reopenCandidateIdentity(
    allocator: std.mem.Allocator,
    identity: candidate_receipt.FileIdentity,
) !void {
    try identity.validate();
    const bytes = try artifact_io.readFileBounded(
        allocator,
        identity.path,
        maximum_candidate_result_bytes,
    );
    defer allocator.free(bytes);
    if (bytes.len != identity.bytes or
        !std.meta.eql(support.sha256(bytes), identity.sha256))
    {
        return error.InvalidMatchedAbCandidateCapture;
    }
}

fn candidateIdentityEql(
    candidate: candidate_receipt.FileIdentity,
    baseline: contract.Identity,
) bool {
    return candidate.bytes == baseline.bytes and
        std.mem.eql(u8, candidate.path, baseline.path) and
        std.meta.eql(candidate.sha256, contract.parseSha256(baseline.sha256) catch
            return false);
}

fn identityEql(left: contract.Identity, right: contract.Identity) bool {
    return left.bytes == right.bytes and
        std.mem.eql(u8, left.path, right.path) and
        std.mem.eql(u8, left.sha256, right.sha256);
}

fn typedIdentity(value: contract.TypedIdentity) contract.Identity {
    return .{ .bytes = value.bytes, .path = value.path, .sha256 = value.sha256 };
}

fn ensureWithinCap(timer: *std.time.Timer, hard_cap_ns: u64) !void {
    if (timer.read() > hard_cap_ns) return error.HardCapExceeded;
}

const FailureReason = enum { staged_peak_exceeds_budget, provider_log_exceeds_target };

fn failureReason(
    estimate: authority.LegacyEstimate,
    provider_log_size: u32,
) ?FailureReason {
    if (estimate.staged_peak_lower_bound_bytes > authority.host_byte_budget)
        return .staged_peak_exceeds_budget;
    if (provider_log_size > authority.target_provider_log_size)
        return .provider_log_exceeds_target;
    return null;
}

fn reportFailure(
    reason: FailureReason,
    segment_index: usize,
    provider_log_size: u32,
    provider_n_rows: u32,
    estimate: authority.LegacyEstimate,
) void {
    std.debug.print(
        "matched_ab_geometry_failure_v1 reason={s} segment_index={d} " ++
            "provider_log_size={d} provider_n_rows={d} " ++
            "tree0_columns={d} tree0_source_bytes={d} " ++
            "tree0_retained_coefficient_bytes={d} " ++
            "tree0_extended_evaluation_bytes={d} tree0_minimum_resident_bytes={d} " ++
            "tree1_columns={d} tree1_source_bytes={d} " ++
            "tree1_retained_coefficient_bytes={d} " ++
            "tree1_extended_evaluation_bytes={d} tree1_minimum_resident_bytes={d} " ++
            "tree2_columns={d} tree2_source_bytes={d} " ++
            "tree2_retained_coefficient_bytes={d} " ++
            "tree2_extended_evaluation_bytes={d} tree2_minimum_resident_bytes={d} " ++
            "composition_columns={d} composition_log_size={d} " ++
            "composition_source_bytes={d} " ++
            "composition_retained_coefficient_bytes={d} " ++
            "composition_extended_evaluation_bytes={d} " ++
            "composition_minimum_resident_bytes={d} " ++
            "retained_opening_lower_bound_bytes={d} " ++
            "commit_transient_lower_bound_bytes={d} " ++
            "staged_peak_lower_bound_bytes={d} host_byte_budget={d}\n",
        .{
            @tagName(reason),
            segment_index,
            provider_log_size,
            provider_n_rows,
            estimate.tree0.column_count,
            estimate.tree0.source_bytes,
            estimate.tree0.retained_coefficient_bytes,
            estimate.tree0.extended_evaluation_bytes,
            estimate.tree0.minimum_resident_bytes,
            estimate.tree1.column_count,
            estimate.tree1.source_bytes,
            estimate.tree1.retained_coefficient_bytes,
            estimate.tree1.extended_evaluation_bytes,
            estimate.tree1.minimum_resident_bytes,
            estimate.tree2.column_count,
            estimate.tree2.source_bytes,
            estimate.tree2.retained_coefficient_bytes,
            estimate.tree2.extended_evaluation_bytes,
            estimate.tree2.minimum_resident_bytes,
            estimate.composition.column_count,
            estimate.composition_column_log_size,
            estimate.composition.source_bytes,
            estimate.composition.retained_coefficient_bytes,
            estimate.composition.extended_evaluation_bytes,
            estimate.composition.minimum_resident_bytes,
            estimate.retained_opening_lower_bound_bytes,
            estimate.commit_transient_lower_bound_bytes,
            estimate.staged_peak_lower_bound_bytes,
            authority.host_byte_budget,
        },
    );
}

const Options = struct {
    audit: []u8,
    baseline_materialization: []u8,
    candidate_capture: []u8,
    hard_cap_ns: u64,

    fn parseAndResolve(
        allocator: std.mem.Allocator,
        arguments: []const []const u8,
    ) !Options {
        if (arguments.len != 8) return error.InvalidArguments;
        var audit_path: ?[]const u8 = null;
        var baseline: ?[]const u8 = null;
        var candidate: ?[]const u8 = null;
        var hard_cap_seconds: ?u64 = null;
        var cursor: usize = 0;
        while (cursor < arguments.len) : (cursor += 2) {
            const name = arguments[cursor];
            const value = arguments[cursor + 1];
            if (value.len == 0) return error.InvalidArguments;
            if (std.mem.eql(u8, name, "--audit")) {
                try set(&audit_path, value);
            } else if (std.mem.eql(u8, name, "--baseline-materialization")) {
                try set(&baseline, value);
            } else if (std.mem.eql(u8, name, "--candidate-capture")) {
                try set(&candidate, value);
            } else if (std.mem.eql(u8, name, "--hard-cap-seconds")) {
                if (hard_cap_seconds != null) return error.DuplicateArgument;
                hard_cap_seconds = std.fmt.parseUnsigned(
                    u64,
                    value,
                    10,
                ) catch return error.InvalidArguments;
            } else return error.InvalidArguments;
        }
        const seconds = hard_cap_seconds orelse return error.InvalidArguments;
        if (seconds < minimum_hard_cap_seconds or
            seconds > maximum_hard_cap_seconds)
        {
            return error.InvalidArguments;
        }
        const hard_cap_ns = std.math.mul(
            u64,
            seconds,
            std.time.ns_per_s,
        ) catch return error.InvalidArguments;
        const resolved_audit = try resolve(
            allocator,
            audit_path orelse return error.InvalidArguments,
        );
        errdefer allocator.free(resolved_audit);
        const resolved_baseline = try resolve(
            allocator,
            baseline orelse return error.InvalidArguments,
        );
        errdefer allocator.free(resolved_baseline);
        const resolved_candidate = try resolve(
            allocator,
            candidate orelse return error.InvalidArguments,
        );
        errdefer allocator.free(resolved_candidate);
        if (std.mem.eql(u8, resolved_audit, resolved_baseline) or
            std.mem.eql(u8, resolved_audit, resolved_candidate) or
            std.mem.eql(u8, resolved_baseline, resolved_candidate))
        {
            return error.DuplicatePath;
        }
        return .{
            .audit = resolved_audit,
            .baseline_materialization = resolved_baseline,
            .candidate_capture = resolved_candidate,
            .hard_cap_ns = hard_cap_ns,
        };
    }

    fn deinit(self: *Options, allocator: std.mem.Allocator) void {
        allocator.free(self.audit);
        allocator.free(self.baseline_materialization);
        allocator.free(self.candidate_capture);
        self.* = undefined;
    }
};

fn resolve(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return artifact_io.resolveAbsolute(allocator, path);
}

fn set(slot: *?[]const u8, value: []const u8) !void {
    if (slot.* != null) return error.DuplicateArgument;
    slot.* = value;
}

test "geometry audit CLI rejects aliases and pins hard cap" {
    const valid = [_][]const u8{
        "--audit",                    "/tmp/audit.json",
        "--baseline-materialization", "/tmp/baseline.json",
        "--candidate-capture",        "/tmp/candidate.json",
        "--hard-cap-seconds",         "600",
    };
    var parsed = try Options.parseAndResolve(std.testing.allocator, &valid);
    defer parsed.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        @as(u64, 600 * std.time.ns_per_s),
        parsed.hard_cap_ns,
    );
    var duplicate = valid;
    duplicate[1] = duplicate[3];
    try std.testing.expectError(
        error.DuplicatePath,
        Options.parseAndResolve(std.testing.allocator, &duplicate),
    );
}

test "failure reason preserves budget-before-provider rejection order" {
    var estimate: authority.LegacyEstimate = undefined;
    estimate.staged_peak_lower_bound_bytes = authority.host_byte_budget + 1;
    try std.testing.expectEqual(
        FailureReason.staged_peak_exceeds_budget,
        failureReason(estimate, authority.target_provider_log_size + 1).?,
    );
    estimate.staged_peak_lower_bound_bytes = authority.host_byte_budget;
    try std.testing.expectEqual(
        FailureReason.provider_log_exceeds_target,
        failureReason(estimate, authority.target_provider_log_size + 1).?,
    );
    try std.testing.expectEqual(
        @as(?FailureReason, null),
        failureReason(estimate, authority.target_provider_log_size),
    );
}

comptime {
    if (authority.production_active or authority.proof_or_fresh_verification or
        candidate_receipt.production_active or
        candidate_receipt.proof_or_fresh_verification)
    {
        @compileError("matched A/B geometry audit became active");
    }
}
