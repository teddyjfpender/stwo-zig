//! Independent cold replay of a sealed combined-candidate execution capture.
//!
//! The replay takes no execution authority besides the final capture result.
//! It reopens every retained identity, reexecutes the admitted ELF, compares
//! every live tape with its cold artifact, and reconstructs the manifest and
//! typed journal in memory. Only the sealed replay receipt is published.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const capture = @import("ethereum_candidate_combined_execution_capture_v1.zig");
const capture_receipt =
    @import("ethereum_candidate_combined_execution_capture_receipt_v1.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const replay_receipt =
    @import("ethereum_candidate_combined_execution_replay_receipt_v1.zig");
const resource_usage = @import("resource_usage.zig");
const tape_artifact = @import("bulk_memcpy_tape_artifact_v1.zig");

const elf_receipt = frontend.testing.ethereum_candidate_combined_elf_receipt_v1;
const registry_mod = frontend.testing.ethereum_candidate_private_registry_v1;
const capability_mod =
    frontend.testing.ethereum_candidate_execution_capability_v1;
const journal_mod = frontend.testing.ethereum_candidate_execution_journal_v1;
const observed_journal = frontend.testing.ethereum_candidate_observed_journal_v1;
const combined_result = frontend.testing.ethereum_candidate_combined_result_v1;

pub const production_active = false;
pub const proof_or_fresh_verification = false;
const Digest = capture_receipt.Digest;
const zero_digest = [_]u8{0} ** 32;
const maximum_general_file_bytes: usize = 512 * 1024 * 1024;
const maximum_manifest_bytes: usize = 64 * 1024 * 1024;

pub const ReplayOptions = struct {
    result_path: []const u8,
    replay_receipt_path: []const u8,
};

pub fn replay(allocator: std.mem.Allocator, options: ReplayOptions) !void {
    if (production_active or proof_or_fresh_verification)
        return error.CandidateExecutionReplayActivated;
    if (std.mem.eql(u8, options.result_path, options.replay_receipt_path))
        return error.DuplicatePath;
    var clock = try evidence.Clock.start();
    const resources_before = resource_usage.capture();

    const result_bytes = try artifact_io.readFileBounded(
        allocator,
        options.result_path,
        capture_receipt.maximum_receipt_bytes,
    );
    defer allocator.free(result_bytes);
    const result_file = fileIdentity(options.result_path, result_bytes);
    try result_file.validate();
    const result_content_identity = try capture_receipt.validateSeal(result_bytes);
    var parsed_result = try std.json.parseFromSlice(
        capture_receipt.ResultSealed,
        allocator,
        result_bytes,
        .{},
    );
    defer parsed_result.deinit();
    if (!std.mem.eql(
        u8,
        &result_content_identity,
        &(try capture_receipt.parseDigest(
            parsed_result.value.content_sha256,
        )),
    )) return error.InvalidCandidateExecutionReceiptSeal;
    const result = parsed_result.value.unsigned();

    const admission_bytes = try reopenIdentity(
        allocator,
        result.admission_receipt,
        capture_receipt.maximum_receipt_bytes,
    );
    defer allocator.free(admission_bytes);
    var parsed_admission = try elf_receipt.decodeAlloc(allocator, admission_bytes);
    defer parsed_admission.deinit();
    const admission = try elf_receipt.fromWire(parsed_admission.value);
    const canonical_admission = try elf_receipt.encodeAlloc(allocator, admission);
    defer allocator.free(canonical_admission);
    try capture.validateCanonicalReceiptFraming(
        canonical_admission,
        admission_bytes,
    );
    try requireSameFile(result.executable, admission.elf);
    try requireSameFile(result.checker, admission.checker);

    const elf_bytes = try reopenIdentity(
        allocator,
        result.executable,
        maximum_general_file_bytes,
    );
    defer allocator.free(elf_bytes);
    const checker_bytes = try reopenIdentity(
        allocator,
        result.checker,
        maximum_general_file_bytes,
    );
    defer allocator.free(checker_bytes);
    const producer_bytes = try reopenIdentity(
        allocator,
        result.producer_executable,
        maximum_general_file_bytes,
    );
    defer allocator.free(producer_bytes);

    var source_paths: [elf_receipt.source_file_capacity][]const u8 = undefined;
    const source_count: usize = admission.source_closure.count;
    for (admission.source_closure.files[0..source_count], 0..) |file, index|
        source_paths[index] = file.?.path;
    const source_closure = try elf_receipt.collectSourceClosure(
        admission.source_root,
        source_paths[0..source_count],
    );
    const capability = try capability_mod.mintCombinedCandidate(
        allocator,
        admission,
        elf_bytes,
        source_closure,
        try registry_mod.Registry.canonical(),
    );
    try result.validate(capability);
    const canonical_result = try capture_receipt.encodeResultAlloc(
        allocator,
        result,
        capability,
    );
    defer allocator.free(canonical_result);
    if (!std.mem.eql(u8, canonical_result, result_bytes))
        return error.NonCanonicalCandidateExecutionReceipt;

    const input = try reopenIdentity(
        allocator,
        result.input,
        maximum_general_file_bytes,
    );
    defer allocator.free(input);
    const expected_output = try reopenIdentity(
        allocator,
        result.expected_output,
        16 * 1024 * 1024,
    );
    defer allocator.free(expected_output);
    const retained_manifest = try reopenIdentity(
        allocator,
        result.manifest,
        maximum_manifest_bytes,
    );
    defer allocator.free(retained_manifest);
    const retained_journal = try reopenIdentity(
        allocator,
        result.journal,
        capture_receipt.maximum_journal_bytes,
    );
    defer allocator.free(retained_journal);
    try validateRetainedJournal(
        allocator,
        retained_journal,
        capability,
        result.journal_identity,
    );
    const segment_step_budget = std.math.cast(
        usize,
        result.segment_step_budget,
    ) orelse return error.CandidateExecutionReplayIntegerOverflow;

    var hard_timer = try std.time.Timer.start();
    var context = ReplayContext{
        .allocator = allocator,
        .capability = capability,
        .segment_receipts = result.segment_receipts,
        .expected_output = expected_output,
        .hard_timer = &hard_timer,
        .hard_cap_ns = result.hard_cap_ns,
    };
    var observer = try observed_journal.ObserverV1.init(
        allocator,
        capability,
        result.input.sha256,
        capture.executionSessionIdentity(
            capability,
            result.input,
            result.expected_output,
            segment_step_budget,
        ),
        segment_step_budget,
        .leaf_local,
        .{
            .context = &context,
            .capture_fn = ReplayContext.captureSegment,
        },
    );
    defer observer.deinit();
    var manifest_writer = std.Io.Writer.Allocating.init(allocator);
    defer manifest_writer.deinit();
    try frontend.diagnostics.segment_manifest.streamCandidateObserved(
        allocator,
        capability,
        elf_bytes,
        input,
        segment_step_budget,
        true,
        .leaf_local,
        &manifest_writer.writer,
        &observer,
    );
    var replayed_journal = try observer.finish();
    defer replayed_journal.deinit();
    try replayed_journal.validateAgainst(capability);
    if (context.next_segment_index != result.segment_count or
        !context.terminal_output_matched or
        !std.mem.eql(u8, manifest_writer.written(), retained_manifest))
    {
        return error.CandidateExecutionReplayMismatch;
    }

    const replayed_journal_identity = try replayed_journal.view().identity(
        capability,
    );
    if (!std.mem.eql(
        u8,
        &replayed_journal_identity,
        &result.journal_identity,
    )) return error.CandidateExecutionJournalIdentityMismatch;
    const replayed_journal_bytes = try capture_receipt.encodeJournalAlloc(
        allocator,
        .{
            .capability_identity = capability.identity,
            .journal_identity = replayed_journal_identity,
            .header = replayed_journal.header,
            .segments = replayed_journal.segments,
            .summary = replayed_journal.summary,
        },
        capability,
    );
    defer allocator.free(replayed_journal_bytes);
    if (!std.mem.eql(u8, replayed_journal_bytes, retained_journal))
        return error.CandidateExecutionJournalReplayMismatch;
    try requireResultTotals(result, replayed_journal.summary);
    if (hard_timer.read() >= result.hard_cap_ns)
        return error.CandidateExecutionHardCapExceeded;

    const replay_executable_path = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(replay_executable_path);
    const replay_executable_bytes = try artifact_io.readFileBounded(
        allocator,
        replay_executable_path,
        maximum_general_file_bytes,
    );
    defer allocator.free(replay_executable_bytes);
    const replay_executable = fileIdentity(
        replay_executable_path,
        replay_executable_bytes,
    );
    const replay_timing = try clock.finish();
    const resources_after = resource_usage.capture();
    const receipt_bytes = try replay_receipt.encodeAlloc(
        allocator,
        .{
            .source_result = result_file,
            .source_result_content_sha256 = result_content_identity,
            .replay_executable = replay_executable,
            .capability_identity = capability.identity,
            .admission_receipt_identity = capability.admission_receipt_identity,
            .source_closure_identity = capability.source_closure_identity,
            .journal_identity = replayed_journal_identity,
            .segment_count = result.segment_count,
            .reopened_segment_receipt_count = context.next_segment_index,
            .reopened_bulk_tape_count = context.reopened_bulk_tape_count,
            .manifest_chain_recomputed = true,
            .journal_chain_recomputed = true,
            .source_closure_recomputed = true,
            .terminal_output_recomputed = true,
            .every_file_identity_reopened = true,
            .every_tape_canonical_roundtrip = true,
            .replay_timing = replay_timing,
            .process_resources = resource_usage.report(
                resources_before,
                resources_after,
            ),
        },
        capability,
    );
    defer allocator.free(receipt_bytes);
    try artifact_io.publishCreateOnlyDurable(
        options.replay_receipt_path,
        receipt_bytes,
    );
    const reopened_receipt = try reopenExactBytes(
        allocator,
        options.replay_receipt_path,
        receipt_bytes,
        replay_receipt.maximum_bytes,
    );
    defer allocator.free(reopened_receipt);
    try validateReplayReceipt(
        allocator,
        reopened_receipt,
        capability,
    );
}

const ReplayContext = struct {
    allocator: std.mem.Allocator,
    capability: capability_mod.Capability,
    segment_receipts: []const capture_receipt.FileIdentity,
    expected_output: []const u8,
    hard_timer: *std.time.Timer,
    hard_cap_ns: u64,
    next_segment_index: u32 = 0,
    reopened_bulk_tape_count: u32 = 0,
    terminal_output_matched: bool = false,

    fn captureSegment(
        erased: *anyopaque,
        capability: capability_mod.Capability,
        candidate: *const combined_result.SegmentResult,
        manifest_record_identity: Digest,
    ) !observed_journal.SegmentExecutionCustodyV1 {
        const self: *ReplayContext = @ptrCast(@alignCast(erased));
        const receipt_index: usize = self.next_segment_index;
        if (!std.meta.eql(capability, self.capability) or
            receipt_index >= self.segment_receipts.len or
            candidate.ethereum.base.segment_index != self.next_segment_index)
        {
            return error.CandidateExecutionReplaySegmentOrderMismatch;
        }
        try self.ensureWithinCap();
        const receipt_bytes = try reopenIdentity(
            self.allocator,
            self.segment_receipts[receipt_index],
            capture_receipt.maximum_segment_receipt_bytes,
        );
        defer self.allocator.free(receipt_bytes);
        var segment = try parseSegment(
            self.allocator,
            receipt_bytes,
            capability,
        );
        defer segment.parsed.deinit();
        const value = segment.value;
        const base = &candidate.ethereum.base;
        const external_origin = candidate.bulk_memcpy.externalStepOrigin();
        const stack_tape_identity = try candidate.stack_swap.captureIdentity();
        const stack_custody_identity = capture.stackCustodyIdentity(
            capability,
            manifest_record_identity,
            base.segment_index,
            external_origin,
            stack_tape_identity,
        );

        var bulk_tape_identity = zero_digest;
        var bulk_custody: ?journal_mod.ExecutionArtifactCustody = null;
        if (candidate.bulk_memcpy.rows().len != 0) {
            const tape_file = value.bulk_tape.file orelse
                return error.MissingCandidateExecutionTape;
            const tape_bytes = try reopenIdentity(
                self.allocator,
                tape_file,
                tape_artifact.maximum_execution_artifact_bytes,
            );
            defer self.allocator.free(tape_bytes);
            const live_bytes = try tape_artifact.encodeExecutionAlloc(
                self.allocator,
                &candidate.bulk_memcpy,
            );
            defer self.allocator.free(live_bytes);
            if (!std.mem.eql(u8, live_bytes, tape_bytes))
                return error.CandidateExecutionTapeReplayMismatch;
            var cold_tape = try tape_artifact.decodeExecutionAlloc(
                self.allocator,
                tape_bytes,
            );
            defer cold_tape.deinit();
            const canonical_tape = try tape_artifact.encodeExecutionAlloc(
                self.allocator,
                &cold_tape,
            );
            defer self.allocator.free(canonical_tape);
            if (!std.mem.eql(u8, canonical_tape, tape_bytes) or
                cold_tape.externalStepOrigin() != external_origin)
            {
                return error.NonCanonicalCandidateExecutionTape;
            }
            bulk_tape_identity = tape_artifact.identity(tape_bytes);
            const cold_reopen_identity = capture.coldReopenCustodyIdentity(
                capability,
                manifest_record_identity,
                base.segment_index,
                external_origin,
                tape_file,
                bulk_tape_identity,
            );
            bulk_custody = try journal_mod.ExecutionArtifactCustody.create(
                capability,
                base.segment_index,
                external_origin,
                bulk_tape_identity,
                cold_reopen_identity,
            );
            self.reopened_bulk_tape_count += 1;
        } else if (value.bulk_tape.present or value.bulk_tape.file != null) {
            return error.UnexpectedCandidateExecutionTape;
        }
        const base_capture_identity = capture.baseCaptureIdentity(
            capability,
            manifest_record_identity,
            candidate,
            bulk_tape_identity,
            stack_tape_identity,
        );
        try requireSegmentMatches(
            value,
            capability,
            candidate,
            manifest_record_identity,
            base_capture_identity,
            bulk_tape_identity,
            bulk_custody,
            stack_tape_identity,
            stack_custody_identity,
        );
        if (base.isComplete()) {
            const output = base.output orelse return error.MissingCandidateOutput;
            if (!std.mem.eql(u8, output, self.expected_output))
                return error.CandidatePublicOutputMismatch;
            self.terminal_output_matched = true;
        }
        self.next_segment_index += 1;
        try self.ensureWithinCap();
        return .{
            .manifest_record_identity = manifest_record_identity,
            .base_segment_capture_identity = base_capture_identity,
            .bulk_execution_artifact = bulk_custody,
            .stack_swap_custody_identity = stack_custody_identity,
        };
    }

    fn ensureWithinCap(self: *ReplayContext) !void {
        if (self.hard_timer.read() >= self.hard_cap_ns)
            return error.CandidateExecutionHardCapExceeded;
    }
};

const ParsedSegment = struct {
    parsed: std.json.Parsed(capture_receipt.SegmentSealed),
    value: capture_receipt.SegmentUnsigned,
};

fn parseSegment(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    capability: capability_mod.Capability,
) !ParsedSegment {
    const seal = try capture_receipt.validateSeal(bytes);
    var parsed = try std.json.parseFromSlice(
        capture_receipt.SegmentSealed,
        allocator,
        bytes,
        .{},
    );
    errdefer parsed.deinit();
    if (!std.mem.eql(
        u8,
        &seal,
        &(try capture_receipt.parseDigest(parsed.value.content_sha256)),
    )) return error.InvalidCandidateExecutionReceiptSeal;
    const value = parsed.value.unsigned();
    try value.validate(capability);
    const canonical = try capture_receipt.encodeSegmentAlloc(
        allocator,
        value,
        capability,
    );
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, bytes))
        return error.NonCanonicalCandidateExecutionReceipt;
    return .{ .parsed = parsed, .value = value };
}

fn requireSegmentMatches(
    value: capture_receipt.SegmentUnsigned,
    capability: capability_mod.Capability,
    candidate: *const combined_result.SegmentResult,
    manifest_record_identity: Digest,
    base_capture_identity: Digest,
    bulk_tape_identity: Digest,
    bulk_custody: ?journal_mod.ExecutionArtifactCustody,
    stack_tape_identity: Digest,
    stack_custody_identity: Digest,
) !void {
    const base = &candidate.ethereum.base;
    const external_origin = std.math.cast(
        u64,
        candidate.bulk_memcpy.externalStepOrigin(),
    ) orelse return error.CandidateExecutionReplayIntegerOverflow;
    const cycle_count = std.math.cast(u64, base.cycle_count) orelse
        return error.CandidateExecutionReplayIntegerOverflow;
    const bulk_calls = std.math.cast(u64, candidate.bulk_memcpy.records().len) orelse
        return error.CandidateExecutionReplayIntegerOverflow;
    const bulk_words = std.math.cast(u64, candidate.bulk_memcpy.wordRows().len) orelse
        return error.CandidateExecutionReplayIntegerOverflow;
    const swap_calls = std.math.cast(u64, candidate.stack_swap.records().len) orelse
        return error.CandidateExecutionReplayIntegerOverflow;
    const swap_words = std.math.cast(u64, candidate.stack_swap.wordRows().len) orelse
        return error.CandidateExecutionReplayIntegerOverflow;
    if (!std.mem.eql(u8, &value.capability_identity, &capability.identity) or
        !std.mem.eql(
            u8,
            &value.admission_receipt_identity,
            &capability.admission_receipt_identity,
        ) or !std.mem.eql(
        u8,
        &value.manifest_record_identity,
        &manifest_record_identity,
    ) or !std.mem.eql(
        u8,
        &value.base_segment_capture_identity,
        &base_capture_identity,
    ) or value.segment_index != base.segment_index or
        value.global_first_cycle != base.global_first_cycle or
        value.cycle_count != cycle_count or
        value.external_step_origin != external_origin or
        value.bulk_call_count != bulk_calls or
        value.bulk_word_row_count != bulk_words or
        !std.mem.eql(u8, &value.bulk_tape_identity, &bulk_tape_identity) or
        !std.mem.eql(
            u8,
            &value.bulk_execution_custody_identity,
            &(if (bulk_custody) |custody| custody.identity else zero_digest),
        ) or value.stack_swap_call_count != swap_calls or
        value.stack_swap_word_row_count != swap_words or
        !std.mem.eql(
            u8,
            &value.stack_swap_tape_identity,
            &stack_tape_identity,
        ) or !std.mem.eql(
        u8,
        &value.stack_swap_custody_identity,
        &stack_custody_identity,
    )) return error.CandidateExecutionSegmentReplayMismatch;
}

fn validateRetainedJournal(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    capability: capability_mod.Capability,
    expected_identity: Digest,
) !void {
    const seal = try capture_receipt.validateSeal(bytes);
    var parsed = try std.json.parseFromSlice(
        capture_receipt.JournalSealed,
        allocator,
        bytes,
        .{},
    );
    defer parsed.deinit();
    if (!std.mem.eql(
        u8,
        &seal,
        &(try capture_receipt.parseDigest(parsed.value.content_sha256)),
    )) return error.InvalidCandidateExecutionReceiptSeal;
    const value = parsed.value.unsigned();
    const view = journal_mod.JournalView{
        .header = value.header,
        .segments = value.segments,
        .summary = value.summary,
    };
    const identity = try view.identity(capability);
    if (!std.mem.eql(u8, &identity, &expected_identity) or
        !std.mem.eql(u8, &identity, &value.journal_identity))
    {
        return error.CandidateExecutionJournalIdentityMismatch;
    }
    const canonical = try capture_receipt.encodeJournalAlloc(
        allocator,
        value,
        capability,
    );
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, bytes))
        return error.NonCanonicalCandidateExecutionJournal;
}

fn validateReplayReceipt(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    capability: capability_mod.Capability,
) !void {
    const seal = try capture_receipt.validateSeal(bytes);
    var parsed = try std.json.parseFromSlice(
        replay_receipt.Sealed,
        allocator,
        bytes,
        .{},
    );
    defer parsed.deinit();
    if (!std.mem.eql(
        u8,
        &seal,
        &(try capture_receipt.parseDigest(parsed.value.content_sha256)),
    )) return error.InvalidCandidateExecutionReplayReceiptSeal;
    const value = parsed.value.unsigned();
    try value.validate(capability);
    const canonical = try replay_receipt.encodeAlloc(
        allocator,
        value,
        capability,
    );
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, bytes))
        return error.NonCanonicalCandidateExecutionReplayReceipt;
}

fn requireResultTotals(
    result: capture_receipt.ResultUnsigned,
    summary: journal_mod.Summary,
) !void {
    if (result.segment_count != summary.segment_count or
        result.total_cycles != summary.total_cycles or
        result.total_core_rows != summary.total_core_trace_rows or
        result.total_base_external_retirements !=
            summary.total_base_profile_external_retirements or
        result.total_bulk_memcpy_retirements !=
            summary.member_retirement_totals[0] or
        result.total_bulk_memcpy_witness_rows !=
            summary.member_witness_row_totals[0] or
        result.total_stack_swap_retirements !=
            summary.member_retirement_totals[1] or
        result.total_stack_swap_witness_rows !=
            summary.member_witness_row_totals[1])
    {
        return error.CandidateExecutionReplayTotalsMismatch;
    }
}

fn reopenIdentity(
    allocator: std.mem.Allocator,
    identity: capture_receipt.FileIdentity,
    maximum_bytes: usize,
) ![]u8 {
    try identity.validate();
    const bytes = try artifact_io.readFileBounded(
        allocator,
        identity.path,
        maximum_bytes,
    );
    errdefer allocator.free(bytes);
    const actual = fileIdentity(identity.path, bytes);
    if (actual.bytes != identity.bytes or
        !std.mem.eql(u8, &actual.sha256, &identity.sha256))
    {
        return error.CandidateExecutionFileIdentityMismatch;
    }
    return bytes;
}

fn reopenExactBytes(
    allocator: std.mem.Allocator,
    path: []const u8,
    expected: []const u8,
    maximum_bytes: usize,
) ![]u8 {
    const bytes = try artifact_io.readFileBounded(allocator, path, maximum_bytes);
    errdefer allocator.free(bytes);
    if (!std.mem.eql(u8, bytes, expected))
        return error.CandidateExecutionArtifactReopenMismatch;
    return bytes;
}

fn requireSameFile(
    actual: capture_receipt.FileIdentity,
    expected: elf_receipt.FileIdentity,
) !void {
    try actual.validate();
    try expected.validate(true);
    if (!std.mem.eql(u8, actual.path, expected.path) or
        actual.bytes != expected.bytes or
        !std.mem.eql(u8, &actual.sha256, &expected.sha256))
    {
        return error.CandidateExecutionFileIdentityMismatch;
    }
}

fn fileIdentity(
    path: []const u8,
    bytes: []const u8,
) capture_receipt.FileIdentity {
    var digest: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return .{ .path = path, .bytes = bytes.len, .sha256 = digest };
}

comptime {
    if (production_active or proof_or_fresh_verification or
        capture.production_active or capture.proof_or_fresh_verification or
        capture_receipt.production_active or
        capture_receipt.proof_or_fresh_verification or
        replay_receipt.production_active or
        replay_receipt.proof_or_fresh_verification or
        journal_mod.production_active or journal_mod.proof_or_fresh_verification)
    {
        @compileError("combined candidate execution replay became active");
    }
}
