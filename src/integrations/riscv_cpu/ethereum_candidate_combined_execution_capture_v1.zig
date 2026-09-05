//! Real execution-only capture for the receipt-admitted combined guest.
//!
//! This route executes the final bulk4+SWAP5 candidate session, persists and
//! cold reopens each nonempty bulk tape, and builds the frontend's typed
//! execution journal. It never proves a tape and cannot construct Product.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const receipt_wire =
    @import("ethereum_candidate_combined_execution_capture_receipt_v1.zig");
const resource_usage = @import("resource_usage.zig");
const tape_artifact = @import("bulk_memcpy_tape_artifact_v1.zig");

const elf_receipt = frontend.testing.ethereum_candidate_combined_elf_receipt_v1;
const registry_mod = frontend.testing.ethereum_candidate_private_registry_v1;
const capability_mod =
    frontend.testing.ethereum_candidate_execution_capability_v1;
const journal_mod = frontend.testing.ethereum_candidate_execution_journal_v1;
const observed_journal = frontend.testing.ethereum_candidate_observed_journal_v1;
const combined_result = frontend.testing.ethereum_candidate_combined_result_v1;

pub const maximum_segment_count: usize = 4_096;
pub const manifest_basename = "execution-manifest-v3.ndjson";
pub const journal_basename = "candidate-execution-journal-v1.json";
pub const result_basename = "candidate-execution-capture-v1.json";
pub const segment_directory_basename = "segments";
pub const production_active = false;
pub const proof_or_fresh_verification = false;

const Digest = [32]u8;
const zero_digest = [_]u8{0} ** 32;
pub const CaptureOptions = struct {
    receipt_path: []const u8,
    elf_path: []const u8,
    input_path: []const u8,
    expected_output_path: []const u8,
    output_root: []const u8,
    power_source: []const u8,
    segment_step_budget: usize,
    hard_cap_ns: u64,
};
pub fn capture(allocator: std.mem.Allocator, options: CaptureOptions) !void {
    if (production_active or proof_or_fresh_verification)
        return error.CandidateExecutionCaptureActivated;
    var hard_timer = try std.time.Timer.start();
    const resources_before = resource_usage.capture();
    var admission_clock = try evidence.Clock.start();

    const receipt_bytes = try artifact_io.readFileBounded(
        allocator,
        options.receipt_path,
        receipt_wire.maximum_receipt_bytes,
    );
    defer allocator.free(receipt_bytes);
    var parsed_receipt = try elf_receipt.decodeAlloc(allocator, receipt_bytes);
    defer parsed_receipt.deinit();
    const admitted_receipt = try elf_receipt.fromWire(parsed_receipt.value);
    const canonical_receipt = try elf_receipt.encodeAlloc(
        allocator,
        admitted_receipt,
    );
    defer allocator.free(canonical_receipt);
    try validateCanonicalReceiptFraming(canonical_receipt, receipt_bytes);
    if (!std.mem.eql(u8, admitted_receipt.elf.path, options.elf_path)) {
        return error.NonCanonicalCombinedCandidateReceipt;
    }
    const admission_receipt_file = fileIdentity(
        options.receipt_path,
        receipt_bytes,
    );

    const elf_bytes = try artifact_io.readFileBounded(
        allocator,
        options.elf_path,
        512 * 1024 * 1024,
    );
    defer allocator.free(elf_bytes);
    const elf_file = fileIdentity(options.elf_path, elf_bytes);
    try requireFileIdentity(elf_file, admitted_receipt.elf);

    const checker_bytes = try artifact_io.readFileBounded(
        allocator,
        admitted_receipt.checker.path,
        512 * 1024 * 1024,
    );
    defer allocator.free(checker_bytes);
    const checker_file = fileIdentity(
        admitted_receipt.checker.path,
        checker_bytes,
    );
    try requireFileIdentity(checker_file, admitted_receipt.checker);

    var source_paths: [elf_receipt.source_file_capacity][]const u8 = undefined;
    const source_count: usize = admitted_receipt.source_closure.count;
    for (admitted_receipt.source_closure.files[0..source_count], 0..) |file, index|
        source_paths[index] = file.?.path;
    const reopened_source_closure = try elf_receipt.collectSourceClosure(
        admitted_receipt.source_root,
        source_paths[0..source_count],
    );
    const registry = try registry_mod.Registry.canonical();
    const capability = try capability_mod.mintCombinedCandidate(
        allocator,
        admitted_receipt,
        elf_bytes,
        reopened_source_closure,
        registry,
    );

    const input_bytes = try artifact_io.readFileBounded(
        allocator,
        options.input_path,
        512 * 1024 * 1024,
    );
    defer allocator.free(input_bytes);
    const input_file = fileIdentity(options.input_path, input_bytes);
    const expected_output = try artifact_io.readFileBounded(
        allocator,
        options.expected_output_path,
        16 * 1024 * 1024,
    );
    defer allocator.free(expected_output);
    const expected_output_file = fileIdentity(
        options.expected_output_path,
        expected_output,
    );

    const producer_path = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(producer_path);
    const producer_bytes = try artifact_io.readFileBounded(
        allocator,
        producer_path,
        512 * 1024 * 1024,
    );
    defer allocator.free(producer_bytes);
    const producer_file = fileIdentity(producer_path, producer_bytes);
    const admission_timing = try admission_clock.finish();
    try ensureTimerWithinCap(&hard_timer, options.hard_cap_ns);

    try artifact_io.createDirectoryCreateOnly(options.output_root);
    const segment_root = try artifact_io.resolveCreateOnlyChild(
        allocator,
        options.output_root,
        segment_directory_basename,
    );
    defer allocator.free(segment_root);
    try artifact_io.createDirectoryCreateOnly(segment_root);

    const input_identity = input_file.sha256;
    const session_identity = executionSessionIdentity(
        capability,
        input_file,
        expected_output_file,
        options.segment_step_budget,
    );
    var context = CaptureContext{
        .allocator = allocator,
        .capability = capability,
        .segment_root = segment_root,
        .expected_output = expected_output,
        .hard_timer = &hard_timer,
        .hard_cap_ns = options.hard_cap_ns,
    };
    defer context.deinit();
    var observer = try observed_journal.ObserverV1.init(
        allocator,
        capability,
        input_identity,
        session_identity,
        options.segment_step_budget,
        .leaf_local,
        .{
            .context = &context,
            .capture_fn = CaptureContext.captureSegment,
        },
    );
    defer observer.deinit();
    var execution_clock = try evidence.Clock.start();
    var manifest_writer = std.Io.Writer.Allocating.init(allocator);
    defer manifest_writer.deinit();
    try frontend.diagnostics.segment_manifest.streamCandidateObserved(
        allocator,
        capability,
        elf_bytes,
        input_bytes,
        options.segment_step_budget,
        true,
        .leaf_local,
        &manifest_writer.writer,
        &observer,
    );
    var owned_journal = try observer.finish();
    defer owned_journal.deinit();
    try owned_journal.validateAgainst(capability);
    if (!context.final_output_matched or
        context.segment_receipts.items.len != owned_journal.segments.len)
    {
        return error.IncompleteCandidateExecutionCapture;
    }
    const execution_timing = try execution_clock.finish();
    try ensureTimerWithinCap(&hard_timer, options.hard_cap_ns);

    const manifest_path = try artifact_io.resolveCreateOnlyChild(
        allocator,
        options.output_root,
        manifest_basename,
    );
    defer allocator.free(manifest_path);
    try artifact_io.publishCreateOnlyDurable(
        manifest_path,
        manifest_writer.written(),
    );
    const reopened_manifest = try reopenExact(
        allocator,
        manifest_path,
        manifest_writer.written(),
        64 * 1024 * 1024,
    );
    defer allocator.free(reopened_manifest);
    const manifest_file = fileIdentity(manifest_path, reopened_manifest);

    const journal_identity = try owned_journal.view().identity(capability);
    const journal_bytes = try receipt_wire.encodeJournalAlloc(
        allocator,
        .{
            .capability_identity = capability.identity,
            .journal_identity = journal_identity,
            .header = owned_journal.header,
            .segments = owned_journal.segments,
            .summary = owned_journal.summary,
        },
        capability,
    );
    defer allocator.free(journal_bytes);
    const journal_path = try artifact_io.resolveCreateOnlyChild(
        allocator,
        options.output_root,
        journal_basename,
    );
    defer allocator.free(journal_path);
    try artifact_io.publishCreateOnlyDurable(journal_path, journal_bytes);
    const reopened_journal = try reopenExact(
        allocator,
        journal_path,
        journal_bytes,
        receipt_wire.maximum_journal_bytes,
    );
    defer allocator.free(reopened_journal);
    try validateJournalArtifact(
        allocator,
        reopened_journal,
        capability,
        journal_identity,
    );
    const journal_file = fileIdentity(journal_path, reopened_journal);

    const resources_after = resource_usage.capture();
    const resources = resource_usage.report(resources_before, resources_after);
    const segment_receipts = try context.fileIdentities(allocator);
    defer allocator.free(segment_receipts);
    const authority = capability.combined_candidate_authority.?;
    const summary = owned_journal.summary;
    const result_value = receipt_wire.ResultUnsigned{
        .power_source = options.power_source,
        .segment_step_budget = options.segment_step_budget,
        .hard_cap_ns = options.hard_cap_ns,
        .capability_identity = capability.identity,
        .admission_receipt_identity = capability.admission_receipt_identity,
        .source_closure_identity = capability.source_closure_identity,
        .program_commitment_identity = capability.program_commitment_identity,
        .candidate_authority_identity = authority.identity,
        .candidate_registry_identity = capability.registry.identity,
        .executable = elf_file,
        .producer_executable = producer_file,
        .admission_receipt = admission_receipt_file,
        .checker = checker_file,
        .input = input_file,
        .expected_output = expected_output_file,
        .manifest = manifest_file,
        .journal = journal_file,
        .journal_identity = journal_identity,
        .segment_receipts = segment_receipts,
        .segment_count = summary.segment_count,
        .total_cycles = summary.total_cycles,
        .total_core_rows = summary.total_core_trace_rows,
        .total_base_external_retirements = summary.total_base_profile_external_retirements,
        .total_bulk_memcpy_retirements = summary.member_retirement_totals[0],
        .total_bulk_memcpy_witness_rows = summary.member_witness_row_totals[0],
        .total_stack_swap_retirements = summary.member_retirement_totals[1],
        .total_stack_swap_witness_rows = summary.member_witness_row_totals[1],
        .admission_timing = admission_timing,
        .execution_and_artifact_timing = execution_timing,
        .artifact_wall_ns = context.artifact_wall_ns,
        .process_resources = resources,
    };
    const result_bytes = try receipt_wire.encodeResultAlloc(
        allocator,
        result_value,
        capability,
    );
    defer allocator.free(result_bytes);
    const result_path = try artifact_io.resolveCreateOnlyChild(
        allocator,
        options.output_root,
        result_basename,
    );
    defer allocator.free(result_path);
    // Seal-last transaction boundary: every authority and segment artifact is
    // already durable and cold validated before the final receipt appears.
    try artifact_io.publishCreateOnlyDurable(result_path, result_bytes);
    const reopened_result = try reopenExact(
        allocator,
        result_path,
        result_bytes,
        receipt_wire.maximum_receipt_bytes,
    );
    defer allocator.free(reopened_result);
    try validateResultArtifact(
        allocator,
        reopened_result,
        capability,
        journal_identity,
    );
    try ensureTimerWithinCap(&hard_timer, options.hard_cap_ns);
}

const OwnedFileIdentity = struct {
    path: []u8,
    identity: receipt_wire.FileIdentity,
};
const OwnedPath = struct {
    path: []u8,

    fn borrowed(self: OwnedPath, bytes: []const u8) receipt_wire.FileIdentity {
        return fileIdentity(self.path, bytes);
    }
};
const CaptureContext = struct {
    allocator: std.mem.Allocator,
    capability: capability_mod.Capability,
    segment_root: []const u8,
    expected_output: []const u8,
    hard_timer: *std.time.Timer,
    hard_cap_ns: u64,
    segment_receipts: std.ArrayList(OwnedFileIdentity) = .empty,
    artifact_wall_ns: u64 = 0,
    final_output_matched: bool = false,

    fn deinit(self: *CaptureContext) void {
        for (self.segment_receipts.items) |item| self.allocator.free(item.path);
        self.segment_receipts.deinit(self.allocator);
        self.* = undefined;
    }

    fn fileIdentities(
        self: *const CaptureContext,
        allocator: std.mem.Allocator,
    ) ![]receipt_wire.FileIdentity {
        const result = try allocator.alloc(
            receipt_wire.FileIdentity,
            self.segment_receipts.items.len,
        );
        for (self.segment_receipts.items, result) |source, *destination|
            destination.* = source.identity;
        return result;
    }

    fn captureSegment(
        erased: *anyopaque,
        capability: capability_mod.Capability,
        candidate: *const combined_result.SegmentResult,
        manifest_record_identity: Digest,
    ) !observed_journal.SegmentExecutionCustodyV1 {
        const self: *CaptureContext = @ptrCast(@alignCast(erased));
        try self.ensureWithinCap();
        try capability.validate();
        if (!std.meta.eql(capability, self.capability) or
            self.segment_receipts.items.len >= maximum_segment_count or
            candidate.ethereum.base.segment_index != self.segment_receipts.items.len)
        {
            return error.InvalidCandidateExecutionSegmentOrder;
        }
        var artifact_clock = try evidence.Clock.start();
        const base = &candidate.ethereum.base;
        const segment_index = base.segment_index;
        const external_origin = candidate.bulk_memcpy.externalStepOrigin();
        const stack_tape_identity = try candidate.stack_swap.captureIdentity();
        const stack_custody_identity = stackCustodyIdentity(
            capability,
            manifest_record_identity,
            segment_index,
            external_origin,
            stack_tape_identity,
        );

        var bulk_tape_file = receipt_wire.OptionalFileIdentity{
            .present = false,
            .file = null,
        };
        var bulk_tape_path: ?OwnedPath = null;
        defer if (bulk_tape_path) |owned| self.allocator.free(owned.path);
        var bulk_tape_identity = zero_digest;
        var bulk_custody: ?journal_mod.ExecutionArtifactCustody = null;
        if (candidate.bulk_memcpy.rows().len != 0) {
            const basename = try std.fmt.allocPrint(
                self.allocator,
                "segment-{d:0>6}-bulk-memcpy-tape-v1.stw",
                .{segment_index},
            );
            defer self.allocator.free(basename);
            bulk_tape_path = .{ .path = try artifact_io.resolveCreateOnlyChild(
                self.allocator,
                self.segment_root,
                basename,
            ) };
            const tape_path = bulk_tape_path.?.path;
            const encoded = try tape_artifact.encodeExecutionAlloc(
                self.allocator,
                &candidate.bulk_memcpy,
            );
            defer self.allocator.free(encoded);
            try artifact_io.publishCreateOnlyDurable(tape_path, encoded);
            const reopened = try reopenExact(
                self.allocator,
                tape_path,
                encoded,
                tape_artifact.maximum_execution_artifact_bytes,
            );
            defer self.allocator.free(reopened);
            var cold_tape = try tape_artifact.decodeExecutionAlloc(
                self.allocator,
                reopened,
            );
            defer cold_tape.deinit();
            const reencoded = try tape_artifact.encodeExecutionAlloc(
                self.allocator,
                &cold_tape,
            );
            defer self.allocator.free(reencoded);
            if (!std.mem.eql(u8, reencoded, reopened) or
                cold_tape.externalStepOrigin() != external_origin)
            {
                return error.NonCanonicalCandidateExecutionTape;
            }
            const tape_file = bulk_tape_path.?.borrowed(reopened);
            bulk_tape_identity = tape_artifact.identity(reopened);
            const cold_reopen_identity = coldReopenCustodyIdentity(
                capability,
                manifest_record_identity,
                segment_index,
                external_origin,
                tape_file,
                bulk_tape_identity,
            );
            bulk_custody = try journal_mod.ExecutionArtifactCustody.create(
                capability,
                segment_index,
                external_origin,
                bulk_tape_identity,
                cold_reopen_identity,
            );
            bulk_tape_file = .{ .present = true, .file = tape_file };
        }

        const base_capture_identity = baseCaptureIdentity(
            capability,
            manifest_record_identity,
            candidate,
            bulk_tape_identity,
            stack_tape_identity,
        );
        const artifact_timing = try artifact_clock.finish();
        self.artifact_wall_ns = std.math.add(
            u64,
            self.artifact_wall_ns,
            artifact_timing.wall_ns,
        ) catch return error.CandidateExecutionTimingOverflow;
        const segment_value = receipt_wire.SegmentUnsigned{
            .capability_identity = capability.identity,
            .admission_receipt_identity = capability.admission_receipt_identity,
            .manifest_record_identity = manifest_record_identity,
            .base_segment_capture_identity = base_capture_identity,
            .segment_index = segment_index,
            .global_first_cycle = base.global_first_cycle,
            .cycle_count = @intCast(base.cycle_count),
            .external_step_origin = @intCast(external_origin),
            .bulk_call_count = @intCast(candidate.bulk_memcpy.records().len),
            .bulk_word_row_count = @intCast(candidate.bulk_memcpy.wordRows().len),
            .bulk_tape = bulk_tape_file,
            .bulk_tape_identity = bulk_tape_identity,
            .bulk_execution_custody_identity = if (bulk_custody) |custody|
                custody.identity
            else
                zero_digest,
            .stack_swap_call_count = @intCast(candidate.stack_swap.records().len),
            .stack_swap_word_row_count = @intCast(candidate.stack_swap.wordRows().len),
            .stack_swap_tape_identity = stack_tape_identity,
            .stack_swap_custody_identity = stack_custody_identity,
            .artifact_timing = artifact_timing,
        };
        const receipt_bytes = try receipt_wire.encodeSegmentAlloc(
            self.allocator,
            segment_value,
            capability,
        );
        defer self.allocator.free(receipt_bytes);
        const receipt_basename = try std.fmt.allocPrint(
            self.allocator,
            "segment-{d:0>6}-execution-custody-v1.json",
            .{segment_index},
        );
        defer self.allocator.free(receipt_basename);
        const receipt_path = try artifact_io.resolveCreateOnlyChild(
            self.allocator,
            self.segment_root,
            receipt_basename,
        );
        var receipt_path_transferred = false;
        errdefer if (!receipt_path_transferred)
            self.allocator.free(receipt_path);
        try artifact_io.publishCreateOnlyDurable(receipt_path, receipt_bytes);
        const reopened_receipt = try reopenExact(
            self.allocator,
            receipt_path,
            receipt_bytes,
            receipt_wire.maximum_segment_receipt_bytes,
        );
        defer self.allocator.free(reopened_receipt);
        try validateSegmentArtifact(
            self.allocator,
            reopened_receipt,
            capability,
            segment_value,
        );
        try self.segment_receipts.append(self.allocator, .{
            .path = receipt_path,
            .identity = fileIdentity(receipt_path, reopened_receipt),
        });
        receipt_path_transferred = true;

        if (base.isComplete()) {
            const output = base.output orelse return error.MissingCandidateOutput;
            if (!std.mem.eql(u8, output, self.expected_output))
                return error.CandidatePublicOutputMismatch;
            self.final_output_matched = true;
        }
        try self.ensureWithinCap();
        return .{
            .manifest_record_identity = manifest_record_identity,
            .base_segment_capture_identity = base_capture_identity,
            .bulk_execution_artifact = bulk_custody,
            .stack_swap_custody_identity = stack_custody_identity,
        };
    }

    fn ensureWithinCap(self: *CaptureContext) !void {
        return ensureTimerWithinCap(self.hard_timer, self.hard_cap_ns);
    }
};

fn validateSegmentArtifact(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    capability: capability_mod.Capability,
    expected: receipt_wire.SegmentUnsigned,
) !void {
    const seal = try receipt_wire.validateSeal(bytes);
    var parsed = try std.json.parseFromSlice(
        receipt_wire.SegmentSealed,
        allocator,
        bytes,
        .{},
    );
    defer parsed.deinit();
    if (!std.mem.eql(
        u8,
        &seal,
        &(try receipt_wire.parseDigest(parsed.value.content_sha256)),
    )) return error.InvalidCandidateExecutionReceiptSeal;
    const actual = parsed.value.unsigned();
    try actual.validate(capability);
    const expected_canonical = try receipt_wire.encodeSegmentAlloc(
        allocator,
        expected,
        capability,
    );
    defer allocator.free(expected_canonical);
    if (!std.mem.eql(u8, expected_canonical, bytes))
        return error.CandidateSegmentExecutionReceiptMismatch;
    const canonical = try receipt_wire.encodeSegmentAlloc(
        allocator,
        actual,
        capability,
    );
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, bytes))
        return error.NonCanonicalCandidateExecutionReceipt;
}

fn validateJournalArtifact(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    capability: capability_mod.Capability,
    expected_identity: Digest,
) !void {
    const seal = try receipt_wire.validateSeal(bytes);
    var parsed = try std.json.parseFromSlice(
        receipt_wire.JournalSealed,
        allocator,
        bytes,
        .{},
    );
    defer parsed.deinit();
    if (!std.mem.eql(
        u8,
        &seal,
        &(try receipt_wire.parseDigest(parsed.value.content_sha256)),
    )) return error.InvalidCandidateExecutionReceiptSeal;
    const unsigned = parsed.value.unsigned();
    const view = journal_mod.JournalView{
        .header = unsigned.header,
        .segments = unsigned.segments,
        .summary = unsigned.summary,
    };
    const actual_identity = try view.identity(capability);
    if (!std.mem.eql(u8, &actual_identity, &expected_identity) or
        !std.mem.eql(u8, &actual_identity, &unsigned.journal_identity))
    {
        return error.CandidateExecutionJournalIdentityMismatch;
    }
    const canonical = try receipt_wire.encodeJournalAlloc(
        allocator,
        unsigned,
        capability,
    );
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, bytes))
        return error.NonCanonicalCandidateExecutionJournal;
}

fn validateResultArtifact(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    capability: capability_mod.Capability,
    expected_journal_identity: Digest,
) !void {
    const seal = try receipt_wire.validateSeal(bytes);
    var parsed = try std.json.parseFromSlice(
        receipt_wire.ResultSealed,
        allocator,
        bytes,
        .{},
    );
    defer parsed.deinit();
    if (!std.mem.eql(
        u8,
        &seal,
        &(try receipt_wire.parseDigest(parsed.value.content_sha256)),
    )) return error.InvalidCandidateExecutionReceiptSeal;
    const unsigned = parsed.value.unsigned();
    try unsigned.validate(capability);
    if (!std.mem.eql(
        u8,
        &unsigned.journal_identity,
        &expected_journal_identity,
    )) return error.CandidateExecutionJournalIdentityMismatch;
    const canonical = try receipt_wire.encodeResultAlloc(
        allocator,
        unsigned,
        capability,
    );
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, bytes))
        return error.NonCanonicalCandidateExecutionReceipt;
}

pub fn coldReopenCustodyIdentity(
    capability: capability_mod.Capability,
    manifest_record_identity: Digest,
    segment_index: u32,
    external_origin: usize,
    file: receipt_wire.FileIdentity,
    tape_identity: Digest,
) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-candidate-bulk-cold-reopen.v1\x00");
    hash.update(&capability.identity);
    hash.update(&capability.admission_receipt_identity);
    hash.update(&manifest_record_identity);
    hashInt(&hash, u32, segment_index);
    hashInt(&hash, u64, external_origin);
    hashInt(&hash, u64, file.path.len);
    hash.update(file.path);
    hashInt(&hash, u64, file.bytes);
    hash.update(&file.sha256);
    hash.update(&tape_identity);
    return hash.finalResult();
}

pub fn stackCustodyIdentity(
    capability: capability_mod.Capability,
    manifest_record_identity: Digest,
    segment_index: u32,
    external_origin: usize,
    tape_identity: Digest,
) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-candidate-stack-tape-custody.v1\x00");
    hash.update(&capability.identity);
    hash.update(&capability.admission_receipt_identity);
    hash.update(&manifest_record_identity);
    hashInt(&hash, u32, segment_index);
    hashInt(&hash, u64, external_origin);
    hash.update(&tape_identity);
    return hash.finalResult();
}

pub fn baseCaptureIdentity(
    capability: capability_mod.Capability,
    manifest_record_identity: Digest,
    candidate: *const combined_result.SegmentResult,
    bulk_tape_identity: Digest,
    stack_tape_identity: Digest,
) Digest {
    const base = &candidate.ethereum.base;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-candidate-base-segment-custody.v1\x00");
    hash.update(&capability.identity);
    hash.update(&manifest_record_identity);
    hashInt(&hash, u32, base.segment_index);
    hashInt(&hash, u64, base.global_first_cycle);
    hashInt(&hash, u64, base.cycle_count);
    hashInt(&hash, u8, @intFromBool(base.segment_role.is_first));
    hashInt(&hash, u8, @intFromBool(base.segment_role.is_last));
    hash.update(&bulk_tape_identity);
    hash.update(&stack_tape_identity);
    return hash.finalResult();
}

pub fn executionSessionIdentity(
    capability: capability_mod.Capability,
    input: receipt_wire.FileIdentity,
    expected_output: receipt_wire.FileIdentity,
    segment_step_budget: usize,
) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-candidate-execution-session.v1\x00");
    hash.update(&capability.identity);
    hash.update(&input.sha256);
    hashInt(&hash, u64, input.bytes);
    hash.update(&expected_output.sha256);
    hashInt(&hash, u64, expected_output.bytes);
    hashInt(&hash, u64, segment_step_budget);
    hashInt(&hash, u8, @intFromEnum(frontend.runner.SegmentClockFrame.leaf_local));
    hashInt(&hash, u8, 1);
    return hash.finalResult();
}

fn requireFileIdentity(
    actual: receipt_wire.FileIdentity,
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

fn reopenExact(
    allocator: std.mem.Allocator,
    path: []const u8,
    expected: []const u8,
    maximum_bytes: usize,
) ![]u8 {
    const reopened = try artifact_io.readFileBounded(
        allocator,
        path,
        maximum_bytes,
    );
    errdefer allocator.free(reopened);
    if (!std.mem.eql(u8, reopened, expected))
        return error.CandidateExecutionArtifactReopenMismatch;
    return reopened;
}

pub fn validateCanonicalReceiptFraming(
    canonical_json: []const u8,
    retained_bytes: []const u8,
) !void {
    const expected_len = std.math.add(usize, canonical_json.len, 1) catch
        return error.NonCanonicalCombinedCandidateReceipt;
    if (retained_bytes.len != expected_len or
        retained_bytes[retained_bytes.len - 1] != '\n' or
        !std.mem.eql(
            u8,
            retained_bytes[0..canonical_json.len],
            canonical_json,
        ))
    {
        return error.NonCanonicalCombinedCandidateReceipt;
    }
}

fn fileIdentity(path: []const u8, bytes: []const u8) receipt_wire.FileIdentity {
    var digest: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return .{ .path = path, .bytes = bytes.len, .sha256 = digest };
}

fn ensureTimerWithinCap(timer: *std.time.Timer, hard_cap_ns: u64) !void {
    if (timer.read() >= hard_cap_ns) return error.CandidateExecutionHardCapExceeded;
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

test "segment tape path remains owned across receipt allocator churn" {
    const allocator = std.testing.allocator;
    const expected = "/private/tmp/segment-000000-bulk-memcpy-tape-v1.stw";
    const owned = OwnedPath{ .path = try allocator.dupe(u8, expected) };
    defer allocator.free(owned.path);
    const churn = try allocator.alloc(u8, 256 * 1024);
    defer allocator.free(churn);
    @memset(churn, 0xa5);
    const identity = owned.borrowed("canonical tape bytes");
    try identity.validate();
    try std.testing.expectEqualStrings(expected, identity.path);
}

comptime {
    if (production_active or proof_or_fresh_verification or
        receipt_wire.production_active or
        receipt_wire.proof_or_fresh_verification or
        journal_mod.production_active or journal_mod.proof_or_fresh_verification or
        observed_journal.production_active or
        observed_journal.proof_or_fresh_verification)
    {
        @compileError("combined candidate execution capture became active");
    }
}
