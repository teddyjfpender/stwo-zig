//! Sealed custody receipts for one execution-only combined candidate run.
//!
//! These receipts deliberately contain no proof or fresh-verification bit.
//! A later prover may consume the exact tape identities, but only the
//! frontend's transactional proof-upgrade API can promote a member capture.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const evidence = @import("ethereum_block_leaf_evidence.zig");
const resource_usage = @import("resource_usage.zig");

const capability_mod =
    frontend.testing.ethereum_candidate_execution_capability_v1;
const journal_mod = frontend.testing.ethereum_candidate_execution_journal_v1;

pub const Digest = [32]u8;
pub const schema = "stwo.riscv.ethereum-combined-candidate-execution-capture.v1";
pub const journal_schema =
    "stwo.riscv.ethereum-combined-candidate-execution-journal-artifact.v1";
pub const segment_schema =
    "stwo.riscv.ethereum-combined-candidate-segment-execution-custody.v1";
pub const production_active = false;
pub const proof_or_fresh_verification = false;
pub const maximum_receipt_bytes: usize = 4 * 1024 * 1024;
pub const maximum_segment_receipt_bytes: usize = 64 * 1024;
pub const maximum_journal_bytes: usize = 16 * 1024 * 1024;

pub const FileIdentity = struct {
    path: []const u8,
    bytes: u64,
    sha256: Digest,

    pub fn validate(self: FileIdentity) !void {
        if (!std.fs.path.isAbsolute(self.path) or self.bytes == 0 or
            isZero(self.sha256))
        {
            return error.InvalidCandidateExecutionFileIdentity;
        }
    }
};

pub const OptionalFileIdentity = struct {
    present: bool,
    file: ?FileIdentity,

    pub fn validate(self: OptionalFileIdentity) !void {
        if (self.present != (self.file != null))
            return error.InvalidCandidateExecutionOptionalFile;
        if (self.file) |file| try file.validate();
    }
};

pub const SegmentUnsigned = struct {
    schema: []const u8 = segment_schema,
    status: []const u8 = "cold-reopened-execution-only",
    production_active: bool = production_active,
    proof_or_fresh_verification: bool = proof_or_fresh_verification,
    capability_identity: Digest,
    admission_receipt_identity: Digest,
    manifest_record_identity: Digest,
    base_segment_capture_identity: Digest,
    segment_index: u32,
    global_first_cycle: u64,
    cycle_count: u64,
    external_step_origin: u64,
    bulk_call_count: u64,
    bulk_word_row_count: u64,
    bulk_tape: OptionalFileIdentity,
    bulk_tape_identity: Digest,
    bulk_execution_custody_identity: Digest,
    stack_swap_call_count: u64,
    stack_swap_word_row_count: u64,
    stack_swap_tape_identity: Digest,
    stack_swap_custody_identity: Digest,
    artifact_timing: evidence.Timing,

    pub fn validate(
        self: SegmentUnsigned,
        capability: capability_mod.Capability,
    ) !void {
        try capability.validate();
        try self.bulk_tape.validate();
        if (production_active or proof_or_fresh_verification or
            !std.mem.eql(u8, self.schema, segment_schema) or
            !std.mem.eql(u8, self.status, "cold-reopened-execution-only") or
            self.production_active or self.proof_or_fresh_verification or
            !std.mem.eql(
                u8,
                &self.capability_identity,
                &capability.identity,
            ) or !std.mem.eql(
            u8,
            &self.admission_receipt_identity,
            &capability.admission_receipt_identity,
        ) or isZero(self.manifest_record_identity) or
            isZero(self.base_segment_capture_identity) or
            self.global_first_cycle == 0 or self.cycle_count == 0 or
            isZero(self.stack_swap_tape_identity) or
            isZero(self.stack_swap_custody_identity))
        {
            return error.InvalidCandidateSegmentExecutionReceipt;
        }
        if (self.bulk_call_count == 0) {
            if (self.bulk_word_row_count != 0 or self.bulk_tape.present or
                !isZero(self.bulk_tape_identity) or
                !isZero(self.bulk_execution_custody_identity))
            {
                return error.InvalidCandidateSegmentExecutionReceipt;
            }
        } else if (self.bulk_word_row_count < self.bulk_call_count or
            !self.bulk_tape.present or isZero(self.bulk_tape_identity) or
            isZero(self.bulk_execution_custody_identity))
        {
            return error.InvalidCandidateSegmentExecutionReceipt;
        }
        if (self.stack_swap_call_count == 0) {
            if (self.stack_swap_word_row_count != 0)
                return error.InvalidCandidateSegmentExecutionReceipt;
        } else if (self.stack_swap_word_row_count < self.stack_swap_call_count) {
            return error.InvalidCandidateSegmentExecutionReceipt;
        }
    }
};

pub const SegmentSealed = struct {
    content_sha256: []const u8,
    schema: []const u8,
    status: []const u8,
    production_active: bool,
    proof_or_fresh_verification: bool,
    capability_identity: Digest,
    admission_receipt_identity: Digest,
    manifest_record_identity: Digest,
    base_segment_capture_identity: Digest,
    segment_index: u32,
    global_first_cycle: u64,
    cycle_count: u64,
    external_step_origin: u64,
    bulk_call_count: u64,
    bulk_word_row_count: u64,
    bulk_tape: OptionalFileIdentity,
    bulk_tape_identity: Digest,
    bulk_execution_custody_identity: Digest,
    stack_swap_call_count: u64,
    stack_swap_word_row_count: u64,
    stack_swap_tape_identity: Digest,
    stack_swap_custody_identity: Digest,
    artifact_timing: evidence.Timing,

    pub fn unsigned(self: SegmentSealed) SegmentUnsigned {
        return .{
            .schema = self.schema,
            .status = self.status,
            .production_active = self.production_active,
            .proof_or_fresh_verification = self.proof_or_fresh_verification,
            .capability_identity = self.capability_identity,
            .admission_receipt_identity = self.admission_receipt_identity,
            .manifest_record_identity = self.manifest_record_identity,
            .base_segment_capture_identity = self.base_segment_capture_identity,
            .segment_index = self.segment_index,
            .global_first_cycle = self.global_first_cycle,
            .cycle_count = self.cycle_count,
            .external_step_origin = self.external_step_origin,
            .bulk_call_count = self.bulk_call_count,
            .bulk_word_row_count = self.bulk_word_row_count,
            .bulk_tape = self.bulk_tape,
            .bulk_tape_identity = self.bulk_tape_identity,
            .bulk_execution_custody_identity = self.bulk_execution_custody_identity,
            .stack_swap_call_count = self.stack_swap_call_count,
            .stack_swap_word_row_count = self.stack_swap_word_row_count,
            .stack_swap_tape_identity = self.stack_swap_tape_identity,
            .stack_swap_custody_identity = self.stack_swap_custody_identity,
            .artifact_timing = self.artifact_timing,
        };
    }
};

pub const JournalUnsigned = struct {
    schema: []const u8 = journal_schema,
    status: []const u8 = "complete-execution-only",
    production_active: bool = production_active,
    proof_or_fresh_verification: bool = proof_or_fresh_verification,
    capability_identity: Digest,
    journal_identity: Digest,
    header: journal_mod.Header,
    segments: []const journal_mod.Segment,
    summary: journal_mod.Summary,
};

pub const JournalSealed = struct {
    content_sha256: []const u8,
    schema: []const u8,
    status: []const u8,
    production_active: bool,
    proof_or_fresh_verification: bool,
    capability_identity: Digest,
    journal_identity: Digest,
    header: journal_mod.Header,
    segments: []journal_mod.Segment,
    summary: journal_mod.Summary,

    pub fn unsigned(self: JournalSealed) JournalUnsigned {
        return .{
            .schema = self.schema,
            .status = self.status,
            .production_active = self.production_active,
            .proof_or_fresh_verification = self.proof_or_fresh_verification,
            .capability_identity = self.capability_identity,
            .journal_identity = self.journal_identity,
            .header = self.header,
            .segments = self.segments,
            .summary = self.summary,
        };
    }
};

pub const ResultUnsigned = struct {
    schema: []const u8 = schema,
    status: []const u8 = "execution-captured-not-proved",
    production_active: bool = production_active,
    proof_or_fresh_verification: bool = proof_or_fresh_verification,
    product_admissible: bool = false,
    power_source: []const u8,
    segment_step_budget: u64,
    hard_cap_ns: u64,
    capability_identity: Digest,
    admission_receipt_identity: Digest,
    source_closure_identity: Digest,
    program_commitment_identity: Digest,
    candidate_authority_identity: Digest,
    candidate_registry_identity: Digest,
    executable: FileIdentity,
    producer_executable: FileIdentity,
    admission_receipt: FileIdentity,
    checker: FileIdentity,
    input: FileIdentity,
    expected_output: FileIdentity,
    manifest: FileIdentity,
    journal: FileIdentity,
    journal_identity: Digest,
    segment_receipts: []const FileIdentity,
    segment_count: u32,
    total_cycles: u64,
    total_core_rows: u64,
    total_base_external_retirements: u64,
    total_bulk_memcpy_retirements: u64,
    total_bulk_memcpy_witness_rows: u64,
    total_stack_swap_retirements: u64,
    total_stack_swap_witness_rows: u64,
    admission_timing: evidence.Timing,
    execution_and_artifact_timing: evidence.Timing,
    artifact_wall_ns: u64,
    proof_timing: ?evidence.Timing = null,
    process_resources: resource_usage.Report,

    pub fn validate(
        self: ResultUnsigned,
        capability: capability_mod.Capability,
    ) !void {
        try capability.validate();
        inline for (.{
            self.executable,
            self.producer_executable,
            self.admission_receipt,
            self.checker,
            self.input,
            self.expected_output,
            self.manifest,
            self.journal,
        }) |file| try file.validate();
        for (self.segment_receipts) |file| try file.validate();
        if (production_active or proof_or_fresh_verification or
            !std.mem.eql(u8, self.schema, schema) or
            !std.mem.eql(u8, self.status, "execution-captured-not-proved") or
            self.production_active or self.proof_or_fresh_verification or
            self.product_admissible or self.proof_timing != null or
            (!std.mem.eql(u8, self.power_source, "ac") and
                !std.mem.eql(u8, self.power_source, "battery")) or
            self.segment_step_budget == 0 or self.hard_cap_ns == 0 or
            !std.mem.eql(u8, &self.capability_identity, &capability.identity) or
            !std.mem.eql(
                u8,
                &self.admission_receipt_identity,
                &capability.admission_receipt_identity,
            ) or !std.mem.eql(
            u8,
            &self.source_closure_identity,
            &capability.source_closure_identity,
        ) or !std.mem.eql(
            u8,
            &self.program_commitment_identity,
            &capability.program_commitment_identity,
        ) or !std.mem.eql(
            u8,
            &self.candidate_registry_identity,
            &capability.registry.identity,
        ) or self.segment_count == 0 or
            self.segment_receipts.len != self.segment_count or
            self.total_cycles == 0 or self.total_core_rows == 0 or
            isZero(self.journal_identity))
        {
            return error.InvalidCandidateExecutionCaptureReceipt;
        }
        const authority = capability.combined_candidate_authority orelse
            return error.FinalEthereumCombinedCandidateCapabilityRequired;
        if (!std.mem.eql(
            u8,
            &self.candidate_authority_identity,
            &authority.identity,
        ) or !std.mem.eql(
            u8,
            &self.executable.sha256,
            &capability.guest_elf_sha256,
        )) return error.InvalidCandidateExecutionCaptureReceipt;
    }
};

pub const ResultSealed = struct {
    content_sha256: []const u8,
    schema: []const u8,
    status: []const u8,
    production_active: bool,
    proof_or_fresh_verification: bool,
    product_admissible: bool,
    power_source: []const u8,
    segment_step_budget: u64,
    hard_cap_ns: u64,
    capability_identity: Digest,
    admission_receipt_identity: Digest,
    source_closure_identity: Digest,
    program_commitment_identity: Digest,
    candidate_authority_identity: Digest,
    candidate_registry_identity: Digest,
    executable: FileIdentity,
    producer_executable: FileIdentity,
    admission_receipt: FileIdentity,
    checker: FileIdentity,
    input: FileIdentity,
    expected_output: FileIdentity,
    manifest: FileIdentity,
    journal: FileIdentity,
    journal_identity: Digest,
    segment_receipts: []FileIdentity,
    segment_count: u32,
    total_cycles: u64,
    total_core_rows: u64,
    total_base_external_retirements: u64,
    total_bulk_memcpy_retirements: u64,
    total_bulk_memcpy_witness_rows: u64,
    total_stack_swap_retirements: u64,
    total_stack_swap_witness_rows: u64,
    admission_timing: evidence.Timing,
    execution_and_artifact_timing: evidence.Timing,
    artifact_wall_ns: u64,
    proof_timing: ?evidence.Timing,
    process_resources: resource_usage.Report,

    pub fn unsigned(self: ResultSealed) ResultUnsigned {
        return .{
            .schema = self.schema,
            .status = self.status,
            .production_active = self.production_active,
            .proof_or_fresh_verification = self.proof_or_fresh_verification,
            .product_admissible = self.product_admissible,
            .power_source = self.power_source,
            .segment_step_budget = self.segment_step_budget,
            .hard_cap_ns = self.hard_cap_ns,
            .capability_identity = self.capability_identity,
            .admission_receipt_identity = self.admission_receipt_identity,
            .source_closure_identity = self.source_closure_identity,
            .program_commitment_identity = self.program_commitment_identity,
            .candidate_authority_identity = self.candidate_authority_identity,
            .candidate_registry_identity = self.candidate_registry_identity,
            .executable = self.executable,
            .producer_executable = self.producer_executable,
            .admission_receipt = self.admission_receipt,
            .checker = self.checker,
            .input = self.input,
            .expected_output = self.expected_output,
            .manifest = self.manifest,
            .journal = self.journal,
            .journal_identity = self.journal_identity,
            .segment_receipts = self.segment_receipts,
            .segment_count = self.segment_count,
            .total_cycles = self.total_cycles,
            .total_core_rows = self.total_core_rows,
            .total_base_external_retirements = self.total_base_external_retirements,
            .total_bulk_memcpy_retirements = self.total_bulk_memcpy_retirements,
            .total_bulk_memcpy_witness_rows = self.total_bulk_memcpy_witness_rows,
            .total_stack_swap_retirements = self.total_stack_swap_retirements,
            .total_stack_swap_witness_rows = self.total_stack_swap_witness_rows,
            .admission_timing = self.admission_timing,
            .execution_and_artifact_timing = self.execution_and_artifact_timing,
            .artifact_wall_ns = self.artifact_wall_ns,
            .proof_timing = self.proof_timing,
            .process_resources = self.process_resources,
        };
    }
};

pub fn encodeSegmentAlloc(
    allocator: std.mem.Allocator,
    value: SegmentUnsigned,
    capability: capability_mod.Capability,
) ![]u8 {
    try value.validate(capability);
    return sealValue(allocator, value);
}

pub fn encodeJournalAlloc(
    allocator: std.mem.Allocator,
    value: JournalUnsigned,
    capability: capability_mod.Capability,
) ![]u8 {
    try capability.validate();
    if (!std.mem.eql(u8, value.schema, journal_schema) or
        !std.mem.eql(u8, value.status, "complete-execution-only") or
        value.production_active or value.proof_or_fresh_verification or
        !std.mem.eql(u8, &value.capability_identity, &capability.identity))
    {
        return error.InvalidCandidateExecutionJournalArtifact;
    }
    const view = journal_mod.JournalView{
        .header = value.header,
        .segments = value.segments,
        .summary = value.summary,
    };
    const expected_identity = try view.identity(capability);
    if (!std.mem.eql(u8, &expected_identity, &value.journal_identity))
        return error.InvalidCandidateExecutionJournalArtifact;
    return sealValue(allocator, value);
}

pub fn encodeResultAlloc(
    allocator: std.mem.Allocator,
    value: ResultUnsigned,
    capability: capability_mod.Capability,
) ![]u8 {
    try value.validate(capability);
    return sealValue(allocator, value);
}

pub fn validateSeal(bytes: []const u8) !Digest {
    const prefix = "{\"content_sha256\":\"";
    if (bytes.len <= prefix.len + 66 or !std.mem.startsWith(u8, bytes, prefix) or
        bytes[bytes.len - 1] != '\n')
    {
        return error.InvalidCandidateExecutionReceiptSeal;
    }
    const digest_end = prefix.len + 64;
    if (bytes[digest_end] != '"' or bytes[digest_end + 1] != ',')
        return error.InvalidCandidateExecutionReceiptSeal;
    const expected = parseDigest(bytes[prefix.len..digest_end]) catch
        return error.InvalidCandidateExecutionReceiptSeal;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("{");
    hash.update(bytes[digest_end + 2 .. bytes.len - 1]);
    hash.update("\n");
    const actual = hash.finalResult();
    if (!std.mem.eql(u8, &actual, &expected))
        return error.InvalidCandidateExecutionReceiptSeal;
    return expected;
}

pub fn parseDigest(encoded: []const u8) !Digest {
    if (encoded.len != 64) return error.InvalidSha256;
    var result: Digest = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch return error.InvalidSha256;
    const canonical = std.fmt.bytesToHex(result, .lower);
    if (!std.mem.eql(u8, encoded, &canonical) or isZero(result))
        return error.InvalidSha256;
    return result;
}

fn sealValue(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    const unsigned = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(unsigned);
    return evidence.seal(allocator, unsigned);
}

fn isZero(value: Digest) bool {
    return std.mem.allEqual(u8, &value, 0);
}

comptime {
    if (production_active or proof_or_fresh_verification or
        journal_mod.production_active or journal_mod.proof_or_fresh_verification or
        capability_mod.production_active or
        capability_mod.proof_or_fresh_verification)
    {
        @compileError("combined candidate execution receipt became active");
    }
}

test "execution-only receipt seal detects mutation" {
    const unsigned = "{\"schema\":\"candidate\",\"proof\":false}";
    const sealed = try evidence.seal(std.testing.allocator, unsigned);
    defer std.testing.allocator.free(sealed);
    _ = try validateSeal(sealed);
    const mutated = try std.testing.allocator.dupe(u8, sealed);
    defer std.testing.allocator.free(mutated);
    mutated[mutated.len - 3] ^= 1;
    try std.testing.expectError(
        error.InvalidCandidateExecutionReceiptSeal,
        validateSeal(mutated),
    );
}

test "cold decoded schema status and path compare by canonical content" {
    const Wire = struct {
        schema: []const u8,
        status: []const u8,
        path: []const u8,
    };
    const expected = Wire{
        .schema = segment_schema,
        .status = "cold-reopened-execution-only",
        .path = "/private/tmp/segment-000000-bulk-memcpy-tape-v1.stw",
    };
    const encoded = try std.json.Stringify.valueAlloc(
        std.testing.allocator,
        expected,
        .{},
    );
    defer std.testing.allocator.free(encoded);
    var decoded = try std.json.parseFromSlice(
        Wire,
        std.testing.allocator,
        encoded,
        .{},
    );
    defer decoded.deinit();
    try std.testing.expect(!std.meta.eql(expected, decoded.value));
    const reencoded = try std.json.Stringify.valueAlloc(
        std.testing.allocator,
        decoded.value,
        .{},
    );
    defer std.testing.allocator.free(reencoded);
    try std.testing.expectEqualSlices(u8, encoded, reencoded);

    const mutated = try std.testing.allocator.dupe(u8, encoded);
    defer std.testing.allocator.free(mutated);
    const marker = std.mem.indexOf(u8, mutated, "segment-000000") orelse
        return error.InvalidTestFixture;
    mutated[marker + "segment-".len] = '1';
    try std.testing.expect(!std.mem.eql(u8, encoded, mutated));
}
