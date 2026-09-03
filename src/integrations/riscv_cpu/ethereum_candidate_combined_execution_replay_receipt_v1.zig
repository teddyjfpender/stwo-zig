//! Independent replay receipt for a combined candidate execution capture.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const evidence = @import("ethereum_block_leaf_evidence.zig");
const capture_receipt =
    @import("ethereum_candidate_combined_execution_capture_receipt_v1.zig");
const resource_usage = @import("resource_usage.zig");

const capability_mod =
    frontend.testing.ethereum_candidate_execution_capability_v1;

pub const schema =
    "stwo.riscv.ethereum-combined-candidate-execution-replay-receipt.v1";
pub const production_active = false;
pub const proof_or_fresh_verification = false;
pub const maximum_bytes: usize = 1024 * 1024;

pub const Unsigned = struct {
    schema: []const u8 = schema,
    status: []const u8 = "independently-replayed-execution-only",
    production_active: bool = production_active,
    proof_or_fresh_verification: bool = proof_or_fresh_verification,
    product_admissible: bool = false,
    source_result: capture_receipt.FileIdentity,
    source_result_content_sha256: capture_receipt.Digest,
    replay_executable: capture_receipt.FileIdentity,
    capability_identity: capture_receipt.Digest,
    admission_receipt_identity: capture_receipt.Digest,
    source_closure_identity: capture_receipt.Digest,
    journal_identity: capture_receipt.Digest,
    segment_count: u32,
    reopened_segment_receipt_count: u32,
    reopened_bulk_tape_count: u32,
    manifest_chain_recomputed: bool,
    journal_chain_recomputed: bool,
    source_closure_recomputed: bool,
    terminal_output_recomputed: bool,
    every_file_identity_reopened: bool,
    every_tape_canonical_roundtrip: bool,
    replay_timing: evidence.Timing,
    process_resources: resource_usage.Report,

    pub fn validate(
        self: Unsigned,
        capability: capability_mod.Capability,
    ) !void {
        try capability.validate();
        try self.source_result.validate();
        try self.replay_executable.validate();
        if (production_active or proof_or_fresh_verification or
            !std.mem.eql(u8, self.schema, schema) or
            !std.mem.eql(
                u8,
                self.status,
                "independently-replayed-execution-only",
            ) or self.production_active or self.proof_or_fresh_verification or
            self.product_admissible or isZero(self.source_result_content_sha256) or
            !std.mem.eql(u8, &self.capability_identity, &capability.identity) or
            !std.mem.eql(
                u8,
                &self.admission_receipt_identity,
                &capability.admission_receipt_identity,
            ) or !std.mem.eql(
            u8,
            &self.source_closure_identity,
            &capability.source_closure_identity,
        ) or isZero(self.journal_identity) or self.segment_count == 0 or
            self.reopened_segment_receipt_count != self.segment_count or
            !self.manifest_chain_recomputed or !self.journal_chain_recomputed or
            !self.source_closure_recomputed or !self.terminal_output_recomputed or
            !self.every_file_identity_reopened or
            !self.every_tape_canonical_roundtrip)
        {
            return error.InvalidCandidateExecutionReplayReceipt;
        }
    }
};

pub const Sealed = struct {
    content_sha256: []const u8,
    schema: []const u8,
    status: []const u8,
    production_active: bool,
    proof_or_fresh_verification: bool,
    product_admissible: bool,
    source_result: capture_receipt.FileIdentity,
    source_result_content_sha256: capture_receipt.Digest,
    replay_executable: capture_receipt.FileIdentity,
    capability_identity: capture_receipt.Digest,
    admission_receipt_identity: capture_receipt.Digest,
    source_closure_identity: capture_receipt.Digest,
    journal_identity: capture_receipt.Digest,
    segment_count: u32,
    reopened_segment_receipt_count: u32,
    reopened_bulk_tape_count: u32,
    manifest_chain_recomputed: bool,
    journal_chain_recomputed: bool,
    source_closure_recomputed: bool,
    terminal_output_recomputed: bool,
    every_file_identity_reopened: bool,
    every_tape_canonical_roundtrip: bool,
    replay_timing: evidence.Timing,
    process_resources: resource_usage.Report,

    pub fn unsigned(self: Sealed) Unsigned {
        return .{
            .schema = self.schema,
            .status = self.status,
            .production_active = self.production_active,
            .proof_or_fresh_verification = self.proof_or_fresh_verification,
            .product_admissible = self.product_admissible,
            .source_result = self.source_result,
            .source_result_content_sha256 = self.source_result_content_sha256,
            .replay_executable = self.replay_executable,
            .capability_identity = self.capability_identity,
            .admission_receipt_identity = self.admission_receipt_identity,
            .source_closure_identity = self.source_closure_identity,
            .journal_identity = self.journal_identity,
            .segment_count = self.segment_count,
            .reopened_segment_receipt_count = self.reopened_segment_receipt_count,
            .reopened_bulk_tape_count = self.reopened_bulk_tape_count,
            .manifest_chain_recomputed = self.manifest_chain_recomputed,
            .journal_chain_recomputed = self.journal_chain_recomputed,
            .source_closure_recomputed = self.source_closure_recomputed,
            .terminal_output_recomputed = self.terminal_output_recomputed,
            .every_file_identity_reopened = self.every_file_identity_reopened,
            .every_tape_canonical_roundtrip = self.every_tape_canonical_roundtrip,
            .replay_timing = self.replay_timing,
            .process_resources = self.process_resources,
        };
    }
};

pub fn encodeAlloc(
    allocator: std.mem.Allocator,
    value: Unsigned,
    capability: capability_mod.Capability,
) ![]u8 {
    try value.validate(capability);
    const unsigned = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(unsigned);
    return evidence.seal(allocator, unsigned);
}

fn isZero(value: capture_receipt.Digest) bool {
    return std.mem.allEqual(u8, &value, 0);
}

comptime {
    if (production_active or proof_or_fresh_verification or
        capture_receipt.production_active or
        capture_receipt.proof_or_fresh_verification or
        capability_mod.production_active or
        capability_mod.proof_or_fresh_verification)
    {
        @compileError("combined candidate execution replay became active");
    }
}
