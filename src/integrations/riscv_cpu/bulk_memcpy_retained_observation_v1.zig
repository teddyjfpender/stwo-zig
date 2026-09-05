//! Cold admission of the retained aggregate bulk-memcpy observation.

const std = @import("std");

pub const schema = "stwo.riscv.bulk-memcpy-admission-observation.v1";
pub const status = "captured-diagnostic-only";
pub const profile = "rv32im-zkvm-ethereum-v1";
pub const clock_frame = "leaf_local";
pub const predicate = "length>=32 && source_mod4==destination_mod4 && endpoints<=2^30 && byte_spans_disjoint && aligned_word_spans_disjoint";
pub const maximum_bytes: usize = 4 * 1024 * 1024;

pub const Bucket = struct {
    calls: u64,
    requested_bytes: u64,
    software_rows: u64,
    word_rows: u64,
};

pub const UnsignedObservation = struct {
    admission_predicate: []const u8,
    admitted: Bucket,
    aligned_word_overlap: Bucket,
    alignment_mismatch: Bucket,
    byte_overlap: Bucket,
    clock_frame: []const u8,
    completed_call_count: u64,
    elf_sha256: []const u8,
    endpoint_invalid: Bucket,
    execution_profile: []const u8,
    first_global_cycle: u64,
    first_segment_index: u32,
    input_sha256: []const u8,
    journal_sha256: []const u8,
    memcpy_entry_pc: u32,
    production: bool,
    removable_core_rows: u64,
    retired_instructions: u64,
    sampled_cycles: u64,
    schema: []const u8,
    segment_count: u32,
    status: []const u8,
    too_short: Bucket,
    total_software_rows_in_memcpy: u64,
    validated_register_reads: u64,
};

pub const Observation = struct {
    admission_predicate: []const u8,
    admitted: Bucket,
    aligned_word_overlap: Bucket,
    alignment_mismatch: Bucket,
    byte_overlap: Bucket,
    clock_frame: []const u8,
    completed_call_count: u64,
    content_sha256: []const u8,
    elf_sha256: []const u8,
    endpoint_invalid: Bucket,
    execution_profile: []const u8,
    first_global_cycle: u64,
    first_segment_index: u32,
    input_sha256: []const u8,
    journal_sha256: []const u8,
    memcpy_entry_pc: u32,
    production: bool,
    removable_core_rows: u64,
    retired_instructions: u64,
    sampled_cycles: u64,
    schema: []const u8,
    segment_count: u32,
    status: []const u8,
    too_short: Bucket,
    total_software_rows_in_memcpy: u64,
    validated_register_reads: u64,

    pub fn validateAgainst(
        self: Observation,
        elf_sha256: [32]u8,
        input_sha256: [32]u8,
        journal_sha256: [32]u8,
        memcpy_entry_pc: u32,
        available_segments: u32,
    ) !void {
        const elf = std.fmt.bytesToHex(elf_sha256, .lower);
        const input = std.fmt.bytesToHex(input_sha256, .lower);
        const journal = std.fmt.bytesToHex(journal_sha256, .lower);
        if (!std.mem.eql(u8, self.schema, schema) or
            !std.mem.eql(u8, self.status, status) or
            !std.mem.eql(u8, self.execution_profile, profile) or
            !std.mem.eql(u8, self.clock_frame, clock_frame) or
            !std.mem.eql(u8, self.admission_predicate, predicate) or
            !std.mem.eql(u8, self.elf_sha256, &elf) or
            !std.mem.eql(u8, self.input_sha256, &input) or
            !std.mem.eql(u8, self.journal_sha256, &journal) or
            self.memcpy_entry_pc != memcpy_entry_pc or self.production or
            self.first_segment_index != 0 or self.first_global_cycle != 1 or
            self.segment_count == 0 or self.segment_count > available_segments or
            self.sampled_cycles == 0 or self.retired_instructions == 0 or
            self.admitted.calls == 0)
        {
            return error.InvalidRetainedBulkMemcpyObservation;
        }
        const completed = try addBuckets(.calls, self);
        const software_rows = try addBuckets(.software_rows, self);
        if (completed != self.completed_call_count or
            software_rows != self.total_software_rows_in_memcpy or
            self.admitted.software_rows < self.admitted.calls or
            self.removable_core_rows !=
                self.admitted.software_rows - self.admitted.calls)
        {
            return error.InvalidRetainedBulkMemcpyObservation;
        }
        try requireDigest(self.content_sha256);
    }
};

pub fn parse(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(Observation) {
    if (bytes.len == 0 or bytes.len > maximum_bytes or
        bytes[bytes.len - 1] != '\n')
    {
        return error.InvalidRetainedBulkMemcpyObservation;
    }
    const body = bytes[0 .. bytes.len - 1];
    var parsed = try std.json.parseFromSlice(Observation, allocator, body, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    errdefer parsed.deinit();
    const canonical = try std.json.Stringify.valueAlloc(
        allocator,
        parsed.value,
        .{},
    );
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, body))
        return error.NonCanonicalRetainedBulkMemcpyObservation;
    const unsigned_bytes = try std.json.Stringify.valueAlloc(
        allocator,
        withoutSeal(parsed.value),
        .{},
    );
    defer allocator.free(unsigned_bytes);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(unsigned_bytes);
    hash.update("\n");
    const expected = std.fmt.bytesToHex(hash.finalResult(), .lower);
    if (!std.mem.eql(u8, parsed.value.content_sha256, &expected))
        return error.InvalidRetainedBulkMemcpyObservationSeal;
    return parsed;
}

fn withoutSeal(value: Observation) UnsignedObservation {
    return .{
        .admission_predicate = value.admission_predicate,
        .admitted = value.admitted,
        .aligned_word_overlap = value.aligned_word_overlap,
        .alignment_mismatch = value.alignment_mismatch,
        .byte_overlap = value.byte_overlap,
        .clock_frame = value.clock_frame,
        .completed_call_count = value.completed_call_count,
        .elf_sha256 = value.elf_sha256,
        .endpoint_invalid = value.endpoint_invalid,
        .execution_profile = value.execution_profile,
        .first_global_cycle = value.first_global_cycle,
        .first_segment_index = value.first_segment_index,
        .input_sha256 = value.input_sha256,
        .journal_sha256 = value.journal_sha256,
        .memcpy_entry_pc = value.memcpy_entry_pc,
        .production = value.production,
        .removable_core_rows = value.removable_core_rows,
        .retired_instructions = value.retired_instructions,
        .sampled_cycles = value.sampled_cycles,
        .schema = value.schema,
        .segment_count = value.segment_count,
        .status = value.status,
        .too_short = value.too_short,
        .total_software_rows_in_memcpy = value.total_software_rows_in_memcpy,
        .validated_register_reads = value.validated_register_reads,
    };
}

const BucketField = enum { calls, software_rows };

fn addBuckets(comptime field: BucketField, value: Observation) !u64 {
    var result: u64 = 0;
    inline for (.{
        value.admitted,
        value.aligned_word_overlap,
        value.alignment_mismatch,
        value.byte_overlap,
        value.endpoint_invalid,
        value.too_short,
    }) |bucket| result = try std.math.add(
        u64,
        result,
        @field(bucket, @tagName(field)),
    );
    return result;
}

fn requireDigest(value: []const u8) !void {
    if (value.len != 64) return error.InvalidRetainedBulkMemcpyObservation;
    var decoded: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&decoded, value) catch
        return error.InvalidRetainedBulkMemcpyObservation;
}
