//! Heterogeneous compiler authority for universal row 34.
//!
//! The native Poseidon2 provider serves exact requests emitted by transcript
//! row 1, trace-Merkle row 23, FRI leaf/node rows 25/26, and Merkle-path row
//! 33. This module derives that workload solely from already reconstructed
//! compiler authorities. Proof values determine call payloads later, but may
//! not alter the provider row count or log size.

const std = @import("std");
const digest = @import("../air/lang/digest.zig");
const schedule = @import("air/verifier_schedule.zig");
const transcript_binding =
    @import("air/transcript_data_rows_heterogeneous_v2.zig");
const transcript =
    @import("air/transcript_execution_program_heterogeneous_v2.zig");
const fri_rows = @import("air/fri_rows_authority_heterogeneous_v2.zig");
const merkle_path = @import("binary_merkle_path_program_heterogeneous_v2.zig");
const provider = @import("air/universal_shared_provider.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const ROW: usize = 34;
const PROGRAM_DOMAIN =
    "stwo-zig/typed-air/binary-poseidon-provider-program/v2\x00";

pub const Error = error{
    ArithmeticOverflow,
    InvalidHeterogeneousPoseidonProviderAuthority,
    ProviderTraceShapeOutOfRange,
};

pub const ProgramInputV2 = struct {
    transcript_authority: *const transcript.ProgramAuthorityV2,
    transcript_calls: *const transcript_binding.TranscriptBindingPreprocessedV2,
    vm_plan: *const schedule.Plan,
    left_plan: *const schedule.Plan,
    right_plan: *const schedule.Plan,
    fri_authority: *const fri_rows.FriRowsAuthorityV2,
    fri_program: fri_rows.ProgramInputV2,
    merkle_path_authority: *const merkle_path.MerklePathProgramAuthorityV2,
};

pub const RequestCountsV2 = struct {
    transcript: usize,
    trace_leaf: usize,
    fri_leaf: usize,
    fri_node: usize,
    merkle_path: usize,
    total: usize,
};

pub const ProgramAuthorityV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    counts: RequestCountsV2,
    log_size: u32,
    provider_source_sha256: digest.Digest,
    transcript_program_sha256: digest.Digest,
    fri_program_sha256: digest.Digest,
    merkle_path_program_sha256: digest.Digest,
    program_sha256: digest.Digest,

    pub fn init(input: ProgramInputV2) !ProgramAuthorityV2 {
        try validateInput(input);
        var result = ProgramAuthorityV2{
            .counts = try requestCounts(input),
            .log_size = undefined,
            .provider_source_sha256 = provider.POSEIDON_SOURCE_AUTHORITY_DIGEST,
            .transcript_program_sha256 = input.transcript_authority.program_sha256,
            .fri_program_sha256 = input.fri_authority.program_sha256,
            .merkle_path_program_sha256 = input.merkle_path_authority.program_sha256,
            .program_sha256 = undefined,
        };
        result.log_size = try traceLogSize(result.counts.total);
        result.program_sha256 = programIdentity(&result);
        try result.validateAgainst(input);
        return result;
    }

    pub fn validateAgainst(
        self: *const ProgramAuthorityV2,
        input: ProgramInputV2,
    ) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION)
        {
            return error.InvalidHeterogeneousPoseidonProviderAuthority;
        }
        try validateInput(input);
        if (!std.meta.eql(self.counts, try requestCounts(input)) or
            self.log_size != try traceLogSize(self.counts.total) or
            !std.mem.eql(
                u8,
                &self.provider_source_sha256,
                &provider.POSEIDON_SOURCE_AUTHORITY_DIGEST,
            ) or !std.mem.eql(
            u8,
            &self.transcript_program_sha256,
            &input.transcript_authority.program_sha256,
        ) or !std.mem.eql(
            u8,
            &self.fri_program_sha256,
            &input.fri_authority.program_sha256,
        ) or !std.mem.eql(
            u8,
            &self.merkle_path_program_sha256,
            &input.merkle_path_authority.program_sha256,
        ) or !std.mem.eql(
            u8,
            &self.program_sha256,
            &programIdentity(self),
        )) {
            return error.InvalidHeterogeneousPoseidonProviderAuthority;
        }
    }
};

fn validateInput(input: ProgramInputV2) !void {
    try input.transcript_authority.validateAgainst(
        input.transcript_calls,
        input.vm_plan,
        input.left_plan,
        input.right_plan,
    );
    try input.fri_authority.validateProgramAgainst(input.fri_program);
    try input.merkle_path_authority.validateProgramAgainst(.{
        .fri_authority = input.fri_authority,
        .fri_program = input.fri_program,
    });
    for (
        [_]*const schedule.Plan{
            input.vm_plan,
            input.left_plan,
            input.right_plan,
        },
        input.fri_program.lanes,
    ) |expected, lane| {
        if (expected.schema != lane.plan.schema or
            !std.meta.eql(expected.authority_digest, lane.plan.authority_digest))
        {
            return error.InvalidHeterogeneousPoseidonProviderAuthority;
        }
    }
    try provider.PoseidonSourceAuthority.pinned().validate();
}

fn requestCounts(input: ProgramInputV2) !RequestCountsV2 {
    const transcript_count =
        try input.transcript_authority.binaryTranscriptProviderCallCount();
    const trace_leaf = try activeBinaryRows(
        input.fri_authority.trace_preprocessing.rows,
    );
    const fri_leaf = try activeBinaryRows(
        input.fri_authority.fri_leaf_preprocessing.rows,
    );
    const fri_node = try activeBinaryRows(
        input.fri_authority.fri_node_preprocessing.rows,
    );
    const path = input.merkle_path_authority.geometry.invocation_count;
    var total = try add(transcript_count, trace_leaf);
    total = try add(total, fri_leaf);
    total = try add(total, fri_node);
    total = try add(total, path);
    return .{
        .transcript = transcript_count,
        .trace_leaf = trace_leaf,
        .fri_leaf = fri_leaf,
        .fri_node = fri_node,
        .merkle_path = path,
        .total = total,
    };
}

fn activeBinaryRows(rows: anytype) !usize {
    var result: usize = 0;
    for (rows) |row| if (row.binary_mask == 1) {
        result = try add(result, 1);
    } else if (row.binary_mask != 0) {
        return error.InvalidHeterogeneousPoseidonProviderAuthority;
    };
    return result;
}

fn traceLogSize(row_count: usize) !u32 {
    const result: u32 = @max(
        4,
        @as(u32, @intCast(std.math.log2_int_ceil(
            usize,
            @max(row_count, 1),
        ))),
    );
    if (result == 0 or result >= provider.POSEIDON_LOG_SIZE_EXCLUSIVE_LIMIT)
        return error.ProviderTraceShapeOutOfRange;
    if (row_count > std.math.maxInt(u32))
        return error.ProviderTraceShapeOutOfRange;
    return result;
}

fn add(left: usize, right: usize) !usize {
    return std.math.add(usize, left, right) catch error.ArithmeticOverflow;
}

fn programIdentity(value: *const ProgramAuthorityV2) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(PROGRAM_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    inline for (std.meta.fields(RequestCountsV2)) |field|
        hashInt(&hash, u64, @field(value.counts, field.name));
    hashInt(&hash, u32, value.log_size);
    hash.update(&value.provider_source_sha256);
    hash.update(&value.transcript_program_sha256);
    hash.update(&value.fri_program_sha256);
    hash.update(&value.merkle_path_program_sha256);
    return hash.finalResult();
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or ROW != 34)
        @compileError("heterogeneous Poseidon provider contract drifted");
}
