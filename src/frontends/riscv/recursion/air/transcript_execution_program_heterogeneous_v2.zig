//! Compiler authority for transcript execution rows 1, 6, and 7.
//!
//! Row 1's proof values remain verifier-transcript witness. Rows 6 and 7 also
//! retain proof-derived PoW words. This authority binds only their immutable
//! program: exact lane call geometry and the ordered PoW sites reconstructed
//! from the fully validated row-2 schedule.

const std = @import("std");
const binding_v2 = @import("transcript_data_rows_heterogeneous_v2.zig");
const binding = @import("transcript_binding_witness_contract.zig");
const pow_check = @import("pow_check.zig");
const pow_check_witness = @import("pow_check_witness.zig");
const pow_frame = @import("pow_frame.zig");
const pow_frame_witness = @import("pow_frame_witness.zig");
const schedule = @import("verifier_schedule.zig");
const transcript_air = @import("transcript_air.zig");
const transcript_air_witness = @import("transcript_air_witness.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const LANE_COUNT: usize = 3;
pub const ACTIVE_KIND_COUNT: usize = 2;
const MIN_LOG_SIZE: u32 = 4;
const MAX_LOG_SIZE: u32 = 30;
const AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/transcript-execution-program-heterogeneous/v2\x00";

pub const Error = binding.Error || error{
    InvalidHeterogeneousScheduleAuthority,
    InvalidTranscriptExecutionProgramAuthority,
};

pub const ScheduledPowV2 = struct {
    verifier_id: u32,
    sequence: u32,
    kind: pow_check.PowKind,
    call_id: u32,
    hash_id: u32,
    bits: u32,
};

pub const ProgramAuthorityV2 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    schemas: [LANE_COUNT]schedule.Schema,
    schedule_digests: [LANE_COUNT][8]u32,
    transcript_call_counts: [LANE_COUNT]usize,
    pow_counts: [LANE_COUNT]usize,
    transcript_log_sizes: [ACTIVE_KIND_COUNT]u32,
    pow_log_sizes: [ACTIVE_KIND_COUNT]u32,
    pow_sites: []ScheduledPowV2,
    transcript_source_sha256: [32]u8,
    transcript_semantic_sha256: [32]u8,
    transcript_binding_sha256: [32]u8,
    pow_check_source_sha256: [32]u8,
    pow_check_semantic_sha256: [32]u8,
    pow_check_binding_sha256: [32]u8,
    pow_frame_source_sha256: [32]u8,
    pow_frame_semantic_sha256: [32]u8,
    pow_frame_binding_sha256: [32]u8,
    row2_authority_sha256: [32]u8,
    program_sha256: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        calls: *const binding_v2.TranscriptBindingPreprocessedV2,
        vm: *const schedule.Plan,
        left: *const schedule.Plan,
        right: *const schedule.Plan,
    ) Error!ProgramAuthorityV2 {
        try calls.validateAgainst(vm, left, right);
        try validatePinnedComponents();
        const plans = [LANE_COUNT]*const schedule.Plan{ vm, left, right };
        var pow_counts: [LANE_COUNT]usize = undefined;
        var pow_count: usize = 0;
        for (plans, &pow_counts) |plan, *count| {
            count.* = scheduledPowCount(plan);
            pow_count = std.math.add(usize, pow_count, count.*) catch
                return error.ArithmeticOverflow;
        }
        const pow_sites = try allocator.alloc(ScheduledPowV2, pow_count);
        errdefer allocator.free(pow_sites);
        try reconstructPowSites(pow_sites, calls, plans);
        const binary_calls = try add(calls.counts[1], calls.counts[2]);
        const binary_pows = try add(pow_counts[1], pow_counts[2]);
        var result = ProgramAuthorityV2{
            .allocator = allocator,
            .schemas = calls.schemas,
            .schedule_digests = calls.schedule_digests,
            .transcript_call_counts = calls.counts,
            .pow_counts = pow_counts,
            .transcript_log_sizes = .{
                try logSize(calls.counts[0]),
                try logSize(binary_calls),
            },
            .pow_log_sizes = .{
                try logSize(pow_counts[0]),
                try logSize(binary_pows),
            },
            .pow_sites = pow_sites,
            .transcript_source_sha256 = transcript_air.SOURCE_AUTHORITY_DIGEST,
            .transcript_semantic_sha256 = transcript_air.SEMANTIC_DIGEST,
            .transcript_binding_sha256 = transcript_air_witness.BINDING_DIGEST,
            .pow_check_source_sha256 = pow_check.SOURCE_AUTHORITY_DIGEST,
            .pow_check_semantic_sha256 = pow_check.SEMANTIC_DIGEST,
            .pow_check_binding_sha256 = pow_check_witness.BINDING_DIGEST,
            .pow_frame_source_sha256 = pow_frame.SOURCE_AUTHORITY_DIGEST,
            .pow_frame_semantic_sha256 = pow_frame.SEMANTIC_DIGEST,
            .pow_frame_binding_sha256 = pow_frame_witness.BINDING_DIGEST,
            .row2_authority_sha256 = calls.authority_sha256,
            .program_sha256 = undefined,
        };
        result.program_sha256 = identity(&result);
        try result.validateAgainst(calls, vm, left, right);
        return result;
    }

    pub fn deinit(self: *ProgramAuthorityV2) void {
        self.allocator.free(self.pow_sites);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const ProgramAuthorityV2,
        calls: *const binding_v2.TranscriptBindingPreprocessedV2,
        vm: *const schedule.Plan,
        left: *const schedule.Plan,
        right: *const schedule.Plan,
    ) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION)
        {
            return error.InvalidTranscriptExecutionProgramAuthority;
        }
        try calls.validateAgainst(vm, left, right);
        try validatePinnedComponents();
        if (!std.meta.eql(self.schemas, calls.schemas) or
            !std.meta.eql(self.schedule_digests, calls.schedule_digests) or
            !std.meta.eql(self.transcript_call_counts, calls.counts) or
            !std.mem.eql(
                u8,
                &self.row2_authority_sha256,
                &calls.authority_sha256,
            ) or !pinnedIdsMatch(self))
        {
            return error.InvalidTranscriptExecutionProgramAuthority;
        }
        const plans = [LANE_COUNT]*const schedule.Plan{ vm, left, right };
        var pow_count: usize = 0;
        for (plans, self.pow_counts) |plan, count| {
            if (count != scheduledPowCount(plan))
                return error.InvalidTranscriptExecutionProgramAuthority;
            pow_count = std.math.add(usize, pow_count, count) catch
                return error.ArithmeticOverflow;
        }
        if (self.pow_sites.len != pow_count or
            !std.meta.eql(self.transcript_log_sizes, [ACTIVE_KIND_COUNT]u32{
                try logSize(calls.counts[0]),
                try logSize(try add(calls.counts[1], calls.counts[2])),
            }) or !std.meta.eql(self.pow_log_sizes, [ACTIVE_KIND_COUNT]u32{
            try logSize(self.pow_counts[0]),
            try logSize(try add(self.pow_counts[1], self.pow_counts[2])),
        })) return error.InvalidTranscriptExecutionProgramAuthority;
        try comparePowSites(self.pow_sites, calls, plans);
        if (!std.mem.eql(u8, &self.program_sha256, &identity(self)))
            return error.InvalidTranscriptExecutionProgramAuthority;
    }

    /// Exact row-34 Poseidon provider calls contributed by row 1 for a binary
    /// parent. Other provider clients are accounted by their own authorities.
    pub fn binaryTranscriptProviderCallCount(
        self: *const ProgramAuthorityV2,
    ) Error!usize {
        return add(
            self.transcript_call_counts[1],
            self.transcript_call_counts[2],
        );
    }
};

fn validatePinnedComponents() Error!void {
    try transcript_air.SourceAuthority.pinned().validate();
    try pow_check.SourceAuthority.pinned().validate();
}

fn pinnedIdsMatch(self: *const ProgramAuthorityV2) bool {
    return std.mem.eql(u8, &self.transcript_source_sha256, &transcript_air.SOURCE_AUTHORITY_DIGEST) and
        std.mem.eql(u8, &self.transcript_semantic_sha256, &transcript_air.SEMANTIC_DIGEST) and
        std.mem.eql(u8, &self.transcript_binding_sha256, &transcript_air_witness.BINDING_DIGEST) and
        std.mem.eql(u8, &self.pow_check_source_sha256, &pow_check.SOURCE_AUTHORITY_DIGEST) and
        std.mem.eql(u8, &self.pow_check_semantic_sha256, &pow_check.SEMANTIC_DIGEST) and
        std.mem.eql(u8, &self.pow_check_binding_sha256, &pow_check_witness.BINDING_DIGEST) and
        std.mem.eql(u8, &self.pow_frame_source_sha256, &pow_frame.SOURCE_AUTHORITY_DIGEST) and
        std.mem.eql(u8, &self.pow_frame_semantic_sha256, &pow_frame.SEMANTIC_DIGEST) and
        std.mem.eql(u8, &self.pow_frame_binding_sha256, &pow_frame_witness.BINDING_DIGEST);
}

fn scheduledPowCount(plan: *const schedule.Plan) usize {
    var result: usize = 0;
    for (plan.steps) |step| result += @intFromBool(powForStep(step) != null);
    return result;
}

fn reconstructPowSites(
    output: []ScheduledPowV2,
    calls: *const binding_v2.TranscriptBindingPreprocessedV2,
    plans: [LANE_COUNT]*const schedule.Plan,
) Error!void {
    var output_at: usize = 0;
    var start: usize = 0;
    for (plans, calls.counts, 0..) |plan, count, lane| {
        const end = try add(start, count);
        if (end > calls.rows.len)
            return error.InvalidTranscriptExecutionProgramAuthority;
        for (calls.rows[start..end]) |row| {
            if (row.pow_final_mask == 0) continue;
            if (row.sequence >= plan.steps.len or output_at >= output.len)
                return error.InvalidTranscriptExecutionProgramAuthority;
            const pow = powForStep(plan.steps[row.sequence]) orelse
                return error.InvalidTranscriptExecutionProgramAuthority;
            output[output_at] = .{
                .verifier_id = @intCast(lane),
                .sequence = row.sequence,
                .kind = pow.kind,
                .call_id = row.call_id,
                .hash_id = row.hash_id,
                .bits = pow.bits,
            };
            output_at += 1;
        }
        start = end;
    }
    if (start != calls.rows.len or output_at != output.len)
        return error.InvalidTranscriptExecutionProgramAuthority;
}

fn comparePowSites(
    actual: []const ScheduledPowV2,
    calls: *const binding_v2.TranscriptBindingPreprocessedV2,
    plans: [LANE_COUNT]*const schedule.Plan,
) Error!void {
    var actual_at: usize = 0;
    var start: usize = 0;
    for (plans, calls.counts, 0..) |plan, count, lane| {
        const end = try add(start, count);
        if (end > calls.rows.len)
            return error.InvalidTranscriptExecutionProgramAuthority;
        for (calls.rows[start..end]) |row| {
            if (row.pow_final_mask == 0) continue;
            if (row.sequence >= plan.steps.len or actual_at >= actual.len)
                return error.InvalidTranscriptExecutionProgramAuthority;
            const pow = powForStep(plan.steps[row.sequence]) orelse
                return error.InvalidTranscriptExecutionProgramAuthority;
            const expected = ScheduledPowV2{
                .verifier_id = @intCast(lane),
                .sequence = row.sequence,
                .kind = pow.kind,
                .call_id = row.call_id,
                .hash_id = row.hash_id,
                .bits = pow.bits,
            };
            if (!std.meta.eql(actual[actual_at], expected))
                return error.InvalidTranscriptExecutionProgramAuthority;
            actual_at += 1;
        }
        start = end;
    }
    if (start != calls.rows.len or actual_at != actual.len)
        return error.InvalidTranscriptExecutionProgramAuthority;
}

const Pow = struct { kind: pow_check.PowKind, bits: u32 };

fn powForStep(step: schedule.VerifierStep) ?Pow {
    return switch (step) {
        .verify_and_absorb_interaction_pow => |item| .{
            .kind = .interaction,
            .bits = item.bits,
        },
        .verify_and_absorb_pcs_pow => |item| .{
            .kind = .pcs,
            .bits = item.bits,
        },
        else => null,
    };
}

fn logSize(count: usize) Error!u32 {
    const padded = std.math.ceilPowerOfTwo(usize, @max(count, 1)) catch
        return error.ArithmeticOverflow;
    const result: u32 = @max(MIN_LOG_SIZE, std.math.log2_int(usize, padded));
    if (result > MAX_LOG_SIZE)
        return error.InvalidTranscriptExecutionProgramAuthority;
    return result;
}

fn add(left: usize, right: usize) Error!usize {
    return std.math.add(usize, left, right) catch error.ArithmeticOverflow;
}

fn identity(self: *const ProgramAuthorityV2) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(AUTHORITY_DOMAIN);
    hashInt(&hash, u16, self.format_version);
    hashInt(&hash, u16, self.schema_version);
    for (
        self.schemas,
        self.schedule_digests,
        self.transcript_call_counts,
        self.pow_counts,
    ) |schema, schedule_digest, call_count, pow_count| {
        hashInt(&hash, u16, @intFromEnum(schema));
        for (schedule_digest) |word| hashInt(&hash, u32, word);
        hashInt(&hash, u64, call_count);
        hashInt(&hash, u64, pow_count);
    }
    for (self.transcript_log_sizes) |value| hashInt(&hash, u32, value);
    for (self.pow_log_sizes) |value| hashInt(&hash, u32, value);
    hashInt(&hash, u64, self.pow_sites.len);
    for (self.pow_sites) |site| {
        hashInt(&hash, u32, site.verifier_id);
        hashInt(&hash, u32, site.sequence);
        hashInt(&hash, u32, @intFromEnum(site.kind));
        hashInt(&hash, u32, site.call_id);
        hashInt(&hash, u32, site.hash_id);
        hashInt(&hash, u32, site.bits);
    }
    hash.update(&self.transcript_source_sha256);
    hash.update(&self.transcript_semantic_sha256);
    hash.update(&self.transcript_binding_sha256);
    hash.update(&self.pow_check_source_sha256);
    hash.update(&self.pow_check_semantic_sha256);
    hash.update(&self.pow_check_binding_sha256);
    hash.update(&self.pow_frame_source_sha256);
    hash.update(&self.pow_frame_semantic_sha256);
    hash.update(&self.pow_frame_binding_sha256);
    hash.update(&self.row2_authority_sha256);
    return hash.finalResult();
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or LANE_COUNT != 3 or
        ACTIVE_KIND_COUNT != 2)
    {
        @compileError("heterogeneous transcript execution program drifted");
    }
}
