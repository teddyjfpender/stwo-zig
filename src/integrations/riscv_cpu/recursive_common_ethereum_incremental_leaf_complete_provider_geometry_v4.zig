//! Exact live geometry of the schema-3 role-0 row-34 Poseidon provider.
//!
//! Campaign geometry fixes only the field-publication subrange.  This receipt
//! seals all three authenticated ranges from the completed native verifier
//! schedule and therefore cannot be minted from publication capacity alone.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const shared = frontend.recursion.segment_shared_poseidon_schedule_v2;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;

const IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-complete-provider-geometry/v4-schema3\x00";

pub const Error = shared.Error || error{
    ArithmeticOverflow,
    EthereumIncrementalCompleteProviderGeometryMismatchV4,
};

/// Typed subdivision of the shared layout's `statement_authority` range.
/// The underlying frontend layout intentionally has only three protocol
/// ranges; this role-specific receipt prevents the row-34 wrapper from
/// silently treating its field-publication suffix as the whole middle range.
pub const StatementAuthorityCallCountsV4 = struct {
    child_claim_hash: u32,
    child_io_hash: u32,
    field_publication: u32,

    pub fn total(self: StatementAuthorityCallCountsV4) Error!u32 {
        return std.math.add(
            u32,
            std.math.add(
                u32,
                self.child_claim_hash,
                self.child_io_hash,
            ) catch return error.ArithmeticOverflow,
            self.field_publication,
        ) catch return error.ArithmeticOverflow;
    }

    pub fn validate(self: StatementAuthorityCallCountsV4) Error!void {
        if (self.child_claim_hash == 0 or self.child_io_hash == 0 or
            self.field_publication == 0)
        {
            return error.EthereumIncrementalCompleteProviderGeometryMismatchV4;
        }
        _ = try self.total();
    }
};

/// Pointer-free description of one live row-34 provider.  It is a geometry
/// input to the role-0 manifest, never a proof/freshness capability.
pub const CompleteProviderGeometryV4 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    stage101_transcript_call_count: u32,
    child_claim_hash_call_count: u32,
    child_io_hash_call_count: u32,
    field_publication_call_count: u32,
    verifier_core_call_count: u32,
    total_call_count: u32,
    provider_log_size: u32,
    provider_row_capacity: u32,
    schedule_identity_sha256: [32]u8,
    call_buffer_identity_sha256: [32]u8,
    identity_sha256: [32]u8,

    pub fn mint(
        layout: *const shared.SharedPoseidonCallLayoutV2,
        calls: []const shared.Call,
        statement_authority: StatementAuthorityCallCountsV4,
        provider_log_size: u32,
    ) Error!CompleteProviderGeometryV4 {
        try layout.validate(calls);
        try statement_authority.validate();
        if (!layout.call_set_complete)
            return error.EthereumIncrementalCompleteProviderGeometryMismatchV4;
        if (try countU32(layout.statement_authority) !=
            try statement_authority.total())
        {
            return error.EthereumIncrementalCompleteProviderGeometryMismatchV4;
        }
        var result = CompleteProviderGeometryV4{
            .stage101_transcript_call_count = try countU32(layout.transcript),
            .child_claim_hash_call_count = statement_authority.child_claim_hash,
            .child_io_hash_call_count = statement_authority.child_io_hash,
            .field_publication_call_count = statement_authority.field_publication,
            .verifier_core_call_count = try countU32(layout.verifier_core),
            .total_call_count = layout.total_call_count,
            .provider_log_size = provider_log_size,
            .provider_row_capacity = try rowCapacity(provider_log_size),
            .schedule_identity_sha256 = layout.identity,
            .call_buffer_identity_sha256 = layout.call_buffer_id,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = identity(result);
        try result.validate();
        return result;
    }

    pub fn validate(self: CompleteProviderGeometryV4) Error!void {
        const statement_authority = StatementAuthorityCallCountsV4{
            .child_claim_hash = self.child_claim_hash_call_count,
            .child_io_hash = self.child_io_hash_call_count,
            .field_publication = self.field_publication_call_count,
        };
        try statement_authority.validate();
        const boundary_count = std.math.add(
            u32,
            self.stage101_transcript_call_count,
            try statement_authority.total(),
        ) catch return error.ArithmeticOverflow;
        const total_count = std.math.add(
            u32,
            boundary_count,
            self.verifier_core_call_count,
        ) catch return error.ArithmeticOverflow;
        const expected_log = try traceLogSize(total_count);
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.stage101_transcript_call_count == 0 or
            self.verifier_core_call_count == 0 or
            self.total_call_count != total_count or
            self.provider_log_size != expected_log or
            self.provider_row_capacity != try rowCapacity(expected_log) or
            self.total_call_count > self.provider_row_capacity or
            std.mem.allEqual(u8, &self.schedule_identity_sha256, 0) or
            std.mem.allEqual(u8, &self.call_buffer_identity_sha256, 0) or
            !std.mem.eql(u8, &self.identity_sha256, &identity(self)))
        {
            return error.EthereumIncrementalCompleteProviderGeometryMismatchV4;
        }
    }
};

fn countU32(value: shared.CallRange) Error!u32 {
    return std.math.cast(u32, try value.count()) orelse
        error.ArithmeticOverflow;
}

fn traceLogSize(row_count: u32) Error!u32 {
    if (row_count == 0)
        return error.EthereumIncrementalCompleteProviderGeometryMismatchV4;
    return @max(
        @as(u32, 4),
        @as(u32, @intCast(std.math.log2_int_ceil(u32, row_count))),
    );
}

fn rowCapacity(log_size: u32) Error!u32 {
    if (log_size >= 31)
        return error.EthereumIncrementalCompleteProviderGeometryMismatchV4;
    return @as(u32, 1) << @intCast(log_size);
}

fn identity(value: CompleteProviderGeometryV4) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(IDENTITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u32, value.stage101_transcript_call_count);
    hashInt(&hash, u32, value.child_claim_hash_call_count);
    hashInt(&hash, u32, value.child_io_hash_call_count);
    hashInt(&hash, u32, value.field_publication_call_count);
    hashInt(&hash, u32, value.verifier_core_call_count);
    hashInt(&hash, u32, value.total_call_count);
    hashInt(&hash, u32, value.provider_log_size);
    hashInt(&hash, u32, value.provider_row_capacity);
    hash.update(&value.schedule_identity_sha256);
    hash.update(&value.call_buffer_identity_sha256);
    return hash.finalResult();
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3)
        @compileError("complete provider geometry V4 drifted");
}
