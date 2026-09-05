//! Shared expected-source custody for the one-leaf Poseidon v4 product.

const std = @import("std");
const contract = @import("ethereum_block_leaf_contract.zig");
const journal_authority = @import("ethereum_block_leaf_journal.zig");
const product_contract = @import("ethereum_poseidon_leaf_product_contract.zig");
const statement_plan = @import("recursive_temporal_statement_plan_v1.zig");
const support = @import("ethereum_block_leaf_support.zig");

pub const max_elf_bytes: usize = 64 * 1024 * 1024;
pub const max_input_bytes: usize = 64 * 1024 * 1024;
pub const max_output_bytes: usize = 16 * 1024 * 1024;
pub const max_journal_bytes: usize = 64 * 1024 * 1024;

pub const OpenedAuthority = struct {
    source: std.json.Parsed(contract.RecursiveSourceRequestV2),
    expected: support.source_wire.Source,

    pub fn deinit(self: *OpenedAuthority) void {
        self.source.deinit();
        self.* = undefined;
    }
};

/// Reopens every proof-independent authority needed to identify one leaf.
/// The journal is parsed canonically and binds the selected STWESG31 record;
/// neither producer nor fresh verifier trusts artifact-declared metadata.
pub fn openAuthority(
    allocator: std.mem.Allocator,
    request: *const product_contract.Request,
) !OpenedAuthority {
    try request.validate();
    const source_bytes = try support.readIdentity(allocator, .{
        .bytes = request.source_request.bytes,
        .path = request.source_request.path,
        .sha256 = request.source_request.sha256,
    }, contract.max_json_bytes);
    defer allocator.free(source_bytes);
    var source = try contract.parseRecursiveSource(allocator, source_bytes);
    errdefer source.deinit();
    if (!std.mem.eql(
        u8,
        source.value.schema,
        request.source_request.schema,
    ) or request.segment_index >= source.value.segment_count) {
        return error.ExpectedSourceMismatch;
    }
    inline for (.{
        source.value.elf.path,
        source.value.execution_journal.path,
        source.value.expected_output.path,
        source.value.input.path,
    }) |path| if (!std.fs.path.isAbsolute(path))
        return error.ExpectedSourceMismatch;

    const segment_bytes = try support.readIdentity(
        allocator,
        request.source_segment,
        support.source_wire.encoded_size,
    );
    defer allocator.free(segment_bytes);
    const expected = try support.source_wire.decode(segment_bytes);
    if (expected.metadata.segment_index != request.segment_index or
        expected.metadata.segment_count != source.value.segment_count or
        !std.meta.eql(
            try expected.statementSha256(),
            try contract.parseSha256(
                request.expected_source_public_statement_sha256,
            ),
        ) or !std.meta.eql(
        statement_plan.statementSha256(
            &expected.metadata.base_statement_words,
        ),
        try contract.parseSha256(request.expected_recursive_statement_sha256),
    )) {
        return error.ExpectedSourceMismatch;
    }

    const journal = try support.readIdentity(
        allocator,
        source.value.execution_journal,
        max_journal_bytes,
    );
    defer allocator.free(journal);
    const records = try journal_authority.validate(
        allocator,
        journal,
        source.value,
    );
    defer allocator.free(records);
    if (records.len != source.value.segment_count or
        !std.meta.eql(records[request.segment_index], expected.journal_record_sha256))
    {
        return error.ExpectedJournalRecordMismatch;
    }
    return .{ .source = source, .expected = expected };
}

pub fn digestHex(value: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(value, .lower);
}

pub fn fieldDigestHex(value: [8]u32) [64]u8 {
    return std.fmt.bytesToHex(fieldDigestBytes(value), .lower);
}

pub fn fieldDigestBytes(value: [8]u32) [32]u8 {
    var bytes: [32]u8 = undefined;
    for (value, 0..) |word, index|
        std.mem.writeInt(u32, bytes[4 * index ..][0..4], word, .little);
    return bytes;
}
