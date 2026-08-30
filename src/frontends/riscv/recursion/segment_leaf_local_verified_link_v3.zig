//! Pointer-free link from a successfully verified local V2 leaf to its V3
//! global position.
//!
//! `VerifiedReceipt` is transactionally published only after the native AIR,
//! PCS, Merkle, and FRI verifier succeeds. This module does not rerun that
//! verifier; callers must pass the receipt and verifier-owned public data from
//! one validated `VerifiedSegmentV2CaptureForEngine`. It then proves natively
//! that the local V2 span is the unique projection of the advertised global
//! V3 metadata and seals that relation in a Poseidon2-M31 identity.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;

const public_data_v2 = @import("../air/public_data_v2.zig");
const statement_v2 = @import("../air/statement_v2.zig");
const channel = @import("poseidon2_channel.zig");
const segment_v2 = @import("segment_statement_v2.zig");
const global_v3 = @import("segment_leaf_local_authority_v3.zig");
const projection_v3 = @import("segment_leaf_local_projection_v3.zig");

pub const FORMAT_VERSION: u16 = 3;
pub const SCHEMA_VERSION: u16 = 1;
pub const IDENTITY_DOMAIN: u32 = 0x4c56_4c33; // "LVL3"
pub const IDENTITY_WORDS: usize = 50;
pub const VERIFIED_CAPTURE_REQUIRED = true;
pub const PRODUCTION_RECURSIVE_ACTIVATION = false;

comptime {
    if (IDENTITY_DOMAIN >= m31.Modulus)
        @compileError("leaf-local V3 link identity domain is not canonical");
    if (IDENTITY_DOMAIN == global_v3.METADATA_ID_DOMAIN)
        @compileError("leaf-local V3 metadata and link domains must be distinct");
}

pub const Error = global_v3.Error || projection_v3.Error ||
    statement_v2.Error || error{
    InvalidVerifiedLink,
    LocalBoundaryMismatch,
    LocalStatementMismatch,
};

pub const VerifiedLinkV3 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    global_metadata_id: channel.Digest,
    local_authority_id: channel.Digest,
    local_wire_id: channel.Digest,
    local_receipt_id: channel.Digest,
    segment_index: u32,
    segment_count: u32,
    global_cycle_start: u64,
    global_cycle_end: u64,
    local_cycle_count: u32,
    entry_continuation_root: u32,
    exit_continuation_root: u32,
    identity: channel.Digest,

    pub fn init(
        global: *const global_v3.MetadataV3,
        local: *const public_data_v2.PublicDataV2,
        receipt: *const statement_v2.VerifiedReceipt,
    ) Error!VerifiedLinkV3 {
        try validateSources(global, local, receipt);
        var result = VerifiedLinkV3{
            .global_metadata_id = try global.identity(),
            .local_authority_id = receipt.authority_id,
            .local_wire_id = receipt.wire_id,
            .local_receipt_id = receipt.identity,
            .segment_index = global.segment_index,
            .segment_count = global.segment_count,
            .global_cycle_start = global.global_cycle_start,
            .global_cycle_end = global.global_cycle_end,
            .local_cycle_count = global.local_cycle_count,
            .entry_continuation_root = global.entry.continuation_root,
            .exit_continuation_root = global.exit.continuation_root,
            .identity = undefined,
        };
        result.identity = identity(&result);
        try result.validateHeader();
        return result;
    }

    pub fn validateAgainst(
        self: *const VerifiedLinkV3,
        global: *const global_v3.MetadataV3,
        local: *const public_data_v2.PublicDataV2,
        receipt: *const statement_v2.VerifiedReceipt,
    ) Error!void {
        try self.validateHeader();
        const expected = try VerifiedLinkV3.init(global, local, receipt);
        if (!std.meta.eql(self.*, expected)) return error.InvalidVerifiedLink;
    }

    pub fn validateHeader(self: *const VerifiedLinkV3) Error!void {
        const expected_end = std.math.add(
            u64,
            self.global_cycle_start,
            self.local_cycle_count,
        ) catch return error.InvalidVerifiedLink;
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.segment_count == 0 or
            self.segment_index >= self.segment_count or
            self.local_cycle_count == 0 or
            self.local_cycle_count > global_v3.MAX_LEAF_CYCLES or
            self.global_cycle_end != expected_end or
            self.entry_continuation_root >= m31.Modulus or
            self.exit_continuation_root >= m31.Modulus)
        {
            return error.InvalidVerifiedLink;
        }
        inline for (.{
            self.global_metadata_id,
            self.local_authority_id,
            self.local_wire_id,
            self.local_receipt_id,
        }) |digest| try requireDigest(digest);
        if (!std.meta.eql(self.identity, identity(self)))
            return error.InvalidVerifiedLink;
    }
};

fn validateSources(
    global: *const global_v3.MetadataV3,
    local: *const public_data_v2.PublicDataV2,
    receipt: *const statement_v2.VerifiedReceipt,
) Error!void {
    try global.validate();
    try local.validate();
    try receipt.validateAgainst(local);
    const view = try segment_v2.authenticateCanonicalWire(local.words());
    const actual_local = try view.statement.base();
    const expected_local = try projection_v3.localStatementFromMetadata(global);
    if (!std.meta.eql(actual_local, expected_local) or
        receipt.segment_index != global.segment_index or
        receipt.segment_count != global.segment_count or
        receipt.global_cycle_start != 0 or
        receipt.global_cycle_end != global.local_cycle_count)
    {
        return error.LocalStatementMismatch;
    }
    if (!std.meta.eql(view.statement.entry_snapshot_id, global.entry.snapshot_id) or
        view.statement.entry_snapshot_count != global.entry.snapshot_count or
        view.statement.entry_continuation_root != global.entry.continuation_root or
        !std.meta.eql(view.statement.exit_snapshot_id, global.exit.snapshot_id) or
        view.statement.exit_snapshot_count != global.exit.snapshot_count or
        view.statement.exit_continuation_root != global.exit.continuation_root or
        !std.meta.eql(
            view.statement.entry_register_clocks,
            global.entry.register_clocks,
        ) or
        !std.meta.eql(
            view.statement.exit_register_clocks,
            global.exit.register_clocks,
        ) or
        !std.meta.eql(
            view.statement.entry_memory_clock_id,
            global.entry.memory_clock_id,
        ) or
        view.statement.entry_memory_clock_count != global.entry.memory_clock_count or
        !std.meta.eql(
            view.statement.exit_memory_clock_id,
            global.exit.memory_clock_id,
        ) or
        view.statement.exit_memory_clock_count != global.exit.memory_clock_count or
        !std.meta.eql(view.statement.completion, global.completion))
    {
        return error.LocalBoundaryMismatch;
    }
}

fn identity(link: *const VerifiedLinkV3) channel.Digest {
    var words: [IDENTITY_WORDS]u32 = undefined;
    var at: usize = 0;
    put(&words, &at, link.format_version);
    put(&words, &at, link.schema_version);
    putDigest(&words, &at, link.global_metadata_id);
    putDigest(&words, &at, link.local_authority_id);
    putDigest(&words, &at, link.local_wire_id);
    putDigest(&words, &at, link.local_receipt_id);
    putU32(&words, &at, link.segment_index);
    putU32(&words, &at, link.segment_count);
    putU64(&words, &at, link.global_cycle_start);
    putU64(&words, &at, link.global_cycle_end);
    putU32(&words, &at, link.local_cycle_count);
    put(&words, &at, link.entry_continuation_root);
    put(&words, &at, link.exit_continuation_root);
    std.debug.assert(at == words.len);
    return channel.hashCanonicalU32s(&words, IDENTITY_DOMAIN);
}

fn put(words: []u32, at: *usize, value: u32) void {
    std.debug.assert(value < m31.Modulus);
    words[at.*] = value;
    at.* += 1;
}

fn putDigest(words: []u32, at: *usize, value: channel.Digest) void {
    for (value) |word| put(words, at, word);
}

fn putU32(words: []u32, at: *usize, value: u32) void {
    put(words, at, value & 0xffff);
    put(words, at, value >> 16);
}

fn putU64(words: []u32, at: *usize, value: u64) void {
    inline for (0..4) |limb|
        put(words, at, @intCast((value >> (16 * limb)) & 0xffff));
}

fn requireDigest(digest: channel.Digest) Error!void {
    var aggregate: u32 = 0;
    for (digest) |word| {
        if (word >= m31.Modulus) return error.InvalidVerifiedLink;
        aggregate |= word;
    }
    if (aggregate == 0) return error.InvalidVerifiedLink;
}
