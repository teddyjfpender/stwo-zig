//! Exact five-phase publication callers and their authenticated source routes.
//! Construction uses the retained schema-3 schedule admitted by rows_10_34.
//! Source descriptors are obligations for the canonical source bridge; this
//! module never manufactures source emits from hash witnesses.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const schema = @import("recursive_common_ethereum_incremental_leaf_field_public_v4_schema3.zig");
const public = @import("recursive_field_node_public_v2.zig");
const shared = @import("recursive_public_hash_rows_v1.zig");
const Air = frontend.recursion.air.ethereum_publication_hash_v1;
pub const Phase = schema.PhaseV4;
pub const DIGEST_INPUT_KIND = frontend.recursion.air.field_public_word_v3.DIGEST_INPUT_KIND;
pub const Row = Air.Relation.Row;
pub const DIGEST_START = public.HEADER_WORD_COUNT + public.STATEMENT_WORD_COUNT;

pub fn hashScope(phase: Phase) u32 {
    return 1100 + @as(u32, @intFromEnum(phase));
}

pub const Source = union(enum) {
    role_io_word: u32,
    statement_word: u32,
    node_header_word: u32,
    native_source_word: u32,
    hash_digest: struct { phase: Phase, limb: u3 },
};

/// Every hash-word consumer must be supplied by the indicated canonical
/// source. Coordinates are fixed by phase and index, never chosen by a row.
pub fn sourceForWord(phase: Phase, index: usize, role_word_count: usize) !Source {
    return switch (phase) {
        .io_stream => if (index < role_word_count) .{ .role_io_word = @intCast(index) } else error.InvalidEthereumPublicationWord,
        .statement => if (index < public.STATEMENT_WORD_COUNT) .{ .statement_word = @intCast(index) } else error.InvalidEthereumPublicationWord,
        .source => if (index < 8)
            .{ .native_source_word = @intCast(index) }
        else if (index < 16)
            digestSource(.statement, index - 8)
        else if (index < 94)
            .{ .native_source_word = @intCast(index) }
        else if (index < 96)
            .{ .role_io_word = @intCast(index - 91) }
        else if (index < schema.SOURCE_PREIMAGE_WORD_COUNT)
            digestSource(.io_stream, index - 96)
        else
            error.InvalidEthereumPublicationWord,
        .subtree => if (index < public.HEADER_WORD_COUNT)
            .{ .node_header_word = @intCast(index) }
        else if (index < public.HEADER_WORD_COUNT + 8)
            digestSource(.statement, index - public.HEADER_WORD_COUNT)
        else if (index < public.HEADER_WORD_COUNT + 16)
            digestSource(.source, index - public.HEADER_WORD_COUNT - 8)
        else
            error.InvalidEthereumPublicationWord,
        .output => if (index < public.HEADER_WORD_COUNT)
            .{ .node_header_word = @intCast(index) }
        else if (index < DIGEST_START)
            .{ .statement_word = @intCast(index - public.HEADER_WORD_COUNT) }
        else if (index < DIGEST_START + 24)
            digestSource(@enumFromInt(1 + (index - DIGEST_START) / 8), (index - DIGEST_START) % 8)
        else
            error.InvalidEthereumPublicationWord,
    };
}

fn digestSource(phase: Phase, limb: usize) Source {
    return .{ .hash_digest = .{ .phase = phase, .limb = @intCast(limb) } };
}

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    rows: []Row,

    /// The input is the materialized capture from an authenticated owner's
    /// preparation view. Replaying these small hashes checks the exact calls
    /// and digests without retaining another capture or a second native owner.
    pub fn initAdmitted(allocator: std.mem.Allocator, materialized: anytype, first_step: u32) !Prepared {
        const schedule = &materialized.schedule;
        const node_words = try schedule.node_public.canonicalAirWords();
        const source_words = try schedule.source.preimage();
        const subtree = node_words[0..public.HEADER_WORD_COUNT].* ++ node_words[DIGEST_START..][0..16].*;
        const preimages = [_][]const u32{
            materialized.role_aware_io.canonical_words,
            &schedule.node_public.statement_words,
            &source_words,
            &subtree,
            node_words[0 .. public.AIR_WORD_COUNT - 8],
        };
        const domains = [_]u32{
            schema.IO_COMMITMENT_DOMAIN, public.STATEMENT_DIGEST_DOMAIN,
            schema.SOURCE_DIGEST_DOMAIN, public.SUBTREE_DIGEST_DOMAIN,
            public.OUTPUT_DIGEST_DOMAIN,
        };
        const rows = try allocator.alloc(Row, schedule.calls.len);
        errdefer allocator.free(rows);
        var at: usize = 0;
        for (preimages, domains, schedule.phases, 0..) |preimage, domain, expected, phase_index| {
            const phase: Phase = @enumFromInt(phase_index);
            const count = try shared.rowCount(preimage.len);
            if (expected.phase != phase or expected.first_call != at or
                expected.call_count != count or at + count > rows.len)
                return error.InvalidEthereumPublicationSchedule;
            const legacy_rows = try allocator.alloc(shared.Row, count);
            defer allocator.free(legacy_rows);
            const calls = try allocator.alloc(shared.Call, count);
            defer allocator.free(calls);
            const digest = try shared.write(preimage, .{
                .domain = domain,
                .scope = hashScope(phase),
                .verifier = hashScope(phase),
                .input_kind = DIGEST_INPUT_KIND,
            }, try std.math.add(u32, first_step, @intCast(at)), legacy_rows, calls);
            if (!std.meta.eql(digest, expected.output_digest))
                return error.InvalidEthereumPublicationSchedule;
            for (calls, schedule.calls[at..][0..count]) |actual, wanted|
                if (!std.meta.eql(actual, wanted)) return error.InvalidEthereumPublicationSchedule;
            for (rows[at..][0..count], legacy_rows) |*destination, row|
                destination.* = Air.fromLegacy(row);
            for (0..preimage.len) |index| _ = try sourceForWord(phase, index, preimages[0].len);
            at += count;
        }
        if (at != rows.len) return error.InvalidEthereumPublicationSchedule;
        return .{ .allocator = allocator, .rows = rows };
    }

    pub fn deinit(self: *Prepared) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }
};

comptime {
    if (schema.SOURCE_PREIMAGE_WORD_COUNT != 104 or public.AIR_WORD_COUNT != 450 or
        DIGEST_START != 418 or core.fields.m31.Modulus <= hashScope(.output))
        @compileError("Ethereum publication source layout drifted");
}
