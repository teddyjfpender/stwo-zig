//! Prepared field-public hash AIRs and word routes for a common-fold node.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const recursion = frontend.recursion;
const air = recursion.air;
const hash_air = air.vm_public_claim_hash;
const hash_rows = @import("recursive_public_hash_rows_v1.zig");
const word_air = air.field_public_word_v3;
const public = @import("recursive_field_node_public_v2.zig");
const schedule = @import("recursive_common_fold_field_public_v2.zig");
const M31 = core.fields.m31.M31;
pub const HashRow = [hash_air.LOGICAL_INPUT_COUNT]M31;
pub const WordRow = [word_air.LOGICAL_INPUT_COUNT]M31;
pub const DIGEST_START = public.HEADER_WORD_COUNT + public.STATEMENT_WORD_COUNT;
pub const CHILD_HASH_START = DIGEST_START + 2 * 8;
pub const CHILD_HASH_WORDS = 16;
pub const Phase = schedule.PhaseV2;

pub fn hashScope(phase: Phase) u32 {
    return 1000 + @as(u32, @intFromEnum(phase));
}
pub fn nodeWordIndex(index: usize) u32 {
    return @intCast(if (index >= public.HEADER_WORD_COUNT and index < DIGEST_START) index - public.HEADER_WORD_COUNT else public.STATEMENT_WORD_COUNT + index);
}

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    hashes: [4][]HashRow,
    words: []WordRow,
    calls: [schedule.POSEIDON_CALL_COUNT]frontend.air.memory_commitment.poseidon2_air.Call,

    pub fn init(allocator: std.mem.Allocator, left: *const public.NodePublicV2, right: *const public.NodePublicV2, expected: *const schedule.PoseidonScheduleV2) !Prepared {
        try expected.validateAgainst(left, right, expected.parent_coordinate);
        const parent = try expected.parent.canonicalAirWords();
        const source = schedule.parentSourcePreimage(left, right);
        const subtree = parent[0..public.HEADER_WORD_COUNT].* ++ parent[DIGEST_START..][0..16].*;
        const preimages = [_][]const u32{ &expected.parent.statement_words, &source, &subtree, parent[0 .. public.AIR_WORD_COUNT - 8] };
        const domains = [_]u32{ public.STATEMENT_DIGEST_DOMAIN, public.PARENT_SOURCE_DOMAIN, public.SUBTREE_DIGEST_DOMAIN, public.OUTPUT_DIGEST_DOMAIN };
        var result = Prepared{ .allocator = allocator, .hashes = .{ &.{}, &.{}, &.{}, &.{} }, .words = &.{}, .calls = undefined };
        errdefer result.deinit();
        var call_at: usize = 0;
        for (preimages, domains, 0..) |preimage, domain, phase_index| {
            const phase: Phase = @enumFromInt(phase_index);
            const count = std.math.divCeil(usize, preimage.len + 1, hash_air.RATE) catch unreachable;
            const rows = try allocator.alloc(HashRow, count);
            result.hashes[phase_index] = rows;
            _ = try hash_rows.write(preimage, .{
                .domain = domain,
                .scope = hashScope(phase),
                .verifier = hashScope(phase),
                .input_kind = word_air.DIGEST_INPUT_KIND,
            }, @intCast(call_at), rows, result.calls[call_at..][0..count]);
            call_at += count;
        }
        if (call_at != result.calls.len or !std.meta.eql(result.calls, expected.calls)) return error.CommonFoldPublicHashMismatch;
        result.words = try allocator.alloc(WordRow, public.AIR_WORD_COUNT + 2 * CHILD_HASH_WORDS);
        for (parent, result.words[0..parent.len], 0..) |value, *row, index| {
            var pp = [_]u32{0} ** word_air.PREPROCESSED_COLUMN_COUNT;
            pp[0] = 1;
            pp[4] = 1;
            pp[5] = @intCast(index);
            if (index >= public.HEADER_WORD_COUNT and index < DIGEST_START) {
                pp[6] = 1;
                pp[7] = @intCast(index - public.HEADER_WORD_COUNT);
                route(&pp, 0, .statement, index - public.HEADER_WORD_COUNT);
            } else if (index < public.HEADER_WORD_COUNT) route(&pp, 0, .subtree, index) else if (index < DIGEST_START + 16) route(&pp, 0, .subtree, public.HEADER_WORD_COUNT + index - DIGEST_START);
            if (index < public.AIR_WORD_COUNT - 8) route(&pp, 1, .output, index);
            if (index >= DIGEST_START) {
                pp[14] = 1;
                pp[15] = hashScope(@enumFromInt((index - DIGEST_START) / 8));
                pp[16] = @intCast((index - DIGEST_START) % 8);
            }
            row.* = logical(value, pp);
        }
        for ([_]*const public.NodePublicV2{ left, right }, 0..) |child, lane| {
            const node_words = try child.canonicalAirWords();
            for (0..CHILD_HASH_WORDS) |offset| {
                // Source hashes absorb output before subtree, matching NodePublic.
                const index = CHILD_HASH_START + (offset + 8) % CHILD_HASH_WORDS;
                var pp = [_]u32{0} ** word_air.PREPROCESSED_COLUMN_COUNT;
                pp[0] = 1;
                pp[1] = 1;
                pp[2] = @intCast(lane + 1);
                pp[3] = nodeWordIndex(index);
                route(&pp, 0, .source, lane * CHILD_HASH_WORDS + offset);
                result.words[public.AIR_WORD_COUNT + lane * CHILD_HASH_WORDS + offset] = logical(node_words[index], pp);
            }
        }
        return result;
    }
    pub fn deinit(self: *Prepared) void {
        for (self.hashes) |rows| self.allocator.free(rows);
        self.allocator.free(self.words);
        self.* = undefined;
    }
};

fn route(pp: *[word_air.PREPROCESSED_COLUMN_COUNT]u32, slot: usize, phase: Phase, index: usize) void {
    const at = 8 + 3 * slot;
    pp[at] = 1;
    pp[at + 1] = hashScope(phase);
    pp[at + 2] = @intCast(index);
}
fn logical(value: u32, pp: [word_air.PREPROCESSED_COLUMN_COUNT]u32) WordRow {
    var row: WordRow = undefined;
    row[0] = M31.one();
    row[1] = M31.fromCanonical(value);
    for (row[2..], pp) |*target, word| target.* = M31.fromCanonical(word);
    return row;
}
