//! Owned assembly of the existing two-child transcript and PCS row inventories.
//! No lookup count or preprocessing field is rewritten here. Graph rows and
//! their provider requests are added by the separate admitted routing owner.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const cohort = @import("recursive_segment_v2_detached_parent_cohort.zig");
const prefix = @import("recursive_segment_v2_detached_prefix.zig");
const pcs_rows = @import("recursive_segment_v2_detached_pcs_rows.zig");
const pcs_checks = @import("recursive_segment_v2_detached_pcs_checks.zig");
const shared_rows = @import("recursive_secure_transcript_rows_v1.zig");

pub const OwnedV1 = opaque {
    const Storage = struct {
        allocator: std.mem.Allocator,
        arena: std.heap.ArenaAllocator,
        rows: cohort.LogicalRowsV1,
        calls: []const cohort.ProviderCall,
    };
    fn storage(self: *const OwnedV1) *const Storage {
        return @ptrCast(@alignCast(self));
    }
    pub fn init(
        allocator: std.mem.Allocator,
        prefixes: [2]*const prefix.OwnedV1,
        transcripts: [2]*const pcs_rows.OwnedV1,
        checks: [2]*const pcs_checks.OwnedV1,
    ) !*OwnedV1 {
        const value = try allocator.create(Storage);
        errdefer allocator.destroy(value);
        value.allocator = allocator;
        value.arena = std.heap.ArenaAllocator.init(allocator);
        errdefer value.arena.deinit();
        inline for (0..cohort.LOGICAL_ROWS.len) |index| value.rows[index] = &.{};
        value.calls = &.{};
        const owned = value.arena.allocator();
        var calls: std.ArrayList(cohort.ProviderCall) = .empty;
        for (prefixes, transcripts, checks, 0..) |prefix_owner, transcript_owner, check_owner, lane_index| {
            const head = prefix_owner.view();
            const tail = transcript_owner.view();
            const check = check_owner.view();
            const lane: u32 = @intCast(lane_index + 1);
            // Reject accidental lane exchange before copying any of its rows.
            // Same-lane proof continuity is admitted by pcs_rows.OwnedV1.init;
            // the caller owns the exact source bundle used for each lane.
            if (head.control.len == 0 or tail.control.len == 0 or check.control.len == 0 or
                head.control[0].verifier_id != lane or tail.control[0].verifier_id != lane or
                check.control[0].verifier_id != lane)
                return error.DetachedBaseRowsLaneMismatch;
            inline for (.{ "control", "sponge", "binding", "state", "word" }, 0..) |field, row| {
                try appendConverted(value, row, @field(head, field));
                try appendConverted(value, row, @field(tail, field));
            }
            // The SD prefix has its own admitted input namespace. Its existing
            // owner supplies the mapper; do not send it through the V1 mapper.
            const head_payload = try reserveAppend(value, 5, head.payload.len);
            for (head_payload, 0..) |*destination, index| destination.* = prefix_owner.payloadLogical(index);
            try appendConverted(value, 5, tail.payload);
            try appendConverted(value, 6, tail.pow_check);
            try appendConverted(value, 7, tail.pow_frame);
            try appendConverted(value, 8, head.challenges);
            try appendConverted(value, 9, tail.randomness);
            // Catalog10 explicitly selects the existing field-statement AIR;
            // this is the same nonce logical row formerly installed at slot12.
            try appendLogical(value, 10, tail.nonce);
            try appendConverted(value, 0, check.control);
            inline for (.{ "query_bits", "query_mapping", "merkle_root", "trace_merkle", "pcs_deep", "fri_leaf", "fri_node", "fri_anchor", "fri_control", "fri_input" }, 20..) |field, row|
                try appendLogical(value, row, @field(check, field));
            try appendLogical(value, 33, check.merkle_path);
            try calls.appendSlice(owned, head.provider);
            try calls.appendSlice(owned, tail.provider);
            try calls.appendSlice(owned, check.provider);
        }
        value.calls = try calls.toOwnedSlice(owned);
        return @ptrCast(value);
    }

    pub fn logicalRows(self: *const OwnedV1) cohort.LogicalRowsV1 {
        return self.storage().rows;
    }
    pub fn providerCalls(self: *const OwnedV1) []const cohort.ProviderCall {
        return self.storage().calls;
    }
    pub fn deinit(self: *OwnedV1) void {
        const value: *Storage = @ptrCast(@alignCast(self));
        const allocator = value.allocator;
        value.arena.deinit();
        allocator.destroy(value);
    }
};

fn LogicalRow(comptime row: usize) type {
    return [cohort.LOGICAL_ROWS[cohort.logicalIndex(row)].Air.LOGICAL_INPUT_COUNT]M31;
}

fn reserveAppend(value: *OwnedV1.Storage, comptime row: usize, count: usize) ![]LogicalRow(row) {
    const index = cohort.logicalIndex(row);
    const previous = value.rows[index];
    const length = try std.math.add(usize, previous.len, count);
    const result = try value.arena.allocator().realloc(@constCast(previous), length);
    value.rows[index] = result;
    return result[previous.len..];
}

fn appendLogical(value: *OwnedV1.Storage, comptime row: usize, input: []const LogicalRow(row)) !void {
    const destination = try reserveAppend(value, row, input.len);
    @memcpy(destination, input);
}

fn appendConverted(value: *OwnedV1.Storage, comptime row: usize, input: anytype) !void {
    const destination = try reserveAppend(value, row, input.len);
    for (input, destination) |source, *target| target.* = try shared_rows.logicalRow(row, source);
}
