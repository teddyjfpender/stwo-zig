//! Process-local query normalization for lifted Merkle verification.
//!
//! The proof keeps queried values in its original position order while a
//! Merkle multiproof authenticates a sorted, deduplicated position set.  A
//! fixed-recursion capture additionally needs paths in raw transcript order.
//! This plan computes those mappings once per tree so every queried column
//! does not repeat the same binary searches and temporary value copies.

const std = @import("std");

pub const QueryPlanError = error{InvalidQueryShape};

/// Exact construction work. This is process-local performance evidence and
/// never enters a proof, transcript, or durable artifact.
pub const Receipt = struct {
    input_position_count: usize,
    unique_position_count: usize,
    raw_position_count: usize,
    position_sort_count: usize,
    raw_lookup_count: usize,
    raw_lookup_comparison_count: usize,

    pub fn validate(self: Receipt) QueryPlanError!void {
        if (self.unique_position_count > self.input_position_count or
            self.position_sort_count != 1 or
            self.raw_lookup_count != self.raw_position_count or
            (self.input_position_count == 0 and
                (self.unique_position_count != 0 or
                    self.raw_position_count != 0 or
                    self.raw_lookup_comparison_count != 0)))
        {
            return error.InvalidQueryShape;
        }
    }
};

pub const PreparedQueryPlan = struct {
    input_positions: []usize,
    query_order: []usize,
    unique_positions: []usize,
    unique_source_indices: []usize,
    duplicate_source_indices: []usize,
    duplicate_canonical_source_indices: []usize,
    raw_positions: []usize,
    raw_to_unique: []usize,
    receipt: Receipt,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        input_positions: []const usize,
        raw_positions: []const usize,
    ) (std.mem.Allocator.Error || QueryPlanError)!Self {
        const owned_input = try allocator.dupe(usize, input_positions);
        errdefer allocator.free(owned_input);
        const query_order = try allocator.alloc(usize, input_positions.len);
        errdefer allocator.free(query_order);
        for (query_order, 0..) |*index, position_index| index.* = position_index;
        std.sort.heap(
            usize,
            query_order,
            QueryOrder{ .positions = owned_input },
            QueryOrder.lessThan,
        );

        var unique_positions = try allocator.alloc(usize, input_positions.len);
        errdefer allocator.free(unique_positions);
        var unique_source_indices = try allocator.alloc(
            usize,
            input_positions.len,
        );
        errdefer allocator.free(unique_source_indices);
        var duplicate_source_indices = try allocator.alloc(
            usize,
            input_positions.len,
        );
        errdefer allocator.free(duplicate_source_indices);
        var duplicate_canonical_source_indices = try allocator.alloc(
            usize,
            input_positions.len,
        );
        errdefer allocator.free(duplicate_canonical_source_indices);
        var unique_count: usize = 0;
        var duplicate_count: usize = 0;
        for (query_order) |source_index| {
            const position = owned_input[source_index];
            if (unique_count == 0 or
                unique_positions[unique_count - 1] != position)
            {
                unique_positions[unique_count] = position;
                unique_source_indices[unique_count] = source_index;
                unique_count += 1;
            } else {
                duplicate_source_indices[duplicate_count] = source_index;
                duplicate_canonical_source_indices[duplicate_count] =
                    unique_source_indices[unique_count - 1];
                duplicate_count += 1;
            }
        }
        if (unique_count != unique_positions.len) {
            unique_positions = try allocator.realloc(
                unique_positions,
                unique_count,
            );
            unique_source_indices = try allocator.realloc(
                unique_source_indices,
                unique_count,
            );
        }
        if (duplicate_count != duplicate_source_indices.len) {
            duplicate_source_indices = try allocator.realloc(
                duplicate_source_indices,
                duplicate_count,
            );
            duplicate_canonical_source_indices = try allocator.realloc(
                duplicate_canonical_source_indices,
                duplicate_count,
            );
        }

        const owned_raw = try allocator.dupe(usize, raw_positions);
        errdefer allocator.free(owned_raw);
        const raw_to_unique = try allocator.alloc(usize, raw_positions.len);
        errdefer allocator.free(raw_to_unique);
        var lookup_comparisons: usize = 0;
        for (owned_raw, raw_to_unique) |position, *unique_index| {
            unique_index.* = findPositionCounting(
                unique_positions,
                position,
                &lookup_comparisons,
            ) orelse return error.InvalidQueryShape;
        }

        const result = Self{
            .input_positions = owned_input,
            .query_order = query_order,
            .unique_positions = unique_positions,
            .unique_source_indices = unique_source_indices,
            .duplicate_source_indices = duplicate_source_indices,
            .duplicate_canonical_source_indices = duplicate_canonical_source_indices,
            .raw_positions = owned_raw,
            .raw_to_unique = raw_to_unique,
            .receipt = .{
                .input_position_count = input_positions.len,
                .unique_position_count = unique_count,
                .raw_position_count = raw_positions.len,
                .position_sort_count = 1,
                .raw_lookup_count = raw_positions.len,
                .raw_lookup_comparison_count = lookup_comparisons,
            },
        };
        try result.validate();
        return result;
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.input_positions);
        allocator.free(self.query_order);
        allocator.free(self.unique_positions);
        allocator.free(self.unique_source_indices);
        allocator.free(self.duplicate_source_indices);
        allocator.free(self.duplicate_canonical_source_indices);
        allocator.free(self.raw_positions);
        allocator.free(self.raw_to_unique);
        self.* = undefined;
    }

    pub fn validate(self: *const Self) QueryPlanError!void {
        try self.receipt.validate();
        if (self.query_order.len != self.input_positions.len or
            self.unique_positions.len != self.unique_source_indices.len or
            self.duplicate_source_indices.len !=
                self.duplicate_canonical_source_indices.len or
            self.duplicate_source_indices.len !=
                self.input_positions.len - self.unique_positions.len or
            self.raw_positions.len != self.raw_to_unique.len or
            self.receipt.input_position_count != self.input_positions.len or
            self.receipt.unique_position_count != self.unique_positions.len or
            self.receipt.raw_position_count != self.raw_positions.len)
        {
            return error.InvalidQueryShape;
        }

        // Validate that query_order is a permutation in canonical
        // position/index order. This is a static/process-local integrity check;
        // the Merkle root remains the cryptographic admission authority.
        for (0..self.input_positions.len) |expected_index| {
            var occurrences: usize = 0;
            for (self.query_order) |actual_index| {
                if (actual_index >= self.input_positions.len)
                    return error.InvalidQueryShape;
                if (actual_index == expected_index) occurrences += 1;
            }
            if (occurrences != 1) return error.InvalidQueryShape;
        }
        for (self.query_order, 0..) |source_index, sorted_index| {
            if (sorted_index != 0) {
                const previous = self.query_order[sorted_index - 1];
                const previous_position = self.input_positions[previous];
                const position = self.input_positions[source_index];
                if (previous_position > position or
                    (previous_position == position and previous > source_index))
                {
                    return error.InvalidQueryShape;
                }
            }
        }

        var unique_index: usize = 0;
        var duplicate_index: usize = 0;
        for (self.query_order, 0..) |source_index, sorted_index| {
            const position = self.input_positions[source_index];
            if (sorted_index == 0 or
                position != self.input_positions[self.query_order[sorted_index - 1]])
            {
                if (unique_index >= self.unique_positions.len or
                    self.unique_positions[unique_index] != position or
                    self.unique_source_indices[unique_index] != source_index)
                {
                    return error.InvalidQueryShape;
                }
                unique_index += 1;
            } else {
                if (duplicate_index >= self.duplicate_source_indices.len or
                    self.duplicate_source_indices[duplicate_index] !=
                        source_index or
                    self.duplicate_canonical_source_indices[duplicate_index] !=
                        self.unique_source_indices[unique_index - 1])
                {
                    return error.InvalidQueryShape;
                }
                duplicate_index += 1;
            }
        }
        if (unique_index != self.unique_positions.len or
            duplicate_index != self.duplicate_source_indices.len)
            return error.InvalidQueryShape;

        var comparison_count: usize = 0;
        for (self.raw_positions, self.raw_to_unique) |position, mapped_index| {
            const expected = findPositionCounting(
                self.unique_positions,
                position,
                &comparison_count,
            ) orelse return error.InvalidQueryShape;
            if (mapped_index != expected) return error.InvalidQueryShape;
        }
        if (comparison_count != self.receipt.raw_lookup_comparison_count)
            return error.InvalidQueryShape;
    }

    pub inline fn sourceIndexForUnique(
        self: *const Self,
        unique_index: usize,
    ) usize {
        std.debug.assert(unique_index < self.unique_source_indices.len);
        return self.unique_source_indices[unique_index];
    }

    pub inline fn sourceIndexForRaw(
        self: *const Self,
        raw_index: usize,
    ) usize {
        std.debug.assert(raw_index < self.raw_to_unique.len);
        return self.sourceIndexForUnique(self.raw_to_unique[raw_index]);
    }

    /// Exact number of lookup invocations performed by the former
    /// per-column raw expansion for this plan. Null indicates usize overflow.
    pub fn legacyRawExpansionLookupCount(
        self: *const Self,
        column_count: usize,
    ) ?usize {
        return std.math.mul(usize, self.raw_positions.len, column_count) catch
            null;
    }
};

const QueryOrder = struct {
    positions: []const usize,

    fn lessThan(context: QueryOrder, lhs: usize, rhs: usize) bool {
        const lhs_position = context.positions[lhs];
        const rhs_position = context.positions[rhs];
        return lhs_position < rhs_position or
            (lhs_position == rhs_position and lhs < rhs);
    }
};

fn findPositionCounting(
    positions: []const usize,
    target: usize,
    comparison_count: *usize,
) ?usize {
    var left: usize = 0;
    var right: usize = positions.len;
    while (left < right) {
        comparison_count.* += 1;
        const middle = left + (right - left) / 2;
        if (positions[middle] < target) {
            left = middle + 1;
        } else {
            right = middle;
        }
    }
    if (left >= positions.len or positions[left] != target) return null;
    return left;
}
