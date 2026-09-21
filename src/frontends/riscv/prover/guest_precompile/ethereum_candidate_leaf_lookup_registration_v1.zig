//! Fixed-table registration for the combined candidate leaf.
//!
//! Candidate caller/word AIRs issue range-table requests that must be added to
//! the same base multiplicity columns before Tree 1. This adapter replays the
//! already cold-validatable tapes transactionally: a malformed request changes
//! no counter. It does not register memory/program/state tuples, which close
//! through ordinary base components rather than fixed tables.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;

const table_counter = @import("../../air/lookups/tables/counter.zig");
const table_schema = @import("../../air/lookups/tables/schema.zig");
const bulk_caller = @import("../../air/guest_precompile/bulk_memcpy_caller_candidate_v1.zig");
const bulk_words = @import("../../air/guest_precompile/bulk_memcpy_word_candidate_v1.zig");
const swap_caller = @import("../../air/guest_precompile/stack_swap_caller_candidate_v1.zig");
const swap_words = @import("../../air/guest_precompile/stack_swap_word_candidate_v1.zig");
const bulk_tape = @import("../../runner/guest_precompile/bulk_memcpy_session_tape_v1.zig");
const swap_tape = @import("../../runner/guest_precompile/stack_swap_session_tape_v1.zig");
const external_tree = @import("external_profile_tree.zig");
const profile_mod = @import("ethereum_candidate_leaf_profile_v1.zig");

pub const production_active = false;

pub const Context = struct {
    profile: *const profile_mod.Profile,
    bulk_memcpy: *const bulk_tape.Frozen,
    stack_swap: *const swap_tape.Frozen,

    pub fn validate(self: *const Context) !void {
        try self.profile.authority.validate();
        try self.bulk_memcpy.validate();
        try self.stack_swap.validate();
        if (!std.meta.eql(
            self.stack_swap.authority,
            self.profile.authority.stack_swap.stack_swap,
        ) or self.bulk_memcpy.records().len !=
            @as(usize, self.profile.bulk_memcpy_call_count) or
            self.bulk_memcpy.wordRows().len !=
                @as(usize, self.profile.bulk_memcpy_word_row_count) or
            self.stack_swap.records().len !=
                @as(usize, self.profile.stack_swap_call_count) or
            self.stack_swap.wordRows().len !=
                @as(usize, self.profile.stack_swap_call_count) * swap_words.lane_count)
        {
            return error.EthereumCandidateLeafLookupCustodyMismatch;
        }
    }

    pub fn registration(self: *const Context) external_tree.LookupRegistration {
        return .{ .context = self, .register_fn = erased };
    }

    pub fn register(self: *const Context, counters: *table_counter.Set) !void {
        try self.validate();
        try validateCounterSet(counters);
        try visit(false, self, null);
        visit(true, self, counters) catch unreachable;
    }

    pub fn erased(
        context: *const anyopaque,
        counters: *table_counter.Set,
    ) anyerror!void {
        const self: *const Context = @ptrCast(@alignCast(context));
        try self.register(counters);
    }
};

fn visit(
    comptime apply: bool,
    context: *const Context,
    counters: ?*table_counter.Set,
) !void {
    for (context.bulk_memcpy.records()) |record| {
        const row = try bulk_caller.materialize(record.caller);
        const events = try row.relationEvents();
        for (events.registers) |chain|
            try range20(apply, chain.gap, counters);
        for (events.range_pairs) |pair|
            try rangePair(apply, pair.left, pair.right, counters);
    }
    for (context.bulk_memcpy.wordRows()) |row| {
        for (try row.memoryEvents()) |event| switch (event) {
            .range_gap => |gap| try range20(apply, gap, counters),
            else => {},
        };
    }
    for (context.stack_swap.records()) |record| {
        const row = try swap_caller.materialize(record.caller);
        const events = try row.relationEvents(
            context.profile.authority.stack_swap.stack_swap,
        );
        for (events.registers) |chain|
            try range20(apply, chain.gap, counters);
        for (events.range_pairs) |pair|
            try rangePair(apply, pair.left, pair.right, counters);
    }
    for (context.stack_swap.wordRows()) |row| {
        for (try row.memoryEvents()) |event| switch (event) {
            .range_gap => |gap| try range20(apply, gap, counters),
            else => {},
        };
    }
}

fn range20(
    comptime apply: bool,
    value: u32,
    counters: ?*table_counter.Set,
) !void {
    try request(
        apply,
        .range_check_20,
        &.{M31.fromCanonical(value)},
        counters,
    );
}

fn rangePair(
    comptime apply: bool,
    left: u8,
    right: u8,
    counters: ?*table_counter.Set,
) !void {
    try request(
        apply,
        .range_check_8_8,
        &.{ M31.fromCanonical(left), M31.fromCanonical(right) },
        counters,
    );
}

fn request(
    comptime apply: bool,
    kind: table_schema.Kind,
    tuple: []const M31,
    counters: ?*table_counter.Set,
) !void {
    const index = if (comptime apply)
        table_schema.indexBase(kind, tuple) catch unreachable
    else
        try table_schema.indexBase(kind, tuple);
    if (comptime apply) {
        const value = &counters.?.get(kind).values[index];
        value.* = value.sub(M31.one());
    }
}

fn validateCounterSet(counters: *const table_counter.Set) !void {
    for (&counters.counters, 0..) |*counter, index| {
        const kind: table_schema.Kind = @enumFromInt(index);
        if (counter.kind != kind or counter.values.len != table_schema.size(kind))
            return error.InvalidCounterSet;
    }
}

comptime {
    if (production_active or profile_mod.production_active or
        bulk_caller.production_active or bulk_words.production_active or
        swap_caller.production_active or swap_words.production_active)
    {
        @compileError("candidate leaf lookup registration became active");
    }
}
