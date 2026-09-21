//! Multiplicity authority for the non-production throughput Keccak profile.
//!
//! The paired permutation witness is unchanged.  Only its lookup projection
//! differs: one chi request authenticates all five outputs and one xor5
//! request authenticates three parity positions.  This authority is kept
//! separate from the compact counters so neither profile can be relabelled as
//! the other by reusing a table-main commitment.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const infra = @import("../../infra_trace.zig");
const authority = @import("keccakf_authority.zig");
const tables = @import("keccakf_throughput_tables_v1.zig");
const witness = @import("keccakf_witness.zig");

pub const production_active = false;

pub const Error = witness.Error || error{
    EmptySlot,
    MultiplicityOverflow,
    OutOfMemory,
    SlotLimitExceeded,
};

pub const Counters = struct {
    allocator: std.mem.Allocator,
    chi: []M31,
    xor5: []M31,
    slots: usize = 0,

    pub fn init(allocator: std.mem.Allocator) Error!Counters {
        const chi = try allocator.alloc(M31, tables.domainSize(.chi));
        errdefer allocator.free(chi);
        const xor5 = try allocator.alloc(M31, tables.domainSize(.xor5));
        @memset(chi, M31.zero());
        @memset(xor5, M31.zero());
        return .{ .allocator = allocator, .chi = chi, .xor5 = xor5 };
    }

    pub fn deinit(self: *Counters) void {
        self.allocator.free(self.xor5);
        self.allocator.free(self.chi);
        self.* = undefined;
    }

    pub fn values(self: *const Counters, kind: tables.Kind) []const M31 {
        return switch (kind) {
            .chi => self.chi,
            .xor5 => self.xor5,
        };
    }

    pub fn recordSlot(self: *Counters, slot: *const witness.Slot) Error!void {
        try witness.validateSlot(slot);
        if (slot.rows[0].in_use_a == 0) return error.EmptySlot;
        if (self.slots >= authority.geometry.maximum_slots)
            return error.SlotLimitExceeded;

        for (0..authority.round_count) |round| {
            var first_position: usize = 0;
            while (first_position < witness.parity_cell_count) : (first_position += authority.geometry.xor5_batch) {
                try increment(
                    self.xor5,
                    try witness.xor5LookupRow(slot, round, first_position),
                );
            }
            for (0..5) |y| for (0..authority.lane_bits) |z| {
                try increment(
                    self.chi,
                    try witness.chiLookupRow(slot, round, y, z),
                );
            };
        }
        self.slots += 1;
    }

    pub fn validateTotals(self: *const Counters) Error!void {
        const expected_chi = std.math.mul(
            usize,
            self.slots,
            authority.geometry.chi_lookups_per_slot,
        ) catch return error.MultiplicityOverflow;
        const expected_xor5 = std.math.mul(
            usize,
            self.slots,
            authority.geometry.xor5_lookups_per_slot,
        ) catch return error.MultiplicityOverflow;
        if (sum(self.chi) != expected_chi or sum(self.xor5) != expected_xor5)
            return error.MultiplicityOverflow;
    }

    /// Returns the exact PCS committed order while retaining canonical
    /// counters for independent replay and table-interaction generation.
    pub fn committedColumn(
        self: *const Counters,
        allocator: std.mem.Allocator,
        kind: tables.Kind,
    ) Error![]M31 {
        const source = self.values(kind);
        const result = try allocator.alloc(M31, source.len);
        errdefer allocator.free(result);
        const reversal = try infra.BitReversalTable.init(
            allocator,
            tables.logSize(kind),
        );
        defer reversal.deinit(allocator);
        for (source, 0..) |value, row| result[reversal.map(row)] = value;
        return result;
    }
};

fn increment(values: []M31, row: u32) Error!void {
    if (row >= values.len) return error.MultiplicityOverflow;
    const current = values[row].toU32();
    if (current == m31.Modulus - 1) return error.MultiplicityOverflow;
    values[row] = M31.fromCanonical(current + 1);
}

fn sum(values: []const M31) usize {
    var result: usize = 0;
    for (values) |value| result += value.toU32();
    return result;
}

comptime {
    if (authority.geometry.maximum_slots *
        authority.geometry.chi_lookups_per_slot >= m31.Modulus or
        authority.geometry.maximum_slots *
            authority.geometry.xor5_lookups_per_slot >= m31.Modulus or
        production_active)
    {
        @compileError("Keccak throughput multiplicity bounds drifted");
    }
}
