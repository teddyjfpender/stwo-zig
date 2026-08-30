//! Single-owner multiplicity authority for Keccak-f lookup tables.
//!
//! Counters are global to one proof, not one component shard or worker.  This
//! is important for both soundness and latency: the compact 2^13 chi vector is
//! allocated once and every paired slot contributes directly to it.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const infra = @import("../../infra_trace.zig");
const authority = @import("keccakf_authority.zig");
const tables = @import("keccakf_tables.zig");
const witness = @import("keccakf_witness.zig");

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
        const chi = try allocator.alloc(M31, tables.size(.chi));
        errdefer allocator.free(chi);
        const xor5 = try allocator.alloc(M31, tables.size(.xor5));
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
        if (self.slots >= authority.candidate.maximum_slots)
            return error.SlotLimitExceeded;

        for (0..authority.round_count) |round| {
            for (0..witness.parity_cell_count) |position| {
                const row = try witness.compactXor5LookupRow(slot, round, position);
                try increment(self.xor5, row);
            }
            for (0..5) |y| for (0..authority.lane_bits) |z| for (0..5) |x| {
                const row = try witness.compactChiLookupRow(slot, round, x, y, z);
                try increment(self.chi, row);
            };
        }
        self.slots += 1;
    }

    pub fn validateTotals(self: *const Counters) Error!void {
        const expected_chi = std.math.mul(
            usize,
            self.slots,
            authority.candidate.compact.chi_lookups_per_slot,
        ) catch return error.MultiplicityOverflow;
        const expected_xor5 = std.math.mul(
            usize,
            self.slots,
            authority.candidate.compact.xor5_lookups_per_slot,
        ) catch return error.MultiplicityOverflow;
        if (sum(self.chi) != expected_chi or sum(self.xor5) != expected_xor5)
            return error.MultiplicityOverflow;
    }

    /// Produce one table-main column in the exact circle bit-reversed order
    /// consumed by the PCS.  The canonical counters remain available for
    /// interaction generation and independent replay.
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
    if (authority.candidate.maximum_slots *
        authority.candidate.compact.chi_lookups_per_slot >= m31.Modulus)
    {
        @compileError("Keccak chi multiplicities exceed the M31 source bound");
    }
}
