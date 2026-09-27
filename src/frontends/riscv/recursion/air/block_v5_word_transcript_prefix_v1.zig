//! One original RAM/range transcript framing body for live and fixed emitters.
//! The live provider supplies values; the fixed provider records routing only.
const std = @import("std");
const Word = @import("../../prover/block_v5_word_memory_protocol_v1.zig");
const U = @import("universal_challenges.zig");
const T = @import("blake3_transcript_witness.zig");
const Ram = @import("../../prover/block_v5_ram_lanes_protocol_v1.zig");
const Range = @import("../../prover/block_v5_range16_v1.zig");
pub const Family = @import("block_v5_word_recursive_shape_composition_v1.zig").Family;
pub const Root = enum { sealed, policy };
pub const Integer = enum { events, endpoints, ranges, requests, claim_count };
pub const LiveDraw = struct {
    pub const Output = Word.Challenges;
    pub fn run(a: std.mem.Allocator, r: anytype) !Output {
        return Word.Challenges.drawFromChannel(a, r);
    }
};
pub const FixedDraw = struct {
    pub const Output = void;
    pub fn run(a: std.mem.Allocator, r: anytype) !void {
        try Word.Challenges.drawWith(a, r, @This());
    }
    pub fn universal(_: std.mem.Allocator, r: anytype) !void {
        try U.requireDrawSchema();
        try r.universalPairs(0, U.RELATION_COUNT);
    }
    pub fn extra(_: std.mem.Allocator, r: anytype, _: void) !void {
        try r.universalPairs(U.RELATION_COUNT, 5);
    }
};

/// Values and success receipts are absent from this emission. Caller policy is
/// still independently validated by the native fixed owner before entry.
pub const FixedValues = struct {
    pub fn root(_: @This(), r: anytype, source: T.Caller, _: Root) !void {
        r.mixPublicRoot(source, @splat(0));
        try r.check();
    }
    pub fn integer(_: @This(), r: anytype, source: T.Caller, _: Integer) !void {
        r.mixPublicInteger(source, 0);
        try r.check();
    }
    pub fn limb(_: @This(), r: anytype, source: T.Caller, _: usize, _: usize) !void {
        try r.routedWords(source, 1);
    }
    pub fn shard(_: @This(), r: anytype, source: T.Caller) !void {
        try r.routedWords(source, 6);
    }
};

pub fn emit(comptime family: Family, a: std.mem.Allocator, r: anytype, values: anytype, comptime Draw: type) !Draw.Output {
    const circuit = if (family == .ram_lanes) @import("../block_v5_ram_lanes_recursive_public_bus_v1.zig").PUBLIC_CIRCUIT else @import("../block_v5_range16_recursive_public_bus_v1.zig").PUBLIC_CIRCUIT;
    const Universal = @import("../../prover/block_v5_universal_channel_v1.zig");
    r.mixU32s(&.{ Universal.TAG, Universal.VERSION });
    try values.root(r, .{ .circuit = circuit, .first_wire = 0 }, .sealed);
    const challenges = try Draw.run(a, r);
    if (family == .ram_lanes) {
        r.mixU32s(&.{ Ram.TAG, Ram.VERSION, 0x50524f46 });
        r.mixStaticRoot(Ram.abiId());
        try values.root(r, .{ .circuit = circuit, .first_wire = 8 }, .policy);
        try values.integer(r, .{ .circuit = circuit, .first_wire = 16 }, .events);
        const fields = 4 + @import("../../prover/block_v5_ram_lanes_interaction_v1.zig").RANGE_PLANES;
        for (0..fields) |field| for (0..4) |limb|
            try values.limb(r, .{ .circuit = circuit, .first_wire = @intCast(18 + 4 * field + limb) }, field, limb);
        try values.integer(r, .{ .circuit = circuit, .first_wire = 102 }, .endpoints);
        try values.integer(r, .{ .circuit = circuit, .first_wire = 104 }, .ranges);
    } else {
        try values.shard(r, .{ .circuit = circuit, .first_wire = 16 });
        try values.integer(r, .{ .circuit = circuit, .first_wire = 22 }, .requests);
        try values.root(r, .{ .circuit = circuit, .first_wire = 8 }, .policy);
        try values.integer(r, .{ .circuit = circuit, .first_wire = 24 }, .claim_count);
        for (0..4) |limb| try values.limb(r, .{ .circuit = circuit, .first_wire = @intCast(26 + limb) }, 0, limb);
    }
    try r.skipCommittedRoots(2);
    try r.check();
    return challenges;
}

pub fn LiveValues(comptime family: Family) type {
    const Admission = if (family == .ram_lanes) @import("../../prover/block_v5_ram_lanes_recursive_admission_v1.zig") else @import("../../prover/block_v5_range16_recursive_admission_v1.zig");
    return LiveValuesFor(family, *const Admission.Prepared);
}
/// Static independently admitted policy selection; exact original transcript
/// emission is shared, never selected by received proof bytes.
pub fn LiveValuesFor(comptime family: Family, comptime AdmittedPointer: type) type {
    const Claim = if (family == .ram_lanes) @import("../../prover/block_v5_ram_lanes_interaction_v1.zig").Claim else @import("../../prover/block_v5_range16_component_v1.zig").Claim;
    return struct {
        admitted: AdmittedPointer,
        sums: Claim,
        pub fn root(self: @This(), r: anytype, source: T.Caller, role: Root) !void {
            const value = switch (role) {
                .sealed => self.admitted.sealed.digest,
                .policy => if (family == .ram_lanes) try self.admitted.pin.identity() else self.admitted.plan_digest,
            };
            r.mixPublicRoot(source, value);
            try r.check();
        }
        pub fn integer(self: @This(), r: anytype, source: T.Caller, role: Integer) !void {
            const value: u64 = if (family == .ram_lanes) switch (role) {
                .events => self.sums.event_count,
                .endpoints => self.sums.endpoint_count,
                .ranges => self.sums.range_count,
                else => return error.InvalidWordPrefixIntegerRole,
            } else switch (role) {
                .requests => self.admitted.shard.request_count,
                .claim_count => self.sums.count,
                else => return error.InvalidWordPrefixIntegerRole,
            };
            r.mixPublicInteger(source, value);
            try r.check();
        }
        pub fn limb(self: @This(), r: anytype, source: T.Caller, field: usize, index: usize) !void {
            const value = if (family == .ram_lanes) value: {
                const Q = @import("stwo_core").fields.qm31.QM31;
                const fields = [_]Q{ self.sums.transition_sum, self.sums.link_sum, self.sums.initial_sum, self.sums.endpoint_sum } ++ self.sums.range_sums;
                if (field >= fields.len or index >= 4) return error.InvalidWordPrefixFieldRole;
                break :value fields[field].toM31Array()[index];
            } else value: {
                if (field != 0 or index >= 4) return error.InvalidWordPrefixFieldRole;
                break :value self.sums.sum.toM31Array()[index];
            };
            r.mixPublicWords(source, &.{value.toU32()});
            try r.check();
        }
        pub fn shard(self: @This(), r: anytype, source: T.Caller) !void {
            comptime if (family != .range16) @compileError("shard framing is range16-only");
            const shard_ = self.admitted.shard;
            r.mixPublicWords(source, &.{ Word.TAG, Word.VERSION, Range.TABLE_LOG, shard_.index, shard_.first_instance, shard_.instance_count });
            try r.check();
        }
    };
}
