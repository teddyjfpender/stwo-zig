//! Constants and statement-independent checks of
//! `crates/stark_verifier/src/verify.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230).
//!
//! `verify()` itself (channel replay, query selection and sorting, Merkle,
//! OODS, `compute_fri_input`, FRI decommit) emits gates and lands with the
//! builder. This file holds what `check_relation_uses` decides without a
//! Context: the overflow sanity bound and the order of the relation keys.

const std = @import("std");
const core = @import("stwo_core");
const component_list = @import("../common/component_list.zig");

const P: u64 = core.fields.m31.Modulus;

/// Bits of a component log size in the packed claim; `2^LOG_SIZE_BITS`
/// exceeds every log trace size up to 30.
pub const LOG_SIZE_BITS: u32 = 5;

/// Shift applied to component row counts in `check_relation_uses`.
pub const RELATION_USES_NUM_ROWS_SHIFT: u5 = 16;

pub const RelationUsesError = error{
    /// `sum(uses_per_row * (floor(P / DIV) + 1))` can reach P for some
    /// relation; upstream asserts this cannot happen for a valid statement.
    RelationUsesMayOverflow,
    TooManyRelations,
};

/// Upper bound on distinct relation ids of one statement (the Cairo AIR has
/// fewer than 64).
pub const MAX_RELATIONS: usize = 128;

/// The relation ids of a statement's components in the order
/// `check_relation_uses` packs their shifted use counts: sorted by `String`
/// (byte-lexicographic) order, each id once. `components` is a slice of
/// per-component `relation_uses_per_row` slices, in statement order.
pub const RelationKeys = struct {
    ids: [MAX_RELATIONS][]const u8 = undefined,
    len: usize = 0,

    pub fn slice(self: *const RelationKeys) []const []const u8 {
        return self.ids[0..self.len];
    }

    /// Index of `id` in the sorted order.
    pub fn indexOf(self: *const RelationKeys, id: []const u8) ?usize {
        for (self.slice(), 0..) |key, index| {
            if (std.mem.eql(u8, key, id)) return index;
        }
        return null;
    }
};

/// The static half of `check_relation_uses`: rejects a statement whose
/// worst-case shifted use count can reach P, and returns its relation keys
/// in packing order.
pub fn relationKeys(components: []const []const component_list.RelationUse) RelationUsesError!RelationKeys {
    var keys: RelationKeys = .{};
    var bounds: [MAX_RELATIONS]u64 = .{0} ** MAX_RELATIONS;
    const per_use_bound: u64 = (P >> RELATION_USES_NUM_ROWS_SHIFT) + 1;
    for (components) |uses| {
        for (uses) |relation_use| {
            const index = keys.indexOf(relation_use.relation_id) orelse blk: {
                if (keys.len == MAX_RELATIONS) return error.TooManyRelations;
                keys.ids[keys.len] = relation_use.relation_id;
                keys.len += 1;
                break :blk keys.len - 1;
            };
            const term = std.math.mul(u64, relation_use.uses, per_use_bound) catch return error.RelationUsesMayOverflow;
            bounds[index] = std.math.add(u64, bounds[index], term) catch return error.RelationUsesMayOverflow;
        }
    }
    for (bounds[0..keys.len]) |bound| {
        if (bound >= P) return error.RelationUsesMayOverflow;
    }
    // `sorted_by_key` over unique `String` keys: byte order.
    std.sort.insertion([]const u8, keys.ids[0..keys.len], {}, lessBytes);
    return keys;
}

fn lessBytes(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

test "verify: circuit statement relation keys are in String order" {
    var uses: [component_list.N_COMPONENTS][]const component_list.RelationUse = undefined;
    for (component_list.component_facts.toArray(), &uses) |facts, *slot| slot.* = facts.relation_uses_per_row;
    const keys = try relationKeys(&uses);
    const expected = [_][]const u8{
        "Gate",
        "RangeCheck_16",
        "VerifyBitwiseXor_12",
        "VerifyBitwiseXor_4",
        "VerifyBitwiseXor_7",
        "VerifyBitwiseXor_8",
        "VerifyBitwiseXor_8_B",
        "VerifyBitwiseXor_9",
    };
    try std.testing.expectEqual(expected.len, keys.len);
    for (expected, keys.slice()) |want, got| try std.testing.expectEqualStrings(want, got);
}

test "verify: relation uses that can reach P are rejected" {
    // 65,536 uses per row times (floor(P / 2^16) + 1) = 2^31 > P.
    const heavy = [_]component_list.RelationUse{.{ .relation_id = "Gate", .uses = 1 << 16 }};
    try std.testing.expectError(error.RelationUsesMayOverflow, relationKeys(&.{&heavy}));
    const light = [_]component_list.RelationUse{.{ .relation_id = "Gate", .uses = (1 << 16) - 1 }};
    _ = try relationKeys(&.{&light});
}
