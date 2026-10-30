//! Independently compiled provider singleton adapters for the direct mixed root.
const std = @import("std");
const Bus = @import("block_v6_provider_batch_public_v1.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
pub fn ForFamily(comptime selected: Bus.Family) type {
    const word = selected == .range16 or selected == .ram_lanes;
    const Factory = if (word)
        @import("block_v5_word_recursive_fixed_roster_v1.zig").ForFamily(if (selected == .range16) .range16 else .ram_lanes)
    else
        @import("block_v6_provider_fixed_roster_v1.zig").ForFamily(if (selected == .program_table) .program_table else .native_lookup);
    const Policy = struct {
        pub const family_tag = selected;
        pub const family = family_tag;
        pub const Original = Factory.Owned;
        pub const Admitted = Bus.Definition(family_tag).Prepared;
        pub const Claims = void;
        pub const Limits = if (word) @import("block_v5_word_recursive_fixed_roster_v1.zig").Limits else @import("block_v6_provider_fixed_roster_v1.zig").Limits;
        pub fn deriveOriginal(a: std.mem.Allocator, admitted: *const Admitted, expected: [32]u8, _: void, capacity: u32, profile: Base.Profile, limits: Limits) !Original {
            try admitted.validate(expected);
            return if (word) Original.derive(a, admitted, expected, capacity, profile, limits) else Original.derive(a, admitted, capacity, profile, limits);
        }
        pub fn index(admitted: *const Admitted) u32 {
            return Bus.Definition(family_tag).index(admitted);
        }
    };
    return @import("block_v6_provider_fixed_singleton_v1.zig").ForPolicy(Policy);
}
pub const CallerArithmetic = blk: {
    const Policy = struct {
        pub const family = @import("block_v6_auxiliary_direct_public_v1.zig").Family.caller_arithmetic;
        pub const Original = @import("block_v6_provider_fixed_roster_v1.zig").ForFamily(.caller_arithmetic).Owned;
        pub const Admitted = @import("../prover/block_v5_caller_arithmetic_recursive_admission_v1.zig").Prepared;
        pub const Claims = void;
        pub const Limits = @import("block_v6_provider_fixed_roster_v1.zig").Limits;
        pub fn deriveOriginal(a: std.mem.Allocator, admitted: *const Admitted, expected: [32]u8, _: void, capacity: u32, profile: Base.Profile, limits: Limits) !Original {
            try admitted.validate(expected);
            return Original.derive(a, admitted, capacity, profile, limits);
        }
        pub fn index(admitted: *const Admitted) u32 {
            return admitted.binding.execution_index;
        }
    };
    break :blk @import("block_v6_auxiliary_fixed_singleton_v1.zig").ForPolicy(Policy);
};
test "provider and caller arithmetic independent singleton codegen" {
    inline for (comptime std.meta.tags(Bus.Family)) |family| {
        std.mem.doNotOptimizeAway(&ForFamily(family).Owned.derive);
        std.mem.doNotOptimizeAway(&ForFamily(family).Owned.validateLive);
    }
    std.mem.doNotOptimizeAway(&CallerArithmetic.Owned.derive);
    std.mem.doNotOptimizeAway(&CallerArithmetic.Owned.validateLive);
}
