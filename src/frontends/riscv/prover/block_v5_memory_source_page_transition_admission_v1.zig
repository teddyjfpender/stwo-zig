//! Shared metadata/identity guards. None of these functions verify a proof or
//! admit a proposed source receipt as authority; callers freshly verify first.
const std = @import("std");
const Memory = @import("block_v5_word_memory_join_impl_v1.zig").ForStack(@import("block_v5_native_receiver_stack_v1.zig").ForCapacity(true));
const External = @import("block_execution_external_trace_v2.zig");
const Lanes = @import("block_v5_ram_lanes_receiver_v1.zig");
const Page = @import("block_v5_memory_source_page_join_owner_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
pub fn requirePublicInput(expected_len: u64, expected_sha256: [32]u8, input: []const u8) !void {
    if (input.len != expected_len or !std.meta.eql(@import("block_v5_initial_sources_v1.zig").sha256(input), expected_sha256)) return error.UntrustedV5PublicInput;
}
pub fn eventCensus(pins: Memory.Pins, mode: u32) !u64 {
    var total: u64 = 0;
    for (pins.ordinary_events) |count| total = try std.math.add(u64, total, count);
    for (pins.extensions) |extension| total = try std.math.add(u64, total, try External.expectedEventCountForMode(extension.public.statement, mode));
    return total;
}
pub fn sameMemory(expected: Lanes.Pins, actual: Lanes.Pins) !void {
    if (!std.meta.eql(expected.seal, actual.seal) or !std.meta.eql(expected.expected_seal_digest, actual.expected_seal_digest) or
        !std.meta.eql(expected.source, actual.source) or !std.meta.eql(expected.limits, actual.limits) or expected.expected_total_events != actual.expected_total_events or
        expected.first_round.len != actual.first_round.len or expected.pins.len != actual.pins.len or expected.range_roots.len != actual.range_roots.len)
        return error.UntrustedSourcePageTransitionMemory;
    for (expected.first_round, actual.first_round) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedSourcePageTransitionMemory;
    for (expected.pins, actual.pins) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedSourcePageTransitionMemory;
    for (expected.range_roots, actual.range_roots) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedSourcePageTransitionMemory;
}
pub fn requireSource(fresh: Page.Open, pins: Lanes.Pins, sealed: Seal.Sealed) !void {
    if (fresh.events != pins.expected_total_events or fresh.memory_instances != pins.pins.len or fresh.range_shards != pins.range_roots.len or
        fresh.first_touches != pins.source.initial.first_touches.records or fresh.endpoints != pins.source.endpoints.records or
        !std.meta.eql(fresh.base_seal, sealed.digest) or !std.meta.eql(fresh.memory_plan, pins.seal.memory_plan_digest) or
        !std.meta.eql(fresh.initial_root, pins.source.initial.initial_rw_root) or !std.meta.eql(fresh.final_root, pins.source.expected_final_rw_root))
        return error.UntrustedSourcePageTransitionSource;
}
