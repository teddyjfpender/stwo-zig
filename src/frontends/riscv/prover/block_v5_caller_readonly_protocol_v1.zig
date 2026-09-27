//! Versioned caller classification fusion. Original ALL-RW obligations remain.
const std = @import("std");
const core = @import("stwo_core");
const Plan = @import("block_v5_readonly_input_plan_v1.zig");
const Selection = @import("block_v5_readonly_input_selection_v1.zig");
const Original = @import("block_v5_readonly_input_protocol_v1.zig");
const Q = core.fields.qm31.QM31;
pub const TAG: u32 = 0x42354943; // B5IC
pub const VERSION: u32 = 1;
pub const METADATA_COLUMNS: usize = 71;
pub const INTERACTION_COLUMNS: usize = 16;
pub const EQUATIONS: usize = 149;
pub const Claim = struct { mutable_sum: Q, classification_sum: Q, read_sum: Q, readonly_count: u64 };
pub const Limits = struct {
    max_slots: usize = 256,
    max_events: u64 = 16_777_216,
    max_intervals: usize = 2_000_001,
    max_metadata_bytes: usize = 512 * 1024 * 1024,
    max_counter_bytes: usize = 64 * 1024 * 1024,
};
pub const Authority = struct {
    selection: Selection.Pins,
    plan: Plan.Pins,
    input: []const u8,
    limits: Limits = .{},
    pub fn admit(self: Authority, a: std.mem.Allocator) !Plan.Owned {
        const max_intervals = try std.math.add(usize, try std.math.mul(usize, self.selection.addresses.len, 2), 1);
        if (max_intervals > self.limits.max_intervals or self.selection.addresses.len > self.selection.limits.max_words) return error.CallerReadonlyResourceLimit;
        var selection = try Selection.admit(a, self.selection, self.input);
        defer selection.deinit();
        try selection.authority.requireSource(self.plan.source);
        var plan = try Plan.admit(a, self.plan, self.input);
        errdefer plan.deinit();
        if (!std.meta.eql(selection.limits, self.plan.limits) or !std.mem.eql(u32, selection.addresses, self.plan.addresses) or selection.intervals.len != plan.intervals.len or
            plan.intervals.len > self.limits.max_intervals) return error.UntrustedCallerReadonlySelection;
        for (selection.intervals, plan.intervals) |early, late| if (!std.meta.eql(early, late)) return error.UntrustedCallerReadonlySelection;
        return plan;
    }
};
pub const Challenges = Original.Challenges;
pub fn abiId() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-v5/caller-readonly-fusion/v1\x00");
    hash.update(&@import("block_v5_word_memory_protocol_v1.zig").abiId());
    hash.update("fixed/main/authentic-access+71membership/interaction;source-address-clock-values-reused;LE16;aligned-u32;u64clock;allRWuniversal+14byte-retained;metadata71;alignment6;interaction16;equations149;degree3;sha-fixed/keccak-signer-enabler-linear;+27-keccak;public-interval-and-input-providers\x00");
    return hash.finalResult();
}
pub fn checkProviders(plan: Plan.Owned, events: u64, claim: Claim, counters: []const u64, challenges: *const Challenges, limits: Limits) !void {
    if (events >= core.fields.m31.Modulus or events > limits.max_events or counters.len != plan.intervals.len or
        counters.len > limits.max_intervals or try std.math.mul(usize, counters.len, @sizeOf(u64)) > limits.max_counter_bytes)
        return error.InvalidCallerReadonlyProviderCensus;
    for ([_]Q{ claim.mutable_sum, claim.classification_sum, claim.read_sum }) |sum| if (!@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&sum)) return error.InvalidCallerReadonlyClaim;
    var mass: u64 = 0;
    var readonly: u64 = 0;
    var classification = Q.zero();
    var read = Q.zero();
    for (counters, plan.intervals) |count, interval| {
        if (count > events) return error.InvalidCallerReadonlyProviderCensus;
        mass = try std.math.add(u64, mass, count);
        if (interval.readonly) readonly = try std.math.add(u64, readonly, count);
        if (count == 0) continue;
        const weight = core.fields.m31.M31.fromCanonical(@intCast(count));
        classification = classification.add((try challenges.classification.combineBase(Original.intervalTuple(interval)).inv()).mulM31(weight));
        if (interval.readonly) read = read.add((try challenges.read.combineBase(Original.inputTuple(interval.lower * 4, interval.value)).inv()).mulM31(weight));
    }
    if (mass != events or readonly != claim.readonly_count) return error.InvalidCallerReadonlyProviderCensus;
    if (!classification.eql(claim.classification_sum) or !read.eql(claim.read_sum)) return error.UnclosedCallerReadonlyProviders;
}
