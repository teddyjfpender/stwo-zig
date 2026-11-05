//! Future envelopes with explicit, joined evaluation retirement boundaries.
//! These discounts are usable ONLY with raise-before-free publication: the
//! active future must be raised to the corresponding *_after_release value
//! before its old evaluations are physically released. No coefficient or
//! immutable cache owner is credited here.
const std = @import("std");
const F = @import("global_admission.zig").Footprint;

pub const Input = struct {
    main_evaluations: F,
    inter_evaluations: F,
    main_commit_peak: F,
    main_coefficients: F,
    interaction_peak: F,
    inter_commit_peak: F,
    inter_coefficients: F,
    composition_peak: F,
    composition_retained: F,
    pcs_peak: F,
};
pub const Plan = struct {
    after_source: F,
    after_main: F,
    /// INTER generation has completed; MAIN evaluations are still live.
    after_interaction: F,
    /// Publish before freeing MAIN, then use for INTER TC admission.
    interaction_after_release: F,
    /// INTER TC starts with INTER evaluations still live. Its callback must
    /// publish inter_commit_after_release BEFORE its joined input release.
    after_inter_commit: F,
    inter_commit_after_release: F,
    after_composition: F,
};
pub fn subtract(a: F, b: F) F {
    return .{ .large = a.large -| b.large, .small = a.small -| b.small };
}
pub fn init(i: Input) !Plan {
    const tail = i.composition_peak.max(try i.composition_retained.add(i.pcs_peak));
    const tc_future = subtract(tail, i.inter_evaluations);
    const inter_next = i.inter_commit_peak.max(try i.inter_coefficients.add(tc_future));
    const interaction_future = subtract(inter_next, i.main_evaluations);
    const main_future = i.interaction_peak.max(try i.inter_evaluations.add(interaction_future));
    return .{
        .after_source = i.main_commit_peak.max(try i.main_coefficients.add(main_future)),
        .after_main = main_future,
        .after_interaction = interaction_future,
        .interaction_after_release = inter_next,
        .after_inter_commit = tc_future,
        .inter_commit_after_release = tail,
        .after_composition = i.pcs_peak,
    };
}

fn fp(n: u64) F {
    return .{ .large = n, .small = n * 3 };
}

test "all MAIN INTER ingress RC and PCS branches remain covered" {
    // Exhaustive small geometries include saturation at both retirement
    // boundaries, with each of the five branches independently dominant.
    for (1..16) |m| for (1..16) |inter| for (0..5) |dominant| {
        var i = Input{
            .main_evaluations = fp(m),
            .inter_evaluations = fp(inter),
            .main_commit_peak = fp(1),
            .main_coefficients = fp(2),
            .interaction_peak = fp(1),
            .inter_commit_peak = fp(1),
            .inter_coefficients = fp(3),
            .composition_peak = fp(1),
            .composition_retained = fp(4),
            .pcs_peak = fp(1),
        };
        switch (dominant) {
            0 => i.main_commit_peak = fp(100),
            1 => i.interaction_peak = fp(100),
            2 => i.inter_commit_peak = fp(100),
            3 => i.composition_peak = fp(100),
            4 => i.pcs_peak = fp(100),
            else => unreachable,
        }
        const p = try init(i);
        const first = try i.main_evaluations.add(p.after_source);
        const cm = i.main_coefficients;
        try std.testing.expect(first.contains(try i.main_evaluations.add(i.main_commit_peak)));
        try std.testing.expect(first.contains(try (try i.main_evaluations.add(cm)).add(i.interaction_peak)));
        try std.testing.expect(first.contains(try (try cm.add(i.inter_evaluations)).add(i.inter_commit_peak)));
        try std.testing.expect(first.contains(try (try cm.add(i.inter_coefficients)).add(i.composition_peak)));
        try std.testing.expect(first.contains(try (try (try cm.add(i.inter_coefficients)).add(i.composition_retained)).add(i.pcs_peak)));
        // Before-free publication grants no new allocation and can only
        // increase the logical reservation; after the exact free it covers
        // the next absolute peak without an interval of lost headroom.
        try std.testing.expect(p.interaction_after_release.contains(p.after_interaction));
        try std.testing.expect(p.inter_commit_after_release.contains(p.after_inter_commit));
        try std.testing.expect((try i.main_evaluations.add(p.after_interaction)).contains(p.interaction_after_release));
        try std.testing.expect((try i.inter_evaluations.add(p.after_inter_commit)).contains(p.inter_commit_after_release));
    };
}

test "retirement never discounts coefficients or permanent owners" {
    const i = Input{ .main_evaluations = fp(4), .inter_evaluations = fp(9), .main_commit_peak = fp(7), .main_coefficients = fp(4), .interaction_peak = fp(11), .inter_commit_peak = fp(12), .inter_coefficients = fp(8), .composition_peak = fp(20), .composition_retained = fp(2), .pcs_peak = fp(16) };
    const p = try init(i);
    try std.testing.expectEqual(fp(20), p.inter_commit_after_release);
    try std.testing.expectEqual(fp(11), p.after_inter_commit);
    try std.testing.expectEqual(fp(19), p.interaction_after_release);
    try std.testing.expectEqual(fp(15), p.after_interaction);
    try std.testing.expectEqual(fp(24), p.after_main);
    try std.testing.expectEqual(fp(28), p.after_source);
}
