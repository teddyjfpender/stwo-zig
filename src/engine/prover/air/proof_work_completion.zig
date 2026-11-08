//! Fail-atomic completion of AIR composition and OODS logical-work receipts.

const std = @import("std");
const builtin = @import("builtin");
const composition_work = @import("composition_work.zig");
const oods_work = @import("oods_work.zig");
const work_profile = @import("stwo_prover_api").work_profile;

const WorkRecorder = work_profile.Recorder(true);

/// Publishes only a backend-authenticated, fail-atomic composition receipt.
/// Missing component authority, a declined accelerated route, and unsupported
/// whole-stage device evaluators all leave the proof profile incomplete rather
/// than substituting a constraint-count estimate.
pub fn completeAirCompositionWork(
    recorder: ?*WorkRecorder,
    capture: *const composition_work.Capture,
) void {
    const active = recorder orelse return;
    const receipt = capture.receipt orelse {
        active.markIncomplete();
        // work-profile-unavailable:air-composition-on-domain
        return;
    };
    receipt.validate() catch {
        active.markIncomplete();
        return;
    };
    active.recordCompletedDelta(.{
        .site = .air_composition_on_domain,
        .producer = work_profile.boundaryForSite(.air_composition_on_domain),
        .source_mask = .{ .bits = work_profile.SourceMask.one(.field_additions).bits |
            work_profile.SourceMask.one(.field_multiplications).bits |
            work_profile.SourceMask.one(.field_inversions).bits },
        .counters = .{
            .field_additions = receipt.operations.additions,
            .field_multiplications = receipt.operations.multiplications,
            .field_inversions = receipt.operations.inversions,
        },
    }) catch {
        active.markIncomplete();
        return;
    };
    if (comptime builtin.is_test)
        composition_work.testing.observeAcceptedReceipt(receipt);
    // work-profile-complete:air-composition-on-domain
}

const exact_oods_seed_source_mask = work_profile.SourceMask{
    .bits = work_profile.SourceMask.one(.field_additions).bits |
        work_profile.SourceMask.one(.field_multiplications).bits |
        work_profile.SourceMask.one(.field_inversions).bits,
};

/// Exact schedule in `circle.secureFieldPointFromRandomSeedChecked`:
///
/// - `t^2`, two output products: three multiplications;
/// - `1 + t^2`, `1 - t^2`, and `t + t`: three additions;
/// - one inversion of `1 + t^2`.
///
/// The transcript draw itself performs no field arithmetic in this boundary.
pub fn completeOodsSeedToPointWork(recorder: ?*WorkRecorder) void {
    const active = recorder orelse return;
    active.recordCompletedDelta(.{
        .site = .oods_seed_to_point,
        .producer = work_profile.boundaryForSite(.oods_seed_to_point),
        .source_mask = exact_oods_seed_source_mask,
        .counters = .{
            .field_additions = 3,
            .field_multiplications = 3,
            .field_inversions = 1,
        },
    }) catch active.markIncomplete();
    // work-profile-complete:oods-seed-to-point
}

/// Accepts only the aggregate assembled from callbacks observed after the
/// actual component vtable calls. Missing, malformed, duplicate, and
/// overflowing authority leave the typed producer plan incomplete.
pub fn completeOodsWork(
    recorder: ?*WorkRecorder,
    capture: *const oods_work.Capture,
    site: oods_work.Site,
) void {
    const active = recorder orelse return;
    const receipt = capture.receipt orelse {
        active.markIncomplete();
        return;
    };
    receipt.validate() catch {
        active.markIncomplete();
        return;
    };
    if (receipt.site != site) {
        active.markIncomplete();
        return;
    }
    const producer_site: work_profile.Site = switch (site) {
        .mask_points => .oods_mask_points,
        .constraint_evaluation => .oods_constraint_evaluation,
    };
    active.recordCompletedDelta(.{
        .site = producer_site,
        .producer = work_profile.boundaryForSite(producer_site),
        .source_mask = exact_oods_seed_source_mask,
        .counters = .{
            .field_additions = receipt.operations.additions,
            .field_multiplications = receipt.operations.multiplications,
            .field_inversions = receipt.operations.inversions,
        },
    }) catch {
        active.markIncomplete();
        return;
    };
    // work-profile-complete:oods-mask-points
    // work-profile-complete:oods-constraint-evaluation
}

test "OODS seed work is exact and absent component receipts fail closed" {
    var seed_recorder: WorkRecorder = .{};
    completeOodsSeedToPointWork(&seed_recorder);
    try std.testing.expect(!seed_recorder.incomplete);
    try std.testing.expectEqual(@as(u64, 3), seed_recorder.counters.field_additions);
    try std.testing.expectEqual(@as(u64, 3), seed_recorder.counters.field_multiplications);
    try std.testing.expectEqual(@as(u64, 1), seed_recorder.counters.field_inversions);
    try std.testing.expectEqual(
        @as(u64, 1),
        seed_recorder.completed_sites[@intFromEnum(work_profile.Site.oods_seed_to_point)],
    );

    var dynamic_recorder: WorkRecorder = .{};
    const absent = oods_work.Capture{};
    completeOodsWork(&dynamic_recorder, &absent, .mask_points);
    completeOodsWork(&dynamic_recorder, &absent, .constraint_evaluation);
    try std.testing.expect(dynamic_recorder.incomplete);
    try std.testing.expect(dynamic_recorder.counters.isZero());
    try std.testing.expectEqual(
        @as(u64, 0),
        dynamic_recorder.completed_sites[@intFromEnum(work_profile.Site.oods_mask_points)],
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        dynamic_recorder.completed_sites[
            @intFromEnum(work_profile.Site.oods_constraint_evaluation)
        ],
    );
}
