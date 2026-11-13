//! Executed composition geometry validation and diagnostic accounting for Cairo transactions.
//! Complete backend-neutral official Cairo proving transaction.
//!
//! The current entrypoint remains profile-gated by an authenticated AIR bundle.
//! Component presence and row geometry are derived from the live input.

const std = @import("std");
const prover = @import("stwo_prover_engine");
const claim_generator = @import("../claim_generator.zig");
const witness = @import("../witness/mod.zig");
const proving_air = @import("air/mod.zig");
const trace_arena = @import("trace_arena.zig");
const geometry = @import("../witness/resident_geometry.zig");
pub const leaf_lane = @import("leaf_lane.zig");

pub fn revisionComponentBound(comptime Engine: type, scheme: *const Engine.Scheme) !u32 {
    if (comptime @hasField(Engine.Scheme, "revision_config")) {
        const config = scheme.revision_config orelse return error.MissingRevisionConfig;
        return config.trace_lifting_log_size - config.fri_config.log_blowup_factor + 1;
    } else return error.LeafLaneRequiresChannelProfile;
}

/// Publishes the stage's coverage as three zero-duration marker scopes, which
/// is how every other decision in this transaction is made observable in
/// `--stage-profile-out` without a debug build.
pub fn recordDeviceCompositionCounts(
    recorder: ?*prover.stage_profile.Recorder,
    counts: proving_air.device_stage.Counts,
) !void {
    const markers = [_]struct { usize, []const u8, []const u8 }{
        .{ counts.device_components, "composition_device_components", "Components evaluated on device" },
        .{ counts.host_components, "composition_device_host_components", "Components evaluated on host inside the device stage" },
        .{ counts.device_fallbacks, "composition_device_fallbacks", "Device evaluations that fell back to the host" },
    };
    for (markers) |marker| {
        var index: usize = 0;
        while (index < marker[0]) : (index += 1) {
            var scope = try prover.stage_profile.StageScope.begin(
                recorder,
                marker[1],
                marker[2],
            );
            scope.end();
        }
    }
}

pub fn componentTreeLogs(
    allocator: std.mem.Allocator,
    composition: *const witness.composition_bundle.Bundle,
    tree: u32,
) ![]u32 {
    var column_count: usize = 0;
    for (composition.components) |component| {
        const span = try geometry.componentSpan(
            component,
            tree,
        );
        if (span.start != column_count) return error.InvalidComponentShape;
        column_count = span.end;
    }
    const logs = try allocator.alloc(u32, column_count);
    errdefer allocator.free(logs);
    for (composition.components) |component| {
        const span = try geometry.componentSpan(
            component,
            tree,
        );
        @memset(logs[span.start..span.end], component.trace_log_size);
    }
    return logs;
}

/// The two ways a pre-execution geometry plan can be contradicted by the
/// executed witness: the claim's predicted log size differs from the component's
/// padded row count (`live_graph.validateClaimGeometry`), or the arena's planned
/// width or extent for a component differs from what was produced
/// (`base_trace.Collector.capture`). Every other error keeps aborting.
pub fn isPlannedGeometryDisagreement(err: anyerror) bool {
    return err == witness.live_graph.Error.ClaimGeometryMismatch or
        err == trace_arena.Error.ArenaPlanMismatch;
}

pub fn validateComposition(
    composition: *const witness.composition_bundle.Bundle,
    live: claim_generator.OwnedClaimGeometry,
) !void {
    if (composition.components.len != live.components.len)
        return error.InvalidCompositionGeometry;
    for (composition.components, live.components) |component, actual| {
        const log_size = switch (actual.log_size) {
            .known => |value| value,
            .deferred => return error.InvalidCompositionGeometry,
        };
        if (component.instance != actual.instance or
            !compositionLabelMatches(component.label, actual) or
            component.trace_log_size != log_size)
            return error.InvalidCompositionGeometry;
    }
}

fn compositionLabelMatches(
    label: []const u8,
    component: claim_generator.ComponentGeometry,
) bool {
    if (!std.mem.eql(u8, component.name, "memory_id_to_big"))
        return std.mem.eql(u8, label, component.name);
    var buffer: [64]u8 = undefined;
    const expected = std.fmt.bufPrint(
        &buffer,
        "memory_id_to_big[{}]",
        .{component.instance},
    ) catch return false;
    return std.mem.eql(u8, label, expected);
}
