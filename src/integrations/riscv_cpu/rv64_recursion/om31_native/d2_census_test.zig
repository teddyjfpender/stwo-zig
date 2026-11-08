//! Exact actual verifier graph census on the same CPU program/publics at D1/D2.
//! Both native bundles are independently accepted before graph construction.
const std = @import("std");
const Candidate = @import("../../word16_execution/om31_security_candidate.zig");
const Fixture = @import("../../word16_global_execution/services/gkr_local/d2_profile_test.zig");
const Execution = @import("../../word16_global_execution/services/gkr_local/execution.zig");
const MW = @import("../../word16_global_execution/services/gkr_local/manifest_wire.zig");
const Graph = @import("leaf_graph.zig");
const Census = @import("geometry_census.zig");
const Capture = struct {
    var baseline: ?Census.Census = null;
    var d2: ?Census.Census = null;
    pub fn run(a: std.mem.Allocator, setups: anytype, bundle: anytype, expected: anytype, config: anytype, authority: anytype) !void {
        var inventory = try Execution.Inventory.initWithAuthority(a, setups, &.{}, bundle.requests, expected, config, authority);
        defer inventory.deinit();
        var stages = try MW.decode(a, inventory.execution_identity, inventory.workers, bundle.stage_one_bytes);
        defer stages.deinit();
        var manifest = try stages.verifyAndSeal(a, inventory.execution_identity, inventory.workers);
        defer manifest.deinit(a);
        var graph = try Graph.cpuTraceOnly(a, .{ .setup = setups[0], .request = bundle.requests[0], .expected = inventory.workers[0], .first = inventory.first_ids[0], .manifest = &manifest, .index = 0, .stage = &stages.stages[0], .config = config, .encoded = &bundle.cpus[0], .fixed = authority.at(0) });
        defer graph.deinit();
        const profile = try Candidate.profileFor(config);
        const measured = try Census.report(a, graph.ctx, profile.name());
        if (profile == Candidate.DEFAULT_PROFILE) baseline = measured else d2 = measured;
    }
};
test "D2 actual native CPU recursive verifier exact cell census against default" {
    Capture.baseline = null;
    Capture.d2 = null;
    try Fixture.exercise(Candidate.DEFAULT_PROFILE, Capture);
    try Fixture.exercise(.d2_native_b4_q54_p20_fold4, Capture);
    const base = Capture.baseline orelse return error.MissingD2ControlCensus;
    const d2 = Capture.d2 orelse return error.MissingD2Census;
    std.debug.print("D2_RECURSIVE_DELTA default_cells={} d2_cells={} delta={} native_fresh_verified=true outer_proof=false\n", .{ base.total_cells, d2.total_cells, @as(i128, d2.total_cells) - @as(i128, base.total_cells) });
}
