//! M9 proof-params prototype (stream m9-proof-params): exact leaf verifier cell census of the
//! same D2 native proof verified with full Merkle paths (cap 0, production) and with a guessed,
//! root-checked Merkle cap of log 3 in the in-circuit native-proof verifier. The native
//! proof bytes and PCS parameters are unchanged; only the leaf circuit changes. The cap-3 graph
//! is also built with witness evaluation and must be a satisfied circuit (the capped verifier
//! accepts the real native proof). The test name keeps the "D2 actual native CPU recursive"
//! prefix so the existing `test-d2-circuit-census` filter runs it.
const std = @import("std");
const Candidate = @import("../../word16_execution/om31_security_candidate.zig");
const Fixture = @import("../../word16_global_execution/services/gkr_local/d2_profile_test.zig");
const Execution = @import("../../word16_global_execution/services/gkr_local/execution.zig");
const MW = @import("../../word16_global_execution/services/gkr_local/manifest_wire.zig");
const Graph = @import("leaf_graph.zig");
const Census = @import("geometry_census.zig");

/// Caps above 3 can fail host cap derivation from the proof's own query paths (`merkle.hostCap`): with 54 native
/// queries a level-c pair is uncovered with probability 2^(c-1) (1 - 2^-(c-1))^54 per tree (c = 4: 5.9e-3, c = 5: 0.49),
/// so each cap is attempted and its error recorded instead of aborting the census.
const CAPS = [_]u32{ 0, 2, 3, 4, 5 };
const FULL_CAP: u32 = 3;

const Capture = struct {
    var cells: [CAPS.len]u64 = .{0} ** CAPS.len;
    var blake: [CAPS.len]u64 = .{0} ** CAPS.len;
    var qm31: [CAPS.len]u64 = .{0} ** CAPS.len;
    var failed: [CAPS.len]?anyerror = .{null} ** CAPS.len;
    var valid_full = false;
    pub fn run(a: std.mem.Allocator, setups: anytype, bundle: anytype, expected: anytype, config: anytype, authority: anytype) !void {
        var inventory = try Execution.Inventory.initWithAuthority(a, setups, &.{}, bundle.requests, expected, config, authority);
        defer inventory.deinit();
        var stages = try MW.decode(a, inventory.execution_identity, inventory.workers, bundle.stage_one_bytes);
        defer stages.deinit();
        var manifest = try stages.verifyAndSeal(a, inventory.execution_identity, inventory.workers);
        defer manifest.deinit(a);
        const base: Graph.CpuInput = .{ .setup = setups[0], .request = bundle.requests[0], .expected = inventory.workers[0], .first = inventory.first_ids[0], .manifest = &manifest, .index = 0, .stage = &stages.stages[0], .config = config, .encoded = &bundle.cpus[0], .fixed = authority.at(0) };
        for (CAPS, 0..) |cap, i| {
            var input = base;
            input.cap_log = cap;
            var graph = Graph.cpuTraceOnly(a, input) catch |err| {
                failed[i] = err;
                continue;
            };
            defer graph.deinit();
            var label: [64]u8 = undefined;
            const measured = try Census.report(a, graph.ctx, try std.fmt.bufPrint(&label, "m9_leaf_cap{d}_d2_native_b4_q54_p20_fold4", .{cap}));
            cells[i] = measured.total_cells;
            blake[i] = measured.raw_rows.blake_g_gate;
            qm31[i] = measured.raw_rows.qm31_ops;
        }
        // Witness-evaluated graph at FULL_CAP: cpuMode checks isCircuitValid() and fails with CurrentOm31LeafRejects otherwise.
        var input = base;
        input.cap_log = FULL_CAP;
        var full = try Graph.cpu(a, input);
        full.deinit();
        valid_full = true;
    }
};

test "D2 actual native CPU recursive verifier M9 leaf Merkle cap census" {
    try Fixture.exercise(.d2_native_b4_q54_p20_fold4, Capture);
    try std.testing.expect(Capture.valid_full);
    try std.testing.expect(Capture.failed[0] == null and Capture.failed[2] == null);
    for (CAPS, Capture.cells, Capture.blake, Capture.qm31, Capture.failed) |cap, c, b, q, f| {
        if (f) |err| {
            std.debug.print("M9_LEAF_CAP_CENSUS cap_log={} failed={s}\n", .{ cap, @errorName(err) });
            continue;
        }
        std.debug.print("M9_LEAF_CAP_CENSUS cap_log={} total_cells={} raw_blake_g_rows={} raw_qm31_rows={} cells_vs_cap0={d:.4} blake_vs_cap0={d:.4}\n", .{ cap, c, b, q, @as(f64, @floatFromInt(c)) / @as(f64, @floatFromInt(Capture.cells[0])), @as(f64, @floatFromInt(b)) / @as(f64, @floatFromInt(Capture.blake[0])) });
    }
    try std.testing.expect(Capture.blake[2] < Capture.blake[0]);
    std.debug.print("M9_LEAF_CAP_VALID cap_log={} circuit_valid=true native_proof_unchanged=true\n", .{FULL_CAP});
}
