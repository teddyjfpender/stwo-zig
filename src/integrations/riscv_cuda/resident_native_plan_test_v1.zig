const std = @import("std");
const core = @import("stwo_core");
const Program = @import("resident_native_program_v1.zig");
const PCS = @import("resident_native_pcs_v1.zig");
const Support = @import("../../frontends/riscv/prover/block_v7_execution_test_support.zig");
const E = @import("../../frontends/riscv/prover/block_v7_execution_epoch_v1.zig");
/// Genuine retired instructions supply only original cold statement/roots.
/// No original proof or CPU capture is made or retained by this fixture.
pub fn fixture(comptime N: usize, a: std.mem.Allocator, q2: bool) !*Program.ForCommitments(N).Owned {
    return fixtureImpl(N, a, q2, false);
}
/// Geometry-only high-gap metadata fixture: a canonical StateChainTracker
/// synthetic update is appended to a tiny trace. This is NOT a claimed execution
/// or a proof of global closure; it exercises the original clock AIR placement.
pub fn clockMetadataFixture(a: std.mem.Allocator) !*Program.ForCommitments(5).Owned {
    return fixtureImpl(5, a, true, true);
}
fn fixtureImpl(comptime N: usize, a: std.mem.Allocator, q2: bool, clock_metadata: bool) !*Program.ForCommitments(N).Owned {
    const code = if (N == 5) [_]u32{ 0x00700313, 0x00900393, 0x02730433, 0x001002b7, 0x10028293, 0x0082a023, 0x0002a483, 0x0000006f } else [_]u32{ 0x00700313, 0x00900393, 0x02730433, 0x0000006f };
    const elf = @import("../../frontends/riscv/runner/guest_precompile/test_elf.zig").buildReleaseProgram(code.len, &code, 512, .rv32im_zkvm_v1);
    var session = try @import("../../frontends/riscv/runner/mod.zig").BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var executed = try session.startSegment(code.len - 1);
    defer executed.deinit();
    if (clock_metadata) {
        var synthetic = @import("../../frontends/riscv/runner/state_chain.zig").StateChainTracker.init(a);
        defer synthetic.deinit();
        try synthetic.recordRegAccess(1, (1 << 20) + 3, 0);
        try executed.state_chain_tracker.clock_updates_reg.appendSlice(a, synthetic.clock_updates_reg.items);
    }
    var counters = try @import("../../frontends/riscv/air/lookups/tables/mod.zig").counter.Set.init(a);
    defer counters.deinit(a);
    const config = @import("../../frontends/riscv/recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config();
    var segment = try Support.Segment.init(a, &executed, config, @splat(7), 0, .rv32im_zkvm_v1, 0, &counters);
    defer segment.deinit();
    var pin = segment.pin;
    if (q2) pin.layout_mode = .degree_bounded_q2_v1;
    const entries = [_]E.Entry{try pin.entry(a)};
    var counts: E.Counts = @splat(0);
    counts[0] = 1;
    const epoch = try E.Epoch.init(@splat(9), config, counts, &entries, 1);
    const profile = try Program.Profile.Owned.derive(a, pin, epoch, &entries, .{});
    defer profile.deinit();
    const p = try Program.ForCommitments(N).Owned.init(a, profile, .{});
    errdefer p.deinit();
    // Independent original handle metadata, with shape-only zero claims.
    const Fused = @import("../../frontends/riscv/prover/block_v5_native_projection_fused_proof_v2.zig");
    const Memory = @import("../../frontends/riscv/prover/block_v5_opcode_memory_sidecar_proof_v1.zig");
    const claims = try a.alloc(Fused.Claim, profile.projections.len);
    defer a.free(claims);
    for (claims, profile.projections) |*c, slot| c.* = .{ .sum = core.fields.qm31.QM31.zero(), .row_count = slot.n_rows };
    const memory = try a.alloc(Memory.Claim, profile.slots.len);
    defer a.free(memory);
    for (memory) |*c| c.* = .{ .transition_sum = .zero(), .universal_sum = .zero(), .active_count = 0, .range_claims = @splat(core.fields.qm31.QM31.zero()) };
    const drawn = try epoch.draw(a);
    var original = try @import("../../frontends/riscv/prover/block_v7_native_components_v1.zig").Owner.init(a, pin, claims, memory, &drawn);
    defer original.deinit();
    var combined = try original.verifying();
    defer combined.deinit(a);
    try std.testing.expectEqual(combined.handles.len, p.view().components.len);
    for (combined.handles, p.view().components) |handle, c| {
        try std.testing.expectEqual(handle.nConstraints(), c.constraints);
        try std.testing.expectEqual(handle.maxConstraintLogDegreeBound(), c.evaluation_log);
        try std.testing.expectEqual(handle.compositionLogSplit(), c.composition_split);
    }
    try std.testing.expectError(error.ResidentNativeResourceLimit, Program.ForCommitments(N).Owned.init(a, profile, .{ .max_polynomial_bytes = 1 }));
    const wrong = if (N == 4) 5 else 4;
    try std.testing.expectError(error.InvalidResidentNativeInventory, Program.ForCommitments(wrong).Owned.init(a, profile, .{}));
    return p;
}
test "resident native original four five tree cold programs exact placement and detached metadata" {
    const a = std.testing.allocator;
    inline for (.{ 4, 5 }) |N| for ([_]bool{ false, true }) |q2| {
        const p = try fixture(N, a, q2);
        defer p.deinit();
        const data = p.view();
        for (data.trees) |tree| {
            for (tree.layouts, 0..) |mask, col| if (mask == .none) std.debug.print("native empty mask tree={d} column={d} log={d}\n", .{ tree.ordinal, col, tree.base_logs[col] });
        }
        var pcs = try PCS.ForCommitments(N).Plans.init(a, p, 96 << 30);
        defer pcs.deinit();
        try std.testing.expectEqual(@as(usize, N), pcs.oods.tree_count);
        try std.testing.expectEqual(@as(usize, N), pcs.quotient.source_trees.len);
        try std.testing.expectEqual(@as(usize, N), pcs.decommit.topology.trace_openings.len);
        try std.testing.expectEqual(try data.profile.sampleCount(), pcs.proof_layout.sample_total);
        for (data.trees, pcs.commitments, 0..) |tree, commit, i| {
            try std.testing.expectEqual(@as(u32, @intCast(i)), tree.ordinal);
            try std.testing.expectEqualSlices(u32, tree.base_logs, commit.column_logs);
            try std.testing.expectEqual(@as(u32, @intCast(i)), pcs.decommit.topology.trace_openings[i].tree_index);
        }
        if (N == 5) {
            try std.testing.expectEqual(Program.TreeKind.access_witness, data.trees[2].kind);
            try std.testing.expectEqual(@as(usize, 2), data.profile.slots.len);
            var ordinal: usize = 0;
            for (data.components) |c| if (c.kind == .access) {
                try std.testing.expectEqual(ordinal, c.physical_ordinal);
                try std.testing.expectEqual(48 * ordinal, c.witness_first.?);
                try std.testing.expectEqual(4 * data.profile.projections.len + 49 * ordinal, c.interaction_first.?);
                ordinal += 1;
            };
            try std.testing.expectEqual(@as(usize, 2), ordinal);
        }
        try std.testing.expectError(error.ResidentNativeResourceLimit, PCS.ForCommitments(N).Plans.init(a, p, 1));
        std.debug.print("native cold trees={d} q2={} components={d} constraints={d} samples={d} bytes={d}\n", .{ N, q2, data.components.len, data.constraints, pcs.proof_layout.sample_total, pcs.numerical_bytes_lower_bound });
    };
}

/// Actual precompile-only and resumed-clock segments from the retained mixed
/// fixture. This remains a cold metadata test, never a native-proof receipt.
pub fn envelopeFixture(comptime N: usize, a: std.mem.Allocator, need_frame: bool) !*Program.ForCommitments(N).Owned {
    const Guest = @import("../../frontends/riscv/prover/tests/block_v7_scaling_guest_test_support.zig");
    const code = try Guest.instructions(1);
    const elf = Guest.releaseElf(&code);
    var session = try @import("../../frontends/riscv/runner/mod.zig").EthereumShaExecutionSession.init(a, &elf, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned, .stop_on_halt_flag = true, .require_current_output_accesses = false });
    defer session.deinit();
    var counters = try @import("../../frontends/riscv/air/lookups/tables/mod.zig").counter.Set.init(a);
    defer counters.deinit(a);
    const config = @import("../../frontends/riscv/recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config();
    var continuation: ?@import("../../frontends/riscv/runner/result.zig").ContinuationToken = null;
    for (0..8) |_| {
        var run = if (continuation) |token| try session.resumeSegment(token, 3) else try session.startSegment(3);
        defer run.deinit();
        continuation = run.base.continuation;
        const external = try @import("../../frontends/riscv/prover/block_v5_cpu_execution_source_v1.zig").externalCount(&run);
        var segment = try Support.Segment.init(a, &run.base, config, @splat(7), 0, .rv32im_zkvm_ethereum_sha_v1, external, &counters);
        defer segment.deinit();
        const frame = @import("../../frontends/riscv/prover/block_v5_native_frame_v1.zig").required(segment.pin.shape);
        const matches = if (need_frame) frame else segment.pin.shape.n_infra != 0;
        if (matches and (if (segment.source.slots.len == 0) @as(usize, 4) else 5) == N) {
            const pin = segment.pin;
            const entries = [_]E.Entry{try pin.entry(a)};
            var counts: E.Counts = @splat(0);
            counts[0] = 1;
            const epoch = try E.Epoch.init(@splat(9), config, counts, &entries, 1);
            const profile = try Program.Profile.Owned.derive(a, pin, epoch, &entries, .{});
            defer profile.deinit();
            return Program.ForCommitments(N).Owned.init(a, profile, .{});
        }
        if (continuation == null) break;
    }
    return error.MissingNativeEnvelopeFixture;
}
