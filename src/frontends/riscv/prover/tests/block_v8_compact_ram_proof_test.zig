//! Conditional compact-memory original proof, not a VM publication. The native
//! tuple-validity/local-root/late-bridge obligations are deliberately separate.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const Window = @import("../block_v7_real_window_policy_v2.zig");
const Proof = @import("../block_v8_compact_ram_proof_v1.zig");
const E = @import("../block_v7_execution_epoch_v1.zig");
const Guest = @import("block_v7_keccak_execution_test_support.zig");
fn epochFor(a: std.mem.Allocator, stage: *const Proof.Stage) !struct { epoch: E.Epoch, entries: [2]E.Entry } {
    _ = a;
    // Explicitly unauthenticated native placeholder in this CONDITIONAL test.
    // The complete bundle's receiver derives it from fresh local proofs.
    const entries = [2]E.Entry{ try E.Entry.init(.native, 0, @splat(1), &.{@splat(2)}), try stage.entry() };
    var counts: E.Counts = @splat(0);
    counts[@intFromEnum(E.Family.native)] = 1;
    counts[@intFromEnum(E.Family.window_memory_joint)] = 1;
    return .{ .epoch = try E.Epoch.init(try stage.policy.digest(), stage.policy.config, counts, &entries, 2), .entries = entries };
}
test "canonical compact conditional original anchors independent initial and final snapshots" {
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 12 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const elf = Guest.elf();
    const span = Capture.Window{ .skip_cycles = 9, .cycles = 4 };
    var captured = try Capture.capture(a, &elf, &.{}, .{ .elf = Capture.sha(&elf), .input = Capture.sha(&.{}) }, span, .{});
    defer captured.deinit();
    const trusted = Window.Trusted{ .elf_sha256 = Capture.sha(&elf), .incoming_sha256 = captured.incoming.identity(), .outgoing_sha256 = captured.outgoing.identity(), .window = span };
    var whole = try Window.Owned.deriveCohorts(a, &elf, captured.incoming, captured.outgoing, trusted, .{ .cohort_count = 1, .max_cohort_cycles = 4 }, .{});
    defer whole.deinit();
    try std.testing.expect(whole.changes.len > 0);
    const events = try a.alloc(@import("../../air/block/memory_transition.zig").Transition, whole.changes.len);
    defer a.free(events);
    const addresses = try a.alloc(u32, whole.changes.len);
    defer a.free(addresses);
    for (events, addresses, whole.changes) |*event, *address, change| {
        event.* = .{ .space = 1, .address = change.address, .clock = 3, .before = change.before, .after = change.after };
        address.* = change.address;
    }
    std.debug.print("B8_COMPACT_PHASE select_actual_changes\n", .{});
    try whole.selectAddresses(addresses, .{});
    const policy = Proof.Policy{ .window = &whole, .config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config(), .event_count = @intCast(events.len) };
    std.debug.print("B8_COMPACT_PHASE genuine_stage\n", .{});
    const stage = try Proof.Stage.init(a, policy, events, .{});
    var stage_live = true;
    defer if (stage_live) stage.deinit();
    const epoch = try epochFor(a, stage);
    var proof = try stage.proveConditional(epoch.epoch, &epoch.entries);
    defer proof.deinit();
    std.debug.print("B8_COMPACT_PHASE original_produced\n", .{});
    stage.deinit();
    stage_live = false;
    var external = try Window.Owned.deriveCohortsForAddresses(a, &elf, captured.incoming, captured.outgoing, trusted, .{ .cohort_count = 1, .max_cohort_cycles = 4 }, addresses, .{});
    defer external.deinit();
    const receiver = Proof.Policy{ .window = &external, .config = policy.config, .event_count = policy.event_count };
    std.debug.print("B8_COMPACT_PHASE fresh_verify\n", .{});
    const verified = try Proof.verifyConditional(a, receiver, epoch.epoch, &epoch.entries, &proof, .{});
    try std.testing.expectEqual(.conditional_compact_memory, verified.scope);
    try std.testing.expectEqual(@as(u32, @intCast(events.len)), verified.event_count);
    const drawn = try epoch.epoch.draw(a);
    var source_sum = core.fields.qm31.QM31.zero();
    for (events) |event| source_sum = source_sum.add(try drawn.memory.transition.combineSecure(@import("../block_v8_compact_ram_kernel_v1.zig").transitionTuple(core.fields.qm31.QM31, blk: {
        const row = try @import("../block_v8_compact_ram_kernel_v1.zig").construct(.{ .cohort_count = 1 }, event, null);
        var lifted: [12]core.fields.qm31.QM31 = undefined;
        for (&lifted, row) |*value, cell| value.* = core.fields.qm31.QM31.fromBase(cell);
        break :blk lifted;
    })).inv());
    try std.testing.expect(source_sum.add(verified.transition).isZero());
    // Keep initial-boundary algebra unchanged while altering two independently
    // absorbed physical claims. An aggregate-only transcript would miss this.
    proof.claims.ram[1] = proof.claims.ram[1].add(core.fields.qm31.QM31.one());
    proof.claims.boundary[0] = proof.claims.boundary[0].sub(core.fields.qm31.QM31.one());
    _ = try Proof.closeClaims(policy.event_count, proof.claims);
    if (Proof.verifyConditional(a, receiver, epoch.epoch, &epoch.entries, &proof, .{})) |_| return error.AcceptedCompensatedCompactClaims else |_| {}
    proof.claims.ram[1] = proof.claims.ram[1].sub(core.fields.qm31.QM31.one());
    proof.claims.boundary[0] = proof.claims.boundary[0].add(core.fields.qm31.QM31.one());
    const wrong_events = try a.dupe(@TypeOf(events[0]), events);
    defer a.free(wrong_events);
    wrong_events[0].before ^= 1;
    const wrong_stage = try Proof.Stage.init(a, policy, wrong_events, .{});
    defer wrong_stage.deinit();
    const wrong_epoch = try epochFor(a, wrong_stage);
    try std.testing.expectError(error.UnclosedCompactRamBoundaries, wrong_stage.proveConditional(wrong_epoch.epoch, &wrong_epoch.entries));
    std.debug.print("B8_COMPACT_PHASE permission_negative\n", .{});
    // This forbidden key is rejected by the independent sparse-policy
    // admission, before a compact fixed table or proof can be constructed.
    try std.testing.expectError(error.UntrustedV7SparseInitialization, Window.Owned.deriveCohortsForAddresses(a, &elf, captured.incoming, captured.outgoing, trusted, .{ .cohort_count = 1, .max_cohort_cycles = 4 }, &.{whole.initial.info.memory_layout.program_base}, .{}));
    std.debug.print("B8_COMPACT_MEMORY canonical70_26=true producer_destroyed=true independent_initial_final=true tuple_validity_still_requires_local_and_bridge=true\n", .{});
}
