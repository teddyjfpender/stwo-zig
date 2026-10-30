//! Real arithmetic and closed local relations cannot hide an earlier halt
//! write behind a zero endpoint. The hostile execution deliberately disables
//! the runner stop check; the ORIGINAL AIR, not host control flow, rejects it.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("stwo_prover_engine");
const Fixture = @import("block_v8_endpoint_mixed_fixture.zig");
const Original = @import("../block_v8_endpoint_mixed_proof_v1.zig");
const Codec = @import("../block_v8_endpoint_mixed_codec_v1.zig");
const Statement = @import("../block_v8_endpoint_mixed_statement_v1.zig");
const Q = core.fields.qm31.QM31;
fn statusEndpoint(fixture: *const Fixture.Owned, address: u32) !@import("../block_v8_ram_endpoint_kernel_v1.zig").Endpoint {
    for (fixture.endpoints.?.endpoints) |endpoint| if (endpoint.address == address) return endpoint;
    return error.MissingTransientHaltEndpoint;
}
test "mixed original AIR rejects actual recovery halt write one then native clear with zero endpoint" {
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 12 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: E.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try E.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    const status_address = 0x100100 + @import("../../isa/ethereum_signer_recovery.zig").status_offset;
    // Positive control has the identical program and valid signature, with
    // the release ABI's halt flag outside the caller's output record.
    const control = try Fixture.Owned.init(a, .transient_halt_control, config);
    var control_live = true;
    defer if (control_live) control.deinit();
    var control_timing: Original.Timings = .{};
    const good = try Original.produceWithOptions(a, control.trusted, control.input(), control.current.?.owner.preprocessed.items, control.stages(), .{}, .{ .timings = &control_timing });
    var good_live = true;
    defer if (good_live) good.deinit();
    const control_endpoint = try statusEndpoint(control, status_address);
    try std.testing.expectEqual(@as(u32, 0), control_endpoint.initial);
    try std.testing.expectEqual(@as(u32, 0), control_endpoint.final);
    var public_input = control.input();
    public_input.native_roots = good.native_roots;
    public_input.caller_roots = good.caller_roots;
    const statement = try Statement.Owned.init(a, control.trusted, public_input);
    defer statement.deinit();
    const bytes = try Codec.encode(a, good, control.trusted, public_input, .{});
    defer a.free(bytes);
    good.deinit();
    good_live = false;
    control.deinit();
    control_live = false;
    var verify_timer = try std.time.Timer.start();
    _ = try Codec.verifyBytes(a, bytes, statement.trusted, statement.input, .{});
    const control_verify_ns = verify_timer.read();
    const attack = try Fixture.Owned.init(a, .transient_halt, config);
    defer attack.deinit();
    try std.testing.expectEqual(@as(u32, status_address), attack.image.?.info.halt_flag);
    const endpoint = try statusEndpoint(attack, status_address);
    try std.testing.expectEqual(@as(u32, 0), endpoint.initial);
    try std.testing.expectEqual(@as(u32, 0), endpoint.final);
    // This is a real successful recovery, not forged caller output: the ABI
    // writes exactly status=1 before the next native instruction clears it.
    const record = attack.current.?.segment.extension.signer_recovery_calls.records()[0];
    try std.testing.expectEqual(@as(u32, 1), record.status);
    try std.testing.expectEqual(@as(u32, 1), attack.caller.?.witness.statement.ethereum.counts.signer_calls);
    try std.testing.expectEqual(@as(u32, 4), attack.input().frame.cycle_count);
    try std.testing.expectEqual(control_endpoint.last_clock, endpoint.last_clock);
    var timing: Original.Timings = .{};
    try std.testing.expectError(error.ConstraintsNotSatisfied, Original.produceWithOptions(a, attack.trusted, attack.input(), attack.current.?.owner.preprocessed.items, attack.stages(), .{}, .{ .timings = &timing }));
    // Guards were witnessed and committed, and every local CPU/register/RAM/
    // ROM/lookup closure passed before the failure reached the core prover.
    try std.testing.expect(timing.interactions_ns > 0);
    try std.testing.expect(timing.preflight_ns > 0);
    try std.testing.expect(timing.interaction_commits_ns > 0);
    try std.testing.expect(timing.claim_copy_ns > 0);
    std.debug.print("B8_MIXED_TRANSIENT_HALT rejected_in_original_AIR=true caller_recovery_status=1 initial=0 final=0 final_clock={d} q=70 pow=26 control_whole_ns={d} control_core_ns={d} control_fresh_verify_ns={d} attack_whole_ns={d}\n", .{ endpoint.last_clock, control_timing.whole_ns, control_timing.core_ns, control_verify_ns, timing.whole_ns });
    if (std.posix.getenv("STWO_B8_MIXED_HALT_REPORT")) |path| {
        const report = try std.json.Stringify.valueAlloc(a, .{
            .schema = "stwo-v8-integrated-mixed-transient-halt-timings-v1",
            .diagnostic_not_isolated = true,
            .queries = 70,
            .pow_bits = 26,
            .caller_status_written = 1,
            .initial_halt_endpoint = endpoint.initial,
            .final_halt_endpoint = endpoint.final,
            .last_local_clock = endpoint.last_clock,
            .control = control_timing,
            .control_fresh_verify_ns = control_verify_ns,
            .attack = timing,
            .attack_rejection = "ConstraintsNotSatisfied",
            .all_local_bus_closures_passed = true,
            .reached_core_prover = true,
            .attack_proof_published = false,
        }, .{ .whitespace = .indent_2 });
        defer a.free(report);
        try std.fs.cwd().writeFile(.{ .sub_path = path, .data = report });
    }
}
