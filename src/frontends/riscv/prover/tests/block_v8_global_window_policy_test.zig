const std = @import("std");
const core = @import("stwo_core");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const Window = @import("../block_v7_real_window_policy_v2.zig");
const Guest = @import("block_v7_keccak_execution_test_support.zig");
test "global cohort span bounds are independent of native clocks and preserve nonwrapping counts" {
    const p = Window.CohortPolicy{ .cohort_count = 266, .max_cohort_cycles = 524288 };
    try p.validate(139214856);
    try std.testing.expectError(error.InvalidB8GlobalCohortSpan, p.validate(266 * 524288 + 1));
    try std.testing.expectError(error.InvalidB8GlobalCohortSpan, p.validate(265));
    try std.testing.expectError(error.InvalidB8GlobalCohortSpan, (Window.CohortPolicy{ .cohort_count = 4097, .max_cohort_cycles = 1 }).validate(4097));
    try std.testing.expectError(error.InvalidB8GlobalCohortSpan, (Window.CohortPolicy{ .cohort_count = 1, .max_cohort_cycles = (1 << 24) + 1 }).validate(1));
    try std.testing.expectError(error.InvalidB8GlobalCohortSpan, (Window.CohortPolicy{ .cohort_count = 4096, .max_cohort_cycles = 1 << 24 }).validate(core.fields.m31.Modulus - 4096));
}
test "new global metadata admission cannot alias legacy native-window framing" {
    const a = std.testing.allocator;
    const elf = Guest.elf();
    const span = Capture.Window{ .skip_cycles = 6, .cycles = 3 };
    var captured = try Capture.capture(a, &elf, &.{}, .{ .elf = Capture.sha(&elf), .input = Capture.sha(&.{}) }, span, .{});
    defer captured.deinit();
    var trusted = Window.Trusted{ .elf_sha256 = Capture.sha(&elf), .incoming_sha256 = captured.incoming.identity(), .outgoing_sha256 = captured.outgoing.identity(), .window = span };
    var old = try Window.Owned.derive(a, &elf, captured.incoming, captured.outgoing, trusted, .{});
    defer old.deinit();
    var new = try Window.Owned.deriveCohorts(a, &elf, captured.incoming, captured.outgoing, trusted, .{ .cohort_count = 2, .max_cohort_cycles = 2 }, .{});
    defer new.deinit();
    var old_ch = core.proof_suites.Blake3.Channel{};
    var new_ch = old_ch;
    old.mix(&old_ch);
    new.mix(&new_ch);
    try std.testing.expect(!std.meta.eql(old_ch.digestBytes(), new_ch.digestBytes()));
    // Reconstruct the historical framing independently. Adding a global-span
    // mode must leave the native-window transcript byte-for-byte unchanged.
    var legacy = core.proof_suites.Blake3.Channel{};
    legacy.mixU32s(&.{ 0x42375753, 2, old.boundary.cycles, old.boundary.initial_cpu.pc, old.boundary.final_cpu.pc });
    legacy.mixU64(old.boundary.skip_cycles);
    legacy.mixU32s(&old.boundary.initial_cpu.regs);
    legacy.mixU32s(&old.boundary.final_cpu.regs);
    legacy.mixRoot(old.boundary.incoming_sha256);
    legacy.mixRoot(old.boundary.outgoing_sha256);
    legacy.mixRoot(old.initial.elf_sha256);
    legacy.mixRoot(old.program_root);
    legacy.mixU64(old.changes.len);
    for (old.changes) |change| legacy.mixU32s(&.{ change.address, change.before, change.after });
    try std.testing.expectEqualDeep(old_ch.digestBytes(), legacy.digestBytes());
    const cloned = try new.cloneAlloc(a);
    defer {
        cloned.deinit();
        a.destroy(cloned);
    }
    try std.testing.expectEqualDeep(new.span_mode, cloned.span_mode);
    try cloned.validate();
    // This admits public metadata only. No execution or STARK is claimed for
    // the larger span: the bundle receiver must verify all genuine cohorts.
    trusted.window.cycles = 139214856;
    try std.testing.expectError(error.UntrustedV7WindowState, Window.Owned.derive(a, &elf, captured.incoming, captured.outgoing, trusted, .{}));
    var large_metadata = try Window.Owned.deriveCohorts(a, &elf, captured.incoming, captured.outgoing, trusted, .{ .cohort_count = 266, .max_cohort_cycles = 524288 }, .{});
    defer large_metadata.deinit();
    try large_metadata.validate();
    large_metadata.boundary.cycles = 266 * 524288 + 1;
    try std.testing.expectError(error.InvalidV7WindowPolicy, large_metadata.validate());
}
