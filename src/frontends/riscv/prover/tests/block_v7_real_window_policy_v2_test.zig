const std = @import("std");
const core = @import("stwo_core");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const Policy = @import("../block_v7_real_window_policy_v2.zig");
const Guest = @import("block_v7_keccak_execution_test_support.zig");
const E = @import("../block_v7_execution_epoch_v1.zig");
const Ram = @import("../block_v7_window_ram_component_v1.zig");
const Air = @import("../block_v7_window_memory_joint_air_v1.zig");
test "window policy independently binds complete states and rejects changed immutable ELF" {
    const a = std.testing.allocator;
    const elf = Guest.elf();
    const span: Capture.Window = .{ .skip_cycles = 6, .cycles = 3 };
    var captured = try Capture.capture(a, &elf, &.{}, .{ .elf = Capture.sha(&elf), .input = Capture.sha(&.{}) }, span, .{});
    defer captured.deinit();
    const trusted: Policy.Trusted = .{ .elf_sha256 = Capture.sha(&elf), .incoming_sha256 = captured.incoming.identity(), .outgoing_sha256 = captured.outgoing.identity(), .window = span };
    var policy = try Policy.Owned.derive(a, &elf, captured.incoming, captured.outgoing, trusted, .{});
    defer policy.deinit();
    try std.testing.expect(policy.changes.len > 0);
    for (policy.initial.intervals) |row| try std.testing.expect(!row.private);
    const copy = try policy.cloneAlloc(a);
    defer {
        copy.deinit();
        a.destroy(copy);
    }
    try std.testing.expectEqualDeep(policy.boundary, copy.boundary);
    try std.testing.expectEqualDeep(policy.changes, copy.changes);
    var clone_initial = try policy.cloneInitial(a);
    defer clone_initial.deinit();
    try std.testing.expectEqualDeep(policy.initial.intervals, clone_initial.intervals);
    const original = policy.changes[0].before;
    policy.changes[0].before ^= 1;
    try std.testing.expectError(error.UntrustedV7WindowDelta, policy.validate());
    policy.changes[0].before = original;
    const field = &captured.incoming.words[0].value;
    field.* ^= 1;
    var replaced = trusted;
    replaced.incoming_sha256 = captured.incoming.identity();
    try std.testing.expectError(error.UntrustedV7WindowReadonly, Policy.Owned.derive(a, &elf, captured.incoming, captured.outgoing, replaced, .{}));
    field.* ^= 1;
}
test "window RAM original and delta constraint paths instantiate" {
    inline for (.{ &Ram.Spec.prepareDomain, &Ram.Spec.evaluate, &Air.Owner.init, &Air.Owner.configureRamQuotient }) |f| std.mem.doNotOptimizeAway(f);
    _ = E;
    try std.testing.expectEqual(@as(usize, 31), Ram.PLANES);
    try std.testing.expectEqual(@as(usize, 163), Ram.Spec.CONSTRAINT_COUNT);
}

test "sparse window selection preserves full endpoint delta and independently cloned source authority" {
    const a = std.testing.allocator;
    const elf = Guest.elf();
    const span: Capture.Window = .{ .skip_cycles = 6, .cycles = 3 };
    var captured = try Capture.capture(a, &elf, &.{}, .{ .elf = Capture.sha(&elf), .input = Capture.sha(&.{}) }, span, .{});
    defer captured.deinit();
    const trusted: Policy.Trusted = .{ .elf_sha256 = Capture.sha(&elf), .incoming_sha256 = captured.incoming.identity(), .outgoing_sha256 = captured.outgoing.identity(), .window = span };
    var full = try Policy.Owned.derive(a, &elf, captured.incoming, captured.outgoing, trusted, .{});
    defer full.deinit();
    var selected = try Policy.Owned.deriveForAddresses(a, &elf, captured.incoming, captured.outgoing, trusted, &.{}, .{});
    defer selected.deinit();
    try std.testing.expectEqualDeep(full.boundary, selected.boundary);
    try std.testing.expectEqualDeep(full.changes, selected.changes);
    try std.testing.expect(selected.selection != null);
    for (full.changes) |change| {
        const row = try selected.initial.find(change.address);
        try std.testing.expect(row.allowed);
        try std.testing.expectEqual(change.before, row.value);
    }
    try std.testing.expectEqual(@as(u32, 0), (try selected.initial.find(selected.initial.info.halt_flag)).value);
    var full_channel = core.proof_suites.Blake3.Channel{};
    var selected_channel = core.proof_suites.Blake3.Channel{};
    full.mix(&full_channel);
    selected.mix(&selected_channel);
    try std.testing.expect(!std.meta.eql(full_channel.digestBytes(), selected_channel.digestBytes()));
    const cloned = try selected.cloneAlloc(a);
    defer {
        cloned.deinit();
        a.destroy(cloned);
    }
    try std.testing.expect(cloned.selection.?.addresses.ptr != selected.selection.?.addresses.ptr);
    try std.testing.expect(cloned.selection.?.source.intervals.ptr != selected.selection.?.source.intervals.ptr);
    try cloned.validate();
    const index = for (cloned.initial.intervals, 0..) |row, i| {
        if (row.allowed) break i;
    } else unreachable;
    cloned.initial.intervals[index].value ^= 1;
    try std.testing.expectError(error.UntrustedV7SparseInitialization, cloned.validate());
    cloned.initial.intervals[index].value ^= 1;
    try std.testing.expectError(error.AlreadySelectedV7WindowInitialization, selected.selectAddresses(&.{}, .{}));
}
