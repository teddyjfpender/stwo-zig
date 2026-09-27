const std = @import("std");
const custody = @import("blake3_memory_custody.zig");
const chain = @import("blake3_memory_update_chain.zig");
const commitment = @import("../../prover/blake3_commitment_plan.zig");
const public = @import("../../air/public_data.zig");
const tree = @import("../../air/memory_commitment/blake3_byte_tree.zig");
test "BLAKE3 memory update proves public custody determines the exact conversion" {
    const a = std.testing.allocator;
    const root = try tree.TreeHasher.init(.memory).root(&.{});
    var plan = try commitment.Plan.init(a, .{ root, root, root }, &.{.{ .address = 0x2004, .clock = 1, .direction = .final, .source_circuit = 1, .path_namespace = 2, .root = root }}, &.{.{ .namespace = 1000, .address = 0x1000, .multiplicity = 1, .root = root }});
    defer plan.deinit();
    const admission = try commitment.Admission.init(&plan, try plan.identity());
    var data = public.Blake3PublicData{
        .initial_pc = 0x1000,
        .final_pc = 0x1010,
        .clock = 10,
        .initial_regs = @splat(0),
        .final_regs = @splat(0),
        .reg_last_clock = @splat(0),
        .program_root = root,
        .initial_rw_root = root,
        .final_rw_root = root,
        .completion = public.Completion.canonicalSelfLoop(0x1010),
        .io_entries = .{ .input_start = 0x2000, .input_len = 8, .input_words = &.{ 0xff, 0x12345678 }, .output_len = 0, .output_len_addr = 0x3004, .output_data_addr = 0x3008, .output_words = &.{.{ .addr = 0x3004, .value = 0, .clock = 1 }} },
    };
    const entry = try custody.edits(a, .entry, &data, admission);
    defer a.free(entry);
    try std.testing.expectEqual(@as(usize, 8), entry.len);
    try std.testing.expectEqual(@as(u8, 255), entry[0].after);
    try std.testing.expectEqual(@as(u8, 0), entry[1].after);
    try std.testing.expectEqual(@as(u8, 0x12), entry[7].after);
    const exit = try custody.edits(a, .exit, &data, admission);
    defer a.free(exit);
    // Untouched input is restored; touched input is already in the ordinary
    // final commitment. All four zero bytes of the public output stay checked.
    try std.testing.expectEqual(@as(usize, 8), exit.len);
    try std.testing.expectEqual(@as(u32, 0x3004), exit[4].address);
    var conversion = try chain.planWitness(a, 2000, 1999, entry, &.{});
    defer conversion.deinit();
    try custody.admit(&conversion, .entry, &data, admission, a);
    const full = [_]tree.Leaf{ .{ .index = 0x2000, .value = 255 }, .{ .index = 0x2004, .value = 0x78 }, .{ .index = 0x2005, .value = 0x56 }, .{ .index = 0x2006, .value = 0x34 }, .{ .index = 0x2007, .value = 0x12 } };
    try std.testing.expectEqualDeep(try tree.TreeHasher.init(.memory).root(&full), conversion.roots[8]);
    var prepared = try custody.prepare(a, .entry, &data, admission, &.{}, conversion.roots[8], 2000, 1999);
    defer prepared.deinit();
    try std.testing.expectEqual(@as(usize, 8), prepared.rows.updates.len);
    try std.testing.expectEqualSlices(u8, &try conversion.identity(), &try prepared.plan.identity());
    try std.testing.expectError(error.UntrustedMemoryUpdateChain, custody.prepare(a, .entry, &data, admission, &.{}, root, 2000, 1999));
    conversion.edits[1].after = 1;
    try std.testing.expectError(error.UntrustedMemoryCustody, custody.admit(&conversion, .entry, &data, admission, a));
    conversion.edits[1].after = 0;
    data.io_entries.input_words = &.{ 0xfe, 0x12345678 };
    try std.testing.expectError(error.UntrustedMemoryCustody, custody.admit(&conversion, .entry, &data, admission, a));
    data.io_entries.input_words = &.{ 0xff, 0x12345678 };
    // Rejected even if a caller pins the conflicting schedule anew.
    plan.memories[0].direction = .initial;
    plan.memories[0].clock = 0;
    const conflict = try commitment.Admission.init(&plan, try plan.identity());
    try std.testing.expectError(error.ConflictingPublicMemoryCustody, custody.edits(a, .entry, &data, conflict));
    try std.testing.expectError(error.UntrustedCommitmentPlan, custody.edits(a, .entry, &data, admission));
}
