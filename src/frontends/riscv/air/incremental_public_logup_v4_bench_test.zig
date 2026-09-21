//! Bounded arithmetic benchmark over an authenticated sparse boundary fixture.
//! No native proof or wrapper is generated. Admission/setup is outside timings.
const std = @import("std");
const public_data = @import("public_data.zig");
const public_data_v2 = @import("public_data_v2.zig");
const statement_v2 = @import("statement_v2.zig");
const subject = @import("incremental_public_logup_v4.zig");
const relations_mod = @import("relation_challenges.zig");
const support = @import("public_data_v2_test_support.zig");
const WordState = @import("../runner/memory_state.zig").WordState;

test "Ethereum surviving public sums sparse work benchmark" {
    const allocator = std.testing.allocator;
    const count_text = std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_PUBLIC_SUMS_BENCH_WORDS") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (count_text) |text| allocator.free(text);
    const count = if (count_text) |text| try std.fmt.parseUnsigned(u32, text, 10) else 4096;
    if (count == 0 or count > (std.math.maxInt(u32) - 0x2000) / 4) return error.InvalidBenchmarkWordCount;
    const memory = try allocator.alloc(WordState, count);
    defer allocator.free(memory);
    for (memory, 0..) |*word, index| word.* = .{
        .addr = 0x2000 + 4 * @as(u32, @intCast(index)),
        .initial_word = 0x0102_0304,
        .final_word = 0x0102_0304,
        .final_clock = 0,
    };
    var fixture = try support.Fixture.init();
    const source = try fixture.leftSourceWithUntouchedMemory(memory);
    const words = try support.encode(allocator, &source);
    var lease = public_data_v2.PublicDataV2.OwnedValidatedLeaseV2.adoptCold(allocator, words, null) catch |err| {
        allocator.free(words);
        return err;
    };
    defer lease.deinit();
    const native = lease.data();
    var role = try statement_v2.canonicalCorePublicData(native);
    role.completion = public_data.Completion.unretiredProgramFetch(role.final_pc, 0x0010_0093);
    const relations = relations_mod.Relations.dummy();

    // Count actual authenticated events/bytes, outside timing. Each appears
    // once in native V2 and once in its removed member in the scalar oracle.
    var sparse_rw_terms: u64 = 0;
    var cursor = try native.eventCursor();
    while (cursor.next()) |event| switch (event) {
        .memory_access => |memory_event| sparse_rw_terms += @intFromBool(memory_event.address_space == 1),
        .registers_state => {},
    };
    var continuation_terms: u64 = 0;
    const view = try native.authenticatedView();
    inline for (.{ view.entry_snapshot, view.exit_snapshot }) |section| {
        if (section.count == 0) continuation_terms += 1;
        for (0..section.count) |index| {
            const entry = view.sparseEntry(section, index);
            for (0..4) |limb| {
                const shift: u5 = @intCast(limb * 8);
                const byte: u8 = @truncate(entry.value >> shift);
                continuation_terms += @intFromBool(byte != 0);
            }
        }
    }
    try std.testing.expectEqual(@as(u64, count) * 2, sparse_rw_terms);
    try std.testing.expectEqual(@as(u64, count) * 8, continuation_terms);

    var scalar_ns: [3]u64 = undefined;
    var surviving_ns: [3]u64 = undefined;
    for (&scalar_ns, &surviving_ns) |*scalar, *surviving| {
        var timer = try std.time.Timer.start();
        const reference = try subject.auditWithCircuitProfile(native, &role, &relations, .fixed_program_narrow_v1);
        scalar.* = timer.lap();
        const actual = try subject.relationSumsWithCircuitProfile(native, &role, &relations, .fixed_program_narrow_v1);
        surviving.* = timer.lap();
        try std.testing.expectEqualDeep(reference.result, actual);
    }
    std.mem.sort(u64, &scalar_ns, {}, std.sort.asc(u64));
    std.mem.sort(u64, &surviving_ns, {}, std.sort.asc(u64));
    std.debug.print("ETHEREUM_PUBLIC_SUMS_BENCH source=expanded_existing_authenticated_fixture words={d} canonical_wire_words={d} sparse_rw_terms={d} sparse_continuation_terms={d} removed_scalar_inversions={d} surviving_removed_term_inversions=0 scalar_median_ns={d} surviving_median_ns={d} rounds=3 setup_included=false native_proving=false wrapper_proving=false\n", .{ count, words.len, sparse_rw_terms, continuation_terms, 2 * (sparse_rw_terms + continuation_terms), scalar_ns[1], surviving_ns[1] });
}
