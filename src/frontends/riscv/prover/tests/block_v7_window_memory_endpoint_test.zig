//! A fresh, cryptographically valid RAM proof must not authenticate an invented
//! change to an untouched endpoint cell. This tests the open memory theorem;
//! execution/caller transition closure remains the execution receiver's job.
const std = @import("std");
const core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const Window = @import("../block_v7_real_window_policy_v2.zig");
const Policy = @import("../block_v7_execution_policy_v1.zig").Policy;
const Joint = @import("../block_v7_window_memory_joint_v1.zig");
const Epoch = @import("../block_v7_execution_epoch_v1.zig");
const Event = @import("../../air/block/memory_transition.zig").Transition;
const Guest = @import("block_v7_keccak_execution_test_support.zig");

fn policy(window: *const Window.Owned) Policy {
    const info = window.initial.info;
    return .{
        .initialized = &window.initial,
        .program_root = window.program_root,
        .terminal = .{ .final_cycle = window.boundary.cycles, .halt_address = info.halt_flag, .length_address = info.output_len, .data_address = info.output_data, .output_end = info.output_end, .output = @splat(0) },
        .config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config(),
        .window = window,
    };
}

fn proveAndReceive(a: std.mem.Allocator, window: *const Window.Owned, events: []const Event, forged: bool) ![32]u8 {
    const selected = policy(window);
    var epoch: Epoch.Epoch = undefined;
    var roster: [1]Epoch.Entry = undefined;
    // Each invocation recommits fixed/main, rederives its epoch, generates all
    // 31 physical RAM claims and proves under the newly selected statement.
    var proof = blk: {
        const stage = try Joint.For(Cpu).Stage.init(a, selected, events, 0, 64, .{});
        defer stage.deinit();
        roster[0] = try stage.entry();
        var counts: Epoch.Counts = @splat(0);
        counts[@intFromEnum(Epoch.Family.window_memory_joint)] = 1;
        epoch = try Epoch.Epoch.init(try selected.digest(), selected.config, counts, &roster, 1);
        break :blk try stage.prove(epoch, &roster);
    };
    defer proof.deinit();
    // Producer witness and PCS state are gone. Replace the proof allocation by
    // a decoded copy before the original verifier reconstructs its fixed root.
    try @import("../block_v7_execution_test_support.zig").roundTrip(proof.allocator, &proof.stark);
    if (forged) {
        // This error is emitted only AFTER original STARK verification succeeds
        // in verifyAndCapture; an OODS/transcript rejection would fail this test.
        try std.testing.expectError(error.UnclosedV7WindowState, Joint.For(Cpu).verify(a, selected, epoch, &roster, &proof, .{}));
    } else {
        const opened = try Joint.For(Cpu).verify(a, selected, epoch, &roster, &proof, .{});
        try std.testing.expectEqual(@as(u64, events.len), opened.event_count);
    }
    return epoch.digest;
}

test "window memory freshly proves actual events but rejects resealed untouched outgoing cell" {
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 4 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: Engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const elf = Guest.elf();
    const span: Capture.Window = .{ .skip_cycles = 6, .cycles = 3 };
    var captured = try Capture.capture(a, &elf, &.{}, .{ .elf = Capture.sha(&elf), .input = Capture.sha(&.{}) }, span, .{});
    defer captured.deinit();
    const calls = captured.segment.extension.keccakf_calls.records();
    try std.testing.expectEqual(@as(usize, 1), calls.len);
    const call = calls[0];
    try std.testing.expectEqual(@as(u32, 1), call.execution_clock);
    // The captured window is Keccak, ADDI, branch: its only RAM accesses are
    // the 50 original Keccak state-word transitions at the +2 memory port.
    var events: [50]Event = undefined;
    for (&events, 0..) |*event, i| {
        event.* = .{ .space = 1, .address = call.state_ptr + @as(u32, @intCast(i * 4)), .clock = 4 * (@as(u64, call.execution_clock) - 1) + 2, .before = call.input[i], .after = call.output[i] };
        try std.testing.expectEqual(event.before, Window.valueAt(captured.incoming.words, event.address));
        try std.testing.expectEqual(event.after, Window.valueAt(captured.outgoing.words, event.address));
    }
    const trusted: Window.Trusted = .{ .elf_sha256 = Capture.sha(&elf), .incoming_sha256 = captured.incoming.identity(), .outgoing_sha256 = captured.outgoing.identity(), .window = span };
    var honest = try Window.Owned.derive(a, &elf, captured.incoming, captured.outgoing, trusted, .{});
    defer honest.deinit();
    const honest_epoch = try proveAndReceive(a, &honest, &events, false);

    // Select a writable word unchanged at the actual endpoints and untouched
    // by every real event. Tiny ELF fixtures may initialize their entire stack,
    // so being absent from the sparse snapshot is deliberately not required.
    const address = find_untouched: {
        for (honest.initial.intervals) |interval| {
            if (!interval.allowed or interval.private) continue;
            var word = interval.lower;
            while (word < interval.upper) : (word += 1) {
                const candidate = word * 4;
                if (candidate == honest.initial.info.halt_flag) continue;
                if (Window.valueAt(captured.incoming.words, candidate) != Window.valueAt(captured.outgoing.words, candidate)) continue;
                var touched = false;
                for (events) |event| if (event.address == candidate) {
                    touched = true;
                    break;
                };
                if (!touched) break :find_untouched candidate;
            }
        }
        return error.NoUntouchedWritableFixtureWord;
    };
    var existing: ?usize = null;
    for (captured.outgoing.words, 0..) |word, i| if (word.address == address) {
        existing = i;
        break;
    };
    const changed_words = try a.alloc(Capture.Word, captured.outgoing.words.len + @intFromBool(existing == null));
    defer a.free(changed_words);
    @memcpy(changed_words[0..captured.outgoing.words.len], captured.outgoing.words);
    const changed_index = existing orelse captured.outgoing.words.len;
    changed_words[changed_index] = .{ .address = address, .value = Window.valueAt(captured.outgoing.words, address) ^ 7 };
    std.mem.sort(Capture.Word, changed_words, {}, struct {
        fn less(_: void, lhs: Capture.Word, rhs: Capture.Word) bool {
            return lhs.address < rhs.address;
        }
    }.less);
    const changed = Capture.Snapshot{ .cpu = captured.outgoing.cpu, .words = changed_words };
    var resealed = trusted;
    resealed.outgoing_sha256 = changed.identity();
    var dishonest = try Window.Owned.derive(a, &elf, captured.incoming, changed, resealed, .{});
    defer dishonest.deinit();
    try std.testing.expectEqual(honest.changes.len + 1, dishonest.changes.len);
    try std.testing.expect(!std.meta.eql(try policy(&honest).digest(), try policy(&dishonest).digest()));
    const forged_epoch = try proveAndReceive(a, &dishonest, &events, true);
    try std.testing.expect(!std.meta.eql(honest_epoch, forged_epoch));

    // Sparse initialization may discard irrelevant unchanged addresses, but
    // must retain EVERY declared endpoint delta, including one with no event.
    // Recommit and prove under these freshly selected policies; neither replay
    // equality nor a mismatch with the old dense commitment rejects the attack.
    var addresses: [events.len]u32 = undefined;
    for (&addresses, events) |*selected, event| selected.* = event.address;
    try honest.selectAddresses(&addresses, .{});
    try dishonest.selectAddresses(&addresses, .{});
    try honest.validate();
    try dishonest.validate();
    try std.testing.expectEqual(honest.changes.len + 1, dishonest.changes.len);
    var kept_forged_delta = false;
    for (dishonest.changes) |change| if (change.address == address) {
        kept_forged_delta = true;
    };
    try std.testing.expect(kept_forged_delta);
    const sparse_honest_epoch = try proveAndReceive(a, &honest, &events, false);
    const sparse_forged_epoch = try proveAndReceive(a, &dishonest, &events, true);
    try std.testing.expect(!std.meta.eql(sparse_honest_epoch, sparse_forged_epoch));
}
