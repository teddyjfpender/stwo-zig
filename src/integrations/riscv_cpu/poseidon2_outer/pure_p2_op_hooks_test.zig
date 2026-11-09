//! Optional real-artifact receiver gate. Set STWO_OP_NATIVE_HOOK_REQUEST and
//! STWO_OP_NATIVE_HOOK_BUNDLE to the independently pinned request/bundle pair.
//! No proving is repeated: default and callback reception verify the same bytes.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Runtime = @import("pure_p2_op_runtime.zig");
const B = @import("pure_p2_op_bundle.zig");
const W = @import("pure_p2_worker_protocol.zig").W;
const Request = @import("../rv64_ethereum_request.zig");
const a = std.testing.allocator;
const Audit = struct {
    next: usize = 0,
    cpus: usize = 0,
    truths: usize = 0,
    miller: usize = 0,
    finished: bool = false,
    fail_first: bool = false,
    corrupt_terminal: bool = false,
    halt: u64,
    statements: [256][32]u8 = undefined,
    main_roots: [256]W.H.Hash = undefined,
    output: [43]u8 = undefined,
    fn self(raw: ?*anyopaque) *Audit {
        return @ptrCast(@alignCast(raw.?));
    }
    fn common(state: *Audit, ordinal: usize, expected: anytype, stage: anytype, capture: *const B.Capture) !void {
        try std.testing.expect(!state.finished);
        try std.testing.expectEqual(state.next, ordinal);
        try std.testing.expectEqual(ordinal, expected.ordinal);
        try std.testing.expectEqual(@as(usize, 4), capture.commitments.len);
        try std.testing.expectEqualSlices(u8, &expected.fixed, &capture.commitments[0]);
        try std.testing.expectEqualSlices(u8, &stage.main, &capture.commitments[1]);
        try std.testing.expect(capture.column_log_sizes.len >= 3 and capture.sampled_values.len > 0);
        state.statements[ordinal] = expected.statement;
        state.main_roots[ordinal] = stage.main;
        state.next += 1;
        if (state.fail_first) return error.TestHookStopped;
    }
    fn cpu(raw: ?*anyopaque, _: std.mem.Allocator, v: B.CpuVerified) !void {
        const state = self(raw);
        state.cpus += 1;
        try state.common(v.ordinal, v.expected, v.stage_one, v.capture);
        try std.testing.expect(v.stage_one.local != null);
        try std.testing.expectEqualSlices(u8, &try v.key.statementForOp(v.setup, v.request, v.first_ids, v.span), &v.expected.statement);
        if (state.corrupt_terminal and v.request.base.memory.terminal.len != 0) {
            // Fault injection into the callback's borrowed host view, AFTER
            // authenticating the CPU proof. This tests finish ordering, not
            // an adversarial permission to mutate receiver-owned authority.
            const cells = @constCast(v.request.base.memory.terminal);
            var found = false;
            for (cells) |*cell| if (cell.address == state.halt & ~@as(u64, 7)) {
                cell.state.value ^= @as(u64, 1) << @intCast(8 * (state.halt & 7));
                found = true;
                break;
            };
            try std.testing.expect(found);
        }
    }
    fn truth(raw: ?*anyopaque, _: std.mem.Allocator, v: B.TruthVerified) !void {
        const state = self(raw);
        state.truths += 1;
        try state.common(v.ordinal, v.expected, v.stage_one, v.capture);
        try std.testing.expect(v.stage_one.local == null);
        try std.testing.expectEqualSlices(u8, &try v.key.statement(v.truth), &v.expected.statement);
    }
    fn tower(raw: ?*anyopaque, _: std.mem.Allocator, v: B.MillerVerified) !void {
        const state = self(raw);
        state.miller += 1;
        try state.common(v.ordinal, v.expected, v.stage_one, v.capture);
        try std.testing.expect(v.stage_one.local == null);
        try std.testing.expectEqualSlices(u8, &try v.key.statement(v.span), &v.expected.statement);
    }
    fn complete(raw: ?*anyopaque, _: std.mem.Allocator, v: Runtime.CompleteVerified) !void {
        const state = self(raw);
        try std.testing.expectEqual(v.inventory.workers.len, state.next);
        try std.testing.expectEqual(v.setups.len, state.cpus);
        try std.testing.expectEqual(v.truths.len, state.truths);
        try std.testing.expectEqual(v.miller.len, state.miller);
        try std.testing.expectEqual(v.setups.len, v.cpu_keys.len);
        try std.testing.expectEqual(v.truths.len, v.truth_keys.len);
        try std.testing.expectEqual(v.image.symbols.output_data, v.output_address);
        try std.testing.expectEqual(v.image.terminal_pc, v.expected.final_pc);
        try std.testing.expectEqualSlices(u8, &v.image.expected_output, &v.output);
        try v.native.manifest.checkGlobalClosure(v.native.claims);
        state.output = v.output;
        state.finished = true;
    }
    fn hooks(state: *Audit) Runtime.ReceptionHooks {
        return .{ .context = state, .complete = complete, .fragments = .{ .context = state, .cpu = cpu, .truth = truth, .miller = tower } };
    }
};
test "OP real native receiver capture hooks finish only after physical closure and terminal" {
    const config_path = std.posix.getenv("STWO_OP_NATIVE_HOOK_REQUEST") orelse return error.SkipZigTest;
    const directory = std.posix.getenv("STWO_OP_NATIVE_HOOK_BUNDLE") orelse return error.SkipZigTest;
    const raw = try std.fs.cwd().readFileAlloc(a, config_path, 16384);
    defer a.free(raw);
    const config = try std.json.parseFromSlice(Request.Config, a, raw, .{});
    defer config.deinit();
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(a, 32 << 30);
    defer budget.destroy();
    const alloc = budget.allocator();
    const profile = @import("pure_p2_worker_protocol.zig").Profile.op_target_b4_q72_p0_fold4_v1;
    const limits = Runtime.Resources{};
    try Runtime.verifyDirectory(alloc, config.value, directory, profile, limits);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    var honest = Audit{ .halt = config.value.symbols.halt_flag };
    try Runtime.verifyDirectoryWithHooks(alloc, config.value, directory, profile, limits, honest.hooks());
    try std.testing.expect(honest.finished and honest.next > 0);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    var aborting = Audit{ .halt = config.value.symbols.halt_flag, .fail_first = true };
    try std.testing.expectError(error.TestHookStopped, Runtime.verifyDirectoryWithHooks(alloc, config.value, directory, profile, limits, aborting.hooks()));
    try std.testing.expectEqual(@as(usize, 1), aborting.next);
    try std.testing.expect(!aborting.finished);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    var terminal = Audit{ .halt = config.value.symbols.halt_flag, .corrupt_terminal = true };
    try std.testing.expectError(error.EthereumHaltNotSet, Runtime.verifyDirectoryWithHooks(alloc, config.value, directory, profile, limits, terminal.hooks()));
    try std.testing.expectEqual(honest.next, terminal.next);
    try std.testing.expect(!terminal.finished);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    // Reframe a corrupted LAST physical proof: earlier callbacks may have
    // produced durable pending leaves, but whole completion must never fire.
    var source = try std.fs.cwd().openDir(directory, .{});
    defer source.close();
    const bundle_bytes = try source.readFileAlloc(a, "native-op.bin", limits.bundle_bytes);
    defer a.free(bundle_bytes);
    var decoded = try B.decode(a, bundle_bytes, honest.next, .{ .bytes = limits.bundle_bytes, .proof_bytes = limits.proof_bytes });
    defer decoded.deinit(a);
    decoded.proofs[decoded.proofs.len - 1].bytes[decoded.proofs[decoded.proofs.len - 1].bytes.len / 2] ^= 1;
    const changed = try B.encode(a, &decoded, .{ .bytes = limits.bundle_bytes, .proof_bytes = limits.proof_bytes });
    defer a.free(changed);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try source.copyFile("native-op.json", tmp.dir, "native-op.json", .{});
    try source.copyFile("cells.bin", tmp.dir, "cells.bin", .{});
    try tmp.dir.writeFile(.{ .sub_path = "native-op.bin", .data = changed });
    const path = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    var later_bad = Audit{ .halt = config.value.symbols.halt_flag };
    try std.testing.expect(std.meta.isError(Runtime.verifyDirectoryWithHooks(alloc, config.value, path, profile, limits, later_bad.hooks())));
    try std.testing.expect(later_bad.next > 0 and later_bad.next < honest.next and !later_bad.finished);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    std.debug.print("OP_NATIVE_HOOKS fragments={} default_and_typed=true callback_abort_clean=true later_proof_refused=true terminal_after_all_fragments_refused=true complete_only_after_all_gates=true\n", .{honest.next});
}
