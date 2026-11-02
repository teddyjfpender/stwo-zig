//! Real-executor V3 full-execution gates. These tests produce no legacy proofs.
//! Fresh receiver setup is reconstructed independently; global debt must close.
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air;
const R = @import("../roster.zig");
const T = @import("../types.zig");
const C = @import("coordinator.zig");
const Config = @import("coordinator_fixture.zig").config;
const a = std.testing.allocator;
const CpuKeys = struct {
    producer: [2]R.CpuSetup,
    receiver: [2]R.CpuSetup,
    fn init(comptime F: type, captured: *const F.Captured, bridges: [2]T.Logs, paired: bool) !@This() {
        var out: @This() = undefined;
        var done: usize = 0;
        errdefer for (out.producer[0..done], out.receiver[0..done]) |*p, *r| {
            p.deinit();
            r.deinit();
        };
        for (&out.producer, &out.receiver, 0..) |*p, *r, i| {
            var g = try captured.native[i].geometry();
            g.initial_log = F.BOUNDARY_LOG;
            g.terminal_log = F.BOUNDARY_LOG;
            g.cpu_u8_pairs = paired;
            g.cpu_fused_tail = paired;
            p.* = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, g, bridges[i]);
            r.* = R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, g, bridges[i]) catch |err| {
                p.deinit();
                return err;
            };
            done += 1;
        }
        return out;
    }
    fn deinit(self: *@This()) void {
        for (&self.producer, &self.receiver) |*p, *r| {
            p.deinit();
            r.deinit();
        }
    }
    fn producers(self: *const @This()) [2]*const R.CpuSetup {
        return .{ &self.producer[0], &self.producer[1] };
    }
    fn receivers(self: *const @This()) [2]*const R.CpuSetup {
        return .{ &self.receiver[0], &self.receiver[1] };
    }
};
fn options() C.Options {
    return .{ .gkr_budget = 2 << 30, .global_budget = 1 << 30, .max_retained_frontend_bytes = 2 << 30, .defer_local_binding = true, .schedule = .{ .lanes = 2, .workers_per_lane = 2, .memory_cap_bytes = 8 << 30 } };
}
fn rejectMutants(bundle: *C.Bundle, cpus: []const *const R.CpuSetup, truths: []const R.Truth, expected: @import("../protocol.zig").Expected) !void {
    var wrong = expected;
    wrong.final_pc += 4;
    if (bundle.verify(a, cpus, truths, wrong, try Config())) |_| return error.V3FalseEndpointAccepted else |_| {}
    const original = bundle.cpus[0].claims[0];
    bundle.cpus[0].claims[0] = original.add(@import("worker_protocol.zig").O.one());
    defer bundle.cpus[0].claims[0] = original;
    if (bundle.verify(a, cpus, truths, expected, try Config())) |_| return error.V3FalseGlobalClaimAccepted else |err| std.debug.print("V3_GLOBAL_MUTANT rejected={s}\n", .{@errorName(err)});
}
test "V3 GKR complete two epoch SHA arith bulk execution freshly closes all global debts with paired CPU" {
    const F = @import("../v3_fixture.zig");
    const HR = @import("../../sha256/roster.zig");
    const AR = @import("../../arith256/roster.zig");
    var captured = try F.Captured.init(a);
    defer captured.deinit();
    var keys = try CpuKeys.init(F, &captured, F.BRIDGES, true);
    defer keys.deinit();
    var sha = try HR.TruthSetup.init(a, F.SHA_LOG);
    defer sha.deinit();
    var arith = try AR.TruthSetup.init(a, F.ARITH_LOG);
    defer arith.deinit();
    var fresh_sha = try HR.TruthSetup.init(a, F.SHA_LOG);
    defer fresh_sha.deinit();
    var fresh_arith = try AR.TruthSetup.init(a, F.ARITH_LOG);
    defer fresh_arith.deinit();
    const truths = F.truthsFor(&sha, &arith);
    const fresh_truths = F.truthsFor(&fresh_sha, &fresh_arith);
    const expected = F.expectedFor(captured.program.identity, captured.loaded);
    var bundle = try C.produce(a, &keys.producers(), &truths, &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expected, try Config(), options());
    defer bundle.deinit(a);
    const accepted = try bundle.verify(a, &keys.receivers(), &fresh_truths, expected, try Config());
    try std.testing.expect(accepted.completed and accepted.physical_proofs == 4);
    try rejectMutants(&bundle, &keys.receivers(), &fresh_truths, expected);
}
test "V3 GKR complete dword head tail plus general LS freshly closes cross epoch RAM and OWNER" {
    const F = @import("../ls_dword_fixture.zig");
    var captured = try F.Captured.init(a);
    defer captured.deinit();
    const bridges = [2]T.Logs{ .{ .ls_dword = 5 }, .{ .ls_dword = 5, .ls_dword_tail = 5 } };
    var keys = try CpuKeys.init(F, &captured, bridges, true);
    defer keys.deinit();
    const expected = F.expectedFor(captured.program.identity, captured.final);
    var bundle = try C.produce(a, &keys.producers(), &.{}, &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expected, try Config(), options());
    defer bundle.deinit(a);
    const accepted = try bundle.verify(a, &keys.receivers(), &.{}, expected, try Config());
    try std.testing.expect(accepted.completed and accepted.physical_proofs == 2);
    try std.testing.expect(bundle.requests[0].ls_dword == F.DWORD_ROWS[0] and bundle.requests[1].ls_dword == F.DWORD_ROWS[1]);
    try rejectMutants(&bundle, &keys.receivers(), &.{}, expected);
}
test "V3 GKR complete sponge explicit permutation IDs freshly close cross shard KIO and RAM" {
    const F = @import("../sponge_fixture.zig");
    const KR = @import("../../keccak/shared/roster.zig");
    var captured = try F.Captured.init(a);
    defer captured.deinit();
    var keys = try CpuKeys.init(F, &captured, F.BRIDGES, true);
    defer keys.deinit();
    var key = try KR.TruthSetup.init(a, F.KECCAK_LOG);
    defer key.deinit();
    var fresh = try KR.TruthSetup.init(a, F.KECCAK_LOG);
    defer fresh.deinit();
    var truth_buffer: [2]R.Truth = undefined;
    var fresh_buffer: [2]R.Truth = undefined;
    const truths = F.truthsFor(&key, true, &truth_buffer);
    const fresh_truths = F.truthsFor(&fresh, true, &fresh_buffer);
    const expected = F.expectedFor(captured.program.identity, captured.loaded);
    var bundle = try C.produce(a, &keys.producers(), truths, &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expected, try Config(), options());
    defer bundle.deinit(a);
    const accepted = try bundle.verify(a, &keys.receivers(), fresh_truths, expected, try Config());
    try std.testing.expect(accepted.completed and accepted.physical_proofs == 4);
    try rejectMutants(&bundle, &keys.receivers(), fresh_truths, expected);
}
