const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Providers = @import("prover/block_v7_complete_union_providers_v1.zig");
const Program = @import("prover/block_v7_program_provider_v1.zig");
const Lookup = @import("prover/block_v7_lookup_compact_proof_v1.zig");
const Memory = @import("prover/block_v7_memory_joint_proof_v1.zig");
const Epoch = @import("prover/block_v7_execution_epoch_v1.zig");
fn instantiate(a: std.mem.Allocator, p: *Program.ForBackend(Cpu).FirstRound, pp: Program.Policy, l: *Lookup.For(Cpu).Stage, lp: Lookup.Policy, m: *Memory.For(Cpu).Stage, epoch: Epoch.Epoch, entries: []const Epoch.Entry) !void {
    const pc = try Providers.Program.prepare(Cpu, a, p, pp);
    defer pc.deinit();
    const pv = try Providers.Program.verifier(Cpu, a, pp, pc.claims);
    defer pv.deinit();
    const lc = try Providers.Lookup.prepare(Cpu, a, l, lp);
    defer lc.deinit();
    const lv = try Providers.Lookup.verifier(Cpu, a, lp, lc.claims, .{});
    defer lv.deinit();
    const mc = try Providers.Memory.prepare(Cpu, m, epoch, entries);
    defer mc.deinit();
    const mv = try Providers.Memory.verifier(Cpu, a, .{ .policy = m.policy, .epoch = epoch, .entries = entries, .roots = m.roots, .interval_log = mc.interval_log, .claims = mc.claims }, .{});
    defer mv.deinit();
}
test "finite union provider APIs instantiate original prover and verifier contexts" {
    std.mem.doNotOptimizeAway(&instantiate);
}
