//! Explicit experimental grouped OP execution root. Existing OP/Ethereum
//! commands and source-suite admission stay unchanged.
const std = @import("std");
const E = @import("stwo_prover_engine");
const Runtime = @import("poseidon2_outer/native_group/runtime.zig");
const Native = @import("poseidon2_outer/sponge_cpu/runtime.zig");
const usage = "usage: rv64-op-group-root <prove|verify|model|qualify> config.json native-or-source-directory root-directory <1|2|4> [resources.json]\n";
pub fn main() !void {
    const base = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(base);
    defer std.process.argsFree(base, args);
    if (args.len < 6 or args.len > 7) {
        std.debug.print(usage, .{});
        return error.ExpectedOpGroupedRootArguments;
    }
    const proving = std.mem.eql(u8, args[1], "prove");
    const verifying = std.mem.eql(u8, args[1], "verify");
    const qualifying = std.mem.eql(u8, args[1], "qualify");
    if (!proving and !verifying and !qualifying and !std.mem.eql(u8, args[1], "model")) return error.InvalidOpGroupedRootMode;
    const maximum = try std.fmt.parseInt(u32, args[5], 10);
    _ = try @import("poseidon2_outer/native_group/plan.zig").Plan.init(1, maximum);
    const raw = try std.fs.cwd().readFileAlloc(base, args[2], 16384);
    defer base.free(raw);
    const parsed = try std.json.parseFromSlice(@import("rv64_ethereum_request.zig").Config, base, raw, .{});
    defer parsed.deinit();
    var resources: Native.Resources = .{};
    var parsed_resources: ?std.json.Parsed(Native.Resources) = null;
    defer if (parsed_resources) |*value| value.deinit();
    if (args.len == 7) {
        const bytes = try std.fs.cwd().readFileAlloc(base, args[6], 16384);
        defer base.free(bytes);
        parsed_resources = try std.json.parseFromSlice(Native.Resources, base, bytes, .{});
        resources = parsed_resources.?.value;
    }
    if (resources.live_bytes == 0) return error.InvalidOpNativeResources;
    const budget = try E.host_budget_allocator.SharedHostBudget.create(base, resources.live_bytes);
    defer budget.destroy();
    {
        var pool: E.work_pool.WorkPool = .{};
        try pool.initInPlaceWithOptions(.{ .worker_count = if (parsed.value.workers == 0) 8 else parsed.value.workers });
        defer pool.deinit();
        var binding = try E.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        const profile = @import("poseidon2_outer/op_profile.zig").Profile.op_target_b4_q72_p0_fold4_v1;
        if (qualifying) {
            const controls = try Runtime.qualify(budget.allocator(), parsed.value, args[3], args[4], profile, resources, maximum);
            std.debug.print("OP_GROUPED_ROOT_ATTACKS controls={} restored_positive=true\n", .{controls});
        } else if (verifying) try Runtime.verify(budget.allocator(), parsed.value, args[3], args[4], profile, resources, maximum) else try Runtime.produce(budget.allocator(), parsed.value, args[3], args[4], profile, resources, maximum, proving);
    }
    const final = budget.snapshot();
    if (final.live_bytes != 0 or final.external_live_bytes != 0) return error.OpGroupedRootResourceLeak;
    std.debug.print("OP_GROUPED_ROOT_TEARDOWN live=0 external=0 peak_requested_bytes={} security_qualified=false production_admission=false\n", .{final.peak_live_bytes});
}
