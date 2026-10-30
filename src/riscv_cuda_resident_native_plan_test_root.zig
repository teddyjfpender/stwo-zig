const std = @import("std");
const P = @import("integrations/riscv_cuda/resident_native_program_v1.zig");
fn force(a: std.mem.Allocator, profile: *const P.Profile.Owned) !void {
    inline for (.{ 4, 5 }) |N| {
        const p = try P.ForCommitments(N).Owned.init(a, profile, .{});
        defer p.deinit();
        var pcs = try @import("integrations/riscv_cuda/resident_native_pcs_v1.zig").ForCommitments(N).Plans.init(a, p, 96 << 30);
        defer pcs.deinit();
        std.mem.doNotOptimizeAway(p.view());
    }
}
test "resident native original source plan semantic" {
    std.mem.doNotOptimizeAway(&force);
}

comptime {
    _ = @import("integrations/riscv_cuda/resident_native_plan_test_v1.zig");
}
