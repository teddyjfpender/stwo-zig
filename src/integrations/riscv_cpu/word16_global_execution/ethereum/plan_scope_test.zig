const std = @import("std");
const CpuLayout = @import("plan.zig").CpuLayout;

test "new classic defaults cannot silently enter authenticated GKR query shapes" {
    const G = @import("../../word16_execution/geometry.zig").Geometry;
    const base = G{ .cpu_log = 5, .cpu_fused_tail = true, .cpu_u8_pairs = true };
    try @import("../services/gkr_local/service_scope.zig").geometry(base);
    const layout = CpuLayout.forGkrProfile(.ethereum_services_v3);
    try std.testing.expect(layout.compact_decode and layout.u8_pairs and !layout.mul_u8_pairs and !layout.ls_fused_pairs and !layout.alu_fused_tail and !layout.ls_dword_fused_pairs);
    var compact = base;
    compact.cpu_compact_decode = true;
    try @import("../services/gkr_local/service_scope.zig").geometry(compact);
    compact.cpu_u8_pairs = false;
    compact.cpu_fused_tail = false;
    try std.testing.expectError(error.InvalidCpuCompactGeometry, @import("../services/gkr_local/service_scope.zig").geometry(compact));
    inline for (.{ "mul_u8_pairs", "ls_fused_pairs", "alu_fused_tail", "ls_dword_fused_pairs" }) |field| {
        var changed = base;
        @field(changed, field) = true;
        try std.testing.expectError(error.UnsupportedClassicEncodingInLocalGkr, @import("../services/gkr_local/service_scope.zig").geometry(changed));
    }
}
