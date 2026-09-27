const std = @import("std");
const Roster = @import("recursion/block_v5_recursive_parent_fixed_roster_v1.zig");
pub export fn stwo_recursive_parent_fixed_roster_body_gate() void {
    inline for (.{ &Roster.Owned.derive, &Roster.Owned.init, &Roster.Owned.deinit, &Roster.Owned.validateAgainst, &@import("recursion/block_v5_recursive_parent_fixed_assembly_v1.zig").Owned.init, &@import("recursion/block_v5_recursive_parent_fixed_assembly_v1.zig").Owned.validateAgainst, &@import("recursion/air/block_v5_recursive_parent_fixed_sources_v1.zig").Owned.init, &@import("recursion/air/block_v5_recursive_parent_fixed_openings_v1.zig").Owned.init, &@import("recursion/air/native_pcs_fusion_rows.zig").materializeFixed }) |body| std.mem.doNotOptimizeAway(body);
    // Retain real original capture→producer/fresh receiver beside fixed setup.
    // This marker is NEVER proof execution in nonproving fixtures.
    std.mem.doNotOptimizeAway(&@import("block_v5_closed_input_request_forest_codegen_v2.zig").stwo_closed_input_request_forest_body_gate);
}
