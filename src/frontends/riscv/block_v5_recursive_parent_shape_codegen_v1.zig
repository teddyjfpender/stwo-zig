const std = @import("std");
const A = @import("recursion/block_v5_closed_input_request_shape_admission_v1.zig");
const S = @import("recursion/block_v5_recursive_parent_shape_v1.zig");
const C = @import("recursion/air/block_v5_open_parent_composition_v2.zig");
fn shape(a: std.mem.Allocator, admission: *const A.Admission) !*S.Shape {
    return S.Shape.initForAdmission(a, admission, .{});
}
fn composition(a: std.mem.Allocator, admission: *const A.Admission) !C.Compiled {
    return C.compileShape(a, admission);
}
pub export fn stwo_recursive_parent_fixed_shape_body_gate() void {
    inline for (.{ &shape, &composition, &A.Admission.init, &A.Admission.validate, &S.Shape.deinit, &@import("recursion/block_v5_recursive_parent_fixed_pieces_v1.zig").Owned.init, &@import("recursion/block_v5_recursive_parent_fixed_pieces_v1.zig").Owned.validateAgainst, &@import("recursion/block_v5_recursive_parent_fixed_pieces_v1.zig").Owned.deinit, &@import("recursion/air/block_v5_recursive_parent_fixed_arithmetic_v1.zig").Owned.materializeFixed }) |body| std.mem.doNotOptimizeAway(body);
    // Retain the actual unchanged proof capture/fresh verifier routes too.
    std.mem.doNotOptimizeAway(&@import("block_v5_closed_input_request_forest_codegen_v2.zig").stwo_closed_input_request_forest_body_gate);
}
