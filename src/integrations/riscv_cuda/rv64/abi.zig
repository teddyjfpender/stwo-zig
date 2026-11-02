//! Exact numerical ABI. No production admission implied by a successful launch.
pub const Plane = extern struct {
    words: [*]u32,
    stride: u64,
    coordinates: u32,
    reserved: u32 = 0,
};
pub extern "c" fn stwo_rv64_gkr_project_on(*anyopaque, u32, Plane, Plane, Plane, u32, u32, [*]const u32, Plane, Plane, [*]u32) c_int;
pub extern "c" fn stwo_rv64_gkr_layer_on(*anyopaque, u32, Plane, Plane, u32, u32, Plane, Plane) c_int;
pub extern "c" fn stwo_rv64_gkr_fold_on(*anyopaque, u32, Plane, Plane, u32, [*]const u32, Plane, Plane) c_int;
pub extern "c" fn stwo_rv64_gkr_eq_on(*anyopaque, u32, [*]const u32, u32, Plane) c_int;
pub extern "c" fn stwo_rv64_gkr_sum_on(*anyopaque, u32, Plane, Plane, u32, Plane, [*]const u32, Plane, Plane, Plane) c_int;
comptime {
    if (@sizeOf(Plane) != 24 or @offsetOf(Plane, "stride") != 8 or @offsetOf(Plane, "coordinates") != 16)
        @compileError("RV64 CUDA plane ABI mismatch (64-bit host required)");
}
