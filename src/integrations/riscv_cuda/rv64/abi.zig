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

pub const round_state_words: usize = 40;
pub const round_record_words: usize = 44;
pub extern "c" fn stwo_rv64_sumcheck_init_on(*anyopaque, u32, [*]u32, [*]const u32, [*]const u32, u32) c_int;
pub extern "c" fn stwo_rv64_sumcheck_round_on(*anyopaque, u32, [*]u32, u32, u32, Plane, [*]const u32, [*]u32) c_int;

pub extern "c" fn stwo_rv64_gkr_sum_split_on(*anyopaque, u32, Plane, Plane, u32, Plane, [*]const u32, Plane, Plane, Plane) c_int;

pub extern "c" fn stwo_rv64_gkr_pack_mask_on(*anyopaque, u32, Plane, Plane, [*]u32) c_int;

pub extern "c" fn stwo_rv64_gkr_eq_fused_on(*anyopaque, u32, [*]const u32, u32, Plane) c_int;

pub extern "c" fn stwo_rv64_gkr_fold_sum_on(*anyopaque, u32, Plane, Plane, u32, [*]const u32, Plane, Plane, Plane, [*]const u32, Plane, Plane, Plane) c_int;

pub const TailJob = extern struct {
    n: Plane,
    d: Plane,
    out_n: Plane,
    out_d: Plane,
    eq: Plane,
    point: [*]const u32,
    lambda: [*]const u32,
    state: [*]u32,
    records: [*]u32,
    mask: [*]u32,
    count: u32,
    variables: u32,
    first: u32,
    reserved: u32 = 0,
};
comptime {
    if (@sizeOf(TailJob) != 176 or @offsetOf(TailJob, "count") != 160)
        @compileError("RV64 tail job ABI mismatch");
}
pub extern "c" fn stwo_rv64_sumcheck_tail_on(*anyopaque, u32, [*]const TailJob, u32) c_int;
