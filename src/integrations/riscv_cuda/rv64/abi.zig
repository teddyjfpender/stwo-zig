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

pub const FriFold = extern struct {
    input: Plane,
    output: Plane,
    twiddles: [*]const u32,
    twiddle_words: u64,
    alpha: [*]const u32,
    offsets: [4]u32,
    count: u32,
    steps: u32,
    first_is_circle: u32,
    accumulate_circle: u32,
};
comptime {
    if (@sizeOf(FriFold) != 104 or @offsetOf(FriFold, "count") != 88)
        @compileError("RV64 OM31 FRI fold ABI mismatch");
}
pub extern "c" fn stwo_rv64_fri_fold_on(*anyopaque, u32, *const FriFold) c_int;
pub extern "c" fn stwo_rv64_fri_leaves_on(*anyopaque, u32, Plane, u32, u32, u32, [*]u32, u64) c_int;

pub const channel_state_words = 16;
pub extern "c" fn stwo_rv64_channel_init_on(*anyopaque, u32, [*]u32, [*]const u32, u64) c_int;
pub extern "c" fn stwo_rv64_channel_mix_on(*anyopaque, u32, [*]u32, u32, u64, u64, ?[*]const u32, u32, u32, [*]u32) c_int;
pub extern "c" fn stwo_rv64_channel_draw_on(*anyopaque, u32, [*]u32, u32, u64, u64, u32, [*]u32, [*]u32) c_int;

pub const batch_max_oracles = 64;
pub const batch_state_words = 2173;
pub const BatchOracle = extern struct {
    raw: ?[*]const u32,
    raw_stride: u64,
    variables: u32,
    reserved: u32 = 0,
};
comptime {
    if (@sizeOf(BatchOracle) != 24 or @offsetOf(BatchOracle, "variables") != 16) @compileError("RV64 mixed oracle ABI mismatch");
}
pub extern "c" fn stwo_rv64_batch_init_on(*anyopaque, u32, [*]u32, [*]const u32, [*]const u32, [*]const u32, [*]const BatchOracle, u32, u32) c_int;
pub extern "c" fn stwo_rv64_batch_round_on(*anyopaque, u32, [*]u32, [*]const BatchOracle, u32, u32, u32, [*]const u32, [*]u32) c_int;
pub extern "c" fn stwo_rv64_batch_mask_on(*anyopaque, u32, Plane, Plane, [*]u32) c_int;

pub const gkr_state_words = 1428;
pub const gkr_alpha_word = 152;
pub const gkr_lambda_word = 160;
pub const gkr_seed_word = 168;
pub const gkr_claims_word = 180;
pub const gkr_point_word = 1204;
pub const GkrRoot = extern struct { n: Plane, d: Plane };
pub extern "c" fn stwo_rv64_gkr_pack_roots_on(*anyopaque, u32, [*]const GkrRoot, u32, [*]u32) c_int;
pub extern "c" fn stwo_rv64_gkr_init_on(*anyopaque, u32, [*]u32, [*]const u32, [*]const u32, u32, u32, u64) c_int;
pub extern "c" fn stwo_rv64_gkr_begin_on(*anyopaque, u32, [*]u32, u32, u32, u32, [*]const u32, [*]u32) c_int;
pub extern "c" fn stwo_rv64_gkr_close_on(*anyopaque, u32, [*]u32, [*]const u32, ?[*]const u32, [*]const u32, u32, u32, u32) c_int;
