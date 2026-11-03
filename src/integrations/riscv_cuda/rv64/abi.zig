//! Exact numerical ABI. No production admission implied by a successful launch.
pub const CpuWitness = extern struct {
    metadata: ?[*]const u32,
    rom: [*]const u32,
    main: [*]u32,
    counts16: [*]u32,
    counts8: [*]u32,
    rom_counts: [*]u32,
    status: [*]u32,
    count: u32,
    log: u32,
    rom_log: u32,
    final_pc: u32,
};
pub extern "c" fn stwo_rv64_cpu_witness_on(*anyopaque, u32, *const CpuWitness) c_int;
comptime {
    if (@sizeOf(CpuWitness) != 72 or @offsetOf(CpuWitness, "count") != 56)
        @compileError("RV64 compact CPU witness ABI mismatch");
}
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

pub const relation_count = 10;
pub const relation_slot_stride = 31;
pub extern "c" fn stwo_rv64_parameter_gather_on(*anyopaque, u32, [*]const u32, [*]u32, [*]const u32, u32, u32, [*]u32) c_int;

pub const joined_parameter_count = 942;
pub const joined_namespace_counts = [5]u32{ 306, 310, 260, 63, 3 };
pub const JoinedParameters = extern struct {
    sources: [5][*]const u32,
    addresses: [*]const u32,
    output: [*]u32,
    status: [*]u32,
    count: u32,
    reserved: u32 = 0,
};
comptime {
    if (@sizeOf(JoinedParameters) != 72 or @offsetOf(JoinedParameters, "count") != 64) @compileError("joined parameter ABI mismatch");
}
pub extern "c" fn stwo_rv64_joined_parameter_gather_on(*anyopaque, u32, *const JoinedParameters) c_int;

pub const BindingMetadata = extern struct {
    state: [*]const u32,
    reservoir: [*]u32,
    row_point: [*]u32,
    carry: [*]u32,
    seed: [*]u32,
    status: [*]u32,
    chain: u64,
    instance: u32,
    row_log: u32,
    lane_log: u32,
    count: u32,
    layers: u32,
    reserved: u32 = 0,
};
comptime {
    if (@sizeOf(BindingMetadata) != 80 or @offsetOf(BindingMetadata, "chain") != 48) @compileError("binding metadata ABI mismatch");
}
pub extern "c" fn stwo_rv64_gkr_binding_metadata_on(*anyopaque, u32, *const BindingMetadata) c_int;

pub const BindingProjection = extern struct {
    n: Plane,
    d: Plane,
    eq: Plane,
    prefix: Plane,
    metadata: [*]const u32,
    status: [*]u32,
    row_log: u32,
    lane_log: u32,
    reserved: [2]u32 = @splat(0),
};
pub const PrefixScan = extern struct {
    data: Plane,
    scratch: [*]u32,
    scratch_words: u64,
    claim: [*]u32,
    status: [*]u32,
    row_log: u32,
    center: u32,
    reserved: [2]u32 = @splat(0),
};
comptime {
    if (@sizeOf(BindingProjection) != 128 or @sizeOf(PrefixScan) != 72) @compileError("binding witness ABI mismatch");
}
pub extern "c" fn stwo_rv64_binding_project_on(*anyopaque, u32, *const BindingProjection) c_int;
pub extern "c" fn stwo_rv64_prefix_scan_on(*anyopaque, u32, *const PrefixScan) c_int;
pub const GlobalPairs = extern struct {
    output: [*]u32,
    contributions: [*]u32,
    scan_scratch: [*]u32,
    claim: [*]u32,
    status: [*]u32,
    stride: u64,
    scan_words: u64,
    row_log: u32,
    pairs: u32,
    reserved: [2]u32 = @splat(0),
};
comptime {
    if (@sizeOf(GlobalPairs) != 72) @compileError("global interaction ABI mismatch");
}
pub extern "c" fn stwo_rv64_global_pairs_on(*anyopaque, u32, *const GlobalPairs) c_int;
pub extern "c" fn stwo_rv64_local_close_on(*anyopaque, u32, [*]const u32, u32, [*]u32) c_int;
pub extern "c" fn stwo_rv64_global_close_on(*anyopaque, u32, [*]const u32, [*]const u32, u32, [*]u32) c_int;
pub const MixedSegment = extern struct {
    columns: [*]const u32,
    stride_words: u64,
    capacity_words: u64,
    source_size: u32,
    reserved: u32 = 0,
};
pub const TraceOpen = extern struct {
    tree: [*]const u32,
    queries: [*]const u32,
    values: [*]u32,
    paths: [*]u32,
    status: [*]u32,
    tree_words: u64,
    value_words: u64,
    path_words: u64,
    tree_log: u32,
    lifting_log: u32,
    query_count: u32,
    reserved: u32 = 0,
};
comptime {
    if (@sizeOf(MixedSegment) != 32 or @sizeOf(TraceOpen) != 80) @compileError("trace commitment/opening ABI mismatch");
}
pub extern "c" fn stwo_rv64_trace_tree_on(*anyopaque, u32, [*]const MixedSegment, u32, u32, [*]u32, u64) c_int;
pub extern "c" fn stwo_rv64_trace_open_on(*anyopaque, u32, [*]const MixedSegment, u32, *const TraceOpen) c_int;

pub extern "c" fn stwo_rv64_binding_eq_on(*anyopaque, u32, [*]const u32, u32, Plane, [*]u32) c_int;

pub const DeepPrepare = extern struct {
    trees: [4]?[*]const u32,
    tree_words: [4]u64,
    sources: [*]const u32,
    terms: [*]const u32,
    groups: [*]const u32,
    points: [*]const u32,
    values: [*]const u32,
    alpha: [*]const u32,
    weights: [*]u32,
    linear: [*]u32,
    coefficients: [*]u32,
    valid: [*]u32,
    status: [*]u32,
    coefficient_words: u64,
    source_count: u32,
    term_count: u32,
    group_count: u32,
    reserved: u32 = 0,
};
pub const DeepCombine = extern struct {
    groups: [*]const u32,
    points: [*]const u32,
    linear: [*]const u32,
    evaluations: [*]const u32,
    domain_xy: [*]const u32,
    valid: [*]const u32,
    output: Plane,
    status: [*]u32,
    evaluation_words: u64,
    group_count: u32,
    output_log: u32,
    reserved: [2]u32 = .{ 0, 0 },
};
comptime {
    if (@sizeOf(DeepPrepare) != 176 or @sizeOf(DeepCombine) != 104 or @offsetOf(DeepPrepare, "coefficient_words") != 152 or @offsetOf(DeepCombine, "output") != 48)
        @compileError("RV64 OM31 DEEP ABI mismatch");
}
pub extern "c" fn stwo_rv64_deep_prepare_on(*anyopaque, u32, *const DeepPrepare) c_int;
pub extern "c" fn stwo_rv64_deep_combine_on(*anyopaque, u32, *const DeepCombine) c_int;

pub const SamplePoints = extern struct {
    parameter: [*]const u32,
    recipes: [*]const u32,
    points: [*]u32,
    factors: [*]u32,
    ready: [*]u32,
    status: [*]u32,
    count: u32,
    reserved: u32 = 0,
};
pub const SampleEvaluation = extern struct {
    trees: [4]?[*]const u32,
    tree_words: [4]u64,
    sources: [*]const u32,
    terms: [*]const u32,
    recipes: [*]const u32,
    factors: [*]const u32,
    point_ready: [*]const u32,
    scratch_a: [*]u32,
    scratch_b: [*]u32,
    values: [*]u32,
    valid: [*]u32,
    status: [*]u32,
    scratch_words: u64,
    value_words: u64,
    source_count: u32,
    term_capacity: u32,
    group_count: u32,
    first: u32,
    count: u32,
    coefficient_log: u32,
};
comptime {
    if (@sizeOf(SamplePoints) != 56 or @sizeOf(SampleEvaluation) != 184 or @offsetOf(SampleEvaluation, "scratch_words") != 144)
        @compileError("RV64 OM31 sampling ABI mismatch");
}
pub extern "c" fn stwo_rv64_sample_points_on(*anyopaque, u32, *const SamplePoints) c_int;
pub extern "c" fn stwo_rv64_sample_points_from_point_on(*anyopaque, u32, *const SamplePoints) c_int;
pub extern "c" fn stwo_rv64_sample_evaluate_on(*anyopaque, u32, *const SampleEvaluation) c_int;
pub extern "c" fn stwo_rv64_sample_order_on(*anyopaque, u32, [*]const u32, u32, [*]const u32, u32, [*]u32, [*]u32) c_int;
pub extern "c" fn stwo_rv64_composition_finalize_on(*anyopaque, u32, [*]u32, [*]u32, u32, u32, [*]const u32, u32, *u32) c_int;
pub extern "c" fn stwo_rv64_ls_dword_witness_on(*anyopaque, u32, ?[*]const u32, u32, u32, [*]u32, [*]u32) c_int;
pub extern "c" fn stwo_rv64_channel_queries_on(*anyopaque, u32, [*]u32, u32, u64, u64, u32, u32, [*]u32, [*]u32) c_int;
pub const FriOpen = extern struct {
    input: Plane,
    tree: [*]const u32,
    queries: [*]const u32,
    values: [*]u32,
    paths: [*]u32,
    status: [*]u32,
    tree_words: u64,
    value_words: u64,
    path_words: u64,
    count: u32,
    query_count: u32,
    fold_step: u32,
    leaf_log: u32,
    shift: u32,
    reserved: u32 = 0,
};
comptime {
    if (@sizeOf(FriOpen) != 112 or @offsetOf(FriOpen, "tree_words") != 64) @compileError("OM31 FRI opening ABI mismatch");
}
pub extern "c" fn stwo_rv64_fri_tree_on(*anyopaque, u32, Plane, u32, u32, [*]u32, u64) c_int;
pub extern "c" fn stwo_rv64_fri_terminal_on(*anyopaque, u32, Plane, u32, [*]u32, [*]u32) c_int;
pub extern "c" fn stwo_rv64_fri_open_on(*anyopaque, u32, *const FriOpen) c_int;

pub extern "c" fn stwo_rv64_composition_lift_add_on(*anyopaque, u32, [*]const u32, u32, [*]u32, u32, *u32) c_int;

pub const CompositionRole = extern struct {
    role: u32,
    trace_log: u32,
    eval_log: u32,
    first_row: u32,
    row_count: u32,
    reserved: u32 = 0,
    trees: [3][*]const u32,
    tree_words: [3]u64,
    column_offsets: [*]const u64,
    mask_count: u64,
    parameters: [*]const u32,
    parameter_count: u64,
    powers: [*]const u32,
    constraint_count: u64,
    denominator_inverses: [*]const u32,
    output: [*]u32,
};
pub extern "c" fn stwo_rv64_composition_role_on(*anyopaque, u32, *const CompositionRole, *u32) c_int;

pub const CompositionBucket = extern struct { words: [*]const u32, log: u32, reserved: u32 = 0 };
pub extern "c" fn stwo_rv64_composition_finish_on(*anyopaque, u32, [*]const CompositionBucket, u32, [*]u32, [*]u32, u32, u32, [*]const u32, u32, *u32) c_int;
