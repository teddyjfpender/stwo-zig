//! Ordinary-Blake2s Fiat-Shamir operations over resident device state.

pub extern "c" fn stwo_blake2s_transcript_init_on(
    state: [*]u32,
    seed: [*]const u32,
    seed_snapshot: [*]u32,
    initial_chain: u64,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_blake2s_transcript_mix_words_on(
    state: [*]u32,
    expected_step: u32,
    expected_chain: u64,
    next_chain: u64,
    source: [*]const u32,
    word_count: u32,
    validate_m31: u32,
    input_snapshot: [*]u32,
    boundary_snapshot: [*]u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_blake2s_transcript_absorb_pow_on(
    state: [*]u32,
    expected_step: u32,
    expected_chain: u64,
    next_chain: u64,
    nonce_words: [*]const u32,
    pow_bits: u32,
    input_snapshot: [*]u32,
    boundary_snapshot: [*]u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_blake2s_transcript_draw_u32s_on(
    state: [*]u32,
    expected_step: u32,
    expected_chain: u64,
    next_chain: u64,
    output: [*]u32,
    output_snapshot: [*]u32,
    boundary_snapshot: [*]u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_blake2s_transcript_draw_secure_on(
    state: [*]u32,
    expected_step: u32,
    expected_chain: u64,
    next_chain: u64,
    felt_count: u32,
    max_rejection_rounds: u32,
    output: [*]u32,
    output_snapshot: [*]u32,
    boundary_snapshot: [*]u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_blake2s_transcript_draw_queries_on(
    state: [*]u32,
    expected_step: u32,
    expected_chain: u64,
    next_chain: u64,
    log_domain_size: u32,
    query_count: u32,
    output: [*]u32,
    output_snapshot: [*]u32,
    boundary_snapshot: [*]u32,
    stream: *anyopaque,
) c_int;
