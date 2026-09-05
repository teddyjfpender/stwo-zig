//! Pointer-free wire types for the role-0 Stage101 transcript program.

const frontend = @import("stwo_riscv_frontend");

const materializer =
    @import("recursive_common_ethereum_incremental_leaf_materializer_v4.zig");
const transcript_mod =
    @import("recursive_common_ethereum_incremental_leaf_transcript_v4.zig");

const recursion = frontend.recursion;
const recording = recursion.recording_poseidon_channel_v4;
const segment_wire = recursion.segment_statement_v2;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const CONTEXT_COUNT: usize = 17;
pub const BASE_STATEMENT_WIRE_OFFSET: u32 = @intCast(
    segment_wire.fixed_layout.base_statement,
);
pub const BASE_STATEMENT_WORD_COUNT: u32 = @intCast(
    segment_wire.V1_PROJECTION_WORD_COUNT,
);
pub const TRANSCRIPT_CLAIM_COUNT: u32 = @intCast(
    materializer.FULL_TRANSCRIPT_CLAIM_COUNT,
);
pub const RELATION_DRAW_COUNT: u32 = transcript_mod.RELATION_DRAW_COUNT;
pub const QUERY_WORD_COUNT: u32 = transcript_mod.QUERY_WORD_COUNT;
pub const PROGRAM_AUTHORITY_AVAILABLE = true;
pub const DIGEST_ONLY_CONSTRUCTION = false;
pub const PRODUCTION_ACTIVATION = false;

pub const Error = error{
    ArithmeticOverflow,
    EthereumIncrementalTranscriptProgramMismatchV4,
};

pub const InputKindV4 = enum(u32) {
    protocol = 1,
    statement = 2,
    pcs_parameters = 3,
    commitment = 4,
    claimed_sum = 5,
    sampled_value = 6,
    fri_commitment = 7,
    last_layer_coefficient = 8,
    interaction_pow_nonce = 9,
    pcs_pow_nonce = 10,
};

pub const ContextRangeV4 = struct {
    first: u32,
    count: u32,
};

pub const StatementSpanV4 = struct {
    wire_offset: u32,
    word_count: u32,
};

pub const PayloadBindingV4 = union(enum(u8)) {
    none,
    constant,
    statement_span: StatementSpanV4,
    commitment: u32,
    interaction_pow_nonce,
    transcript_claimed_sum: u32,
    sampled_values: u32,
    fri_commitment: u32,
    last_layer_coefficients: u32,
    pcs_pow_nonce,
};

pub const DrawBindingV4 = union(enum(u8)) {
    none,
    relation_limb: struct {
        challenge: u32,
        half: u32,
    },
    composition,
    oods,
    deep,
    fri_alpha: u32,
    query_block: struct {
        block: u32,
        first_word: u32,
        word_count: u32,
    },
};

pub const OperationV4 = struct {
    recording_index: u32,
    context: transcript_mod.ContextV4,
    context_ordinal: u32,
    effect: recording.Effect,
    verifier_sequence: u32,
    tag: u32,
    args: [4]u32,
    payload: PayloadBindingV4,
    draw: DrawBindingV4,
};

pub const PayloadMetadataV4 = struct {
    source_kind: InputKindV4,
    item_index: u32,
    limb_index: u32,
    constant_mask: u32,
    input_use_count: u32,
};

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or CONTEXT_COUNT != 17 or
        BASE_STATEMENT_WIRE_OFFSET != 60 or BASE_STATEMENT_WORD_COUNT != 412 or
        TRANSCRIPT_CLAIM_COUNT != 43 or RELATION_DRAW_COUNT != 50 or
        QUERY_WORD_COUNT != 193 or !PROGRAM_AUTHORITY_AVAILABLE or
        DIGEST_ONLY_CONSTRUCTION or PRODUCTION_ACTIVATION)
    {
        @compileError("Ethereum incremental transcript program V4 drifted");
    }
}
