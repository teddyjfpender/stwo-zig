//! Single authority for the geometry identity bound by recursive transcripts.
//!
//! The native scheduled channel and the outer verifier must derive the same
//! `ScheduleShape` before either may consume proof values.  Keeping the
//! preimage here prevents a locally equivalent but differently framed shape
//! hash from splitting their Fiat--Shamir transcripts.

const std = @import("std");
const fixed_profile = @import("fixed_profile.zig");
const channel = @import("poseidon2_channel.zig");
const protocol = @import("protocol.zig");
const circuit = @import("air/fri_verifier_circuit.zig");
const schedule = @import("air/verifier_schedule.zig");

pub const PROFILE_ID_DOMAIN: u32 = 0x5246_5031; // "RFP1"
pub const SHAPE_ID_DOMAIN: u32 = 0x5246_5331; // "RFS1"
pub const SHAPE_WORD_COUNT: usize = 25;

pub const Facts = struct {
    sampled_value_count: u32,
    queried_values_per_query: u32,
    claimed_sum_count: u32,
    interaction_pow_bits: u32,
    pcs_pow_bits: u32,
};

pub const Error = circuit.Error || fixed_profile.Error || schedule.Error || error{
    ArithmeticOverflow,
    InvalidProfile,
};

pub fn derive(
    profile: circuit.Profile,
    tree_heights: [fixed_profile.TREE_COUNT]u32,
    facts: Facts,
) Error!schedule.ScheduleShape {
    try profile.validate();
    if (profile.fold_widths.len == 0 or
        !std.math.isPowerOfTwo(profile.fold_widths[0]))
    {
        return error.InvalidProfile;
    }
    const column_log_degree = std.math.sub(
        u32,
        profile.lifting_log_size,
        profile.log_blowup_factor,
    ) catch return error.ArithmeticOverflow;
    var fri_config = protocol.PCS_CONFIG.fri_config;
    fri_config.log_blowup_factor = profile.log_blowup_factor;
    fri_config.log_last_layer_degree_bound =
        profile.log_last_layer_degree_bound;
    fri_config.n_queries = profile.query_count;
    fri_config.fold_step = std.math.log2_int(u32, profile.fold_widths[0]);
    const fri = try fixed_profile.FriSchedule.init(
        column_log_degree,
        fri_config,
    );
    if (@as(usize, fri.count) != profile.fold_widths.len)
        return error.InvalidProfile;
    for (fri.active(), profile.fold_widths) |round, width| {
        if (round.fold_width != width) return error.InvalidProfile;
    }

    const protocol_id = protocol.protocolId();
    const profile_digest = profile.identityDigest();
    const profile_id = channel.hashBytes(&profile_digest, PROFILE_ID_DOMAIN);
    var words: [SHAPE_WORD_COUNT]u32 = undefined;
    @memcpy(words[0..8], &protocol_id);
    @memcpy(words[8..16], &profile_id);
    @memcpy(words[16..20], &tree_heights);
    words[20] = facts.sampled_value_count;
    words[21] = facts.queried_values_per_query;
    words[22] = facts.claimed_sum_count;
    words[23] = facts.interaction_pow_bits;
    words[24] = facts.pcs_pow_bits;

    const result = schedule.ScheduleShape{
        .protocol_id = protocol_id,
        .shape_id = channel.hashCanonicalU32s(&words, SHAPE_ID_DOMAIN),
        .interaction_pow_bits = facts.interaction_pow_bits,
        .pcs_pow_bits = facts.pcs_pow_bits,
        .query_count = profile.query_count,
        .table_count = facts.queried_values_per_query,
        .claimed_sum_count = facts.claimed_sum_count,
        .sampled_value_count = facts.sampled_value_count,
        .tree_heights = tree_heights,
        .fri = fri,
    };
    try result.validate();
    return result;
}

test "recursive transcript shape preimage binds every verifier geometry axis" {
    const widths = [_]u32{ 16, 16, 16, 16, 16 };
    const profile = circuit.Profile{
        .lifting_log_size = 21,
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .fold_widths = &widths,
        .query_count = 193,
    };
    const heights = [_]u32{21} ** fixed_profile.TREE_COUNT;
    const facts = Facts{
        .sampled_value_count = 1_071,
        .queried_values_per_query = 871,
        .claimed_sum_count = 28,
        .interaction_pow_bits = protocol.INTERACTION_POW_BITS,
        .pcs_pow_bits = protocol.PCS_POW_BITS,
    };
    const baseline = try derive(profile, heights, facts);

    var changed_facts = facts;
    changed_facts.sampled_value_count += 1;
    const changed = try derive(profile, heights, changed_facts);
    try std.testing.expect(!std.meta.eql(baseline.shape_id, changed.shape_id));

    var changed_heights = heights;
    changed_heights[1] -= 1;
    const changed_tree = try derive(profile, changed_heights, facts);
    try std.testing.expect(!std.meta.eql(
        baseline.shape_id,
        changed_tree.shape_id,
    ));
}
