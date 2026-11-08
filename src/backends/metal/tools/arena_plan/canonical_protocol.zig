const std = @import("std");
const stwo = @import("stwo");

const resident_verifier = stwo.frontends.cairo.witness.resident_verifier;

pub const CanonicalProtocol = struct {
    channel: []const u8,
    channel_salt: u32,
    log_blowup_factor: u32,
    n_queries: u32,
    interaction_pow_bits: u32,
    query_pow_bits: u32,
    fri_fold_step: u32,
    fri_lifting: ?u32,
    fri_log_last_layer_degree_bound: u32,
};

pub const canonical_protocol = CanonicalProtocol{
    .channel = "blake2s",
    .channel_salt = 0,
    .log_blowup_factor = 1,
    .n_queries = @intCast(resident_verifier.sn2_query_count),
    .interaction_pow_bits = resident_verifier.sn2_interaction_pow_bits,
    .query_pow_bits = resident_verifier.sn2_pow_bits,
    .fri_fold_step = resident_verifier.sn2_fold_step,
    .fri_lifting = null,
    .fri_log_last_layer_degree_bound = 0,
};

/// Checks the serialized proof protocol without JSON number coercions. The
/// one-shot runner and persistent service share this exact admission rule.
pub fn objectIsCanonical(value: ?std.json.Value) bool {
    const object = switch (value orelse return false) {
        .object => |object| object,
        else => return false,
    };
    if (object.count() != 9) return false;
    return jsonStringEquals(object.get("channel"), canonical_protocol.channel) and
        jsonIntegerEquals(object.get("channel_salt"), canonical_protocol.channel_salt) and
        jsonIntegerEquals(object.get("log_blowup_factor"), canonical_protocol.log_blowup_factor) and
        jsonIntegerEquals(object.get("n_queries"), canonical_protocol.n_queries) and
        jsonIntegerEquals(object.get("interaction_pow_bits"), canonical_protocol.interaction_pow_bits) and
        jsonIntegerEquals(object.get("query_pow_bits"), canonical_protocol.query_pow_bits) and
        jsonIntegerEquals(object.get("fri_fold_step"), canonical_protocol.fri_fold_step) and
        jsonNull(object.get("fri_lifting")) and
        jsonIntegerEquals(
            object.get("fri_log_last_layer_degree_bound"),
            canonical_protocol.fri_log_last_layer_degree_bound,
        );
}

fn jsonStringEquals(value: ?std.json.Value, expected: []const u8) bool {
    const actual = value orelse return false;
    return actual == .string and std.mem.eql(u8, actual.string, expected);
}

fn jsonIntegerEquals(value: ?std.json.Value, expected: u32) bool {
    const actual = value orelse return false;
    return actual == .integer and actual.integer >= 0 and actual.integer == expected;
}

fn jsonNull(value: ?std.json.Value) bool {
    const actual = value orelse return false;
    return actual == .null;
}
