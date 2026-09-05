const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const subject =
    @import("recursive_temporal_secure_parent_protocol_v1.zig");

const admission = frontend.recursion.outer_parent_child_admission;
const protocol = frontend.recursion.protocol;

test "secure parent protocol preserves functional outer default bytes" {
    const functional = subject.AuthorityV1.functionalDefault();
    try functional.validate();
    try std.testing.expectEqual(
        subject.KindV1.functional_default,
        functional.kind,
    );
    try std.testing.expectEqualDeep(
        subject.FUNCTIONAL_DEFAULT_PROFILE_BYTES,
        try functional.profileBytes(),
    );
    const config = try functional.pcsConfig();
    try std.testing.expectEqual(
        admission.OUTER_PCS_CONFIG.pow_bits,
        config.pow_bits,
    );
    try std.testing.expectEqual(
        admission.OUTER_PCS_CONFIG.fri_config.log_blowup_factor,
        config.fri_config.log_blowup_factor,
    );
    try std.testing.expectEqual(
        admission.OUTER_PCS_CONFIG.fri_config.n_queries,
        config.fri_config.n_queries,
    );
    try std.testing.expectEqual(
        admission.OUTER_PCS_CONFIG.fri_config.fold_step,
        config.fri_config.fold_step,
    );
    try std.testing.expectEqual(
        admission.OUTER_PCS_CONFIG.fri_config
            .log_last_layer_degree_bound,
        config.fri_config.log_last_layer_degree_bound,
    );
    try std.testing.expectEqual(
        admission.INTERACTION_POW_BITS,
        functional.interaction_pow_bits,
    );
    try std.testing.expectEqual(@as(u32, 3), config.securityBits());
    try std.testing.expectError(
        error.SecureTemporalParentProtocolRequired,
        functional.requireSecure(),
    );
}

test "secure parent protocol selects exact q193 pow and fold authority" {
    const secure = subject.AuthorityV1.secureParent();
    try secure.validate();
    try secure.requireSecure();
    try std.testing.expectEqualDeep(
        subject.SECURE_PARENT_PROFILE_BYTES,
        try secure.profileBytes(),
    );
    const config = try secure.pcsConfig();
    try std.testing.expectEqual(protocol.PCS_CONFIG.pow_bits, config.pow_bits);
    try std.testing.expectEqual(
        protocol.PCS_CONFIG.fri_config.log_blowup_factor,
        config.fri_config.log_blowup_factor,
    );
    try std.testing.expectEqual(
        protocol.PCS_CONFIG.fri_config.n_queries,
        config.fri_config.n_queries,
    );
    try std.testing.expectEqual(
        protocol.PCS_CONFIG.fri_config.fold_step,
        config.fri_config.fold_step,
    );
    try std.testing.expectEqual(
        protocol.PCS_CONFIG.fri_config.log_last_layer_degree_bound,
        config.fri_config.log_last_layer_degree_bound,
    );
    try std.testing.expectEqual(protocol.INTERACTION_POW_BITS, secure.interaction_pow_bits);
    try std.testing.expectEqual(@as(u32, 209), config.securityBits());
    try std.testing.expectError(
        error.SecureTemporalParentProductionUnavailable,
        secure.requireProduction(),
    );
}

test "secure parent protocol codec and field mutations fail closed" {
    const secure = subject.AuthorityV1.secureParent();
    const encoded = try secure.encodeCanonical();
    const decoded = try subject.AuthorityV1.decodeCanonical(&encoded);
    try std.testing.expectEqualDeep(secure, decoded);

    var truncated = encoded;
    try std.testing.expectError(
        error.InvalidTemporalParentProtocolAuthority,
        subject.AuthorityV1.decodeCanonical(truncated[0 .. truncated.len - 1]),
    );
    truncated[truncated.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidTemporalParentProtocolAuthority,
        subject.AuthorityV1.decodeCanonical(&truncated),
    );

    var mutation = secure;
    mutation.interaction_pow_bits -= 1;
    try expectInvalid(&mutation);
    mutation = secure;
    mutation.pcs_pow_bits -= 1;
    try expectInvalid(&mutation);
    mutation = secure;
    mutation.fri_log_blowup_factor += 1;
    try expectInvalid(&mutation);
    mutation = secure;
    mutation.fri_query_count -= 1;
    try expectInvalid(&mutation);
    mutation = secure;
    mutation.fri_fold_step -= 1;
    try expectInvalid(&mutation);
    mutation = secure;
    mutation.fri_log_last_layer_degree_bound += 1;
    try expectInvalid(&mutation);
    mutation = secure;
    mutation.pcs_lifting_mode += 1;
    try expectInvalid(&mutation);
    mutation = secure;
    mutation.configured_pcs_bits -= 1;
    try expectInvalid(&mutation);
    mutation = secure;
    mutation.conjectured_security_bits -= 1;
    try expectInvalid(&mutation);
    mutation = secure;
    mutation.proof_security_sha256[0] ^= 1;
    try expectInvalid(&mutation);
    mutation = secure;
    mutation.production_activation = true;
    try expectInvalid(&mutation);
}

fn expectInvalid(value: *const subject.AuthorityV1) !void {
    try std.testing.expectError(
        error.InvalidTemporalParentProtocolAuthority,
        value.validate(),
    );
}
