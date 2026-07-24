//! Source- and protocol-bound identities for Native Poseidon.

const std = @import("std");
const ir = @import("stwo_backend_contracts").proof_program;
const cpu_poseidon = @import("../../../examples/poseidon.zig");
const pcs = @import("stwo_core").pcs;

pub const rust_oracle_repository =
    "https://github.com/starkware-libs/stwo";
pub const rust_oracle_commit =
    "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2";

pub const air = digest(
    "stwo/native/poseidon/air:constant-qm31(log_instances,158,1264,1):v1",
);
pub const ingress_recipe = digest(
    "stwo/native/poseidon/trace:m31-permutation-16x8-replicas:v1",
);
pub const ingress_layout = digest(
    "stwo/native/poseidon/trace-layout:m31-column-major:circle-domain:v1",
);
pub const transcript_recipe = digest(
    "stwo/native/poseidon/transcript:pcs-config,empty-preprocessed,main,log-instances:u32:v1",
);
pub const public_input_abi = digest(
    "stwo/native/poseidon/public-input:u32-log-instances:v1",
);
pub const sampling_recipe = digest(
    "stwo/native/poseidon/oods:main-points,composition-split-points:v1",
);
pub const mask_layout = digest(
    "stwo/native/poseidon/mask:preprocessed[],main[1264x[0]],composition[8x[0]]:v1",
);
pub const constraint_expression = digest(
    "stwo/native/poseidon/constraint:constant-qm31(log-instances,158,1264,1):v1",
);
pub const constraint_parameter_abi = digest(
    "stwo/native/poseidon/constraint-parameters:u32-log-instances,qm31-alpha:v1",
);

pub fn statement(value: cpu_poseidon.Statement) ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo/native/poseidon/statement/v1");
    hashInt(&hash, u32, value.log_n_instances);
    var result: ir.Digest = undefined;
    hash.final(&result);
    return result;
}

pub fn protocol(value: pcs.PcsConfig) ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo/native/blake2s-pcs/protocol/v1");
    hashInt(&hash, u32, value.pow_bits);
    hashInt(&hash, u32, value.fri_config.log_blowup_factor);
    hashInt(
        &hash,
        u32,
        value.fri_config.log_last_layer_degree_bound,
    );
    hashInt(&hash, u64, @intCast(value.fri_config.n_queries));
    hashInt(&hash, u32, value.fri_config.fold_step);
    hashInt(
        &hash,
        u32,
        if (value.lifting_log_size) |log_size|
            log_size + 1
        else
            0,
    );
    var result: ir.Digest = undefined;
    hash.final(&result);
    return result;
}

fn digest(value: []const u8) ir.Digest {
    @setEvalBranchQuota(10_000);
    return ir.identityDigest(value);
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: T,
) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

test "Poseidon identities bind the pinned Rust authority" {
    try std.testing.expectEqual(
        @as(usize, 40),
        rust_oracle_commit.len,
    );
    try std.testing.expect(!std.mem.allEqual(u8, &air, 0));
    try std.testing.expect(!std.mem.allEqual(
        u8,
        &ingress_recipe,
        0,
    ));
}
