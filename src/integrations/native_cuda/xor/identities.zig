//! Source- and protocol-bound identities for the Native XOR adapter.

const std = @import("std");
const ir = @import("stwo_backend_contracts").proof_program;
const cpu_xor = @import("../../../examples/xor.zig");
const pcs = @import("stwo_core").pcs;

pub const rust_oracle_repository =
    "https://github.com/starkware-libs/stwo";
pub const rust_oracle_commit =
    "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2";

pub const Artifact = struct {
    authority: []const u8,
    revision: []const u8,
    trace_recipe: ir.Digest,
    air_recipe: ir.Digest,
};

pub const zig_artifact = Artifact{
    .authority = "stwo-zig repository source closure",
    .revision = "src/examples/xor/{input,interaction,component}.zig",
    .trace_recipe = digest("stwo-zig/native-xor:preprocessed7+main4:v2"),
    .air_recipe = digest("stwo-zig/native-xor:truth-table-logup14:v2"),
};

pub const rust_artifact = Artifact{
    .authority = rust_oracle_repository,
    .revision = rust_oracle_commit,
    .trace_recipe = digest(
        "stwo-rust:a8fcf4bd+repo-oracle:native-xor:preprocessed7+main4:v2",
    ),
    .air_recipe = digest(
        "stwo-rust:a8fcf4bd+repo-oracle:native-xor:truth-table-logup14:v2",
    ),
};

pub const air = pairDigest(
    "stwo/native/xor/air/bilateral/v1",
    zig_artifact.air_recipe,
    rust_artifact.air_recipe,
);
pub const ingress_recipe = pairDigest(
    "stwo/native/xor/materialized-trace/bilateral/v1",
    zig_artifact.trace_recipe,
    rust_artifact.trace_recipe,
);
pub const ingress_layout = digest(
    "stwo/native/xor/trace-layout:m31-column-major:bit-reversed-circle:v1",
);
pub const transcript_recipe = digest(
    "stwo/native/xor/transcript:pcs,pre,main,lookup,interaction,statement,composition:v2",
);
pub const public_input_abi = digest(
    "stwo/native/xor/public-input:u32-log,u32-step,u64le-offset,qm31-sum:v2",
);
pub const sampling_recipe = digest(
    "stwo/native/xor/oods:pre7-current,main4-current,interaction4-current-previous,composition8:v2",
);
pub const mask_layout = digest(
    "stwo/native/xor/mask:pre7x[0],main4x[0],interaction4x[-1,0],composition8x[0]:v2",
);
pub const constraint_parameter_abi = digest(
    "stwo/native/xor/constraint-abi:lookup[2xqm31],claimed[1xqm31],powers[14xqm31]:v2",
);
pub const constraint_expression = pairDigest(
    "stwo/native/xor/constraint:truth-table-logup14:previous-circle-row:v2",
    zig_artifact.air_recipe,
    rust_artifact.air_recipe,
);

pub fn statement(value: cpu_xor.Statement) ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo/native/xor/statement/v1");
    hashInt(&hash, u32, value.log_size);
    hashInt(&hash, u32, value.log_step);
    hashInt(&hash, u64, @intCast(value.offset));
    for (value.claimed_sum.toM31Array()) |coordinate| {
        hashInt(&hash, u32, coordinate.toU32());
    }
    var result: ir.Digest = undefined;
    hash.final(&result);
    return result;
}

pub fn protocol(value: pcs.PcsConfig) ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo/native/blake2s-pcs/protocol/v1");
    hashInt(&hash, u32, value.pow_bits);
    hashInt(&hash, u32, value.fri_config.log_blowup_factor);
    hashInt(&hash, u32, value.fri_config.log_last_layer_degree_bound);
    hashInt(&hash, u64, @intCast(value.fri_config.n_queries));
    hashInt(&hash, u32, value.fri_config.fold_step);
    hashInt(
        &hash,
        u32,
        if (value.lifting_log_size) |log_size| log_size + 1 else 0,
    );
    var result: ir.Digest = undefined;
    hash.final(&result);
    return result;
}

fn digest(value: []const u8) ir.Digest {
    @setEvalBranchQuota(100_000);
    return ir.identityDigest(value);
}

fn pairDigest(
    label: []const u8,
    left: ir.Digest,
    right: ir.Digest,
) ir.Digest {
    @setEvalBranchQuota(20_000);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(label);
    hash.update(&left);
    hash.update(&right);
    var result: ir.Digest = undefined;
    hash.final(&result);
    return result;
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

test "XOR identities bind both implementation and pinned Rust authority" {
    try std.testing.expect(!std.mem.eql(
        u8,
        &zig_artifact.trace_recipe,
        &rust_artifact.trace_recipe,
    ));
    try std.testing.expectEqual(@as(usize, 40), rust_artifact.revision.len);
    try std.testing.expect(!std.mem.allEqual(u8, &air, 0));
    try std.testing.expect(!std.mem.allEqual(u8, &ingress_recipe, 0));
}
