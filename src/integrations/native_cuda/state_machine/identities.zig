//! Source- and protocol-bound identities for the Native state-machine adapter.

const std = @import("std");
const ir = @import("stwo_backend_contracts").proof_program;
const cpu_state_machine = @import(
    "../../../examples/state_machine/input.zig",
);
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
    .revision = "src/examples/state_machine.zig+src/examples/state_machine/input.zig",
    .trace_recipe = digest("stwo-zig/src/examples/state_machine/input.zig:prepare:v1"),
    .air_recipe = digest("stwo-zig/src/examples/state_machine.zig:StateMachineExampleComponent:v1"),
};

pub const rust_artifact = Artifact{
    .authority = rust_oracle_repository,
    .revision = rust_oracle_commit,
    .trace_recipe = digest(
        "stwo-rust:a8fcf4bd:examples-state_machine:gen-is-first+is-step+gen-state_machine-main:v1",
    ),
    .air_recipe = digest(
        "stwo-rust:a8fcf4bd:examples-state_machine:StateMachineComponent:v1",
    ),
};

pub const air = pairDigest(
    "stwo/native/state_machine/air/bilateral/v1",
    zig_artifact.air_recipe,
    rust_artifact.air_recipe,
);
pub const ingress_recipe = pairDigest(
    "stwo/native/state_machine/materialized-trace/bilateral/v1",
    zig_artifact.trace_recipe,
    rust_artifact.trace_recipe,
);
pub const ingress_layout = digest(
    "stwo/native/state_machine/trace-layout:m31-column-major:bit-reversed-circle:v1",
);
pub const transcript_recipe = digest(
    "stwo/native/state_machine/transcript:pcs,preprocessed,main,stmt0,draw-z,draw-alpha,public-input,stmt1:v1",
);
pub const public_input_abi = digest(
    "stwo/native/state_machine/public-input:initial-state[2xm31],final-state[2xm31]:v1",
);
pub const sampling_recipe = digest(
    "stwo/native/state_machine/oods:main-points,composition-split-points;preprocessed-unsampled:v1",
);
pub const mask_layout = digest(
    "stwo/native/state_machine/mask:preprocessed[[]],main[[0],[0]],interaction[],composition[8x[0]]:v1",
);
pub const constraint_parameter_abi = digest(
    "stwo/native/state_machine/constraint-abi:statement[14xu32le],alpha[4xm31],total[18xu32]:v1",
);
pub const constraint_expression = pairDigest(
    "stwo/native/state_machine/constraint:x-axis-claimed-sum+y-axis-claimed-sum:v1",
    zig_artifact.air_recipe,
    rust_artifact.air_recipe,
);

pub fn statement(value: cpu_state_machine.Request) ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo/native/state_machine/statement/v1");
    hashInt(&hash, u32, value.log_n_rows);
    hashInt(&hash, u32, value.initial_state[0].toU32());
    hashInt(&hash, u32, value.initial_state[1].toU32());
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
    @setEvalBranchQuota(100_000);
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

test "state-machine identities bind both implementation and pinned Rust authority" {
    try std.testing.expect(!std.mem.eql(
        u8,
        &zig_artifact.trace_recipe,
        &rust_artifact.trace_recipe,
    ));
    try std.testing.expectEqual(@as(usize, 40), rust_artifact.revision.len);
    try std.testing.expect(!std.mem.allEqual(u8, &air, 0));
    try std.testing.expect(!std.mem.allEqual(u8, &ingress_recipe, 0));
}
