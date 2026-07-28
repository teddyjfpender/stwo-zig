//! Exact Rust-verifier binary payload before bzip2 compression.

const adapter = @import("../../adapter/mod.zig");
const composition = @import("../../witness/composition_bundle.zig");
const preprocessed = @import("../../preprocessed/trace.zig");
const binary = @import("writer.zig");
const pcs = @import("pcs.zig");
const statement = @import("statement.zig");
const QM31 = @import("stwo_core").fields.qm31.QM31;

pub fn writeDocument(
    output: anytype,
    input: *const adapter.ProverInput,
    bundle: *const composition.Bundle,
    claimed_sums: []const QM31,
    interaction_pow: u64,
    channel_salt: u32,
    variant: preprocessed.Variant,
    stark_proof: anytype,
) !void {
    try statement.writeClaim(output, input, bundle);
    try binary.int(output, u64, interaction_pow);
    try statement.writeInteractionClaim(output, bundle, claimed_sums);
    try pcs.write(output, stark_proof.commitment_scheme_proof);
    try binary.int(output, u32, channel_salt);
    try binary.int(output, u32, @intFromEnum(variant));
}

test {
    _ = binary;
    _ = pcs;
    _ = statement;
}
