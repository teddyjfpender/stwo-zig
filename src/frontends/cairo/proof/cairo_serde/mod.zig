//! Official field-element transport consumed by the Cairo verifier.

const std = @import("std");
const adapter = @import("../../adapter/mod.zig");
const composition = @import("../../witness/composition_bundle.zig");
const felt_json = @import("felt_json.zig");
const pcs = @import("pcs.zig");
const statement = @import("statement.zig");
const QM31 = @import("stwo_core").fields.qm31.QM31;

pub const validateInput = statement.validateInput;

pub fn writeDocument(
    allocator: std.mem.Allocator,
    writer: anytype,
    input: *const adapter.ProverInput,
    bundle: *const composition.Bundle,
    claimed_sums: []const QM31,
    interaction_pow: u64,
    channel_salt: u32,
    stark_proof: anytype,
) !void {
    var state = felt_json.State{};
    try felt_json.begin(writer);
    try statement.writeClaim(writer, &state, input, bundle);
    try felt_json.write(writer, &state, interaction_pow);
    try statement.writeFlattenedInteractionClaim(
        writer,
        &state,
        bundle,
        claimed_sums,
    );
    try pcs.write(
        allocator,
        writer,
        &state,
        stark_proof.commitment_scheme_proof,
        bundle,
    );
    try felt_json.write(writer, &state, channel_salt);
    try felt_json.end(writer, state);
}

test {
    _ = felt_json;
    _ = pcs;
    _ = statement;
}
