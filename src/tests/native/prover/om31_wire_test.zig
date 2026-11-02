//! Real proof-file roundtrips, distinct from codec-only serialization fixtures.
const std = @import("std");
const core = @import("stwo_core");
const Fixture = @import("om31_stark_test.zig");
const Wire = @import("stwo_proof_wire").ForField(core.fields.om31.OM31);
const a = std.testing.allocator;

test "OM31 actual STARK JSON and binary proof files reach fresh receivers at fold1 and fold4" {
    for ([_]u32{ 1, 4 }) |fold| {
        var extended = try Fixture.produceTraceWithFold(a, false, fold);
        defer extended.deinit(a);
        for ([_]bool{ false, true }) |binary| {
            const bytes = if (binary) try Wire.encodeProofBytesBinary(a, extended.proof) else try Wire.encodeProofBytes(a, extended.proof);
            defer a.free(bytes);
            const decoded = if (binary) try Wire.decodeProofBytesBinary(a, bytes) else try Wire.decodeProofBytes(a, bytes);
            // verifyFold consumes the newly decoded owner, including rejection paths.
            try Fixture.verifyFold(a, decoded, fold);
            std.debug.print("OM31_WIRE_FRESH fold={d} binary={} bytes={d}\n", .{ fold, binary, bytes.len });
        }
    }
}

test "OM31 serialized upper-half OODS tamper fails fresh receiver" {
    var extended = try Fixture.produceTraceWithFold(a, false, 1);
    defer extended.deinit(a);
    const sample = &extended.proof.commitment_scheme_proof.sampled_values.items[1][0][0];
    sample.* = sample.add(core.fields.om31.OM31.basis());
    const bytes = try Wire.encodeProofBytesBinary(a, extended.proof);
    defer a.free(bytes);
    const decoded = try Wire.decodeProofBytesBinary(a, bytes);
    try std.testing.expectError(error.OodsNotMatching, Fixture.verifyFold(a, decoded, 1));
}
