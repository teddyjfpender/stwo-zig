//! Detached v5 mixed-forest plus exact-root verification. Complete-block
//! authority still requires the fresh execution, program, memory, and source
//! closures before the caller may use the returned recursive root.
const std = @import("std");
const spans = @import("../recursion/span_statement_blake3.zig");
const linked = @import("../recursion/blake3_exact_root_receiver_v3.zig");
const parent = @import("../recursion/blake3_execution_parent_proof.zig");
const exact = @import("../recursion/blake3_exact_root_aggregate.zig");
const forest = @import("block_v5_mixed_forest_manifest_v1.zig");
const mixed_receiver = @import("block_v5_mixed_forest_receiver_v1.zig");
const outer = @import("block_v4_cpu_incremental_outer_stage.zig");

pub const Pin = struct {
    admission: parent.protocol.Admission,
    statement: spans.RootStatement,
    byte_len: usize,
    sha256: [32]u8,
};

/// Forest SHA and digest, the outer key ID, job and fresh leaf descriptors are
/// independent receiver policy. The `Pin` may be transported in a bundle but
/// cannot choose the expected key or the accepted complete-job statement.
pub fn verifyCanonical(
    a: std.mem.Allocator,
    dir: std.fs.Dir,
    forest_manifest_sha256: [32]u8,
    expected_forest_digest: [32]u8,
    job: spans.JobContext,
    profile: parent.protocol.Profile,
    fresh_leaves: []const linked.Descriptor,
    expected_outer_key_id: [32]u8,
    pin: Pin,
) !parent.tree.Node {
    try job.validate();
    if (pin.admission.key.profile != profile or
        !std.meta.eql(pin.admission.expected_id, expected_outer_key_id) or
        !std.meta.eql(pin.statement, try exact.expectedRoot(job)))
        return error.UntrustedMixedOuterPin;
    const roots = try forest.verifyCanonical(a, dir, forest_manifest_sha256, expected_forest_digest, job, profile, fresh_leaves);
    defer a.free(roots);
    if (pin.byte_len == 0 or pin.byte_len > mixed_receiver.MAX_PARENT_BYTES)
        return error.InvalidMixedOuterSize;
    var file = try dir.openFile(outer.OUTER_FILE, .{});
    defer file.close();
    if ((try file.stat()).size != pin.byte_len) return error.TamperedMixedOuter;
    const bytes = try file.readToEndAlloc(a, pin.byte_len);
    defer a.free(bytes);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    if (bytes.len != pin.byte_len or !std.meta.eql(digest, pin.sha256))
        return error.TamperedMixedOuter;
    return if (profile == .diagnostic_q8_pow0)
        linked.verifyDiagnosticExactBytes(a, bytes, pin.admission, expected_outer_key_id, job, roots)
    else
        linked.verifyExactBytes(a, bytes, pin.admission, expected_outer_key_id, job, roots);
}
