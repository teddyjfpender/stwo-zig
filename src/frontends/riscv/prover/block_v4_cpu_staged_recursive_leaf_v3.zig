//! One bounded block-v4 recursive leaf from a staged native STARK.
//! The caller must first obtain `receipt` by fresh native/opcode-sidecar
//! verification under the same pinned SourceSeal. Global block closure and
//! the exact recursive forest remain separate admission steps.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Native = @import("blake3_ethereum_sha_proof.zig");
const sidecar = @import("block_execution_sidecar_batch_v2.zig");
const seal_mod = @import("block_memory_source_seal_v2.zig");
const parent = @import("../recursion/blake3_execution_parent_proof.zig");
const linked = @import("../recursion/blake3_exact_root_receiver_v3.zig");
const span = @import("../recursion/span_statement_blake3.zig");
const v3 = @import("../recursion/blake3_block_execution_span_v3.zig");

pub const Produced = struct {
    bytes: []u8,
    admission: parent.protocol.Admission,
    descriptor: linked.Descriptor,

    /// Materialize only this verified node for a bounded dyadic frontier.
    /// The caller releases it after folding; proof transport remains in bytes.
    pub fn openNode(self: *const Produced, a: std.mem.Allocator) !parent.tree.Node {
        var artifact = try parent.codec.decode(a, self.bytes, &self.admission);
        return parent.tree.Node.verifyOwned(&artifact, self.admission, self.admission.expected_id, self.descriptor.statement);
    }

    pub fn deinit(self: *Produced, a: std.mem.Allocator) void {
        a.free(self.bytes);
        self.* = undefined;
    }
};

/// Reopens exactly one staged native artifact and re-verifies its STARK before
/// building the v3 leaf witness. `prepared`, native key, span, SourceSeal and
/// sidecar receipt are independently pinned by the block receiver. This can
/// be called serially after core closure while retaining only one native
/// capture and one recursive leaf witness. The returned bytes can be written
/// immediately to a hashed proof file; no other execution artifact is needed.
pub fn prove(
    a: std.mem.Allocator,
    native_bytes: []const u8,
    prepared: *Native.ForBackend(Cpu).PreparedVerifier,
    native_key_id: [32]u8,
    statement: span.SpanStatement,
    seal: seal_mod.SourceSeal,
    receipt: *const sidecar.VerifiedExecutionReceipt,
    profile: parent.protocol.Profile,
) !Produced {
    if (!std.meta.eql(prepared.config, profile.config()))
        return error.UnexpectedBlockRecursiveSecurity;
    try prepared.validate(native_key_id);
    const native_proof = try Native.codec.decode(a, native_bytes, prepared, native_key_id);
    var capture = try Native.ForBackend(Cpu).verifyCaptureOwned(a, native_proof, prepared, native_key_id);
    defer capture.deinit();
    var witness = try v3.prepare(a, prepared, &capture, native_key_id, 2, statement, seal, receipt.witness_root, receipt);
    defer witness.deinit();
    const Api = parent.ForBackend(Cpu);
    const key = try Api.deriveKeyWithProfile(a, &witness, profile);
    const admission = try parent.protocol.Admission.init(key, try key.identity());
    const plan = try Api.Plan.init(a, &witness.rows, admission);
    defer plan.deinit();
    var artifact = try plan.prove(a, &witness.rows);
    defer artifact.deinit();
    const bytes = try parent.codec.encode(a, &artifact, &admission);
    errdefer a.free(bytes);
    // The same fresh recursive verification used by the complete receiver
    // yields a descriptor suitable for exact-count forest construction.
    const descriptor = try linked.verifyLeafBytes(a, bytes, admission, admission.expected_id, statement, &prepared.native.public_data, profile.config(), seal, native_key_id, receipt.native_roots, receipt.witness_root, receipt);
    return .{ .bytes = bytes, .admission = admission, .descriptor = descriptor };
}
