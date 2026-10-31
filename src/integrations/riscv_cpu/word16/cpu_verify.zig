//! One physical verifier body. A delegated return is FUNCTION debt only; local
//! register/ROM/ranges close before it can leave this function. No RAM claim.
const std = @import("std");
const core = @import("stwo_core");
const wire = @import("stwo_proof_wire");
const W = @import("stwo_riscv_frontend").rv64_air.word16_cpu;
const Mat = @import("cpu_materials.zig");
const Stage = @import("cpu_stage.zig");
const Protocol = @import("cpu_protocol.zig");
const Components = @import("cpu_components.zig").Components;
const D = @import("../rv64_distributed_v1/manifest.zig");
const T = D.T;
const Q = core.fields.qm31.QM31;
const Mode = union(enum) { local, delegated: struct { manifest: *const D.Manifest, ordinal: usize } };
pub fn verifyClosed(a: std.mem.Allocator, materials: *const Mat.Materials, public: W.public.Public, encoded: Stage.Encoded) !void {
    if (materials.geometry.mode != .local_binary) return error.ExpectedClosedThinCpuMaterials;
    _ = try verify(a, materials, public, encoded, .local);
}
pub fn verifyOpen(a: std.mem.Allocator, materials: *const Mat.Materials, manifest: *const D.Manifest, ordinal: usize, public: W.public.Public, encoded: Stage.Encoded) !Q {
    if (materials.geometry.mode != .open_function) return error.ExpectedOpenThinCpuMaterials;
    if (ordinal >= manifest.specs.len) return error.DistributedInventoryMismatch;
    try Mat.validateSpec(materials, public, manifest.specs[ordinal]);
    if (!std.mem.eql(u8, &manifest.context.program_key, &materials.program.identity)) return error.ThinCpuProgramMismatch;
    return verify(a, materials, public, encoded, .{ .delegated = .{ .manifest = manifest, .ordinal = ordinal } });
}
fn verify(a: std.mem.Allocator, materials: *const Mat.Materials, public: W.public.Public, encoded: Stage.Encoded, mode: Mode) !Q {
    try public.validate(materials.geometry.cpu_log);
    try encoded.claims.validate(materials.geometry.mode);
    if (encoded.bytes.len > 64 * 1024 * 1024) return error.ThinCpuProofResourceLimit;
    var proof = try wire.decodeProofBytesBinary(a, encoded.bytes);
    var owns = true;
    defer if (owns) proof.deinit(a);
    const pcs = &proof.commitment_scheme_proof;
    if (!std.meta.eql(pcs.config, T.P.config()) or pcs.revision_config != null or pcs.commitments.items.len != 4) return error.InvalidThinCpuProof;
    if (!std.mem.eql(u8, &pcs.commitments.items[0], &materials.fixed_root.value)) return error.UnexpectedThinCpuFixedRoot;
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(T.P.Hasher, T.P.MerkleChannel).init(a, T.P.config());
    defer verifier.deinit(a);
    var channel = T.P.Channel{};
    switch (mode) {
        .local => try Protocol.mixLocal(&channel, materials, public),
        .delegated => |stage2| try D.beginStage1(stage2.manifest.context, stage2.manifest.specs[stage2.ordinal], &channel),
    }
    for ([_]usize{ 0, 1 }) |tree| {
        const logs = try materials.logs(a, tree);
        defer a.free(logs);
        try verifier.commit(a, pcs.commitments.items[tree], logs, &channel);
    }
    const draw = switch (mode) {
        .local => Protocol.drawLocal(&channel, null),
        .delegated => |stage2| Protocol.drawLocal(&channel, (try stage2.manifest.resumeReceiver(stage2.ordinal, &proof, &channel)).binary),
    };
    Protocol.mixClaims(&channel, encoded.claims);
    const logs = try materials.logs(a, 2);
    defer a.free(logs);
    try verifier.commit(a, pcs.commitments.items[2], logs, &channel);
    var components = try Components.init(materials, public, draw, encoded.claims, false);
    const handles = try components.verifiers(a);
    defer a.free(handles);
    owns = false;
    try core.verifier.verify(T.P.Hasher, T.P.MerkleChannel, a, handles, &channel, &verifier, proof);
    return encoded.claims.cpu.function;
}
