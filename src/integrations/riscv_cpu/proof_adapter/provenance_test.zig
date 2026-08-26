//! Build-identity and witness-layout binding checks for staged verification.

const std = @import("std");
const stwo = @import("stwo");
const build_identity = @import("build_identity");
const artifact_validation = @import("artifact_validation.zig");

test "staged verifier binds build and witness-layout provenance" {
    const artifact = stwo.interop.riscv_artifact;
    const layout = std.fmt.bytesToHex(stwo.frontends.riscv.witness_layout.digest(), .lower);
    var provenance = artifact.ProvenanceWire{
        .oracle_repository = artifact.ORACLE_REPOSITORY,
        .oracle_commit = artifact.ORACLE_COMMIT,
        .implementation_repository = artifact.IMPLEMENTATION_REPOSITORY,
        .implementation_commit = build_identity.implementation_commit,
        .implementation_dirty = build_identity.implementation_dirty,
        .witness_layout_sha256 = &layout,
    };
    try artifact_validation.validateLocalProvenance(provenance);

    provenance.implementation_commit = "00" ** 20;
    try std.testing.expectError(
        error.ImplementationIdentityMismatch,
        artifact_validation.validateLocalProvenance(provenance),
    );
    provenance.implementation_commit = build_identity.implementation_commit;
    provenance.witness_layout_sha256 = "00" ** 32;
    try std.testing.expectError(
        error.WitnessLayoutMismatch,
        artifact_validation.validateLocalProvenance(provenance),
    );
}
