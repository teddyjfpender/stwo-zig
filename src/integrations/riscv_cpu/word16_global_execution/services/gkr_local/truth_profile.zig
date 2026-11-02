//! Receiver-owned Keccak source/tuple geometry. No producer-selected clearing
//! mode or old-v2 admission is implied by this profile authority.
const A = @import("stwo_riscv_frontend").rv64_air;
const K = A.crypto.keccak;
const Wire = @import("../wire.zig");
const R = @import("../roster.zig");
pub fn fromDeclaration(d: Wire.TruthDeclaration) !K.equations.BatchPolicy {
    if (d.family != .keccak) return error.InvalidWideTruthGeometry;
    const policy = try Wire.keccakPolicy(d.logs[1]);
    try K.layout.validateGeometryFor(policy.geometry(), d.calls, d.first_id, d.logs[0]);
    return policy;
}
pub fn validateDeclaration(d: Wire.TruthDeclaration) !void {
    if (d.family == .keccak) { _ = try fromDeclaration(d); } else try @import("v2_scope.zig").truthDeclaration(d);
}
pub fn validate(truth: R.Truth) !void {
    if (truth == .keccak) {
        const policy = try fromDeclaration(Wire.TruthDeclaration.from(truth));
        if (policy != truth.keccak.setup.policy) return error.InvalidWideTruthGeometry;
    } else try @import("v2_scope.zig").truth(truth);
}
