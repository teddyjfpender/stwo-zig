//! Hash-independent checked GKR terminal input to physical AIR binding.
//! This is a BORROWED view, valid only while its verified artifact owner lives.
//! Data.initChecked copies the succinct point/weights/challenges before return.
//! A receipt hash is deliberately absent: each protocol authenticates its full
//! digest separately. Constructing this value alone proves no source binding.
const core = @import("stwo_core");
const O = core.fields.om31.OM31;
pub const Checked = struct {
    artifact: *const @import("stwo_prover_engine").lookups.gkr_verifier.ForField(O).GkrArtifact,
    challenges: @import("challenges.zig").For(O),
    eta: O,
    pub fn validate(self: @This()) !void {
        if (self.artifact.claims_to_verify_by_instance.len != self.artifact.n_variables_by_instance.len) return error.LocalGkrProjectionShape;
    }
};
