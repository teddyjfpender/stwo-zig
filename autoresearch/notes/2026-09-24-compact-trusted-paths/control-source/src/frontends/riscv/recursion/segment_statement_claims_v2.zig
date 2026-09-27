//! Shared inactive-row claim contract for statement routing.
const QM31 = @import("stwo_core").fields.qm31.QM31;
const manifest_mod = @import("air/segment_outer_manifest_contract_v2.zig");

pub const ClaimsV2 = struct {
    row10_inactive: QM31 = QM31.zero(),
    row11_statement: QM31,

    pub fn validate(self: ClaimsV2) error{InactiveRowInvariantMismatch}!void {
        if (!self.row10_inactive.isZero())
            return error.InactiveRowInvariantMismatch;
    }

    pub fn asArray(self: ClaimsV2) [2]QM31 {
        return .{ self.row10_inactive, self.row11_statement };
    }

    pub fn bindInto(
        self: ClaimsV2,
        vector: *manifest_mod.ClaimVector,
    ) !void {
        try self.validate();
        try vector.bind(.statement_input, self.row10_inactive);
        try vector.bind(.statement_semantics_input, self.row11_statement);
    }
};
