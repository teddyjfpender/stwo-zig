//! Compatibility exports for the shared recursion owner.
const owner = @import("stwo_riscv_frontend").recursion.detached_parent_statement_preparation_v1;
pub const InputSource = owner.InputSource;
pub const InputBinding = owner.InputBinding;
pub const OwnedV1 = owner.OwnedV1;
pub const testFromExpectedFiles = owner.testFromExpectedFiles;
pub const testStatementRejections = owner.testStatementRejections;

test "SegmentV2 detached parent folds actual child projections and constrains complete root" {
    try owner.testParentStatement();
}
