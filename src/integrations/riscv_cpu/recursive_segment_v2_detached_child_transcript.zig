//! Compatibility exports for the shared recursion owner.
const owner = @import("stwo_riscv_frontend").recursion.detached_child_capture_v1;
pub const CaptureViewV1 = owner.CaptureViewV1;
pub const FriLayerViewV1 = owner.FriLayerViewV1;
pub const TracePathViewV1 = owner.TracePathViewV1;
pub const RecordingViewV1 = owner.RecordingViewV1;
pub const Family = owner.Family;
pub const OwnedV1 = owner.OwnedV1;
pub const ParentOwnedV1 = owner.ParentOwnedV1;
pub const OwnedFor = owner.OwnedFor;

test "SegmentV2 detached child owns genuine capture and exact recorded transcript" {
    try owner.testOwnedCapture();
}
