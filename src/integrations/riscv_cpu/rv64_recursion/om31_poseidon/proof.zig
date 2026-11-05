//! Capture conversion/shape checks shared with legacy; explicit P2 crypto type.
const Family = @import("crypto.zig").ProofFamily;
pub const NativeProof = Family.NativeProof;
pub const NativeCapture = Family.NativeCapture;
pub const CapturedLayer = Family.CapturedLayer;
pub const Captured = Family.Captured;
pub const Layer = Family.Layer;
pub const Proof = Family.Proof;
pub const fromNative = Family.fromNative;
pub const fromNativeCapped = Family.fromNativeCapped;
pub const guess = Family.guess;
