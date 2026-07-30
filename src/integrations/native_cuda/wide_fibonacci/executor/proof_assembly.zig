//! Wide-Fibonacci facade for shared resident proof capture.

const shared = @import("../../common/proof_assembly.zig");

pub const captureTraceRoot = shared.captureTraceRoot;
pub const captureStaticTraceRoot = shared.captureStaticTraceRoot;
pub const captureSampledValues = shared.captureSampledValues;
pub const captureFriRoot = shared.captureFriRoot;
pub const captureLastLayer = shared.captureLastLayer;
pub const capturePowNonce = shared.capturePowNonce;
pub const validateLayout = shared.validateLayout;
