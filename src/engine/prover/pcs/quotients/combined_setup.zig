//! Shared pooled M31 coefficient combination and aggregate FFT authority.
pub const ForCoordinates = @import("combined_setup_family.zig").ForCoordinates;
const Default = ForCoordinates(@import("stwo_core").fields.qm31.SECURE_EXTENSION_DEGREE, @import("../quotient_row_executor.zig").CombinedContributionView);
pub const Member = Default.Member;
pub const combine = Default.combine;
pub const evaluateCoefficientViews = Default.evaluateCoefficientViews;
