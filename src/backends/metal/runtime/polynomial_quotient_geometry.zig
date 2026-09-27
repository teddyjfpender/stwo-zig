//! Compatibility path for the shared original quotient-coset arithmetic.
const geometry = @import("stwo_core").poly.circle.quotient_geometry;
pub const MAX_DENOMINATORS = geometry.MAX_DENOMINATORS;
pub const Set = geometry.Set;
pub const derive = geometry.derive;
pub const words = geometry.words;

test {
    _ = geometry;
}
