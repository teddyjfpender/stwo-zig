//! Test-only backend policy for the shared tree0 comparison fixture.
//! The Metal integration selects the device; the CPU fixture remains generic.
pub const Backend = @import("stwo_metal_backend").MetalCommitBackend;
