//! Compatibility import for proof and benchmark harnesses.
//!
//! The authority graduated to production when universal recursion began using
//! the canonical typed Poseidon2 provider. Keep the historical module path so
//! focused harnesses do not acquire a second construction path.

pub const ProgramIdentityError =
    @import("typed_poseidon2_authority.zig").ProgramIdentityError;
pub const Authority = @import("typed_poseidon2_authority.zig").Authority;
