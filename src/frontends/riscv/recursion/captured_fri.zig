//! Owned bridge from a successfully verified native FRI capture to row 29.
//!
//! The native verifier remains the authority for every value entering this
//! bridge. Construction snapshots the arithmetic inputs into two bulk arenas,
//! derives all position/offset fields, builds the profile-authenticated FRI
//! circuit, and requires an exact successful replay before publishing the
//! result. No slice in the published witness aliases decoded proof storage.
const shard_0 = @import("captured_fri_contract.zig");
const shard_1 = @import("captured_fri_owned.zig");

pub const Error = shard_0.Error;
pub const ProfileConfig = shard_0.ProfileConfig;
/// Immutable, independently replayed input authority for the universal FRI
/// verifier input and arithmetic rows. `init` accepts a pointer to the core
/// verifier's successful proof capture; the generic parameter deliberately
/// avoids coupling this leaf-owned bridge to one hash engine.
pub const Owned = shard_1.Owned;
