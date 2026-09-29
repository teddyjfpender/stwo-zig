//! Protocol-revision primitives for circuit recursion (proving@5a7c5ed):
//! config and transcript laws, explicit tree heights, channel profiles, word
//! hashing, ChaCha20Rng and QM31 lane helpers. The upstream PoW order is the
//! default Blake2s grind (`channel/blake2s_pow_order.zig`).
test {
    _ = @import("protocol_revision.zig");
    _ = @import("pcs/config_v2.zig");
    _ = @import("channel/lookup_transcript.zig");
    _ = @import("vcs_lifted/channel_profile.zig");
    _ = @import("vcs_lifted/verifier_height_test.zig");
    _ = @import("vcs_lifted/blake2_merkle.zig");
    _ = @import("crypto/chacha20_rng.zig");
    _ = @import("fields/qm31_pointwise.zig");
    _ = @import("preprocessed_tables.zig");
    _ = @import("cairo_air_layout.zig");
}
