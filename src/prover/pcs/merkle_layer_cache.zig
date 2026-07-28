//! Optional external source for an already-computed Merkle layer set.
//!
//! The PCS never decides *whether* a tree may be loaded rather than built; it
//! only offers the seam. A frontend arms a source immediately around one commit
//! whose committed data it knows to be a pure function of the protocol identity,
//! and disarms straight afterwards. With nothing armed the prover behaves
//! exactly as it did before this module existed.
//!
//! The seam is deliberately non-generic: the hasher type stays a compile-time
//! parameter of the prover, and the source sees only opaque byte views plus a
//! structural description of what those bytes must be. That keeps artifact
//! formats, key derivation and filesystem policy out of the prover entirely.
//!
//! Soundness. A loaded tree can only ever change the committed root, and the
//! root is the single value the channel observes. A wrong root produces a
//! transcript the verifier does not reproduce, so a bad load fails closed at
//! `--verify` and at the official verifier rather than yielding an accepted
//! proof. The seam is an availability mechanism, never a soundness one, and the
//! prover additionally re-derives the top layers from their children before
//! accepting a load.

const std = @import("std");

/// Structural description of the tree a source is asked to supply.
///
/// Every field must participate in the source's key derivation: a tree is a
/// function of the hasher, the digest width, the committed domain and the exact
/// multiset of committed column heights.
pub const Request = struct {
    /// Compile-time identity of the Merkle hasher (`@typeName(H)`).
    hasher_tag: []const u8,
    /// Width of one digest in bytes.
    hash_bytes: u32,
    /// Log size of the committed domain; the layer set has `log_size + 1`
    /// layers, root first, with `layers[i].len == 1 << i`.
    log_size: u32,
    /// Committed column log sizes, ascending, as the committer sorted them.
    column_log_sizes: []const u32,
};

pub const LayerSource = struct {
    ctx: *anyopaque,

    /// Fills `layers` (root first, byte views over the prover's own storage)
    /// from an authenticated artifact. Returns `true` only when every byte was
    /// written and the artifact verified; on `false` the prover computes.
    load: *const fn (ctx: *anyopaque, request: Request, layers: []const []u8) bool,

    /// Records a freshly built layer set. Failures are absorbed by the source.
    store: *const fn (ctx: *anyopaque, request: Request, layers: []const []const u8) void,
};

var armed_source: ?LayerSource = null;

/// Arms a source for the immediately following commit on this thread.
pub fn arm(source: LayerSource) void {
    armed_source = source;
}

pub fn disarm() void {
    armed_source = null;
}

pub fn armed() ?LayerSource {
    return armed_source;
}

test "the seam is inert until armed" {
    try std.testing.expect(armed() == null);
}
