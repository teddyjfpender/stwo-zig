//! Native verification of one batch proof with proof capture: the receiver
//! key's session (the transcript up to the interaction commitment and the
//! component roster), then the core verifier in capture mode so that every
//! Merkle path, FRI coset and DEEP answer is expanded per raw transcript
//! query. The capture is the fixed-width witness source of the leaf circuit;
//! the roster is the constraint authority the circuit instantiates over its
//! own lane. The session is pinned: its components borrow its challenges.
const std = @import("std");
const A = @import("../rv64_authenticated_execution.zig");
const Key = @import("../rv64_execution_verifier_key.zig");
const core = A.core;
const P = A.P;

pub const Capture = core.verifier.ProofCapture(P.Hasher);

pub const Verified = struct {
    allocator: std.mem.Allocator,
    session: Key.Session,
    capture: Capture,
    /// The channel right after the interaction commitment (before the
    /// composition draw); the circuit's channel must agree here.
    channel_before_core: P.Channel,

    pub fn roster(self: *const Verified) *const Key.Components {
        return &self.session.components;
    }
    pub fn deinit(self: *Verified) void {
        self.capture.deinit(self.allocator);
        self.session.deinit(self.allocator);
        self.allocator.destroy(self);
    }
};

/// Verifies `proof` (borrowed) exactly as `ReceiverKey.verifyOwned` does
/// and returns the pinned session plus the proof capture.
pub fn verify(a: std.mem.Allocator, key: *const Key.ReceiverKey, public: A.Public, claims: A.Claims, proof: *const P.Proof) !*Verified {
    const out = try a.create(Verified);
    errdefer a.destroy(out);
    out.allocator = a;
    try key.openSession(a, public, claims, proof, &out.session);
    errdefer out.session.deinit(a);
    out.channel_before_core = out.session.channel;
    try core.verifier.verifyBorrowedWithProofCapture(P.Hasher, P.MerkleChannel, a, out.session.components.verifiers(), &out.session.channel, &out.session.verifier, proof, &out.capture);
    return out;
}
