//! Explicit strong native SegmentV2 child ingress for a future V3 wrapper.
//!
//! The key ID must come from independent setup. Constructing a key ID from
//! proof bytes or this function's returned capture is not independent pinning.
//! This module does not activate recursive V3 publication.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const native = @import("recursive_segment_v3_native_ingress.zig");
const prepared_mod = @import("recursive_segment_v2_leaf_outer.zig");

const recursion = frontend.recursion;
const Digest = recursion.poseidon2_channel.Digest;

pub const KEY_VERSION: u32 = 1;
pub const KEY_DOMAIN = "stwo-zig/riscv/v3-native-segment-v2-q193-key/v1\x00";
pub const PRODUCTION_PROOF_ACTIVATION = false;

/// Tree0 is independently recomputed by the native V2 verifier from the
/// authenticated statement. This additional pin selects the expected ELF and
/// fixed preprocessing at V3 ingress rather than accepting any valid program.
pub const PinnedKeyV1 = struct {
    version: u32 = KEY_VERSION,
    tree0_root: Digest,
    identity: [32]u8,

    pub fn admit(tree0_root: Digest, independently_pinned_identity: [32]u8) !PinnedKeyV1 {
        const candidate = PinnedKeyV1{
            .tree0_root = tree0_root,
            .identity = independently_pinned_identity,
        };
        try candidate.validate();
        return candidate;
    }

    pub fn validate(self: *const PinnedKeyV1) !void {
        if (self.version != KEY_VERSION or std.mem.allEqual(u8, &self.identity, 0))
            return error.InvalidV3NativeKey;
        var nonzero: u32 = 0;
        for (self.tree0_root) |word| {
            if (word >= core.fields.m31.Modulus) return error.InvalidV3NativeKey;
            nonzero |= word;
        }
        if (nonzero == 0 or !std.mem.eql(u8, &self.identity, &identity(self.tree0_root)))
            return error.V3NativeKeyPinMismatch;
    }

    pub fn validateCapture(self: *const PinnedKeyV1, comptime Engine: type, capture: *const frontend.prover_mod.VerifiedSegmentV2CaptureForEngine(Engine)) !void {
        try self.validate();
        try capture.validate();
        if (capture.proof.commitments.len == 0 or
            !std.meta.eql(capture.proof.commitments[0], self.tree0_root))
            return error.V3NativeTree0KeyMismatch;
    }
};

/// The recursive-preparation boundary carries the PCS profile and captured
/// interaction schedule beside the genuinely verified native proof. This
/// check uses those verifier-owned facts rather than caller-provided numbers.
pub fn admitPreparedNativeV2(
    prepared: *const prepared_mod.PreparedNativeV2LeafOuter,
    pinned_key: PinnedKeyV1,
) !void {
    if (!std.meta.eql(prepared.pcs_config, recursion.protocol.PCS_CONFIG))
        return error.V3NativePcsProfileMismatch;
    if (prepared.captured_fri.interaction_pow_bits != recursion.protocol.INTERACTION_POW_BITS)
        return error.V3NativeInteractionPowMismatch;
    try prepared.validate();
    try pinned_key.validateCapture(prepared_mod.Engine, &prepared.capture);
}

/// Setup helper for calculating a key ID from independently known Tree0. The
/// caller is responsible for pinning these bytes outside the proof transaction.
pub fn identity(root: Digest) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(KEY_DOMAIN);
    hashWord(&hash, KEY_VERSION);
    hashWord(&hash, recursion.protocol.INTERACTION_POW_BITS);
    const pcs = recursion.protocol.PCS_CONFIG;
    inline for (.{ pcs.pow_bits, pcs.fri_config.log_blowup_factor, pcs.fri_config.log_last_layer_degree_bound, @as(u32, @intCast(pcs.fri_config.n_queries)), pcs.fri_config.fold_step, @as(u32, @intFromBool(pcs.lifting_log_size != null)), pcs.lifting_log_size orelse 0 }) |value| hashWord(&hash, value);
    for (root) |word| hashWord(&hash, word);
    return hash.finalResult();
}

fn hashWord(hash: *std.crypto.hash.sha2.Sha256, value: u32) void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    hash.update(&bytes);
}

pub fn Verified(comptime Engine: type) type {
    return struct {
        native: native.Verified(Engine),
        pinned_key: PinnedKeyV1,

        pub fn validate(self: *const @This()) !void {
            try self.native.validate();
            try self.pinned_key.validateCapture(Engine, &self.native.capture);
        }

        pub fn deinit(self: *@This()) void {
            self.native.deinit();
            self.* = undefined;
        }
    };
}

/// Exactly the q193/fold4/PCS-PoW16 profile; native transcript verification
/// separately checks its frozen 10-bit interaction PoW before capture minting.
pub fn proveAndVerifyPinned(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    source: *const recursion.segment_leaf_local_authority_v3.SourceV3,
    session_id: recursion.segment_statement_v2.Digest,
    pinned_key: PinnedKeyV1,
) !Verified(Engine) {
    try (recursion.protocol.Profile{}).validate();
    try pinned_key.validate();
    var result = Verified(Engine){
        .native = try native.proveAndVerify(
            Engine,
            allocator,
            source,
            recursion.protocol.PCS_CONFIG,
            session_id,
        ),
        .pinned_key = pinned_key,
    };
    errdefer result.deinit();
    try result.validate();
    return result;
}
