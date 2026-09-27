//! Bounded native receiver for a complete roster of joint-transcript leaves.
//! The result certifies the listed STARK proofs and their shared PCS census.
//! It is not a complete block root until memory permutations, execution-span
//! continuity, initialization and recursive global closure are proven.
const std = @import("std");
const manifest_mod = @import("block_commitment_manifest.zig");
const Digest = [32]u8;
const max_proof_bytes = @import("../recursion/artifact_limits.zig").MAX_CANONICAL_PROOF_BYTES;
pub fn ForProfileBackend(comptime Profile: type, comptime Backend: type) type {
    const Leaf = @import("blake3_extension_proof.zig").ForProfile(Profile);
    const Api = Leaf.ForBackend(Backend);
    return struct {
        pub const Receipt = struct {
            a: std.mem.Allocator,
            manifest: manifest_mod.Sealed,
            transcript_digests: []Digest,
            pub fn deinit(self: *Receipt) void {
                self.a.free(self.transcript_digests);
                self.* = undefined;
            }
        };
        /// `context`, admissions, key pointers and ordered paths must be
        /// selected independently by the receiver. Each proof is decoded and
        /// released in both passes; retained memory does not grow with proof count.
        pub fn verifyPaths(a: std.mem.Allocator, dir: std.fs.Dir, context: manifest_mod.Context, admissions: []const manifest_mod.Admission, prepared: []const *Api.PreparedVerifier, paths: []const []const u8) !Receipt {
            if (admissions.len == 0 or admissions.len != prepared.len or admissions.len != paths.len) return error.InvalidComponentCensus;
            var builder = try manifest_mod.Builder.init(context, admissions);
            const roots = try a.alloc([2]Digest, paths.len);
            defer a.free(roots);
            for (paths, prepared, admissions, roots, 0..) |path, key, admission, *pair, i| {
                if (admission.instance.index != i or !std.meta.eql(key.root, admission.fixed_root)) return error.UntrustedComponentRoot;
                try key.validate(admission.key_id);
                const bytes = try dir.readFileAlloc(a, path, max_proof_bytes);
                defer a.free(bytes);
                var proof = try Leaf.codec.decode(a, bytes, key, admission.key_id);
                defer proof.deinit(a);
                if (proof.stark.commitment_scheme_proof.commitments.items.len != 4) return error.InvalidExecutionProof;
                pair.* = proof.stark.commitment_scheme_proof.commitments.items[0..2].*;
                try builder.append(@intCast(i), pair.*);
            }
            const manifest = try builder.seal();
            const digests = try a.alloc(Digest, paths.len);
            errdefer a.free(digests);
            for (paths, prepared, admissions, roots, 0..) |path, key, admission, pair, i| {
                const bytes = try dir.readFileAlloc(a, path, max_proof_bytes);
                defer a.free(bytes);
                const proof = try Leaf.codec.decode(a, bytes, key, admission.key_id);
                digests[i] = try Api.verifyWithManifestOwned(a, proof, key, admission.key_id, pair, manifest);
            }
            return .{ .a = a, .manifest = manifest, .transcript_digests = digests };
        }
    };
}
