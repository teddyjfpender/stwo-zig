//! Provider checks for existing explicit families; no proof verification is implied.
const std = @import("std");
const core = @import("stwo_core");
const codec = @import("mod.zig");
const a = std.testing.allocator;
const Default = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const P1 = core.vcs.poseidon2_m31_merkle.Poseidon2M31MerkleHasher;
const P2 = core.vcs.poseidon2_m31_merkle.Poseidon2M31MerkleHasherV2;

fn Checks(comptime Secure: type, comptime H: type) type {
    return struct {
        const W = codec.ForHasher(Secure, H);
        fn fixture(allocator: std.mem.Allocator) !W.Proof {
            var hash: W.HashWire = undefined;
            for (&hash, 0..) |*byte, i| byte.* = @intCast(i + 1);
            var hashes = [_]W.HashWire{hash};
            var value: W.SecureWire = undefined;
            for (&value, 0..) |*coordinate, i| coordinate.* = @intCast(i + 1);
            var values = [_]W.SecureWire{value};
            var columns = [_][]W.SecureWire{ &values, &.{} };
            var trees = [_][][]W.SecureWire{ &columns, &.{} };
            var decommitments = [_]W.MerkleDecommitmentWire{.{ .hash_witness = &hashes }};
            var queried = [_]u32{ 5, 6 };
            var queried_columns = [_][]u32{ &queried, &.{} };
            var queried_trees = [_][][]u32{ &queried_columns, &.{} };
            const layer = W.FriLayerWire{ .fri_witness = &values, .decommitment = decommitments[0], .commitment = hash };
            var layers = [_]W.FriLayerWire{layer};
            var polynomial = [_]W.SecureWire{ value, value };
            const wire = W.ProofWire{
                .config = .{ .pow_bits = 26, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 70, .fold_step = 4 } },
                .commitments = &hashes,
                .sampled_values = &trees,
                .decommitments = &decommitments,
                .queried_values = &queried_trees,
                .proof_of_work = 0x123456789abcdef0,
                .fri_proof = .{ .first_layer = layer, .inner_layers = &layers, .last_layer_poly = &polynomial },
            };
            var proof = try W.wireToProof(allocator, wire);
            errdefer proof.deinit(allocator);
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();
            try std.testing.expectEqualDeep(wire, try W.proofToWire(arena.allocator(), proof));
            return proof;
        }
        fn roundtrip(allocator: std.mem.Allocator, binary: bool, bytes: []const u8) !void {
            var proof = if (binary) try W.decodeProofBytesBinary(allocator, bytes) else try W.decodeProofBytes(allocator, bytes);
            defer proof.deinit(allocator);
            const encoded = if (binary) try W.encodeProofBytesBinary(allocator, proof) else try W.encodeProofBytes(allocator, proof);
            defer allocator.free(encoded);
            try std.testing.expectEqualSlices(u8, bytes, encoded);
        }
        fn reconstruct(allocator: std.mem.Allocator, wire: W.ProofWire) !void {
            const Plain = core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
            var proof = try W.wireToProofFor(Plain, allocator, wire);
            defer proof.deinit(allocator);
            try std.testing.expect(@TypeOf(proof) == core.proof.ForField(Secure).StarkProof(Plain));
            try std.testing.expectEqualDeep(wire.commitments, proof.commitment_scheme_proof.commitments.items);
            try std.testing.expect(wire.commitments.ptr != proof.commitment_scheme_proof.commitments.items.ptr);
        }
    };
}

test "api signature: explicit families preserve selected proof authority" {
    inline for (.{ core.fields.qm31.QM31, core.fields.om31.OM31 }) |Secure| inline for (.{ Default, P1, P2 }) |H| {
        const W = codec.ForHasher(Secure, H);
        const decoded = @typeInfo(@typeInfo(@TypeOf(W.decodeProofBytesBinary)).@"fn".return_type.?).error_union.payload;
        try std.testing.expect(W.Hasher == H and decoded == core.proof.ForField(Secure).StarkProof(H));
    };
}

test "explicit hash families preserve framing coordinates and allocation ownership" {
    inline for (.{ core.fields.qm31.QM31, core.fields.om31.OM31 }, 0..) |Secure, field| {
        inline for (.{ Default, P1, P2 }, 0..) |H, family| {
            const C = Checks(Secure, H);
            const W = C.W;
            try std.testing.expect(W.Hasher == H);
            try std.testing.expect(W.Proof == core.proof.ForField(Secure).StarkProof(H));
            var proof = try C.fixture(a);
            defer proof.deinit(a);
            const headers = [2][3][]const u8{ .{ "STWOPRW1", "STP2QW01", "STP2QW02" }, .{ "STWOPRW8", "STP2OW01", "STP2OW02" } };
            for ([_]bool{ false, true }) |binary| {
                const bytes = if (binary) try W.encodeProofBytesBinary(a, proof) else try W.encodeProofBytes(a, proof);
                defer a.free(bytes);
                try C.roundtrip(a, binary, bytes);
                try std.testing.checkAllAllocationFailures(a, C.roundtrip, .{ binary, bytes });
                if (binary) {
                    try std.testing.expectEqualStrings(headers[field][family], bytes[0..8]);
                    const changed = try a.dupe(u8, bytes);
                    defer a.free(changed);
                    for (headers) |row| for (row) |header| {
                        if (std.mem.eql(u8, header, headers[field][family])) continue;
                        @memcpy(changed[0..8], header);
                        try std.testing.expectError(error.UnsupportedBinaryVersion, W.decodeProofBytesBinary(a, changed));
                    };
                } else if (comptime H != Default) {
                    const Other = codec.ForHasher(Secure, if (H == P1) P2 else P1);
                    try std.testing.expectError(error.UnsupportedBinaryVersion, Other.decodeProofBytes(a, bytes));
                }
            }
        }
    }
}

test "Poseidon wire rejects every noncanonical digest word before allocation without mutating input" {
    inline for (.{ core.fields.qm31.QM31, core.fields.om31.OM31 }) |Secure| {
        inline for (.{ P1, P2 }) |H| {
            const C = Checks(Secure, H);
            var proof = try C.fixture(a);
            defer proof.deinit(a);
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            var wire = try C.W.proofToWire(arena.allocator(), proof);
            const hashes = [_]*C.W.HashWire{ &wire.commitments[0], &wire.decommitments[0].hash_witness[0], &wire.fri_proof.first_layer.commitment, &wire.fri_proof.first_layer.decommitment.hash_witness[0], &wire.fri_proof.inner_layers[0].commitment, &wire.fri_proof.inner_layers[0].decommitment.hash_witness[0] };
            for (hashes) |hash| for (0..hash.len / 4) |coordinate| {
                const original = hash.*;
                defer hash.* = original;
                std.mem.writeInt(u32, hash[coordinate * 4 ..][0..4], core.fields.m31.Modulus, .little);
                const invalid = hash.*;
                var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
                try std.testing.expectError(error.NonCanonicalPoseidonDigest, C.W.wireToProof(failing.allocator(), wire));
                try std.testing.expectEqualDeep(invalid, hash.*);
                try std.testing.expectEqual(@as(usize, 0), failing.allocations);
            };
        }
    }
}

test "caller selected hash reconstruction owns bytes and does not authenticate algorithm choice" {
    inline for (.{ core.fields.qm31.QM31, core.fields.om31.OM31 }) |Secure| {
        const C = Checks(Secure, Default);
        var proof = try C.fixture(a);
        defer proof.deinit(a);
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const wire = try C.W.proofToWire(arena.allocator(), proof);
        try C.reconstruct(a, wire);
        try std.testing.checkAllAllocationFailures(a, C.reconstruct, .{wire});
    }
}
