//! Secure-field-explicit proof wire codec. Legacy QM31 bytes retain their v1 contract.
const std = @import("std");
const core = @import("stwo_core");
const m31 = core.fields.m31;
const line = core.poly.line;
const vcs_verifier = core.vcs_lifted.verifier;
const blake2_merkle = core.vcs_lifted.blake2_merkle;
const M31 = m31.M31;

pub fn ForField(comptime Secure: type) type {
    const DEGREE = @typeInfo(@TypeOf(Secure.zero().toM31Array())).array.len;
    if (Secure != core.fields.qm31.QM31 and Secure != core.fields.om31.OM31)
        @compileError("proof wire supports only the qualified QM31 and OM31 field authorities");
    return struct {
        const fri = core.fri.ForField(Secure);
        const pcs = core.pcs.ForField(Secure);
        const proof_mod = core.proof.ForField(Secure);
        /// Default QM31 exchange preserves pinned raw Stwo `a8fcf4bd`;
        /// explicit OM31 uses a distinct eight-coordinate wire version.
        pub const Hasher = blake2_merkle.Blake2sPrefixedMerkleHasher;
        pub const Proof = proof_mod.StarkProof(Hasher);
        const MerkleDecommitment = vcs_verifier.MerkleDecommitmentLifted(Hasher);

        pub const FriConfigWire = struct {
            log_blowup_factor: u32,
            log_last_layer_degree_bound: u32,
            n_queries: u64,
            fold_step: u32 = 1,
        };

        pub const PcsConfigWire = struct {
            pow_bits: u32,
            fri_config: FriConfigWire,
            lifting_log_size: ?u32 = null,
        };

        pub const SecureWire = [DEGREE]u32;
        pub const HashWire = [32]u8;

        pub const MerkleDecommitmentWire = struct {
            hash_witness: []HashWire,
        };

        pub const FriLayerWire = struct {
            fri_witness: []SecureWire,
            decommitment: MerkleDecommitmentWire,
            commitment: HashWire,
        };

        pub const FriProofWire = struct {
            first_layer: FriLayerWire,
            inner_layers: []FriLayerWire,
            last_layer_poly: []SecureWire,
        };

        pub const ProofWire = struct {
            config: PcsConfigWire,
            commitments: []HashWire,
            sampled_values: [][][]SecureWire,
            decommitments: []MerkleDecommitmentWire,
            queried_values: [][][]u32,
            proof_of_work: u64,
            fri_proof: FriProofWire,
        };

        pub const CodecError = error{
            NonCanonicalM31,
            ValueOutOfRange,
            InvalidBinaryProof,
            UnsupportedBinaryVersion,
        };

        const BINARY_WIRE_MAGIC = if (DEGREE == 4) "STWOPRW1" else "STWOPRW8";
        const JSON_PROTOCOL = "stwo-om31-proof-v1";
        const Envelope = struct { protocol: []const u8, proof: ProofWire };

        /// Encodes a Stark proof into wire bytes for cross-language interchange.
        pub fn encodeProofBytes(allocator: std.mem.Allocator, proof: Proof) ![]u8 {
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();

            const wire = try proofToWire(arena.allocator(), proof);
            return std.json.Stringify.valueAlloc(allocator, if (DEGREE == 4) wire else Envelope{ .protocol = JSON_PROTOCOL, .proof = wire }, .{});
        }

        /// Encodes a Stark proof directly to hex JSON-wire bytes without allocating an
        /// intermediate raw byte buffer.
        pub fn encodeProofHexAlloc(allocator: std.mem.Allocator, proof: Proof) ![]u8 {
            const bytes = try encodeProofBytes(allocator, proof);
            defer allocator.free(bytes);

            const out = try allocator.alloc(u8, bytes.len * 2);
            const alphabet = "0123456789abcdef";
            for (bytes, 0..) |byte, i| {
                out[2 * i] = alphabet[byte >> 4];
                out[2 * i + 1] = alphabet[byte & 0x0f];
            }
            return out;
        }

        /// Decodes wire bytes into a Stark proof with owned allocations.
        pub fn decodeProofBytes(allocator: std.mem.Allocator, encoded: []const u8) !Proof {
            const parsed = try std.json.parseFromSlice(if (DEGREE == 4) ProofWire else Envelope, allocator, encoded, .{
                .ignore_unknown_fields = false,
            });
            defer parsed.deinit();

            if (DEGREE == 8 and !std.mem.eql(u8, parsed.value.protocol, JSON_PROTOCOL)) return CodecError.UnsupportedBinaryVersion;
            return wireToProof(allocator, if (DEGREE == 4) parsed.value else parsed.value.proof);
        }

        /// Encodes a Stark proof into a compact binary wire format for internal benchmarking.
        ///
        /// Format:
        /// - 8-byte magic/version header.
        /// - little-endian scalar fields and u32 length-prefixed vectors.
        pub fn encodeProofBytesBinary(allocator: std.mem.Allocator, proof: Proof) ![]u8 {
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();

            const wire = try proofToWire(arena.allocator(), proof);
            var out = std.ArrayList(u8).empty;
            errdefer out.deinit(allocator);
            const writer = out.writer(allocator);

            try writer.writeAll(BINARY_WIRE_MAGIC);
            try writeProofWireBinary(writer, wire);
            return out.toOwnedSlice(allocator);
        }

        /// Decodes a compact binary wire payload produced by `encodeProofBytesBinary`.
        pub fn decodeProofBytesBinary(allocator: std.mem.Allocator, encoded: []const u8) !Proof {
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();

            var cursor = BinaryCursor.init(encoded);
            const wire = try readProofWireBinary(arena.allocator(), &cursor);
            if (!cursor.done()) return CodecError.InvalidBinaryProof;
            return wireToProof(allocator, wire);
        }

        /// Materializes the canonical interchange shape from an owned STARK proof.
        pub fn proofToWire(allocator: std.mem.Allocator, proof: Proof) !ProofWire {
            const pcs_proof = proof.commitment_scheme_proof;

            const commitments = try allocator.alloc(HashWire, pcs_proof.commitments.items.len);
            for (pcs_proof.commitments.items, 0..) |commitment, i| commitments[i] = commitment;

            const sampled_values = try encodeTreeSecure(allocator, pcs_proof.sampled_values.items);
            const decommitments = try encodeDecommitments(allocator, pcs_proof.decommitments.items);
            const queried_values = try encodeTreeM31(allocator, pcs_proof.queried_values.items);
            const fri_proof_wire = try encodeFriProof(allocator, pcs_proof.fri_proof);

            return .{
                .config = .{
                    .pow_bits = pcs_proof.config.pow_bits,
                    .fri_config = .{
                        .log_blowup_factor = pcs_proof.config.fri_config.log_blowup_factor,
                        .log_last_layer_degree_bound = pcs_proof.config.fri_config.log_last_layer_degree_bound,
                        .n_queries = pcs_proof.config.fri_config.n_queries,
                        .fold_step = pcs_proof.config.fri_config.fold_step,
                    },
                    .lifting_log_size = pcs_proof.config.lifting_log_size,
                },
                .commitments = commitments,
                .sampled_values = sampled_values,
                .decommitments = decommitments,
                .queried_values = queried_values,
                .proof_of_work = pcs_proof.proof_of_work,
                .fri_proof = fri_proof_wire,
            };
        }

        /// Converts a validated wire shape into an independently owned STARK proof.
        pub fn wireToProof(allocator: std.mem.Allocator, wire: ProofWire) !Proof {
            return wireToProofFor(Hasher, allocator, wire);
        }

        /// Decode the same wire contract under a caller-selected Blake2s Merkle
        /// domain. Circuit recursion uses plain Blake2s; the historical exchange
        /// format uses prefixed Blake2s. Hash bytes are identical in representation.
        pub fn wireToProofFor(comptime H: type, allocator: std.mem.Allocator, wire: ProofWire) !proof_mod.StarkProof(H) {
            if (!validLastPolyLength(wire.fri_proof.last_layer_poly.len)) return CodecError.ValueOutOfRange;
            if (wire.config.fri_config.n_queries > std.math.maxInt(usize)) return CodecError.ValueOutOfRange;

            var fri_config = try fri.FriConfig.init(
                wire.config.fri_config.log_last_layer_degree_bound,
                wire.config.fri_config.log_blowup_factor,
                @intCast(wire.config.fri_config.n_queries),
            );
            fri_config.fold_step = wire.config.fri_config.fold_step;
            const config = pcs.PcsConfig{
                .pow_bits = wire.config.pow_bits,
                .fri_config = fri_config,
                .lifting_log_size = wire.config.lifting_log_size,
            };

            const commitments = pcs.TreeVec(HashWire).initOwned(try allocator.dupe(HashWire, wire.commitments));
            errdefer {
                var c = commitments;
                c.deinit(allocator);
            }

            const sampled_values = try decodeTreeSecure(allocator, wire.sampled_values);
            errdefer {
                var sv = sampled_values;
                sv.deinitDeep(allocator);
            }

            const decommitments = try decodeDecommitmentsFor(H, allocator, wire.decommitments);
            errdefer {
                var ds = decommitments;
                for (ds.items) |*decommitment| decommitment.deinit(allocator);
                ds.deinit(allocator);
            }

            const queried_values = try decodeTreeM31(allocator, wire.queried_values);
            errdefer {
                var qv = queried_values;
                qv.deinitDeep(allocator);
            }

            const fri_proof = try decodeFriProofFor(H, allocator, wire.fri_proof);
            errdefer {
                var fp = fri_proof;
                fp.deinit(allocator);
            }

            return .{
                .commitment_scheme_proof = .{
                    .config = config,
                    .commitments = commitments,
                    .sampled_values = sampled_values,
                    .decommitments = decommitments,
                    .queried_values = queried_values,
                    .proof_of_work = wire.proof_of_work,
                    .fri_proof = fri_proof,
                },
            };
        }

        fn encodeTreeSecure(allocator: std.mem.Allocator, tree: []const [][]Secure) ![][][]SecureWire {
            const out = try allocator.alloc([][]SecureWire, tree.len);
            for (tree, 0..) |tree_cols, tree_idx| {
                out[tree_idx] = try allocator.alloc([]SecureWire, tree_cols.len);
                for (tree_cols, 0..) |col, col_idx| {
                    out[tree_idx][col_idx] = try allocator.alloc(SecureWire, col.len);
                    for (col, 0..) |value, value_idx| {
                        out[tree_idx][col_idx][value_idx] = secureToWire(value);
                    }
                }
            }
            return out;
        }

        fn encodeTreeM31(allocator: std.mem.Allocator, tree: []const [][]M31) ![][][]u32 {
            const out = try allocator.alloc([][]u32, tree.len);
            for (tree, 0..) |tree_cols, tree_idx| {
                out[tree_idx] = try allocator.alloc([]u32, tree_cols.len);
                for (tree_cols, 0..) |col, col_idx| {
                    out[tree_idx][col_idx] = try allocator.alloc(u32, col.len);
                    for (col, 0..) |value, value_idx| {
                        out[tree_idx][col_idx][value_idx] = value.toU32();
                    }
                }
            }
            return out;
        }

        fn encodeDecommitments(
            allocator: std.mem.Allocator,
            decommitments: []const MerkleDecommitment,
        ) ![]MerkleDecommitmentWire {
            const out = try allocator.alloc(MerkleDecommitmentWire, decommitments.len);
            for (decommitments, 0..) |decommitment, i| {
                out[i] = .{
                    .hash_witness = try allocator.dupe(HashWire, decommitment.hash_witness),
                };
            }
            return out;
        }

        fn encodeFriProof(allocator: std.mem.Allocator, fri_proof: fri.FriProof(Hasher)) !FriProofWire {
            const first_layer = try encodeFriLayer(allocator, fri_proof.first_layer);

            const inner_layers = try allocator.alloc(FriLayerWire, fri_proof.inner_layers.len);
            for (fri_proof.inner_layers, 0..) |layer, i| {
                inner_layers[i] = try encodeFriLayer(allocator, layer);
            }

            const last_layer_poly = try allocator.alloc(SecureWire, fri_proof.last_layer_poly.coefficients().len);
            for (fri_proof.last_layer_poly.coefficients(), 0..) |coeff, i| {
                last_layer_poly[i] = secureToWire(coeff);
            }

            return .{
                .first_layer = first_layer,
                .inner_layers = inner_layers,
                .last_layer_poly = last_layer_poly,
            };
        }

        fn encodeFriLayer(allocator: std.mem.Allocator, layer: fri.FriLayerProof(Hasher)) !FriLayerWire {
            const fri_witness = try allocator.alloc(SecureWire, layer.fri_witness.len);
            for (layer.fri_witness, 0..) |value, i| fri_witness[i] = secureToWire(value);

            return .{
                .fri_witness = fri_witness,
                .decommitment = .{
                    .hash_witness = try allocator.dupe(HashWire, layer.decommitment.hash_witness),
                },
                .commitment = layer.commitment,
            };
        }

        fn decodeTreeSecure(allocator: std.mem.Allocator, tree: []const [][]SecureWire) !pcs.TreeVec([][]Secure) {
            const out = try allocator.alloc([][]Secure, tree.len);
            errdefer allocator.free(out);

            var initialized: usize = 0;
            errdefer {
                for (out[0..initialized]) |tree_cols| freeSecureTree(allocator, tree_cols);
            }

            for (tree, 0..) |tree_cols, i| {
                out[i] = try decodeSecureTree(allocator, tree_cols);
                initialized += 1;
            }
            return pcs.TreeVec([][]Secure).initOwned(out);
        }

        fn decodeTreeM31(allocator: std.mem.Allocator, tree: []const [][]u32) !pcs.TreeVec([][]M31) {
            const out = try allocator.alloc([][]M31, tree.len);
            errdefer allocator.free(out);

            var initialized: usize = 0;
            errdefer {
                for (out[0..initialized]) |tree_cols| freeM31Tree(allocator, tree_cols);
            }

            for (tree, 0..) |tree_cols, i| {
                out[i] = try decodeM31Tree(allocator, tree_cols);
                initialized += 1;
            }
            return pcs.TreeVec([][]M31).initOwned(out);
        }

        fn decodeSecureTree(allocator: std.mem.Allocator, tree_cols: []const []SecureWire) ![][]Secure {
            const out = try allocator.alloc([]Secure, tree_cols.len);
            errdefer allocator.free(out);

            var initialized: usize = 0;
            errdefer {
                for (out[0..initialized]) |col| allocator.free(col);
            }

            for (tree_cols, 0..) |col, i| {
                out[i] = try allocator.alloc(Secure, col.len);
                errdefer allocator.free(out[i]);
                for (col, 0..) |value, j| {
                    out[i][j] = try secureFromWire(value);
                }
                initialized += 1;
            }
            return out;
        }

        fn decodeM31Tree(allocator: std.mem.Allocator, tree_cols: []const []u32) ![][]M31 {
            const out = try allocator.alloc([]M31, tree_cols.len);
            errdefer allocator.free(out);

            var initialized: usize = 0;
            errdefer {
                for (out[0..initialized]) |col| allocator.free(col);
            }

            for (tree_cols, 0..) |col, i| {
                out[i] = try allocator.alloc(M31, col.len);
                errdefer allocator.free(out[i]);
                for (col, 0..) |value, j| {
                    out[i][j] = try m31FromU32(value);
                }
                initialized += 1;
            }
            return out;
        }

        fn decodeDecommitments(
            allocator: std.mem.Allocator,
            decommitments: []const MerkleDecommitmentWire,
        ) !pcs.TreeVec(MerkleDecommitment) {
            return decodeDecommitmentsFor(Hasher, allocator, decommitments);
        }

        fn decodeDecommitmentsFor(
            comptime H: type,
            allocator: std.mem.Allocator,
            decommitments: []const MerkleDecommitmentWire,
        ) !pcs.TreeVec(vcs_verifier.MerkleDecommitmentLifted(H)) {
            const D = vcs_verifier.MerkleDecommitmentLifted(H);
            const out = try allocator.alloc(D, decommitments.len);
            errdefer allocator.free(out);

            var initialized: usize = 0;
            errdefer {
                for (out[0..initialized]) |*decommitment| decommitment.deinit(allocator);
            }

            for (decommitments, 0..) |decommitment, i| {
                out[i] = .{
                    .hash_witness = try allocator.dupe(HashWire, decommitment.hash_witness),
                };
                initialized += 1;
            }

            return pcs.TreeVec(D).initOwned(out);
        }

        fn decodeFriProof(allocator: std.mem.Allocator, wire: FriProofWire) !fri.FriProof(Hasher) {
            return decodeFriProofFor(Hasher, allocator, wire);
        }

        fn decodeFriProofFor(comptime H: type, allocator: std.mem.Allocator, wire: FriProofWire) !fri.FriProof(H) {
            const first_layer = try decodeFriLayerFor(H, allocator, wire.first_layer);
            errdefer {
                var layer = first_layer;
                layer.deinit(allocator);
            }

            const inner_layers = try allocator.alloc(fri.FriLayerProof(H), wire.inner_layers.len);
            errdefer allocator.free(inner_layers);

            var initialized: usize = 0;
            errdefer {
                for (inner_layers[0..initialized]) |*layer| layer.deinit(allocator);
            }

            for (wire.inner_layers, 0..) |layer, i| {
                inner_layers[i] = try decodeFriLayerFor(H, allocator, layer);
                initialized += 1;
            }

            const coeffs = try allocator.alloc(Secure, wire.last_layer_poly.len);
            errdefer allocator.free(coeffs);
            for (wire.last_layer_poly, 0..) |coeff, i| coeffs[i] = try secureFromWire(coeff);

            return .{
                .first_layer = first_layer,
                .inner_layers = inner_layers,
                .last_layer_poly = line.LinePolyFor(Secure).initOwned(coeffs),
            };
        }

        fn decodeFriLayer(allocator: std.mem.Allocator, wire: FriLayerWire) !fri.FriLayerProof(Hasher) {
            return decodeFriLayerFor(Hasher, allocator, wire);
        }

        fn decodeFriLayerFor(comptime H: type, allocator: std.mem.Allocator, wire: FriLayerWire) !fri.FriLayerProof(H) {
            const fri_witness = try allocator.alloc(Secure, wire.fri_witness.len);
            errdefer allocator.free(fri_witness);
            for (wire.fri_witness, 0..) |value, i| {
                fri_witness[i] = try secureFromWire(value);
            }

            return .{
                .fri_witness = fri_witness,
                .decommitment = .{
                    .hash_witness = try allocator.dupe(HashWire, wire.decommitment.hash_witness),
                },
                .commitment = wire.commitment,
            };
        }

        fn freeSecureTree(allocator: std.mem.Allocator, tree_cols: [][]Secure) void {
            for (tree_cols) |col| allocator.free(col);
            allocator.free(tree_cols);
        }

        fn freeM31Tree(allocator: std.mem.Allocator, tree_cols: [][]M31) void {
            for (tree_cols) |col| allocator.free(col);
            allocator.free(tree_cols);
        }

        fn m31FromU32(value: u32) CodecError!M31 {
            if (value >= m31.Modulus) return CodecError.NonCanonicalM31;
            return M31.fromCanonical(value);
        }

        fn secureFromWire(value: SecureWire) CodecError!Secure {
            var coordinates: [DEGREE]M31 = undefined;
            for (value, 0..) |coordinate, i| coordinates[i] = try m31FromU32(coordinate);
            return Secure.fromM31Array(coordinates);
        }

        fn secureToWire(value: Secure) SecureWire {
            var out: SecureWire = undefined;
            for (value.toM31Array(), 0..) |coordinate, i| out[i] = coordinate.toU32();
            return out;
        }

        fn validLastPolyLength(len: usize) bool {
            return len != 0 and (len & (len - 1)) == 0;
        }

        const BinaryCursor = struct {
            bytes: []const u8,
            at: usize = 0,

            fn init(bytes: []const u8) BinaryCursor {
                return .{ .bytes = bytes, .at = 0 };
            }

            fn done(self: BinaryCursor) bool {
                return self.at == self.bytes.len;
            }

            fn readBytes(self: *BinaryCursor, n: usize) CodecError![]const u8 {
                const end = std.math.add(usize, self.at, n) catch return CodecError.InvalidBinaryProof;
                if (end > self.bytes.len) return CodecError.InvalidBinaryProof;
                const out = self.bytes[self.at..end];
                self.at = end;
                return out;
            }

            fn readU32(self: *BinaryCursor) CodecError!u32 {
                const raw = try self.readBytes(@sizeOf(u32));
                return std.mem.readInt(u32, raw[0..@sizeOf(u32)], .little);
            }

            fn readU64(self: *BinaryCursor) CodecError!u64 {
                const raw = try self.readBytes(@sizeOf(u64));
                return std.mem.readInt(u64, raw[0..@sizeOf(u64)], .little);
            }

            /// Check the wire's minimum bytes per item BEFORE allocating a vector.
            /// Division avoids count*size overflow, including on 32-bit receivers.
            fn readCount(self: *BinaryCursor, comptime min_item_bytes: usize) CodecError!usize {
                comptime std.debug.assert(min_item_bytes > 0);
                const n: usize = @intCast(try self.readU32());
                if (n > (self.bytes.len - self.at) / min_item_bytes) return CodecError.InvalidBinaryProof;
                return n;
            }
        };

        fn writeCount(writer: anytype, n: usize) !void {
            if (n > std.math.maxInt(u32)) return CodecError.ValueOutOfRange;
            try writer.writeInt(u32, @intCast(n), .little);
        }

        fn writeSecureWire(writer: anytype, value: SecureWire) !void {
            for (value) |coordinate| try writer.writeInt(u32, coordinate, .little);
        }

        fn readSecureWire(cursor: *BinaryCursor) CodecError!SecureWire {
            var out: SecureWire = undefined;
            for (&out) |*coordinate| coordinate.* = try cursor.readU32();
            return out;
        }

        fn writeHashWire(writer: anytype, hash: HashWire) !void {
            try writer.writeAll(hash[0..]);
        }

        fn readHashWire(cursor: *BinaryCursor) CodecError!HashWire {
            var out: HashWire = undefined;
            const raw = try cursor.readBytes(out.len);
            @memcpy(out[0..], raw);
            return out;
        }

        fn writeMerkleDecommitmentWire(writer: anytype, value: MerkleDecommitmentWire) !void {
            try writeCount(writer, value.hash_witness.len);
            for (value.hash_witness) |hash| try writeHashWire(writer, hash);
        }

        fn readMerkleDecommitmentWire(
            allocator: std.mem.Allocator,
            cursor: *BinaryCursor,
        ) !MerkleDecommitmentWire {
            const witness_len = try cursor.readCount(32);
            const witness = try allocator.alloc(HashWire, witness_len);
            for (witness) |*hash| hash.* = try readHashWire(cursor);
            return .{ .hash_witness = witness };
        }

        fn writeFriLayerWire(writer: anytype, layer: FriLayerWire) !void {
            try writeCount(writer, layer.fri_witness.len);
            for (layer.fri_witness) |value| try writeSecureWire(writer, value);
            try writeMerkleDecommitmentWire(writer, layer.decommitment);
            try writeHashWire(writer, layer.commitment);
        }

        fn readFriLayerWire(
            allocator: std.mem.Allocator,
            cursor: *BinaryCursor,
        ) !FriLayerWire {
            const witness_len = try cursor.readCount(4 * DEGREE);
            const fri_witness = try allocator.alloc(SecureWire, witness_len);
            for (fri_witness) |*value| value.* = try readSecureWire(cursor);

            const decommitment = try readMerkleDecommitmentWire(allocator, cursor);
            const commitment = try readHashWire(cursor);
            return .{
                .fri_witness = fri_witness,
                .decommitment = decommitment,
                .commitment = commitment,
            };
        }

        fn writeProofWireBinary(writer: anytype, wire: ProofWire) !void {
            try writer.writeInt(u32, wire.config.pow_bits, .little);
            try writer.writeInt(u32, wire.config.fri_config.log_blowup_factor, .little);
            try writer.writeInt(u32, wire.config.fri_config.log_last_layer_degree_bound, .little);
            if (wire.config.fri_config.n_queries > std.math.maxInt(u32)) return CodecError.ValueOutOfRange;
            try writer.writeInt(u32, @intCast(wire.config.fri_config.n_queries), .little);
            try writer.writeInt(u32, wire.config.fri_config.fold_step, .little);
            try writer.writeInt(u32, wire.config.lifting_log_size orelse std.math.maxInt(u32), .little);

            try writeCount(writer, wire.commitments.len);
            for (wire.commitments) |hash| try writeHashWire(writer, hash);

            try writeCount(writer, wire.sampled_values.len);
            for (wire.sampled_values) |tree| {
                try writeCount(writer, tree.len);
                for (tree) |column| {
                    try writeCount(writer, column.len);
                    for (column) |value| try writeSecureWire(writer, value);
                }
            }

            try writeCount(writer, wire.decommitments.len);
            for (wire.decommitments) |decommitment| {
                try writeMerkleDecommitmentWire(writer, decommitment);
            }

            try writeCount(writer, wire.queried_values.len);
            for (wire.queried_values) |tree| {
                try writeCount(writer, tree.len);
                for (tree) |column| {
                    try writeCount(writer, column.len);
                    for (column) |value| try writer.writeInt(u32, value, .little);
                }
            }

            try writer.writeInt(u64, wire.proof_of_work, .little);
            try writeFriLayerWire(writer, wire.fri_proof.first_layer);
            try writeCount(writer, wire.fri_proof.inner_layers.len);
            for (wire.fri_proof.inner_layers) |layer| try writeFriLayerWire(writer, layer);
            try writeCount(writer, wire.fri_proof.last_layer_poly.len);
            for (wire.fri_proof.last_layer_poly) |value| try writeSecureWire(writer, value);
        }

        fn readProofWireBinary(
            allocator: std.mem.Allocator,
            cursor: *BinaryCursor,
        ) !ProofWire {
            const magic = try cursor.readBytes(BINARY_WIRE_MAGIC.len);
            if (!std.mem.eql(u8, magic, BINARY_WIRE_MAGIC)) return CodecError.UnsupportedBinaryVersion;

            const pow_bits = try cursor.readU32();
            const fri_log_blowup_factor = try cursor.readU32();
            const fri_log_last_layer_degree_bound = try cursor.readU32();
            const fri_n_queries = try cursor.readU32();
            const fri_fold_step = try cursor.readU32();
            const lifting_raw = try cursor.readU32();
            const lifting_log_size: ?u32 = if (lifting_raw == std.math.maxInt(u32)) null else lifting_raw;

            const commitments_len = try cursor.readCount(32);
            const commitments = try allocator.alloc(HashWire, commitments_len);
            for (commitments) |*hash| hash.* = try readHashWire(cursor);

            const sampled_tree_len = try cursor.readCount(4);
            const sampled_values = try allocator.alloc([][]SecureWire, sampled_tree_len);
            for (sampled_values) |*tree| {
                const cols_len = try cursor.readCount(4);
                tree.* = try allocator.alloc([]SecureWire, cols_len);
                for (tree.*) |*column| {
                    const values_len = try cursor.readCount(4 * DEGREE);
                    column.* = try allocator.alloc(SecureWire, values_len);
                    for (column.*) |*value| value.* = try readSecureWire(cursor);
                }
            }

            const decommitments_len = try cursor.readCount(4);
            const decommitments = try allocator.alloc(MerkleDecommitmentWire, decommitments_len);
            for (decommitments) |*decommitment| {
                decommitment.* = try readMerkleDecommitmentWire(allocator, cursor);
            }

            const queried_tree_len = try cursor.readCount(4);
            const queried_values = try allocator.alloc([][]u32, queried_tree_len);
            for (queried_values) |*tree| {
                const cols_len = try cursor.readCount(4);
                tree.* = try allocator.alloc([]u32, cols_len);
                for (tree.*) |*column| {
                    const values_len = try cursor.readCount(4);
                    column.* = try allocator.alloc(u32, values_len);
                    for (column.*) |*value| value.* = try cursor.readU32();
                }
            }

            const proof_of_work = try cursor.readU64();
            const first_layer = try readFriLayerWire(allocator, cursor);
            const inner_len = try cursor.readCount(40);
            const inner_layers = try allocator.alloc(FriLayerWire, inner_len);
            for (inner_layers) |*layer| layer.* = try readFriLayerWire(allocator, cursor);

            const last_poly_len = try cursor.readCount(4 * DEGREE);
            if (!validLastPolyLength(last_poly_len)) return CodecError.InvalidBinaryProof;
            const last_layer_poly = try allocator.alloc(SecureWire, last_poly_len);
            for (last_layer_poly) |*value| value.* = try readSecureWire(cursor);

            return .{
                .config = .{
                    .pow_bits = pow_bits,
                    .fri_config = .{
                        .log_blowup_factor = fri_log_blowup_factor,
                        .log_last_layer_degree_bound = fri_log_last_layer_degree_bound,
                        .n_queries = fri_n_queries,
                        .fold_step = fri_fold_step,
                    },
                    .lifting_log_size = lifting_log_size,
                },
                .commitments = commitments,
                .sampled_values = sampled_values,
                .decommitments = decommitments,
                .queried_values = queried_values,
                .proof_of_work = proof_of_work,
                .fri_proof = .{
                    .first_layer = first_layer,
                    .inner_layers = inner_layers,
                    .last_layer_poly = last_layer_poly,
                },
            };
        }
    };
}
