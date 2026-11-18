//! Native verified-capture conversion and fixed-shape guessed OM31 proof wires.
//! Capture conversion is not acceptance. Callers own an arena for nested views.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const C = @import("common.zig");
const Shape = @import("shape.zig").Shape;
const F = C.F;
const O = C.O;
const Q = C.Q;
const M = core.fields.m31.M31;
const B = circuit.builder;
const Word = B.wrappers.U32Wrapper(C.Var);
const Base = B.wrappers.M31Wrapper(C.Var);
/// Hash representation and canonical digest ingress vary by named suite;
/// capture geometry, cap reconstruction and secure-field wires stay shared.
pub fn ForCrypto(comptime Crypto: type) type {
    return struct {
        const H = Crypto.H;
        pub const NativeProofImpl = core.proof.ForField(O).StarkProof(H);
        pub const NativeCaptureImpl = core.pcs.ForField(O).verifier.VerifiedProofCapture(H);
        /// `cap` (empty = uncapped): the layer tree's Merkle cap, `auth_paths` then
        /// hold only the siblings below it (M6 diet-wire, `fromNativeCappedImpl`).
        pub const CapturedLayerImpl = struct { commitment: H.Hash, cosets: []const []const O, auth_paths: []const []const H.Hash, cap: []const H.Hash = &.{} };
        pub const CapturedImpl = struct {
            commitments: []const H.Hash,
            sampled_values: []const []const []const O,
            queried_values: []const []const []const M,
            auth_paths: []const []const []const H.Hash,
            pow_nonce: u64,
            layers: []const CapturedLayerImpl,
            last_layer_coefs: []const O,
            /// Merkle cap log of the verifier circuit (0 = full paths, the M5 form).
            /// With cap_log c > 0 every tree taller than c carries `caps[t]` (2^c
            /// nodes) and auth paths of `height - c` siblings.
            cap_log: u32 = 0,
            caps: []const []const H.Hash = &.{},
        };
        pub const LayerImpl = struct { commitment: Crypto.CircuitHash, cosets: []const []const F, auth_paths: []const []const Crypto.CircuitHash, cap: []const Crypto.CircuitHash = &.{} };
        pub const ProofImpl = struct {
            commitments: []const Crypto.CircuitHash,
            sampled_values: []const []const []const F,
            queried_values: []const []const []const Base,
            auth_paths: []const []const []const Crypto.CircuitHash,
            pow_nonce: [2]Word,
            layers: []const LayerImpl,
            last_layer_coefs: []const F,
            cap_log: u32 = 0,
            caps: []const []const Crypto.CircuitHash = &.{},
            pub fn validate(self: *const ProofImpl, shape: *const Shape) !void {
                try validateProof(self.*, shape);
            }
        };
        fn captureCap(cap: []H.Hash, positions: []const usize, leaves: []const H.Hash, siblings: []const []const H.Hash, height: u32, root: H.Hash) !void {
            const merkle = circuit.native_verifier.merkle;
            if (H == LegacyCrypto.H and cap.len >= 1 << merkle.sparse_cap_log)
                return merkle.hostSparseCap(H, cap, positions, leaves, siblings, height, root);
            return merkle.hostCap(H, cap, positions, leaves, siblings, height, root);
        }

        fn capLen(height: u32, cap_log: u32) usize {
            const cl = circuit.native_verifier.merkle.capLogFor(height, cap_log);
            return if (cl == 0) 0 else @as(usize, 1) << @intCast(cl);
        }
        fn validateProof(proof: anytype, shape: *const Shape) !void {
            try validateForCap(proof, shape, proof.cap_log);
        }
        fn validateForCap(proof: anytype, shape: *const Shape, planned_cap: u32) !void {
            try shape.validate();
            const cap_log: u32 = proof.cap_log;
            if (cap_log > 5) return error.ShapeMismatch;
            if (cap_log != 0 and proof.caps.len != shape.nTrees()) return error.ShapeMismatch;
            if (cap_log == 0 and proof.caps.len != 0) return error.ShapeMismatch;
            if (proof.commitments.len != shape.nTrees() or proof.sampled_values.len != shape.nTrees() or
                proof.queried_values.len != shape.nTrees() or proof.auth_paths.len != shape.nTrees()) return error.ShapeMismatch;
            for (0..shape.nTrees()) |t| {
                if (proof.sampled_values[t].len != shape.nColumns(t) or proof.queried_values[t].len != shape.nColumns(t)) return error.ShapeMismatch;
                for (proof.sampled_values[t], proof.queried_values[t], 0..) |samples, queried, col| {
                    if (samples.len != shape.sampleCount(t, col) or queried.len != shape.nQueries()) return error.ShapeMismatch;
                }
                if (shape.nColumns(t) == 0) {
                    if (proof.auth_paths[t].len != 0) return error.ShapeMismatch;
                } else {
                    if (proof.auth_paths[t].len != shape.nQueries()) return error.ShapeMismatch;
                    const cl = circuit.native_verifier.merkle.capLogFor(shape.treeHeight(t), cap_log);
                    for (proof.auth_paths[t]) |path| if (path.len != shape.treeHeight(t) - cl) return error.ShapeMismatch;
                }
                if (cap_log != 0 and proof.caps[t].len != (if (shape.nColumns(t) == 0) 0 else capLen(shape.treeHeight(t), cap_log))) return error.ShapeMismatch;
            }
            var buffer: [64]u32 = undefined;
            const steps = shape.foldSteps(&buffer);
            if (proof.layers.len != steps.len or proof.last_layer_coefs.len != shape.nLastLayerCoefficients()) return error.ShapeMismatch;
            var log = shape.liftingLogSize();
            for (proof.layers, steps, 0..) |layer, step, index| {
                log -= step;
                const groups = if (H == LegacyCrypto.H) circuit.native_verifier.fri.shortLineGroups(index, log, step, shape.nQueries(), circuit.native_verifier.merkle.capLogFor(log, planned_cap)) else 0;
                const rows = if (groups != 0) groups else shape.nQueries();
                if (layer.cosets.len != rows or layer.auth_paths.len != rows) return error.ShapeMismatch;
                const cl = circuit.native_verifier.merkle.capLogFor(log, cap_log);
                if (layer.cap.len != capLen(log, cap_log)) return error.ShapeMismatch;
                for (layer.cosets, layer.auth_paths) |coset, path| {
                    if (coset.len != @as(usize, 1) << @intCast(step) or path.len != log - cl) return error.ShapeMismatch;
                }
            }
        }
        fn paths(a: std.mem.Allocator, queries: usize, depth: usize, siblings: []const H.Hash) ![]const []const H.Hash {
            if (siblings.len != queries * depth) return error.ShapeMismatch;
            const result = try a.alloc([]const H.Hash, queries);
            for (result, 0..) |*path, q| path.* = try a.dupe(H.Hash, siblings[q * depth ..][0..depth]);
            return result;
        }
        pub fn fromNativeImpl(a: std.mem.Allocator, native: *const NativeProofImpl, capture: *const NativeCaptureImpl, shape: *const Shape) !CapturedImpl {
            return captureForCap(a, native, capture, shape, 0);
        }
        fn captureForCap(a: std.mem.Allocator, native: *const NativeProofImpl, capture: *const NativeCaptureImpl, shape: *const Shape, planned_cap: u32) !CapturedImpl {
            try shape.validate();
            const pcs = &native.commitment_scheme_proof;
            const nt = shape.nTrees();
            const nq = shape.nQueries();
            if (capture.queries.raw.len != nq or pcs.commitments.items.len != nt or pcs.sampled_values.items.len != nt or
                capture.column_log_sizes.len != nt or capture.trace_paths.len != nt) return error.ShapeMismatch;
            const sampled = try a.alloc([]const []const O, nt);
            const queried = try a.alloc([]const []const M, nt);
            const auth = try a.alloc([]const []const H.Hash, nt);
            var flat: usize = 0;
            for (0..nt) |t| {
                const nc = shape.nColumns(t);
                if (pcs.sampled_values.items[t].len != nc or capture.column_log_sizes[t].len != nc) return error.ShapeMismatch;
                const columns = try a.alloc([]const O, nc);
                const values = try a.alloc([]const M, nc);
                for (columns, values, 0..) |*samples, *base_values, col| {
                    if (capture.column_log_sizes[t][col] != shape.extendedLogSize(t, col) or flat + nq > capture.queried_values.len) return error.ShapeMismatch;
                    samples.* = try a.dupe(O, pcs.sampled_values.items[t][col]);
                    base_values.* = try a.dupe(M, capture.queried_values[flat..][0..nq]);
                    flat += nq;
                }
                sampled[t] = columns;
                queried[t] = values;
                if (nc == 0) {
                    auth[t] = &.{};
                    continue;
                }
                const trace = capture.trace_paths[t];
                if (trace.positions.len != nq or trace.path_depth != shape.treeHeight(t)) return error.ShapeMismatch;
                auth[t] = try paths(a, nq, trace.path_depth, trace.siblings);
            }
            if (flat != capture.queried_values.len) return error.ShapeMismatch;
            const layers = try a.alloc(CapturedLayerImpl, capture.fri.layers.len);
            var schedule: [64]u32 = undefined;
            const steps = shape.foldSteps(&schedule);
            if (layers.len != steps.len) return error.ShapeMismatch;
            var log = shape.liftingLogSize();
            for (layers, capture.fri.layers, steps, 0..) |*out, in, step, index| {
                log -= step;
                if (in.fold_step != step or in.fold_width != @as(usize, 1) << @intCast(step) or in.path_depth != log or in.query_count != nq or in.values.len != (std.math.mul(usize, nq, in.fold_width) catch return error.ShapeMismatch)) return error.ShapeMismatch;
                if (comptime H == LegacyCrypto.H) {
                    const groups = circuit.native_verifier.fri.shortLineGroups(index, log, step, nq, circuit.native_verifier.merkle.capLogFor(log, planned_cap));
                    if (groups != 0) {
                        out.* = try packLineGroups(a, in, groups);
                        continue;
                    }
                }
                const cosets = try a.alloc([]const O, nq);
                for (cosets, 0..) |*coset, q| coset.* = try a.dupe(O, in.queryValues(q));
                out.* = .{ .commitment = in.commitment, .cosets = cosets, .auth_paths = try paths(a, nq, in.path_depth, in.siblings) };
            }
            const result: CapturedImpl = .{ .commitments = try a.dupe(H.Hash, pcs.commitments.items), .sampled_values = sampled, .queried_values = queried, .auth_paths = auth, .pow_nonce = capture.proof_of_work, .layers = layers, .last_layer_coefs = try a.dupe(O, capture.last_layer_coefficients) };
            try validateForCap(result, shape, planned_cap);
            return result;
        }

        /// The FRI layer leaf of one query, as `fri.zig decommit` hashes it in
        /// circuit: packed leaves of `width` OM31 values (c0 limbs then c1 limbs,
        /// one LE word per M31), then the in-coset node levels.
        fn friGroupRoot(a: std.mem.Allocator, coset: []const O, layer_log: usize, step: usize) !H.Hash {
            const pack = layer_log >= core.fri.LOG_PACKED_LEAF_SIZE and step > 1;
            const width: usize = if (pack) @as(usize, 1) << core.fri.LOG_PACKED_LEAF_SIZE else 1;
            const nfolds = step - if (pack) @as(usize, core.fri.LOG_PACKED_LEAF_SIZE) else 0;
            const leaves = try a.alloc(H.Hash, coset.len / width);
            defer a.free(leaves);
            const words = try a.alloc(M, 8 * width);
            defer a.free(words);
            for (leaves, 0..) |*leaf, i| {
                for (coset[i * width ..][0..width], 0..) |value, j| {
                    const limbs = value.toM31Array();
                    @memcpy(words[8 * j ..][0..8], &limbs);
                }
                var hasher = H.defaultWithInitialState();
                hasher.updateLeaf(words);
                leaf.* = hasher.finalize();
            }
            for (0..nfolds) |f| for (0..@as(usize, 1) << @intCast(nfolds - f - 1)) |i| {
                leaves[i] = H.hashChildren(.{ .left = leaves[2 * i], .right = leaves[2 * i + 1] });
            };
            return leaves[0];
        }
        fn truncatePaths(a: std.mem.Allocator, source: []const []const H.Hash, keep: usize) ![]const []const H.Hash {
            const out = try a.alloc([]const H.Hash, source.len);
            for (out, source) |*dst, src| dst.* = src[0..keep];
            return out;
        }
        /// `fromNativeImpl` for a verifier circuit with a Merkle cap of log `cap_log`
        /// (rv64-m6-diet-wire.md section 5): every tree taller than the cap gets its
        /// 2^cap_log cap nodes, derived on the host from the captured query paths
        /// (`merkle.hostCap`, which also re-hashes the cap to the committed root),
        /// and its auth paths are cut to the siblings below the cap.
        pub fn fromNativeCappedImpl(a: std.mem.Allocator, native: *const NativeProofImpl, capture: *const NativeCaptureImpl, shape: *const Shape, cap_log: u32) !CapturedImpl {
            if (cap_log > 5) return error.ShapeMismatch;
            var result = try captureForCap(a, native, capture, shape, cap_log);
            if (cap_log == 0) return result;
            const merkle = circuit.native_verifier.merkle;
            const nq = shape.nQueries();
            const caps = try a.alloc([]const H.Hash, shape.nTrees());
            const auth = try a.alloc([]const []const H.Hash, shape.nTrees());
            for (0..shape.nTrees()) |t| {
                const height = shape.treeHeight(t);
                const cl = merkle.capLogFor(height, cap_log);
                if (shape.nColumns(t) == 0 or cl == 0) {
                    caps[t] = &.{};
                    auth[t] = result.auth_paths[t];
                    continue;
                }
                const logs = try shape.extendedLogSizes(a, t);
                const order = try merkle.columnPermutation(a, logs);
                const row = try a.alloc(M, order.len);
                const leaves = try a.alloc(H.Hash, nq);
                for (leaves, 0..) |*leaf, q| {
                    for (row, order) |*value, column| value.* = result.queried_values[t][column][q];
                    var hasher = H.defaultWithInitialState();
                    hasher.updateLeaf(row);
                    leaf.* = hasher.finalize();
                }
                const cap = try a.alloc(H.Hash, @as(usize, 1) << @intCast(cl));
                try captureCap(cap, capture.trace_paths[t].positions, leaves, result.auth_paths[t], height, result.commitments[t]);
                caps[t] = cap;
                auth[t] = try truncatePaths(a, result.auth_paths[t], height - cl);
            }
            var buffer: [64]u32 = undefined;
            const steps = shape.foldSteps(&buffer);
            const layers = try a.alloc(CapturedLayerImpl, result.layers.len);
            var log: usize = shape.liftingLogSize();
            for (layers, result.layers, steps, capture.fri.layers) |*out, in, step_u32, raw| {
                const step: usize = step_u32;
                const layer_log = log;
                log -= step;
                const cl: usize = merkle.capLogFor(@intCast(log), cap_log);
                out.* = in;
                if (cl == 0) continue;
                if (raw.positions.len != nq) return error.ShapeMismatch;
                const leaves = try a.alloc(H.Hash, nq);
                const positions = try a.alloc(usize, nq);
                for (leaves, positions, in.cosets, raw.positions) |*leaf, *position, coset, raw_position| {
                    leaf.* = try friGroupRoot(a, coset, layer_log, step);
                    position.* = raw_position >> @intCast(step);
                }
                const cap = try a.alloc(H.Hash, @as(usize, 1) << @intCast(cl));
                try captureCap(cap, positions, leaves, in.auth_paths, @intCast(log), in.commitment);
                out.cap = cap;
                out.auth_paths = try truncatePaths(a, in.auth_paths, log - cl);
            }
            result.auth_paths = auth;
            result.layers = layers;
            result.caps = caps;
            result.cap_log = cap_log;
            try validateProof(result, shape);
            return result;
        }
        fn guessHash(ctx: *C.Context, value: H.Hash) !Crypto.CircuitHash {
            return Crypto.guessHash(ctx, value);
        }
        fn guessPaths(ctx: *C.Context, source: []const []const H.Hash) ![]const []const Crypto.CircuitHash {
            const output = try ctx.scratch().alloc([]const Crypto.CircuitHash, source.len);
            for (output, source) |*out, in| {
                const nodes = try ctx.scratch().alloc(Crypto.CircuitHash, in.len);
                for (nodes, in) |*node, value| node.* = try guessHash(ctx, value);
                out.* = nodes;
            }
            return output;
        }
        fn guessValues(ctx: *C.Context, values: []const O) ![]const F {
            const result = try ctx.scratch().alloc(F, values.len);
            for (result, values) |*wire, value| wire.* = try F.guess(ctx, value);
            return result;
        }
        pub fn guessImpl(ctx: *C.Context, source: *const CapturedImpl, shape: *const Shape) !ProofImpl {
            try validateProof(source.*, shape);
            const a = ctx.scratch();
            const roots = try a.alloc(Crypto.CircuitHash, source.commitments.len);
            for (roots, source.commitments) |*root, value| root.* = try guessHash(ctx, value);
            const sampled = try a.alloc([]const []const F, shape.nTrees());
            const queried = try a.alloc([]const []const Base, shape.nTrees());
            const auth = try a.alloc([]const []const Crypto.CircuitHash, shape.nTrees());
            for (0..shape.nTrees()) |t| {
                const columns = try a.alloc([]const F, shape.nColumns(t));
                const base_columns = try a.alloc([]const Base, shape.nColumns(t));
                for (columns, base_columns, source.sampled_values[t], source.queried_values[t]) |*samples, *base_values, src, bases| {
                    samples.* = try guessValues(ctx, src);
                    const b = try a.alloc(Base, bases.len);
                    for (b, bases) |*wire, value| wire.* = try B.wrappers.guessM31(Q, ctx, B.wrappers.m31Value(Q, value));
                    base_values.* = b;
                }
                sampled[t] = columns;
                queried[t] = base_columns;
                auth[t] = try guessPaths(ctx, source.auth_paths[t]);
            }
            const caps = try a.alloc([]const Crypto.CircuitHash, source.caps.len);
            for (caps, source.caps) |*out, in| {
                const nodes = try a.alloc(Crypto.CircuitHash, in.len);
                for (nodes, in) |*node, value| node.* = try guessHash(ctx, value);
                out.* = nodes;
            }
            const layers = try a.alloc(LayerImpl, source.layers.len);
            for (layers, source.layers) |*out, in| {
                const cosets = try a.alloc([]const F, in.cosets.len);
                for (cosets, in.cosets) |*c, values| c.* = try guessValues(ctx, values);
                const cap = try a.alloc(Crypto.CircuitHash, in.cap.len);
                for (cap, in.cap) |*node, value| node.* = try guessHash(ctx, value);
                out.* = .{ .commitment = try guessHash(ctx, in.commitment), .cosets = cosets, .auth_paths = try guessPaths(ctx, in.auth_paths), .cap = cap };
            }
            return .{ .cap_log = source.cap_log, .caps = caps, .commitments = roots, .sampled_values = sampled, .queried_values = queried, .auth_paths = auth, .pow_nonce = .{ try B.wrappers.guessU32(Q, ctx, B.wrappers.u32Value(Q, @truncate(source.pow_nonce))), try B.wrappers.guessU32(Q, ctx, B.wrappers.u32Value(Q, @truncate(source.pow_nonce >> 32))) }, .layers = layers, .last_layer_coefs = try guessValues(ctx, source.last_layer_coefs) };
        }

        pub const NativeProof = NativeProofImpl;
        pub const NativeCapture = NativeCaptureImpl;
        pub const CapturedLayer = CapturedLayerImpl;
        pub const Captured = CapturedImpl;
        pub const Layer = LayerImpl;
        pub const Proof = ProofImpl;
        pub const fromNative = fromNativeImpl;
        pub const fromNativeCapped = fromNativeCappedImpl;
        pub const guess = guessImpl;
    };
}
const LegacyCrypto = struct {
    pub const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
    pub const CircuitHash = C.Hash;
    pub fn guessHash(ctx: *C.Context, value: H.Hash) !CircuitHash {
        return B.blake.guessHash(Q, ctx, B.blake.hashValueFromDigest(Q, value));
    }
};
const Default = ForCrypto(LegacyCrypto);
pub const NativeProof = Default.NativeProof;
pub const NativeCapture = Default.NativeCapture;
pub const CapturedLayer = Default.CapturedLayer;
pub const Captured = Default.Captured;
pub const Layer = Default.Layer;
pub const Proof = Default.Proof;
pub const fromNative = Default.fromNative;
pub const fromNativeCapped = Default.fromNativeCapped;
pub const guess = Default.guess;

/// Copy only the first authenticated representative of each coset. Zero-filled
/// slots have no authority. The circuit derives all membership from Fiat–Shamir.
pub fn packLineGroups(a: std.mem.Allocator, raw: core.fri.ForField(O).FriLayerQueryCapture(LegacyCrypto.H), groups: usize) !CapturedLayer {
    if (groups == 0 or groups > 8 or raw.path_depth > 3 or groups != @as(usize, 1) << @intCast(raw.path_depth) or
        raw.fold_step == 0 or raw.fold_step > 4 or raw.fold_width != @as(usize, 1) << @intCast(raw.fold_step) or raw.positions.len != raw.query_count or
        raw.values.len != (std.math.mul(usize, raw.query_count, raw.fold_width) catch return error.ShapeMismatch) or raw.siblings.len != (std.math.mul(usize, raw.query_count, raw.path_depth) catch return error.ShapeMismatch)) return error.ShapeMismatch;
    var first: [8]?usize = @splat(null);
    for (raw.positions, 0..) |position, q| {
        const index = position >> @intCast(raw.fold_step);
        if (index >= groups) return error.ShapeMismatch;
        if (first[index]) |previous| {
            for (raw.queryValues(previous), raw.queryValues(q)) |x, y| if (!x.eql(y)) return error.ShapeMismatch;
            if (!std.mem.eql(u8, std.mem.sliceAsBytes(raw.queryPath(previous)), std.mem.sliceAsBytes(raw.queryPath(q)))) return error.ShapeMismatch;
        } else first[index] = q;
    }
    const cosets = try a.alloc([]const O, groups);
    const paths_out = try a.alloc([]const LegacyCrypto.H.Hash, groups);
    for (cosets, paths_out, first[0..groups]) |*vs, *ss, representative| {
        if (representative) |q| {
            vs.* = try a.dupe(O, raw.queryValues(q));
            ss.* = try a.dupe(LegacyCrypto.H.Hash, raw.queryPath(q));
        } else {
            const zeros = try a.alloc(O, raw.fold_width);
            @memset(zeros, O.zero());
            const nodes = try a.alloc(LegacyCrypto.H.Hash, raw.path_depth);
            @memset(nodes, @splat(0));
            vs.* = zeros;
            ss.* = nodes;
        }
    }
    return .{ .commitment = raw.commitment, .cosets = cosets, .auth_paths = paths_out };
}
