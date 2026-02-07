const std = @import("std");
const qm31 = @import("fields/qm31.zig");
const line = @import("poly/line.zig");
const vcs_verifier = @import("vcs_lifted/verifier.zig");

const QM31 = qm31.QM31;

/// FRI proof configuration.
pub const FriConfig = struct {
    log_blowup_factor: u32,
    log_last_layer_degree_bound: u32,
    n_queries: usize,

    pub const Error = error{
        InvalidLastLayerDegreeBound,
        InvalidBlowupFactor,
    };

    pub const LOG_MIN_LAST_LAYER_DEGREE_BOUND: u32 = 0;
    pub const LOG_MAX_LAST_LAYER_DEGREE_BOUND: u32 = 10;
    pub const LOG_MIN_BLOWUP_FACTOR: u32 = 1;
    pub const LOG_MAX_BLOWUP_FACTOR: u32 = 16;

    pub fn init(
        log_last_layer_degree_bound: u32,
        log_blowup_factor: u32,
        n_queries: usize,
    ) Error!FriConfig {
        if (log_last_layer_degree_bound < LOG_MIN_LAST_LAYER_DEGREE_BOUND or
            log_last_layer_degree_bound > LOG_MAX_LAST_LAYER_DEGREE_BOUND)
        {
            return Error.InvalidLastLayerDegreeBound;
        }
        if (log_blowup_factor < LOG_MIN_BLOWUP_FACTOR or
            log_blowup_factor > LOG_MAX_BLOWUP_FACTOR)
        {
            return Error.InvalidBlowupFactor;
        }
        return .{
            .log_blowup_factor = log_blowup_factor,
            .log_last_layer_degree_bound = log_last_layer_degree_bound,
            .n_queries = n_queries,
        };
    }

    pub inline fn lastLayerDomainSize(self: FriConfig) usize {
        return @as(usize, 1) << @intCast(self.log_last_layer_degree_bound + self.log_blowup_factor);
    }

    pub inline fn securityBits(self: FriConfig) u32 {
        return self.log_blowup_factor * @as(u32, @intCast(self.n_queries));
    }

    pub fn default() FriConfig {
        return FriConfig.init(0, 1, 3) catch unreachable;
    }
};

/// Number of folds for univariate polynomials.
pub const FOLD_STEP: u32 = 1;

/// Number of folds when reducing circle to line polynomial.
pub const CIRCLE_TO_LINE_FOLD_STEP: u32 = 1;

pub const FriVerificationError = error{
    InvalidNumFriLayers,
    FirstLayerEvaluationsInvalid,
    FirstLayerCommitmentInvalid,
    InnerLayerCommitmentInvalid,
    InnerLayerEvaluationsInvalid,
    LastLayerDegreeInvalid,
    LastLayerEvaluationsInvalid,
};

pub const CirclePolyDegreeBound = struct {
    log_degree_bound: u32,

    pub inline fn init(log_degree_bound: u32) CirclePolyDegreeBound {
        return .{ .log_degree_bound = log_degree_bound };
    }

    pub inline fn foldToLine(self: CirclePolyDegreeBound) LinePolyDegreeBound {
        return .{ .log_degree_bound = self.log_degree_bound - CIRCLE_TO_LINE_FOLD_STEP };
    }
};

pub const LinePolyDegreeBound = struct {
    log_degree_bound: u32,

    pub fn fold(self: LinePolyDegreeBound, n_folds: u32) ?LinePolyDegreeBound {
        if (self.log_degree_bound < n_folds) return null;
        return .{ .log_degree_bound = self.log_degree_bound - n_folds };
    }
};

pub fn FriLayerProof(comptime H: type) type {
    return struct {
        fri_witness: []QM31,
        decommitment: vcs_verifier.MerkleDecommitmentLifted(H),
        commitment: H.Hash,

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.fri_witness);
            self.decommitment.deinit(allocator);
            self.* = undefined;
        }
    };
}

pub fn FriLayerProofAux(comptime H: type) type {
    return struct {
        all_values: [][]IndexedValue,
        decommitment: vcs_verifier.MerkleDecommitmentLiftedAux(H),

        pub const IndexedValue = struct {
            index: usize,
            value: QM31,
        };

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            for (self.all_values) |layer_values| allocator.free(layer_values);
            allocator.free(self.all_values);
            self.decommitment.deinit(allocator);
            self.* = undefined;
        }
    };
}

pub fn ExtendedFriLayerProof(comptime H: type) type {
    return struct {
        proof: FriLayerProof(H),
        aux: FriLayerProofAux(H),

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.proof.deinit(allocator);
            self.aux.deinit(allocator);
            self.* = undefined;
        }
    };
}

pub fn FriProof(comptime H: type) type {
    return struct {
        first_layer: FriLayerProof(H),
        inner_layers: []FriLayerProof(H),
        last_layer_poly: line.LinePoly,

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.first_layer.deinit(allocator);
            for (self.inner_layers) |*layer_proof| layer_proof.deinit(allocator);
            allocator.free(self.inner_layers);
            self.last_layer_poly.deinit(allocator);
            self.* = undefined;
        }
    };
}

pub fn FriProofAux(comptime H: type) type {
    return struct {
        first_layer: FriLayerProofAux(H),
        inner_layers: []FriLayerProofAux(H),

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.first_layer.deinit(allocator);
            for (self.inner_layers) |*layer_aux| layer_aux.deinit(allocator);
            allocator.free(self.inner_layers);
            self.* = undefined;
        }
    };
}

pub fn ExtendedFriProof(comptime H: type) type {
    return struct {
        proof: FriProof(H),
        aux: FriProofAux(H),

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.proof.deinit(allocator);
            self.aux.deinit(allocator);
            self.* = undefined;
        }
    };
}

pub fn accumulateLine(layer_query_evals: []QM31, column_query_evals: []const QM31, folding_alpha: QM31) void {
    std.debug.assert(layer_query_evals.len == column_query_evals.len);
    const alpha_sq = folding_alpha.square();
    for (layer_query_evals, 0..) |*curr, i| {
        curr.* = curr.*.mul(alpha_sq).add(column_query_evals[i]);
    }
}

test "fri config: security bits" {
    const config = try FriConfig.init(10, 10, 70);
    try std.testing.expectEqual(@as(u32, 700), config.securityBits());
}

test "fri config: default values" {
    const cfg = FriConfig.default();
    try std.testing.expectEqual(@as(u32, 0), cfg.log_last_layer_degree_bound);
    try std.testing.expectEqual(@as(u32, 1), cfg.log_blowup_factor);
    try std.testing.expectEqual(@as(usize, 3), cfg.n_queries);
}

test "fri config: bounds checks" {
    try std.testing.expectError(FriConfig.Error.InvalidLastLayerDegreeBound, FriConfig.init(11, 1, 1));
    try std.testing.expectError(FriConfig.Error.InvalidBlowupFactor, FriConfig.init(0, 0, 1));
}

test "fri: degree bound folding" {
    const circle_bound = CirclePolyDegreeBound.init(7);
    const line_bound = circle_bound.foldToLine();
    try std.testing.expectEqual(@as(u32, 6), line_bound.log_degree_bound);
    try std.testing.expectEqual(@as(u32, 5), (line_bound.fold(1) orelse unreachable).log_degree_bound);
    try std.testing.expect((line_bound.fold(7)) == null);
}

test "fri: accumulate line" {
    var layer = [_]QM31{
        QM31.fromU32Unchecked(1, 0, 0, 0),
        QM31.fromU32Unchecked(2, 0, 0, 0),
    };
    const folded = [_]QM31{
        QM31.fromU32Unchecked(3, 0, 0, 0),
        QM31.fromU32Unchecked(4, 0, 0, 0),
    };
    const alpha = QM31.fromU32Unchecked(5, 0, 0, 0);
    accumulateLine(layer[0..], folded[0..], alpha);

    const alpha_sq = alpha.square();
    try std.testing.expect(layer[0].eql(QM31.fromU32Unchecked(1, 0, 0, 0).mul(alpha_sq).add(folded[0])));
    try std.testing.expect(layer[1].eql(QM31.fromU32Unchecked(2, 0, 0, 0).mul(alpha_sq).add(folded[1])));
}

test "fri proof containers: deinit owned buffers" {
    const Hasher = @import("vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const LayerProof = FriLayerProof(Hasher);
    const LayerProofAux = FriLayerProofAux(Hasher);
    const Proof = FriProof(Hasher);
    const ProofAux = FriProofAux(Hasher);
    const Extended = ExtendedFriProof(Hasher);
    const MerkleAux = vcs_verifier.MerkleDecommitmentLiftedAux(Hasher);

    const alloc = std.testing.allocator;

    const first_witness = try alloc.dupe(QM31, &[_]QM31{
        QM31.fromU32Unchecked(1, 0, 0, 0),
        QM31.fromU32Unchecked(2, 0, 0, 0),
    });
    const first_decommitment = vcs_verifier.MerkleDecommitmentLifted(Hasher){
        .hash_witness = try alloc.alloc(Hasher.Hash, 0),
    };
    const first_layer = LayerProof{
        .fri_witness = first_witness,
        .decommitment = first_decommitment,
        .commitment = [_]u8{0} ** 32,
    };

    const inner_witness = try alloc.dupe(QM31, &[_]QM31{
        QM31.fromU32Unchecked(3, 0, 0, 0),
    });
    const inner_decommitment = vcs_verifier.MerkleDecommitmentLifted(Hasher){
        .hash_witness = try alloc.alloc(Hasher.Hash, 0),
    };
    const inner_layers = try alloc.alloc(LayerProof, 1);
    inner_layers[0] = .{
        .fri_witness = inner_witness,
        .decommitment = inner_decommitment,
        .commitment = [_]u8{1} ** 32,
    };

    const poly_coeffs = try alloc.dupe(QM31, &[_]QM31{
        QM31.fromU32Unchecked(5, 0, 0, 0),
    });
    const proof = Proof{
        .first_layer = first_layer,
        .inner_layers = inner_layers,
        .last_layer_poly = line.LinePoly.initOwned(poly_coeffs),
    };

    const first_aux = LayerProofAux{
        .all_values = try alloc.alloc([]LayerProofAux.IndexedValue, 0),
        .decommitment = MerkleAux{
            .all_node_values = try alloc.alloc([]MerkleAux.NodeValue, 0),
        },
    };
    const inner_aux_layers = try alloc.alloc(LayerProofAux, 0);
    const proof_aux = ProofAux{
        .first_layer = first_aux,
        .inner_layers = inner_aux_layers,
    };

    var extended = Extended{
        .proof = proof,
        .aux = proof_aux,
    };
    extended.deinit(alloc);
}
