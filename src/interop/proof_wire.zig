const std = @import("std");
const fri = @import("../core/fri.zig");
const m31 = @import("../core/fields/m31.zig");
const line = @import("../core/poly/line.zig");
const qm31 = @import("../core/fields/qm31.zig");
const pcs = @import("../core/pcs/mod.zig");
const proof_mod = @import("../core/proof.zig");
const vcs_verifier = @import("../core/vcs_lifted/verifier.zig");
const blake2_merkle = @import("../core/vcs_lifted/blake2_merkle.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;

pub const Hasher = blake2_merkle.Blake2sMerkleHasher;
pub const Proof = proof_mod.StarkProof(Hasher);
const MerkleDecommitment = vcs_verifier.MerkleDecommitmentLifted(Hasher);

pub const FriConfigWire = struct {
    log_blowup_factor: u32,
    log_last_layer_degree_bound: u32,
    n_queries: u64,
};

pub const PcsConfigWire = struct {
    pow_bits: u32,
    fri_config: FriConfigWire,
};

pub const Qm31Wire = [4]u32;
pub const HashWire = [32]u8;

pub const MerkleDecommitmentWire = struct {
    hash_witness: []HashWire,
};

pub const FriLayerWire = struct {
    fri_witness: []Qm31Wire,
    decommitment: MerkleDecommitmentWire,
    commitment: HashWire,
};

pub const FriProofWire = struct {
    first_layer: FriLayerWire,
    inner_layers: []FriLayerWire,
    last_layer_poly: []Qm31Wire,
};

pub const ProofWire = struct {
    config: PcsConfigWire,
    commitments: []HashWire,
    sampled_values: [][][]Qm31Wire,
    decommitments: []MerkleDecommitmentWire,
    queried_values: [][][]u32,
    proof_of_work: u64,
    fri_proof: FriProofWire,
};

pub const CodecError = error{
    NonCanonicalM31,
    ValueOutOfRange,
};

/// Encodes a Stark proof into wire bytes for cross-language interchange.
pub fn encodeProofBytes(allocator: std.mem.Allocator, proof: Proof) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const wire = try proofToWire(arena.allocator(), proof);
    return std.json.Stringify.valueAlloc(allocator, wire, .{});
}

/// Decodes wire bytes into a Stark proof with owned allocations.
pub fn decodeProofBytes(allocator: std.mem.Allocator, encoded: []const u8) !Proof {
    const parsed = try std.json.parseFromSlice(ProofWire, allocator, encoded, .{
        .ignore_unknown_fields = false,
    });
    defer parsed.deinit();

    return wireToProof(allocator, parsed.value);
}

fn proofToWire(allocator: std.mem.Allocator, proof: Proof) !ProofWire {
    const pcs_proof = proof.commitment_scheme_proof;

    const commitments = try allocator.alloc(HashWire, pcs_proof.commitments.items.len);
    for (pcs_proof.commitments.items, 0..) |commitment, i| commitments[i] = commitment;

    const sampled_values = try encodeTreeQm31(allocator, pcs_proof.sampled_values.items);
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
            },
        },
        .commitments = commitments,
        .sampled_values = sampled_values,
        .decommitments = decommitments,
        .queried_values = queried_values,
        .proof_of_work = pcs_proof.proof_of_work,
        .fri_proof = fri_proof_wire,
    };
}

fn wireToProof(allocator: std.mem.Allocator, wire: ProofWire) !Proof {
    if (wire.config.fri_config.n_queries > std.math.maxInt(usize)) return CodecError.ValueOutOfRange;

    const config = pcs.PcsConfig{
        .pow_bits = wire.config.pow_bits,
        .fri_config = try fri.FriConfig.init(
            wire.config.fri_config.log_last_layer_degree_bound,
            wire.config.fri_config.log_blowup_factor,
            @intCast(wire.config.fri_config.n_queries),
        ),
    };

    const commitments = pcs.TreeVec(HashWire).initOwned(try allocator.dupe(HashWire, wire.commitments));
    errdefer {
        var c = commitments;
        c.deinit(allocator);
    }

    const sampled_values = try decodeTreeQm31(allocator, wire.sampled_values);
    errdefer {
        var sv = sampled_values;
        sv.deinitDeep(allocator);
    }

    const decommitments = try decodeDecommitments(allocator, wire.decommitments);
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

    const fri_proof = try decodeFriProof(allocator, wire.fri_proof);
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

fn encodeTreeQm31(allocator: std.mem.Allocator, tree: []const [][]QM31) ![][][]Qm31Wire {
    const out = try allocator.alloc([][]Qm31Wire, tree.len);
    for (tree, 0..) |tree_cols, tree_idx| {
        out[tree_idx] = try allocator.alloc([]Qm31Wire, tree_cols.len);
        for (tree_cols, 0..) |col, col_idx| {
            out[tree_idx][col_idx] = try allocator.alloc(Qm31Wire, col.len);
            for (col, 0..) |value, value_idx| {
                out[tree_idx][col_idx][value_idx] = qm31ToWire(value);
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

    const last_layer_poly = try allocator.alloc(Qm31Wire, fri_proof.last_layer_poly.coefficients().len);
    for (fri_proof.last_layer_poly.coefficients(), 0..) |coeff, i| {
        last_layer_poly[i] = qm31ToWire(coeff);
    }

    return .{
        .first_layer = first_layer,
        .inner_layers = inner_layers,
        .last_layer_poly = last_layer_poly,
    };
}

fn encodeFriLayer(allocator: std.mem.Allocator, layer: fri.FriLayerProof(Hasher)) !FriLayerWire {
    const fri_witness = try allocator.alloc(Qm31Wire, layer.fri_witness.len);
    for (layer.fri_witness, 0..) |value, i| fri_witness[i] = qm31ToWire(value);

    return .{
        .fri_witness = fri_witness,
        .decommitment = .{
            .hash_witness = try allocator.dupe(HashWire, layer.decommitment.hash_witness),
        },
        .commitment = layer.commitment,
    };
}

fn decodeTreeQm31(allocator: std.mem.Allocator, tree: []const [][]Qm31Wire) !pcs.TreeVec([][]QM31) {
    const out = try allocator.alloc([][]QM31, tree.len);
    errdefer allocator.free(out);

    var initialized: usize = 0;
    errdefer {
        for (out[0..initialized]) |tree_cols| freeQm31Tree(allocator, tree_cols);
    }

    for (tree, 0..) |tree_cols, i| {
        out[i] = try decodeQm31Tree(allocator, tree_cols);
        initialized += 1;
    }
    return pcs.TreeVec([][]QM31).initOwned(out);
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

fn decodeQm31Tree(allocator: std.mem.Allocator, tree_cols: []const []Qm31Wire) ![][]QM31 {
    const out = try allocator.alloc([]QM31, tree_cols.len);
    errdefer allocator.free(out);

    var initialized: usize = 0;
    errdefer {
        for (out[0..initialized]) |col| allocator.free(col);
    }

    for (tree_cols, 0..) |col, i| {
        out[i] = try allocator.alloc(QM31, col.len);
        for (col, 0..) |value, j| {
            out[i][j] = try qm31FromWire(value);
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
    const out = try allocator.alloc(MerkleDecommitment, decommitments.len);
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

    return pcs.TreeVec(MerkleDecommitment).initOwned(out);
}

fn decodeFriProof(allocator: std.mem.Allocator, wire: FriProofWire) !fri.FriProof(Hasher) {
    const first_layer = try decodeFriLayer(allocator, wire.first_layer);
    errdefer {
        var layer = first_layer;
        layer.deinit(allocator);
    }

    const inner_layers = try allocator.alloc(fri.FriLayerProof(Hasher), wire.inner_layers.len);
    errdefer allocator.free(inner_layers);

    var initialized: usize = 0;
    errdefer {
        for (inner_layers[0..initialized]) |*layer| layer.deinit(allocator);
    }

    for (wire.inner_layers, 0..) |layer, i| {
        inner_layers[i] = try decodeFriLayer(allocator, layer);
        initialized += 1;
    }

    const coeffs = try allocator.alloc(QM31, wire.last_layer_poly.len);
    errdefer allocator.free(coeffs);
    for (wire.last_layer_poly, 0..) |coeff, i| coeffs[i] = try qm31FromWire(coeff);

    return .{
        .first_layer = first_layer,
        .inner_layers = inner_layers,
        .last_layer_poly = line.LinePoly.initOwned(coeffs),
    };
}

fn decodeFriLayer(allocator: std.mem.Allocator, wire: FriLayerWire) !fri.FriLayerProof(Hasher) {
    const fri_witness = try allocator.alloc(QM31, wire.fri_witness.len);
    errdefer allocator.free(fri_witness);
    for (wire.fri_witness, 0..) |value, i| {
        fri_witness[i] = try qm31FromWire(value);
    }

    return .{
        .fri_witness = fri_witness,
        .decommitment = .{
            .hash_witness = try allocator.dupe(HashWire, wire.decommitment.hash_witness),
        },
        .commitment = wire.commitment,
    };
}

fn freeQm31Tree(allocator: std.mem.Allocator, tree_cols: [][]QM31) void {
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

fn qm31FromWire(value: Qm31Wire) CodecError!QM31 {
    return QM31.fromM31Array(.{
        try m31FromU32(value[0]),
        try m31FromU32(value[1]),
        try m31FromU32(value[2]),
        try m31FromU32(value[3]),
    });
}

fn qm31ToWire(value: QM31) Qm31Wire {
    const coeffs = value.toM31Array();
    return .{
        coeffs[0].toU32(),
        coeffs[1].toU32(),
        coeffs[2].toU32(),
        coeffs[3].toU32(),
    };
}

test "interop proof wire: encode/decode xor proof" {
    const xor = @import("../examples/xor.zig");
    const alloc = std.testing.allocator;

    const config = pcs.PcsConfig{
        .pow_bits = 0,
        .fri_config = try fri.FriConfig.init(0, 1, 3),
    };
    const statement = xor.Statement{
        .log_size = 5,
        .log_step = 2,
        .offset = 3,
    };

    var output = try xor.prove(alloc, config, statement);
    defer output.proof.deinit(alloc);
    const encoded = try encodeProofBytes(alloc, output.proof);
    defer alloc.free(encoded);

    const decoded = try decodeProofBytes(alloc, encoded);
    try xor.verify(alloc, config, output.statement, decoded);
}
