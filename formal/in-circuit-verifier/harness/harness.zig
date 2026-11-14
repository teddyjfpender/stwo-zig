//! Differential-test vector generator for the Lean `NativeAccepts` spec.
//!
//! Proves a small batch of committed columns at the PCS level under the
//! pinned profile (`proving_5a7c5ed`, Blake2sM31 channel, plain Blake2s
//! Merkle, blowup 1, fold step 1, 70 queries, PoW 26), then runs the native
//! verifier (`CommitmentSchemeVerifier.verifyValues`) on the original proof
//! and on a battery of mutations, recording each verdict. The Lean side
//! replays the same inputs through the executable spec and must agree on
//! accept/reject for every case.
//!
//! Build (from the repo root):
//!   zig build-exe formal/in-circuit-verifier/harness/harness.zig \
//!     --dep stwo_core --dep stwo_prover_engine --dep stwo_cpu_backend \
//!     -Mroot=formal/in-circuit-verifier/harness/harness.zig \
//!     --dep stwo_core --dep stwo_backend_contracts --dep stwo_prover_api \
//!     -Mstwo_prover_engine=src/prover/mod.zig \
//!     --dep stwo_core -Mstwo_backend_contracts=src/backend/mod.zig \
//!     --dep stwo_core -Mstwo_prover_api=src/prover_api/mod.zig \
//!     --dep stwo_core --dep stwo_backend_contracts --dep stwo_prover_engine \
//!     -Mstwo_cpu_backend=src/backends/cpu_scalar/mod.zig \
//!     -Mstwo_core=src/core/mod.zig -O ReleaseSafe
//!
//! Run: ./harness <output.json> [pow_bits] [n_queries]

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const cpu = @import("stwo_cpu_backend");

const component_prover = prover.air.component_prover;
const prover_air_accumulation = prover.air.accumulation;
const core_air_components = core.air.components;
const core_air_accumulation = core.air.accumulation;
const SecureColumnByCoords = prover.secure_column.SecureColumnByCoords;

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const CirclePointQM31 = core.circle.CirclePointQM31;
const TreeVec = core.pcs.TreeVec;

const profile = core.vcs_lifted.channel_profile.proving_5a7c5ed.Blake2sM31MerkleChannel;
const Hasher = profile.MerkleHasher;
const Channel = profile.Channel;
const Scheme = prover.pcs.CommitmentSchemeProver(cpu.CpuBackend, Hasher, profile);
const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(Hasher, profile);
const PcsConfigV2 = core.pcs.config_v2.PcsConfigV2;
const FriConfigV2 = core.pcs.config_v2.FriConfigV2;
const Proof = core.pcs.CommitmentSchemeProof(Hasher);

/// Column layout: two trees. Tree 0 ("preprocessed") has one column of
/// log size 4; tree 1 has three columns of log sizes 4, 4, 3 (the short
/// one exercises the lifted-tree position mapping). Lifting height is the
/// extended max (5).
const tree0_log_sizes = [_]u32{8};
const tree1_log_sizes = [_]u32{ 8, 8, 7 };

fn makeColumn(allocator: std.mem.Allocator, log_size: u32, seed: u32) ![]M31 {
    const n = @as(usize, 1) << @intCast(log_size);
    const values = try allocator.alloc(M31, n);
    var state: u64 = seed;
    for (values) |*v| {
        state = state *% 6364136223846793005 +% 1442695040888963407;
        v.* = M31.fromU64(@as(u32, @truncate(state >> 32)));
    }
    return values;
}

const Case = struct {
    label: []const u8,
    verdict: []const u8, // "accept" or error name
    proof_json: []const u8,
};

fn qm31Json(w: anytype, v: QM31) !void {
    const limbs = v.toM31Array();
    try w.print("[{d},{d},{d},{d}]", .{ limbs[0].toU32(), limbs[1].toU32(), limbs[2].toU32(), limbs[3].toU32() });
}

fn hashJson(w: anytype, h: [32]u8) !void {
    try w.print("\"{s}\"", .{std.fmt.bytesToHex(h, .lower)});
}

fn proofJson(allocator: std.mem.Allocator, proof: *const Proof) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    const w = &out.writer;
    try w.writeAll("{\"commitments\":[");
    for (proof.commitments.items, 0..) |c, i| {
        if (i > 0) try w.writeAll(",");
        try hashJson(w, c);
    }
    try w.writeAll("],\"sampled_values\":[");
    for (proof.sampled_values.items, 0..) |tree, i| {
        if (i > 0) try w.writeAll(",");
        try w.writeAll("[");
        for (tree, 0..) |col, j| {
            if (j > 0) try w.writeAll(",");
            try w.writeAll("[");
            for (col, 0..) |v, k| {
                if (k > 0) try w.writeAll(",");
                try qm31Json(w, v);
            }
            try w.writeAll("]");
        }
        try w.writeAll("]");
    }
    try w.writeAll("],\"decommitments\":[");
    for (proof.decommitments.items, 0..) |d, i| {
        if (i > 0) try w.writeAll(",");
        try w.writeAll("[");
        for (d.hash_witness, 0..) |h, j| {
            if (j > 0) try w.writeAll(",");
            try hashJson(w, h);
        }
        try w.writeAll("]");
    }
    try w.writeAll("],\"queried_values\":[");
    for (proof.queried_values.items, 0..) |tree, i| {
        if (i > 0) try w.writeAll(",");
        try w.writeAll("[");
        for (tree, 0..) |col, j| {
            if (j > 0) try w.writeAll(",");
            try w.writeAll("[");
            for (col, 0..) |v, k| {
                if (k > 0) try w.writeAll(",");
                try w.print("{d}", .{v.toU32()});
            }
            try w.writeAll("]");
        }
        try w.writeAll("]");
    }
    try w.print("],\"proof_of_work\":{d},\"fri\":{{", .{proof.proof_of_work});
    try w.writeAll("\"first_layer\":");
    try friLayerJson(w, proof.fri_proof.first_layer);
    try w.writeAll(",\"inner_layers\":[");
    for (proof.fri_proof.inner_layers, 0..) |layer, i| {
        if (i > 0) try w.writeAll(",");
        try friLayerJson(w, layer);
    }
    try w.writeAll("],\"last_layer_poly\":[");
    for (proof.fri_proof.last_layer_poly.coefficients(), 0..) |c, i| {
        if (i > 0) try w.writeAll(",");
        try qm31Json(w, c);
    }
    try w.writeAll("]}}");
    return out.toOwnedSlice();
}

fn friLayerJson(w: anytype, layer: core.fri.FriLayerProof(Hasher)) !void {
    try w.writeAll("{\"witness\":[");
    for (layer.fri_witness, 0..) |v, i| {
        if (i > 0) try w.writeAll(",");
        try qm31Json(w, v);
    }
    try w.writeAll("],\"hash_witness\":[");
    for (layer.decommitment.hash_witness, 0..) |h, i| {
        if (i > 0) try w.writeAll(",");
        try hashJson(w, h);
    }
    try w.writeAll("],\"commitment\":");
    try hashJson(w, layer.commitment);
    try w.writeAll("}");
}

fn cloneProof(allocator: std.mem.Allocator, proof: *const Proof) !Proof {
    var out: Proof = undefined;
    out.config = proof.config;
    out.proof_of_work = proof.proof_of_work;
    out.commitments = TreeVec(Hasher.Hash).initOwned(try allocator.dupe(Hasher.Hash, proof.commitments.items));
    out.sampled_values = TreeVec([][]QM31).initOwned(try dupe3(QM31, allocator, proof.sampled_values.items));
    out.queried_values = TreeVec([][]M31).initOwned(try dupe3(M31, allocator, proof.queried_values.items));
    const decommitments = try allocator.alloc(core.vcs_lifted.verifier.MerkleDecommitmentLifted(Hasher), proof.decommitments.items.len);
    for (proof.decommitments.items, decommitments) |src, *dst| {
        dst.* = .{ .hash_witness = try allocator.dupe(Hasher.Hash, src.hash_witness) };
    }
    out.decommitments = TreeVec(core.vcs_lifted.verifier.MerkleDecommitmentLifted(Hasher)).initOwned(decommitments);
    out.fri_proof = .{
        .first_layer = try cloneLayer(allocator, proof.fri_proof.first_layer),
        .inner_layers = blk: {
            const layers = try allocator.alloc(core.fri.FriLayerProof(Hasher), proof.fri_proof.inner_layers.len);
            for (proof.fri_proof.inner_layers, layers) |src, *dst| dst.* = try cloneLayer(allocator, src);
            break :blk layers;
        },
        .last_layer_poly = core.poly.line.LinePoly.initOwned(
            try allocator.dupe(QM31, proof.fri_proof.last_layer_poly.coefficients()),
        ),
    };
    return out;
}

fn cloneLayer(allocator: std.mem.Allocator, layer: core.fri.FriLayerProof(Hasher)) !core.fri.FriLayerProof(Hasher) {
    return .{
        .fri_witness = try allocator.dupe(QM31, layer.fri_witness),
        .decommitment = .{ .hash_witness = try allocator.dupe(Hasher.Hash, layer.decommitment.hash_witness) },
        .commitment = layer.commitment,
    };
}

fn dupe3(comptime T: type, allocator: std.mem.Allocator, source: []const [][]T) ![][][]T {
    const trees = try allocator.alloc([][]T, source.len);
    for (source, trees) |src_tree, *tree| {
        tree.* = try allocator.alloc([]T, src_tree.len);
        for (src_tree, tree.*) |src_col, *col| col.* = try allocator.dupe(T, src_col);
    }
    return trees;
}

fn samplePointsTree(allocator: std.mem.Allocator) !TreeVec([][]CirclePointQM31) {
    // Tree 0: one column, one sample point. Tree 1: col 0 has two points
    // (exercises the periodicity duplicate), cols 1-2 one point each.
    const g = core.circle.SECURE_FIELD_CIRCLE_GEN;
    const p13 = g.mul(13);
    const p29 = g.mul(29);
    const t0c0 = try allocator.dupe(CirclePointQM31, &.{p13});
    const t0 = try allocator.dupe([]CirclePointQM31, &.{t0c0});
    const t1c0 = try allocator.dupe(CirclePointQM31, &.{ p13, p29 });
    const t1c1 = try allocator.dupe(CirclePointQM31, &.{p13});
    const t1c2 = try allocator.dupe(CirclePointQM31, &.{p29});
    const t1 = try allocator.dupe([]CirclePointQM31, &.{ t1c0, t1c1, t1c2 });
    return TreeVec([][]CirclePointQM31).initOwned(
        try allocator.dupe([][]CirclePointQM31, &.{ t0, t1 }),
    );
}

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    const gpa = gpa_state.allocator();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = try std.process.argsAlloc(arena);
    if (args.len < 2) {
        std.debug.print("usage: harness <output.json> [pow_bits] [n_queries] [n_fuzz] [statement]\n", .{});
        return error.BadUsage;
    }
    if (args.len > 5 and std.mem.eql(u8, args[5], "statement"))
        return statementMain(arena, args);
    const out_path = args[1];
    const pow_bits: u32 = if (args.len > 2) try std.fmt.parseInt(u32, args[2], 10) else 26;
    const n_queries: u32 = if (args.len > 3) try std.fmt.parseInt(u32, args[3], 10) else 70;

    const fri_config = try FriConfigV2.init(pow_bits, 0, 1, n_queries, 1);
    const config = PcsConfigV2.fromFriAndTraceSize(fri_config, 8);

    // ---- Prove.
    var scheme = try Scheme.initRevision(arena, config);
    var prover_channel = Channel{};
    fri_config.mixInto(&prover_channel);

    const t0c0 = try makeColumn(arena, 8, 1);
    try scheme.commit(arena, &.{.{ .log_size = 8, .values = t0c0 }}, &prover_channel);
    const t1c0 = try makeColumn(arena, 8, 2);
    const t1c1 = try makeColumn(arena, 8, 3);
    const t1c2 = try makeColumn(arena, 7, 4);
    try scheme.commit(arena, &.{
        .{ .log_size = 8, .values = t1c0 },
        .{ .log_size = 8, .values = t1c1 },
        .{ .log_size = 7, .values = t1c2 },
    }, &prover_channel);

    var ext = try scheme.proveValues(arena, try samplePointsTree(arena), &prover_channel);
    const proof = &ext.proof;

    // ---- Baseline verify + mutations.
    var cases = std.ArrayList(Case).empty;

    try runCase(arena, &cases, config, proof, "baseline", null);

    // Debug capture of the baseline verification's internals, for pinpointing
    // spec divergences: query positions, DEEP randomness and answers, and
    // each FRI layer's folding alpha and opened values.
    const debug_json = try captureDebug(arena, config, proof);

    const mutations = [_]Mutation{
        .{ .label = "sampled_value_flip", .kind = .sampled_value },
        .{ .label = "queried_value_flip", .kind = .queried_value },
        .{ .label = "commitment_root_flip", .kind = .root },
        .{ .label = "fri_first_commitment_flip", .kind = .fri_first_commitment },
        .{ .label = "fri_inner_commitment_flip", .kind = .fri_inner_commitment },
        .{ .label = "fri_witness_flip", .kind = .fri_witness },
        .{ .label = "fri_hash_witness_flip", .kind = .fri_hash_witness },
        .{ .label = "last_layer_flip", .kind = .last_layer },
        .{ .label = "pow_nonce_flip", .kind = .pow },
        .{ .label = "merkle_witness_truncate", .kind = .witness_truncate },
        .{ .label = "merkle_witness_flip", .kind = .merkle_witness },
        .{ .label = "drop_inner_layer", .kind = .drop_inner_layer },
        .{ .label = "duplicate_inner_layer", .kind = .duplicate_inner_layer },
        .{ .label = "extend_last_layer", .kind = .extend_last_layer },
    };
    for (mutations) |mutation| {
        try runCase(arena, &cases, config, proof, mutation.label, mutation);
    }

    // Seeded fuzz battery: random single-site corruptions over the whole
    // proof surface, including paths the fixed battery misses.
    const n_fuzz: usize = if (args.len > 4) try std.fmt.parseInt(usize, args[4], 10) else 48;
    var fuzz_index: usize = 0;
    while (fuzz_index < n_fuzz) : (fuzz_index += 1) {
        const label = try std.fmt.allocPrint(arena, "fuzz_{d}", .{fuzz_index});
        try runFuzzCase(arena, &cases, config, proof, label, fuzz_index);
    }

    // ---- Emit JSON.
    var out: std.Io.Writer.Allocating = .init(arena);
    const w = &out.writer;
    try w.print(
        "{{\"profile\":{{\"m31_channel\":true,\"pow_bits\":{d},\"log_blowup\":1," ++
            "\"log_last_layer\":0,\"n_queries\":{d},\"fold_step\":1," ++
            "\"trace_lifting_log_size\":{d},\"preprocessed_lifting_log_size\":{d}}},",
        .{ pow_bits, n_queries, config.trace_lifting_log_size, config.preprocessed_lifting_log_size },
    );
    try w.writeAll("\"trees\":[");
    const tree_sizes = [_][]const u32{ &tree0_log_sizes, &tree1_log_sizes };
    for (tree_sizes, 0..) |sizes, i| {
        if (i > 0) try w.writeAll(",");
        try w.writeAll("{\"root\":");
        try hashJson(w, proof.commitments.items[i]);
        try w.writeAll(",\"log_sizes\":[");
        for (sizes, 0..) |ls, j| {
            if (j > 0) try w.writeAll(",");
            try w.print("{d}", .{ls});
        }
        try w.writeAll("]}");
    }
    try w.writeAll("],\"sample_points\":");
    try samplePointsJson(w, arena);
    try w.print(",\"debug\":{s}", .{debug_json});
    try w.writeAll(",\"cases\":[");
    for (cases.items, 0..) |case, i| {
        if (i > 0) try w.writeAll(",");
        try w.print("{{\"label\":\"{s}\",\"verdict\":\"{s}\",\"proof\":{s}}}", .{ case.label, case.verdict, case.proof_json });
    }
    try w.writeAll("]}\n");

    try std.fs.cwd().writeFile(.{ .sub_path = out_path, .data = out.written() });
    std.debug.print("wrote {d} cases to {s}\n", .{ cases.items.len, out_path });
}

fn samplePointsJson(w: anytype, arena: std.mem.Allocator) !void {
    var points = try samplePointsTree(arena);
    defer points.deinitDeep(arena);
    try w.writeAll("[");
    for (points.items, 0..) |tree, i| {
        if (i > 0) try w.writeAll(",");
        try w.writeAll("[");
        for (tree, 0..) |col, j| {
            if (j > 0) try w.writeAll(",");
            try w.writeAll("[");
            for (col, 0..) |p, k| {
                if (k > 0) try w.writeAll(",");
                try w.writeAll("{\"x\":");
                try qm31Json(w, p.x);
                try w.writeAll(",\"y\":");
                try qm31Json(w, p.y);
                try w.writeAll("}");
            }
            try w.writeAll("]");
        }
        try w.writeAll("]");
    }
    try w.writeAll("]");
}

const Mutation = struct {
    label: []const u8,
    kind: Kind,

    const Kind = enum {
        sampled_value,
        queried_value,
        root,
        fri_first_commitment,
        fri_inner_commitment,
        fri_witness,
        fri_hash_witness,
        last_layer,
        pow,
        witness_truncate,
        merkle_witness,
        drop_inner_layer,
        duplicate_inner_layer,
        extend_last_layer,
    };
};

fn applyMutation(proof: *Proof, mutation: Mutation) void {
    const one = QM31.fromBase(M31.fromCanonical(1));
    switch (mutation.kind) {
        .sampled_value => {
            const tree = proof.sampled_values.items[1];
            tree[0][0] = tree[0][0].add(one);
        },
        .queried_value => {
            const tree = proof.queried_values.items[1];
            tree[0][0] = tree[0][0].add(M31.fromCanonical(1));
        },
        .root => proof.commitments.items[1][0] ^= 1,
        .fri_first_commitment => proof.fri_proof.first_layer.commitment[0] ^= 1,
        .fri_inner_commitment => {
            if (proof.fri_proof.inner_layers.len > 0)
                proof.fri_proof.inner_layers[0].commitment[0] ^= 1;
        },
        .fri_witness => {
            if (proof.fri_proof.first_layer.fri_witness.len > 0) {
                proof.fri_proof.first_layer.fri_witness[0] =
                    proof.fri_proof.first_layer.fri_witness[0].add(one);
            }
        },
        .fri_hash_witness => {
            if (proof.fri_proof.first_layer.decommitment.hash_witness.len > 0)
                proof.fri_proof.first_layer.decommitment.hash_witness[0][0] ^= 1;
        },
        .last_layer => {
            const coefficients = proof.fri_proof.last_layer_poly.coefficientsMut();
            coefficients[0] = coefficients[0].add(one);
        },
        .pow => proof.proof_of_work +%= 1,
        .witness_truncate => {
            const witness = proof.decommitments.items[1].hash_witness;
            if (witness.len > 0)
                proof.decommitments.items[1].hash_witness = witness[0 .. witness.len - 1];
        },
        .merkle_witness => {
            if (proof.decommitments.items[1].hash_witness.len > 0)
                proof.decommitments.items[1].hash_witness[0][0] ^= 1;
        },
        .drop_inner_layer => {
            if (proof.fri_proof.inner_layers.len > 0)
                proof.fri_proof.inner_layers = proof.fri_proof.inner_layers[0 .. proof.fri_proof.inner_layers.len - 1];
        },
        .duplicate_inner_layer => {
            if (proof.fri_proof.inner_layers.len > 0) {
                const layers = proof.fri_proof.inner_layers;
                const extended = std.heap.page_allocator.alloc(core.fri.FriLayerProof(Hasher), layers.len + 1) catch return;
                @memcpy(extended[0..layers.len], layers);
                extended[layers.len] = layers[layers.len - 1];
                proof.fri_proof.inner_layers = extended;
            }
        },
        .extend_last_layer => {
            const coefficients = proof.fri_proof.last_layer_poly.coefficients();
            const extended = std.heap.page_allocator.alloc(QM31, coefficients.len * 2) catch return;
            @memcpy(extended[0..coefficients.len], coefficients);
            @memset(extended[coefficients.len..], QM31.zero());
            proof.fri_proof.last_layer_poly = core.poly.line.LinePoly.initOwned(extended);
        },
    }
}

fn runCase(
    arena: std.mem.Allocator,
    cases: *std.ArrayList(Case),
    config: PcsConfigV2,
    proof: *const Proof,
    label: []const u8,
    mutation: ?Mutation,
) !void {
    var trial = try cloneProof(arena, proof);
    if (mutation) |m| applyMutation(&trial, m);
    const serialized = try proofJson(arena, &trial);

    var verifier = try Verifier.init(arena, config);
    var channel = Channel{};
    config.fri_config.mixInto(&channel);
    try verifier.commit(arena, trial.commitments.items[0], &tree0_log_sizes, &channel);
    try verifier.commit(arena, trial.commitments.items[1], &tree1_log_sizes, &channel);

    const points = try samplePointsTree(arena);
    const verdict: []const u8 = blk: {
        verifier.verifyValues(arena, points, trial, &channel) catch |err| {
            break :blk @errorName(err);
        };
        break :blk "accept";
    };
    try cases.append(arena, .{ .label = label, .verdict = verdict, .proof_json = serialized });
}

fn captureDebug(
    arena: std.mem.Allocator,
    config: PcsConfigV2,
    proof: *const Proof,
) ![]u8 {
    var verifier = try Verifier.init(arena, config);
    var channel = Channel{};
    config.fri_config.mixInto(&channel);
    try verifier.commit(arena, proof.commitments.items[0], &tree0_log_sizes, &channel);
    try verifier.commit(arena, proof.commitments.items[1], &tree1_log_sizes, &channel);
    const trial = try cloneProof(arena, proof);
    const points = try samplePointsTree(arena);
    var capture: core.pcs.verifier.VerifiedProofCapture(Hasher) = undefined;
    try verifier.verifyValuesWithProofCapture(arena, points, trial, &channel, .{
        .composition_randomness = QM31.zero(),
        .oods_seed = QM31.zero(),
    }, &capture);

    var out: std.Io.Writer.Allocating = .init(arena);
    const w = &out.writer;
    try w.writeAll("{\"raw_queries\":[");
    for (capture.queries.raw, 0..) |q, i| {
        if (i > 0) try w.writeAll(",");
        try w.print("{d}", .{q});
    }
    try w.writeAll("],\"unique_queries\":[");
    for (capture.queries.unique, 0..) |q, i| {
        if (i > 0) try w.writeAll(",");
        try w.print("{d}", .{q});
    }
    try w.writeAll("],\"deep_randomness\":");
    try qm31Json(w, capture.deep_randomness);
    try w.writeAll(",\"deep_answers_raw\":[");
    for (capture.deep_answers, 0..) |v, i| {
        if (i > 0) try w.writeAll(",");
        try qm31Json(w, v);
    }
    try w.writeAll("],\"fri_layers\":[");
    for (capture.fri.layers, 0..) |layer, i| {
        if (i > 0) try w.writeAll(",");
        try w.writeAll("{\"alpha\":");
        try qm31Json(w, layer.folding_alpha);
        try w.writeAll(",\"positions\":[");
        for (layer.positions, 0..) |q, j| {
            if (j > 0) try w.writeAll(",");
            try w.print("{d}", .{q});
        }
        try w.writeAll("],\"values\":[");
        for (layer.values, 0..) |v, j| {
            if (j > 0) try w.writeAll(",");
            try qm31Json(w, v);
        }
        try w.writeAll("]}");
    }
    try w.writeAll("],\"last_layer\":[");
    for (capture.last_layer_coefficients, 0..) |v, i| {
        if (i > 0) try w.writeAll(",");
        try qm31Json(w, v);
    }
    try w.writeAll("]}");
    return out.toOwnedSlice();
}

fn runFuzzCase(
    arena: std.mem.Allocator,
    cases: *std.ArrayList(Case),
    config: PcsConfigV2,
    proof: *const Proof,
    label: []const u8,
    seed: usize,
) !void {
    var trial = try cloneProof(arena, proof);
    var prng = std.Random.DefaultPrng.init(0x5eed_0000 + @as(u64, seed));
    const random = prng.random();
    fuzzMutate(&trial, random);
    const serialized = try proofJson(arena, &trial);

    var verifier = try Verifier.init(arena, config);
    var channel = Channel{};
    config.fri_config.mixInto(&channel);
    try verifier.commit(arena, trial.commitments.items[0], &tree0_log_sizes, &channel);
    try verifier.commit(arena, trial.commitments.items[1], &tree1_log_sizes, &channel);
    const points = try samplePointsTree(arena);
    const verdict: []const u8 = blk: {
        verifier.verifyValues(arena, points, trial, &channel) catch |err| {
            break :blk @errorName(err);
        };
        break :blk "accept";
    };
    try cases.append(arena, .{ .label = label, .verdict = verdict, .proof_json = serialized });
}

fn fuzzMutate(proof: *Proof, random: std.Random) void {
    const one = QM31.fromBase(M31.fromCanonical(random.intRangeAtMost(u32, 1, 100)));
    switch (random.intRangeAtMost(u8, 0, 9)) {
        0 => {
            // A sampled value anywhere.
            const tree = proof.sampled_values.items[random.uintLessThan(usize, proof.sampled_values.items.len)];
            const col = tree[random.uintLessThan(usize, tree.len)];
            if (col.len > 0) {
                const i = random.uintLessThan(usize, col.len);
                col[i] = col[i].add(one);
            }
        },
        1 => {
            // A queried value anywhere.
            const tree = proof.queried_values.items[random.uintLessThan(usize, proof.queried_values.items.len)];
            const col = tree[random.uintLessThan(usize, tree.len)];
            if (col.len > 0) {
                const i = random.uintLessThan(usize, col.len);
                col[i] = col[i].add(M31.fromCanonical(1 + random.uintLessThan(u32, 1000)));
            }
        },
        2 => {
            // A commitment byte.
            const i = random.uintLessThan(usize, proof.commitments.items.len);
            proof.commitments.items[i][random.uintLessThan(usize, 32)] ^=
                @as(u8, 1) << random.int(u3);
        },
        3 => {
            // A trace Merkle witness hash byte.
            const d = &proof.decommitments.items[random.uintLessThan(usize, proof.decommitments.items.len)];
            if (d.hash_witness.len > 0) {
                const i = random.uintLessThan(usize, d.hash_witness.len);
                d.hash_witness[i][random.uintLessThan(usize, 32)] ^= 1;
            }
        },
        4 => {
            // A FRI witness value in a random layer.
            const n_layers = proof.fri_proof.inner_layers.len + 1;
            const layer_index = random.uintLessThan(usize, n_layers);
            const layer = if (layer_index == 0)
                &proof.fri_proof.first_layer
            else
                &proof.fri_proof.inner_layers[layer_index - 1];
            if (layer.fri_witness.len > 0) {
                const i = random.uintLessThan(usize, layer.fri_witness.len);
                layer.fri_witness[i] = layer.fri_witness[i].add(one);
            }
        },
        5 => {
            // A FRI hash witness byte in a random layer.
            const n_layers = proof.fri_proof.inner_layers.len + 1;
            const layer_index = random.uintLessThan(usize, n_layers);
            const layer = if (layer_index == 0)
                &proof.fri_proof.first_layer
            else
                &proof.fri_proof.inner_layers[layer_index - 1];
            if (layer.decommitment.hash_witness.len > 0) {
                const i = random.uintLessThan(usize, layer.decommitment.hash_witness.len);
                layer.decommitment.hash_witness[i][random.uintLessThan(usize, 32)] ^= 1;
            }
        },
        6 => {
            // A FRI layer commitment byte.
            const n_layers = proof.fri_proof.inner_layers.len + 1;
            const layer_index = random.uintLessThan(usize, n_layers);
            if (layer_index == 0) {
                proof.fri_proof.first_layer.commitment[random.uintLessThan(usize, 32)] ^= 1;
            } else {
                proof.fri_proof.inner_layers[layer_index - 1].commitment[random.uintLessThan(usize, 32)] ^= 1;
            }
        },
        7 => {
            const coefficients = proof.fri_proof.last_layer_poly.coefficientsMut();
            const i = random.uintLessThan(usize, coefficients.len);
            coefficients[i] = coefficients[i].add(one);
        },
        8 => proof.proof_of_work ^= @as(u64, 1) << @intCast(random.uintLessThan(u6, 40)),
        9 => {
            // Truncate a random FRI layer's QM31 witness by one.
            const n_layers = proof.fri_proof.inner_layers.len + 1;
            const layer_index = random.uintLessThan(usize, n_layers);
            const layer = if (layer_index == 0)
                &proof.fri_proof.first_layer
            else
                &proof.fri_proof.inner_layers[layer_index - 1];
            if (layer.fri_witness.len > 0)
                layer.fri_witness = layer.fri_witness[0 .. layer.fri_witness.len - 1];
        },
        else => unreachable,
    }
}

// ---------------------------------------------------------------------------
// Statement-level vectors: a one-constraint mock AIR whose composition
// polynomial is a constant, proved with the engine's `proveEx` and verified
// with the full native `core.verifier.verify` (the `NativeAccepts` law).

const MockComponent = struct {
    max_log_degree_bound: u32,
    value: QM31,

    const trace_log: u32 = 3;

    fn asProverComponent(self: *const @This()) component_prover.ComponentProver {
        return .{
            .ctx = self,
            .vtable = &.{
                .nConstraints = nConstraints,
                .maxConstraintLogDegreeBound = maxConstraintLogDegreeBound,
                .traceLogDegreeBounds = traceLogDegreeBounds,
                .maskPoints = maskPoints,
                .preprocessedColumnIndices = preprocessedColumnIndices,
                .evaluateConstraintQuotientsAtPoint = evaluateConstraintQuotientsAtPoint,
                .evaluateConstraintQuotientsOnDomain = evaluateConstraintQuotientsOnDomain,
            },
        };
    }

    fn cast(ctx: *const anyopaque) *const @This() {
        return @ptrCast(@alignCast(ctx));
    }
    fn nConstraints(_: *const anyopaque) usize {
        return 1;
    }
    fn maxConstraintLogDegreeBound(ctx: *const anyopaque) u32 {
        return cast(ctx).max_log_degree_bound;
    }
    fn traceLogDegreeBounds(_: *const anyopaque, allocator: std.mem.Allocator) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try allocator.dupe(u32, &[_]u32{trace_log});
        const main_sizes = try allocator.dupe(u32, &[_]u32{trace_log});
        return core_air_components.TraceLogDegreeBounds.initOwned(
            try allocator.dupe([]u32, &[_][]u32{ preprocessed, main_sizes }),
        );
    }
    fn maskPoints(
        _: *const anyopaque,
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        _: u32,
    ) !core_air_components.MaskPoints {
        const preprocessed_col = try allocator.alloc(CirclePointQM31, 1);
        preprocessed_col[0] = point;
        const preprocessed_cols = try allocator.dupe([]CirclePointQM31, &[_][]CirclePointQM31{preprocessed_col});
        const main_col = try allocator.alloc(CirclePointQM31, 1);
        main_col[0] = point;
        const main_cols = try allocator.dupe([]CirclePointQM31, &[_][]CirclePointQM31{main_col});
        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{ preprocessed_cols, main_cols }),
        );
    }
    fn preprocessedColumnIndices(_: *const anyopaque, allocator: std.mem.Allocator) ![]usize {
        return allocator.dupe(usize, &[_]usize{0});
    }
    fn evaluateConstraintQuotientsAtPoint(
        ctx: *const anyopaque,
        _: CirclePointQM31,
        _: *const core_air_components.MaskValues,
        evaluation_accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        _: u32,
    ) !void {
        evaluation_accumulator.accumulate(cast(ctx).value);
    }
    fn evaluateConstraintQuotientsOnDomain(
        ctx: *const anyopaque,
        _: *const component_prover.Trace,
        evaluation_accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !void {
        const self = cast(ctx);
        const domain_size = @as(usize, 1) << @intCast(self.max_log_degree_bound);
        const values = try std.heap.page_allocator.alloc(QM31, domain_size);
        defer std.heap.page_allocator.free(values);
        @memset(values, self.value);
        var col = try SecureColumnByCoords.fromSecureSlice(std.heap.page_allocator, values);
        defer col.deinit(std.heap.page_allocator);
        try evaluation_accumulator.accumulateColumn(self.max_log_degree_bound, &col);
    }
};

const statement_tree0_log_sizes = [_]u32{ MockComponent.trace_log, MockComponent.trace_log };
const statement_tree1_log_sizes = [_]u32{MockComponent.trace_log};

fn statementMain(arena: std.mem.Allocator, args: [][:0]u8) !void {
    const out_path = args[1];
    const pow_bits: u32 = if (args.len > 2) try std.fmt.parseInt(u32, args[2], 10) else 26;
    const n_queries: u32 = if (args.len > 3) try std.fmt.parseInt(u32, args[3], 10) else 70;
    const n_fuzz: usize = if (args.len > 4) try std.fmt.parseInt(usize, args[4], 10) else 48;

    const fri_config = try FriConfigV2.init(pow_bits, 0, 1, n_queries, 1);
    const config = PcsConfigV2.fromFriAndTraceSize(fri_config, MockComponent.trace_log);
    const composition_value = QM31.fromU32Unchecked(9, 8, 7, 6);
    const mock = MockComponent{ .max_log_degree_bound = MockComponent.trace_log + 1, .value = composition_value };
    const prover_components = [_]component_prover.ComponentProver{mock.asProverComponent()};

    var scheme = try Scheme.initRevision(arena, config);
    var prover_channel = Channel{};
    fri_config.mixInto(&prover_channel);

    const pre0 = try makeColumn(arena, MockComponent.trace_log, 11);
    const pre1 = try makeColumn(arena, MockComponent.trace_log, 12);
    try scheme.commit(arena, &.{
        .{ .log_size = MockComponent.trace_log, .values = pre0 },
        .{ .log_size = MockComponent.trace_log, .values = pre1 },
    }, &prover_channel);
    const main_values = try makeColumn(arena, MockComponent.trace_log, 13);
    try scheme.commit(arena, &.{
        .{ .log_size = MockComponent.trace_log, .values = main_values },
    }, &prover_channel);

    var ext = try prover.prove.proveEx(
        cpu.CpuBackend,
        Hasher,
        profile,
        arena,
        prover_components[0..],
        &prover_channel,
        scheme,
        false,
    );
    const proof = &ext.proof.commitment_scheme_proof;

    var cases = std.ArrayList(Case).empty;
    try runStatementCase(arena, &cases, config, &mock, proof, "baseline", null);
    const mutations = [_]Mutation{
        .{ .label = "sampled_value_flip", .kind = .sampled_value },
        .{ .label = "queried_value_flip", .kind = .queried_value },
        .{ .label = "commitment_root_flip", .kind = .root },
        .{ .label = "fri_first_commitment_flip", .kind = .fri_first_commitment },
        .{ .label = "fri_inner_commitment_flip", .kind = .fri_inner_commitment },
        .{ .label = "fri_witness_flip", .kind = .fri_witness },
        .{ .label = "fri_hash_witness_flip", .kind = .fri_hash_witness },
        .{ .label = "last_layer_flip", .kind = .last_layer },
        .{ .label = "pow_nonce_flip", .kind = .pow },
        .{ .label = "merkle_witness_truncate", .kind = .witness_truncate },
        .{ .label = "merkle_witness_flip", .kind = .merkle_witness },
        .{ .label = "drop_inner_layer", .kind = .drop_inner_layer },
        .{ .label = "duplicate_inner_layer", .kind = .duplicate_inner_layer },
        .{ .label = "extend_last_layer", .kind = .extend_last_layer },
    };
    for (mutations) |mutation| {
        try runStatementCase(arena, &cases, config, &mock, proof, mutation.label, mutation);
    }
    var fuzz_index: usize = 0;
    while (fuzz_index < n_fuzz) : (fuzz_index += 1) {
        const label = try std.fmt.allocPrint(arena, "fuzz_{d}", .{fuzz_index});
        var trial = try cloneProof(arena, proof);
        var prng = std.Random.DefaultPrng.init(0x57a7_0000 + @as(u64, fuzz_index));
        fuzzMutate(&trial, prng.random());
        const serialized = try proofJson(arena, &trial);
        const verdict = try statementVerify(arena, config, &mock, trial);
        try cases.append(arena, .{ .label = label, .verdict = verdict, .proof_json = serialized });
    }

    var out: std.Io.Writer.Allocating = .init(arena);
    const w = &out.writer;
    try w.print(
        "{{\"profile\":{{\"m31_channel\":true,\"pow_bits\":{d},\"log_blowup\":1," ++
            "\"log_last_layer\":0,\"n_queries\":{d},\"fold_step\":1," ++
            "\"trace_lifting_log_size\":{d},\"preprocessed_lifting_log_size\":{d}}},",
        .{ pow_bits, n_queries, config.trace_lifting_log_size, config.preprocessed_lifting_log_size },
    );
    try w.print(
        "\"statement\":{{\"composition_log_degree_bound\":{d},\"split\":1," ++
            "\"n_preprocessed_columns\":{d},\"preprocessed_mask_indices\":[0],\"composition_value\":",
        .{ mock.max_log_degree_bound, statement_tree0_log_sizes.len },
    );
    try qm31Json(w, composition_value);
    try w.writeAll("},\"trees\":[");
    const tree_sizes = [_][]const u32{ &statement_tree0_log_sizes, &statement_tree1_log_sizes };
    for (tree_sizes, 0..) |sizes, i| {
        if (i > 0) try w.writeAll(",");
        try w.writeAll("{\"root\":");
        try hashJson(w, proof.commitments.items[i]);
        try w.writeAll(",\"log_sizes\":[");
        for (sizes, 0..) |ls, j| {
            if (j > 0) try w.writeAll(",");
            try w.print("{d}", .{ls});
        }
        try w.writeAll("]}");
    }
    try w.writeAll("],\"cases\":[");
    for (cases.items, 0..) |case, i| {
        if (i > 0) try w.writeAll(",");
        try w.print("{{\"label\":\"{s}\",\"verdict\":\"{s}\",\"proof\":{s}}}", .{ case.label, case.verdict, case.proof_json });
    }
    try w.writeAll("]}\n");
    try std.fs.cwd().writeFile(.{ .sub_path = out_path, .data = out.written() });
    std.debug.print("wrote {d} statement cases to {s}\n", .{ cases.items.len, out_path });
}

fn runStatementCase(
    arena: std.mem.Allocator,
    cases: *std.ArrayList(Case),
    config: PcsConfigV2,
    mock: *const MockComponent,
    proof: *const Proof,
    label: []const u8,
    mutation: ?Mutation,
) !void {
    var trial = try cloneProof(arena, proof);
    if (mutation) |m| applyMutation(&trial, m);
    const serialized = try proofJson(arena, &trial);
    const verdict = try statementVerify(arena, config, mock, trial);
    try cases.append(arena, .{ .label = label, .verdict = verdict, .proof_json = serialized });
}

fn statementVerify(
    arena: std.mem.Allocator,
    config: PcsConfigV2,
    mock: *const MockComponent,
    trial: Proof,
) ![]const u8 {
    var verifier = try Verifier.init(arena, config);
    var channel = Channel{};
    config.fri_config.mixInto(&channel);
    try verifier.commit(arena, trial.commitments.items[0], &statement_tree0_log_sizes, &channel);
    try verifier.commit(arena, trial.commitments.items[1], &statement_tree1_log_sizes, &channel);

    const prover_components = [_]component_prover.ComponentProver{mock.asProverComponent()};
    const component_provers = component_prover.ComponentProvers{
        .components = prover_components[0..],
        .n_preprocessed_columns = statement_tree0_log_sizes.len,
    };
    var components_view = try component_provers.componentsView(arena);
    const stark_proof = core.proof.StarkProof(Hasher){ .commitment_scheme_proof = trial };
    core.verifier.verify(
        Hasher,
        profile,
        arena,
        components_view.asCore().components,
        &channel,
        &verifier,
        stark_proof,
    ) catch |err| {
        return @errorName(err);
    };
    return "accept";
}
