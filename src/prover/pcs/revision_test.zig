//! PCS prover under protocol revision `proving_5a7c5ed` against the Rust
//! `CommitmentSchemeProver<SimdBackend, MC>` of
//! https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230 (crates/stwo, feature `prover`).
//!
//! Oracle program (one scenario; `MC`, `preprocessed_lifting_log_size` vary):
//!
//! ```text
//! col(log, seed)[i] = seed * 1000 + i * 7 + 1   (BitReversedOrder evaluation)
//! fri = FriConfig::new(20, 0, 1, 3, 4)
//! config = PcsConfig { fri, trace_lifting_log_size: 6, preprocessed_lifting_log_size }
//! channel = MC::C::default(); channel.mix_u64(0); fri.mix_into(channel)
//! scheme = CommitmentSchemeProver::<SimdBackend, MC>::new(config, twiddles(7))
//! trees: [col(3,1), col(4,2)], [col(5,3), col(4,4), col(5,5)], [col(5,6), col(5,7)]
//! p = SECURE_FIELD_CIRCLE_GEN.mul(47), q = SECURE_FIELD_CIRCLE_GEN.mul(1013)
//! points = [[[p], []], [[p, q], [p], []], [[p], [p]]]
//! scheme.prove_values(points, channel)
//! ```
//!
//! Every tree except the last is lifted above its largest column, and at seed
//! 0 the 20-bit FRI nonce of the lift-6 scenarios needs `hi > 0`, where the
//! SIMD grind order and the lowest nonce disagree. Digests are Blake2s-256 of
//! the little-endian u32 words: sampled values (tree, column, sample, QM31
//! coordinates), queried values (tree, column, query), trace decommitment
//! witnesses (tree order), and FRI witnesses (per layer: Merkle witness, then
//! `fri_witness` coordinates).

const std = @import("std");
const core = @import("stwo_core");
const scheme_mod = @import("scheme.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const CirclePointQM31 = core.circle.CirclePointQM31;
const Column = scheme_mod.ColumnEvaluation;
const Points = core.pcs.TreeVec([][]CirclePointQM31);
const profiles = core.vcs_lifted.channel_profile.proving_5a7c5ed;
const config_v2 = core.pcs.config_v2;

const HostBackend = struct {
    pub fn MerkleTree(comptime Hasher: type) type {
        return @import("../vcs_lifted/prover.zig").MerkleProverLifted(Hasher);
    }
    pub fn commitMerkle(comptime Hasher: type, allocator: std.mem.Allocator, columns: []const []const M31) !MerkleTree(Hasher) {
        return MerkleTree(Hasher).commit(allocator, columns);
    }
};

const Expected = struct {
    roots: [3]*const [64]u8,
    pow: u64,
    fri_roots: [2]*const [64]u8,
    last_layer: *const [32]u8,
    queried_digest: *const [64]u8,
    trace_witness_digest: *const [64]u8,
    fri_witness_digest: *const [64]u8,
    queries: [3]usize,
    final_digest: *const [64]u8,
};

const sampled_digest = "9db9f49321c56a5b0ac56050a78067626b72b139bcc7d115b8acd58902f3174b";
const trace_root_1 = "c2f0c7941803f7f4f1872b92897e5680cd5c086f1d771f85a681114430f0cb76";
const trace_root_2 = "fb029aa70dd6b1ddfcd4a5be922315595fef346821a0a4c0aeb9d6ef1540ac48";

const m31_lift6 = Expected{
    .roots = .{ "8802f1400a9fa1eb5d2f7e1300e970d05eedddf66c0ce229fa9de3fb9c7ee8a9", trace_root_1, trace_root_2 },
    .pow = 0x2_0005_ac13,
    .fri_roots = .{
        "1155514d06618c11ff96982fc00680e2f4966963019fb18e616f285abf01ce3d",
        "c4f4f4047002fd851b25201526f124de4c5bb648a6a6913bad47a527657226d5",
    },
    .last_layer = "f18b9f0e7395e4619b96561ea84ccb71",
    .queried_digest = "678a5194ef1b188926d1e5d480b237faed2de25ae5cfb4aede1430fbc5c44791",
    .trace_witness_digest = "39d08af9d4f4bde20b6ca4ee4ce960b31dae38d67c3ea3df9186ae3fb82f1ccd",
    .fri_witness_digest = "8df28c20bb561d5681e3ca1eee0ef271c8d76932b4eccd1c37d044aa3ca8f4d1",
    .queries = .{ 1, 53, 20 },
    .final_digest = "48126172408db9711f56b27187c7c406c75ed24fd770fc44d4997850dd807636",
};

const m31_lift5 = Expected{
    .roots = .{ "c5e6959998d75e9d1402d482ba210d36dd499939958ad0d66e55f239ac40a4fc", trace_root_1, trace_root_2 },
    .pow = 0xea0ca,
    .fri_roots = .{
        "c5f067af9e9199d3d23253f868b049c541b0871e8afcae309cc912610a918d53",
        "3cacda5b5571454709b1cb9fd05201946ca9f942ec702b8c799e9c169a86d651",
    },
    .last_layer = "f1bb8c34f05c99079b29866ff45a3f7f",
    .queried_digest = "3db9362fa3c3b75f49a5da9e4c8f445b60905b6062f735a3727d28a046065a33",
    .trace_witness_digest = "b7176abf24ad24fede4801855a44671e4655b5885354a6a996d30c4a3f7641f6",
    .fri_witness_digest = "35ac2b29bd5c905da51424509ab9db9f107d836c5462247e9c7402f25eaa8a18",
    .queries = .{ 48, 62, 62 },
    .final_digest = "9c759c2712f581684dd82362f60b8a255a8b351b30bfbc1268e90c69bfca6353",
};

const plain_lift6 = Expected{
    .roots = .{ "8802f1400a9fa1eb5d2f7e1300e970d05eedddf66c0ce229fa9de3fb9c7ee8a9", trace_root_1, trace_root_2 },
    .pow = 0x1_000f_458d,
    .fri_roots = .{
        "4f5a487ce54d201df7dd0bc7c185ba1748974877455c1b03308a9b5e780c7ea2",
        "30d5c46b7891f2c15d130b995bda3126b57baee3b48c18a1fba979490c06900e",
    },
    .last_layer = "2bb333055a9e1e79017d0045fb301447",
    .queried_digest = "b4c73473c8f15d093e856256fdefa41d3cd0dd4d8c4cfec3364b38256ce85075",
    .trace_witness_digest = "fe018eab1a65313e02efd670bd279add10d8649161236ad3a3fe52d01198bfba",
    .fri_witness_digest = "ba22a2768a69b4d0f866518daab1d67fba1dbfff6c44b31fec1861742900d424",
    .queries = .{ 46, 57, 53 },
    .final_digest = "d09ed8daabc8750a7371bc17d9b64106bc575456232a6b1dedc3fafdb938b5e2",
};

fn makeColumn(allocator: std.mem.Allocator, log_size: u32, seed: u32) !Column {
    const values = try allocator.alloc(M31, @as(usize, 1) << @intCast(log_size));
    for (values, 0..) |*value, i| value.* = M31.fromCanonical(seed * 1000 + @as(u32, @intCast(i)) * 7 + 1);
    return .{ .log_size = log_size, .values = values };
}

fn commitTree(scheme: anytype, allocator: std.mem.Allocator, shape: []const [2]u32, channel: anytype) !void {
    const columns = try allocator.alloc(Column, shape.len);
    defer allocator.free(columns);
    var initialized: usize = 0;
    defer for (columns[0..initialized]) |column| allocator.free(column.values);
    for (shape, columns) |entry, *column| {
        column.* = try makeColumn(allocator, entry[0], entry[1]);
        initialized += 1;
    }
    try scheme.commit(allocator, columns, channel);
}

fn samplePoints(allocator: std.mem.Allocator) !Points {
    const p = core.circle.SECURE_FIELD_CIRCLE_GEN.mul(47);
    const q = core.circle.SECURE_FIELD_CIRCLE_GEN.mul(1013);
    const shape = [_][]const []const CirclePointQM31{
        &.{ &.{p}, &.{} },
        &.{ &.{ p, q }, &.{p}, &.{} },
        &.{ &.{p}, &.{p} },
    };
    const trees = try allocator.alloc([][]CirclePointQM31, shape.len);
    for (shape, trees) |tree_shape, *tree| {
        tree.* = try allocator.alloc([]CirclePointQM31, tree_shape.len);
        for (tree_shape, tree.*) |column_points, *points| points.* = try allocator.dupe(CirclePointQM31, column_points);
    }
    return Points.initOwned(trees);
}

fn Digest() type {
    return struct {
        hasher: std.crypto.hash.blake2.Blake2s256 = .init(.{}),

        fn word(self: *@This(), value: u32) void {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, value, .little);
            self.hasher.update(&bytes);
        }
        fn qm31(self: *@This(), value: QM31) void {
            for (value.toM31Array()) |coordinate| self.word(coordinate.toU32());
        }
        fn hex(self: *@This()) [64]u8 {
            var out: [32]u8 = undefined;
            self.hasher.final(&out);
            return std.fmt.bytesToHex(out, .lower);
        }
    };
}

fn proveScenario(comptime Profile: type, preprocessed_lifting_log_size: u32, expected: Expected) !void {
    const allocator = std.testing.allocator;
    const Scheme = scheme_mod.CommitmentSchemeProver(HostBackend, Profile.MerkleHasher, Profile);
    comptime std.debug.assert(Scheme.explicit_tree_heights);
    const fri = try config_v2.FriConfigV2.init(20, 0, 1, 3, 4);
    const config = config_v2.PcsConfigV2{
        .fri_config = fri,
        .trace_lifting_log_size = 6,
        .preprocessed_lifting_log_size = preprocessed_lifting_log_size,
    };

    var channel = Profile.Channel{};
    channel.mixU64(0);
    fri.mixInto(&channel);
    var scheme = try Scheme.init(allocator, config);
    scheme.setStorePolynomialsCoefficients();
    {
        errdefer scheme.deinit(allocator);
        try commitTree(&scheme, allocator, &.{ .{ 3, 1 }, .{ 4, 2 } }, &channel);
        try commitTree(&scheme, allocator, &.{ .{ 5, 3 }, .{ 4, 4 }, .{ 5, 5 } }, &channel);
        try commitTree(&scheme, allocator, &.{ .{ 5, 6 }, .{ 5, 7 } }, &channel);
        try std.testing.expectEqual(@as(?u32, preprocessed_lifting_log_size), scheme.trees.items[0].merkle_log_height);
        try std.testing.expectEqual(@as(?u32, 6), scheme.trees.items[1].merkle_log_height);
    }
    var ext = try scheme.proveValues(allocator, try samplePoints(allocator), &channel);
    defer ext.aux.deinit(allocator);
    var proof_owned = true;
    defer if (proof_owned) ext.proof.deinit(allocator);
    const proof = ext.proof;

    for (expected.roots, proof.commitments.items) |root, actual|
        try std.testing.expectEqualStrings(root, &std.fmt.bytesToHex(actual, .lower));
    try std.testing.expectEqual(expected.pow, proof.proof_of_work);
    try std.testing.expectEqualStrings(expected.fri_roots[0], &std.fmt.bytesToHex(proof.fri_proof.first_layer.commitment, .lower));
    try std.testing.expectEqual(@as(usize, 1), proof.fri_proof.inner_layers.len);
    try std.testing.expectEqualStrings(expected.fri_roots[1], &std.fmt.bytesToHex(proof.fri_proof.inner_layers[0].commitment, .lower));

    var last_layer_bytes: [16]u8 = undefined;
    const last_layer = proof.fri_proof.last_layer_poly.coefficients();
    try std.testing.expectEqual(@as(usize, 1), last_layer.len);
    for (last_layer[0].toM31Array(), 0..) |coordinate, i|
        std.mem.writeInt(u32, last_layer_bytes[i * 4 ..][0..4], coordinate.toU32(), .little);
    try std.testing.expectEqualStrings(expected.last_layer, &std.fmt.bytesToHex(last_layer_bytes, .lower));

    var sampled = Digest(){};
    for (proof.sampled_values.items) |tree| for (tree) |column| for (column) |value| sampled.qm31(value);
    try std.testing.expectEqualStrings(sampled_digest, &sampled.hex());

    var queried = Digest(){};
    for (proof.queried_values.items) |tree| for (tree) |column| for (column) |value| queried.word(value.toU32());
    try std.testing.expectEqualStrings(expected.queried_digest, &queried.hex());

    var trace_witness = Digest(){};
    for (proof.decommitments.items) |decommitment| for (decommitment.hash_witness) |hash| trace_witness.hasher.update(&hash);
    try std.testing.expectEqualStrings(expected.trace_witness_digest, &trace_witness.hex());

    var fri_witness = Digest(){};
    const layers = [_]@TypeOf(proof.fri_proof.first_layer){ proof.fri_proof.first_layer, proof.fri_proof.inner_layers[0] };
    for (layers) |layer| {
        for (layer.decommitment.hash_witness) |hash| fri_witness.hasher.update(&hash);
        for (layer.fri_witness) |value| fri_witness.qm31(value);
    }
    try std.testing.expectEqualStrings(expected.fri_witness_digest, &fri_witness.hex());

    try std.testing.expectEqualSlices(usize, &expected.queries, ext.aux.unsorted_query_locations);
    try std.testing.expectEqualStrings(expected.final_digest, &std.fmt.bytesToHex(channel.digestBytes(), .lower));

    // The native verifier of the same revision accepts the proof and ends
    // on the prover's transcript.
    const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(Profile.MerkleHasher, Profile);
    var verifier = try Verifier.init(allocator, config);
    defer verifier.deinit(allocator);
    var verifier_channel = Profile.Channel{};
    verifier_channel.mixU64(0);
    fri.mixInto(&verifier_channel);
    for ([_][]const u32{ &.{ 3, 4 }, &.{ 5, 4, 5 }, &.{ 5, 5 } }, proof.commitments.items) |log_sizes, root|
        try verifier.commit(allocator, root, log_sizes, &verifier_channel);
    proof_owned = false;
    try verifier.verifyValues(allocator, try samplePoints(allocator), proof, &verifier_channel);
    try std.testing.expectEqualSlices(u8, &channel.digestBytes(), &verifier_channel.digestBytes());
}

test "PCS revision: Blake2sM31MerkleChannel proof with lifted trees matches proving@5a7c5ed" {
    try proveScenario(profiles.Blake2sM31MerkleChannel, 6, m31_lift6);
}

test "PCS revision: preprocessed tree below the trace height matches proving@5a7c5ed" {
    try proveScenario(profiles.Blake2sM31MerkleChannel, 5, m31_lift5);
}

test "PCS revision: Blake2sMerkleChannel root profile matches proving@5a7c5ed" {
    try proveScenario(profiles.Blake2sMerkleChannel, 6, plain_lift6);
}

test "PCS revision: a nonempty tree above its configured height is refused" {
    const allocator = std.testing.allocator;
    const Profile = profiles.Blake2sM31MerkleChannel;
    const Scheme = scheme_mod.CommitmentSchemeProver(HostBackend, Profile.MerkleHasher, Profile);
    const config = config_v2.PcsConfigV2{
        .fri_config = try config_v2.FriConfigV2.init(0, 0, 1, 3, 4),
        .trace_lifting_log_size = 6,
        .preprocessed_lifting_log_size = 4,
    };
    var scheme = try Scheme.init(allocator, config);
    defer scheme.deinit(allocator);
    var channel = Profile.Channel{};
    const before = channel.digestBytes();
    try std.testing.expectError(error.InvalidTreeHeight, commitTree(&scheme, allocator, &.{.{ 4, 1 }}, &channel));
    try std.testing.expectEqual(@as(usize, 0), scheme.trees.items.len);
    try std.testing.expectEqualSlices(u8, &before, &channel.digestBytes());
}
