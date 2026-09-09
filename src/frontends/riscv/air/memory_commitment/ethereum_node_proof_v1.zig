//! Bounded development proof of a 30-level path and all 120 permutations.
//! Public position, leaf digest and root are constrained; VM leaf encoding and
//! memory/program execution linkage remain outside this diagnostic.
//! The deliberately cheap PCS configuration is not a security admission.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const postcard = @import("interop_postcard");
const node = @import("ethereum_node_v1.zig");
const path = @import("ethereum_path_v1.zig");
const word_tree = @import("ethereum_word_tree_v1.zig");
const adapter = @import("ethereum_node_component_v1.zig");
const poseidon = @import("poseidon2_air.zig");
const hash = @import("hash_component.zig");
const relations_mod = @import("../relation_challenges.zig");
const BitReversalTable = @import("../../infra_trace.zig").BitReversalTable;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const log_size: u32 = 5;
const provider_log_size: u32 = 7;
const row_count: usize = 30;
const caller_size = 1 << log_size;
const provider_size = 1 << provider_log_size;
const header_bytes = path.STATEMENT_BYTES + 64;
const widths = [_]usize{ path.PREPROCESSED_COLUMNS + 1, node.N_MAIN_COLUMNS + poseidon.N_MAIN_COLUMNS, node.N_INTERACTION_COLUMNS + poseidon.N_INTERACTION_COLUMNS };
const max_bytes = 2 * 1024 * 1024;
const Mutation = enum { none, squeeze, height, link, root };

pub const Receipt = struct {
    proof_bytes: usize,
    proof_sha256: [32]u8,
    produce_ns: u64,
    fresh_verify_ns: u64,
};

fn config() !core.pcs.PcsConfig {
    return .{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 3) };
}

fn prefix(channel: anytype, pcs: core.pcs.PcsConfig, statement: path.Statement) void {
    pcs.mixInto(channel);
    channel.mixU32s(&.{ 0x45545031, 2, log_size, provider_log_size, row_count, node.CALLS, node.DIGEST_WORDS });
    channel.mixU32s(&.{ @intFromEnum(statement.kind), statement.depth, statement.index });
    channel.mixU32s(&statement.leaf);
    channel.mixU32s(&statement.root);
}

fn provider(relations: *const relations_mod.Relations, claims: [2]QM31) hash.HashComponent {
    return .{
        .kind = .poseidon2,
        .poseidon_shell = .universal,
        .log_size = provider_log_size,
        .n_rows = row_count * node.CALLS,
        .is_first_col_idx = path.PREPROCESSED_COLUMNS,
        .is_active_col_idx = path.PREPROCESSED_COLUMNS, // Unused by the universal shell.
        .main_col_offset = node.N_MAIN_COLUMNS,
        .interaction_col_offset = node.N_INTERACTION_COLUMNS,
        .relations = relations,
        .poseidon_claims = claims,
    };
}

fn validateClaims(claims: [4]QM31) !void {
    var sum = QM31.zero();
    for (claims) |claim| sum = sum.add(claim);
    if (!sum.isZero()) return error.UnbalancedNodeProviderClaims;
}

/// The tiny diagnostic copies columns into the consuming engine API. A real
/// leaf must transfer its owned columns instead of duplicating this storage.
// ponytail: fixed small diagnostic copies columns; transfer ownership for real leaves.
fn commit(comptime Engine: type, allocator: std.mem.Allocator, scheme: *Engine.Scheme, channel: *Engine.Channel, sources: []const []const M31) !void {
    const columns = try allocator.alloc(engine.pcs.ColumnEvaluation, sources.len);
    var initialized: usize = 0;
    var moved = false;
    defer if (!moved) {
        for (columns[0..initialized]) |column| allocator.free(column.values);
        allocator.free(columns);
    };
    for (columns, sources) |*column, values| {
        column.* = .{ .log_size = std.math.log2_int(usize, values.len), .values = try allocator.dupe(M31, values) };
        initialized += 1;
    }
    moved = true;
    try Engine.commit(scheme, allocator, columns, null, channel);
    try Engine.flushPendingCommit(scheme, allocator, channel);
}

fn commitPreprocessed(comptime Engine: type, allocator: std.mem.Allocator, scheme: *Engine.Scheme, channel: *Engine.Channel, statement: path.Statement) !void {
    const placement = try BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);
    var pp = [_][caller_size]M31{.{M31.zero()} ** caller_size} ** path.PREPROCESSED_COLUMNS;
    for (0..caller_size) |logical| {
        for (&pp, statement.preprocessedAt(logical)) |*column, value| column[placement.map(logical)] = value;
    }
    var provider_pp = [_][provider_size]M31{.{M31.zero()} ** provider_size} ** 1;
    provider_pp[0][0] = M31.one();
    var columns: [widths[0]][]const M31 = undefined;
    for (columns[0..path.PREPROCESSED_COLUMNS], &pp) |*column, *values| column.* = values;
    for (columns[path.PREPROCESSED_COLUMNS..], &provider_pp) |*column, *values| column.* = values;
    try commit(Engine, allocator, scheme, channel, &columns);
}

/// All witness, scheme, pool and in-memory proof owners die before returning.
fn produce(comptime Engine: type, allocator: std.mem.Allocator, mutation: Mutation, supplied: ?*const word_tree.Witness) ![]u8 {
    var rows: [row_count]node.Row(M31) = undefined;
    var siblings: [row_count]node.Digest = undefined;
    for (&siblings, 0..) |*sibling, index| sibling.* = .{@as(u32, @intCast(index + 1))} ** node.DIGEST_WORDS;
    var statement = try path.buildInto(&rows, .memory, 0x2aaa_aaaa, .{7} ** node.DIGEST_WORDS, &siblings);
    if (supplied) |witness| {
        rows = witness.rows;
        statement = witness.statement;
    }
    if (mutation == .link) {
        const original = rows[5];
        var left: node.Digest = undefined;
        var right: node.Digest = undefined;
        for (&left, original.left, &right, original.right) |*a, x, *b, y| {
            a.* = x.toU32();
            b.* = y.toU32();
        }
        // Change the selected child and recompute an otherwise valid node.
        if (((statement.index >> 5) & 1) == 0) left[8] +%= 1 else right[8] +%= 1;
        left[8] %= core.fields.m31.Modulus;
        right[8] %= core.fields.m31.Modulus;
        rows[5] = try node.build(.memory, 5, left, right);
    }
    if (mutation == .root) statement.root[8] = (statement.root[8] + 1) % core.fields.m31.Modulus;
    var calls: [row_count * node.CALLS]poseidon.Call = undefined;
    for (&rows, 0..) |*row, index| @memcpy(calls[index * node.CALLS ..][0..node.CALLS], &node.providerCalls(row));
    if (mutation == .squeeze) {
        rows[0].outputs[3][1] = rows[0].outputs[3][1].add(M31.one());
        rows[0].digest[8] = rows[0].digest[8].add(M31.one());
    }
    // Keep the full permutation bus balanced but violate the caller AIR.
    if (mutation == .height) rows[0].height_bits[0] = M31.fromCanonical(2);
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 1, .backing_allocator = allocator });
    defer pool.deinit();
    var scheme = try Engine.init(allocator, try config());
    var moved = false;
    defer if (!moved) Engine.deinit(&scheme, allocator);
    scheme.setCoefficientRetentionPolicy(.always);
    var channel = Engine.Channel{};
    prefix(&channel, try config(), statement);
    try commitPreprocessed(Engine, allocator, &scheme, &channel, statement);
    var caller_main = [_][caller_size]M31{.{M31.zero()} ** caller_size} ** node.N_MAIN_COLUMNS;
    const placement = try BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);
    for (rows, 0..) |row, logical| {
        const physical = placement.map(logical);
        for (node.columns(M31, row), &caller_main) |value, *column| column[physical] = value;
    }
    var provider_main = try poseidon.generateMain(allocator, &calls, provider_log_size);
    defer provider_main.deinit(allocator);
    var main: [widths[1]][]const M31 = undefined;
    for (main[0..node.N_MAIN_COLUMNS], &caller_main) |*column, *values| column.* = values;
    for (main[node.N_MAIN_COLUMNS..], provider_main.values) |*column, values| column.* = values;
    try commit(Engine, allocator, &scheme, &channel, &main);
    const relations = try relations_mod.Relations.draw(allocator, &channel);
    var caller_interaction = try node.generateInteraction(allocator, &rows, log_size, &relations, &pool);
    defer caller_interaction.deinit(allocator);
    var provider_interaction = try poseidon.generateInteraction(allocator, &calls, provider_log_size, &relations);
    defer provider_interaction.deinit(allocator);
    const claims = caller_interaction.claims ++ provider_interaction.claims.sums;
    try validateClaims(claims);
    channel.mixFelts(&claims);
    var interaction: [widths[2]][]const M31 = undefined;
    for (interaction[0..node.N_INTERACTION_COLUMNS], caller_interaction.columns) |*column, values| column.* = values;
    for (interaction[node.N_INTERACTION_COLUMNS..], provider_interaction.columns) |*column, values| column.* = values;
    try commit(Engine, allocator, &scheme, &channel, &interaction);
    const caller_component = try adapter.Component.init(log_size, .{ 0, 0, 0 }, &relations, claims[0..2].*, statement);
    const provider_component = provider(&relations, claims[2..4].*);
    const components = [_]engine.air.component_prover.ComponentProver{ caller_component.asProverComponent(), provider_component.asProverComponent() };
    moved = true;
    var output = try Engine.prove(allocator, &components, &channel, scheme, .{});
    defer output.deinit(allocator);
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try bytes.appendSlice(allocator, &try statement.encode());
    // Canonical public path and claims precede the existing exact proof codec.
    for (claims) |claim| {
        for (claim.toM31Array()) |limb| {
            var encoded: [4]u8 = undefined;
            std.mem.writeInt(u32, &encoded, limb.toU32(), .little);
            try bytes.appendSlice(allocator, &encoded);
        }
    }
    try postcard.serializeProof(Engine.Hasher, bytes.writer(allocator), output.proof);
    if (bytes.items.len > max_bytes) return error.InvalidNodeProofBytes;
    return bytes.toOwnedSlice(allocator);
}

/// Accepts only serialized data, re-derives the transcript, and independently
/// reconstructs the activity/first-row commitment before verifying the proof.
fn verify(comptime Engine: type, allocator: std.mem.Allocator, bytes: []const u8) !path.Statement {
    if (bytes.len <= header_bytes or bytes.len > max_bytes) return error.InvalidNodeProofBytes;
    const statement = try path.Statement.decode(bytes[0..path.STATEMENT_BYTES]);
    if (statement.depth != row_count) return error.InvalidNodeProofBytes;
    var claims: [4]QM31 = undefined;
    for (&claims, 0..) |*claim, index| {
        var words: [4]M31 = undefined;
        for (&words, 0..) |*word, limb| {
            const value = std.mem.readInt(u32, bytes[path.STATEMENT_BYTES + 16 * index + 4 * limb ..][0..4], .little);
            if (value >= core.fields.m31.Modulus) return error.NonCanonicalClaim;
            word.* = M31.fromCanonical(value);
        }
        claim.* = QM31.fromM31Array(words);
    }
    try validateClaims(claims);
    const pcs = try config();
    // A small file can advertise enormous nested vectors. Reuse the ordinary
    // artifact admission walk before any length-prefixed decoder allocation.
    try postcard.proof_preflight.validate(bytes[header_bytes..], .{
        .config = .{
            .pow_bits = pcs.pow_bits,
            .log_blowup_factor = pcs.fri_config.log_blowup_factor,
            .n_queries = pcs.fri_config.n_queries,
            .log_last_layer_degree_bound = pcs.fri_config.log_last_layer_degree_bound,
            .fold_step = pcs.fri_config.fold_step,
            .lifting_log_size = pcs.lifting_log_size,
        },
        .tree_columns = .{ widths[0], widths[1], widths[2], 8 },
        .max_column_log_size = provider_log_size,
        .hash_size = @sizeOf(Engine.Hasher.Hash),
        .max_wire_bytes = max_bytes - header_bytes,
    });
    var stream = std.io.fixedBufferStream(bytes[header_bytes..]);
    var proof = try postcard.deserializeProof(Engine.Hasher, allocator, stream.reader());
    var moved = false;
    defer if (!moved) proof.deinit(allocator);
    if (stream.pos != bytes.len - header_bytes) return error.TrailingNodeProofBytes;
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4) return error.InvalidNodeProofBytes;
    {
        var canonical = try Engine.init(allocator, try config());
        defer Engine.deinit(&canonical, allocator);
        var channel = Engine.Channel{};
        prefix(&channel, try config(), statement);
        try commitPreprocessed(Engine, allocator, &canonical, &channel, statement);
        var expected = try canonical.roots(allocator);
        defer expected.deinit(allocator);
        if (!std.meta.eql(expected.items[0], roots[0])) return error.InvalidPreprocessedRoot;
    }
    const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(Engine.Hasher, Engine.MerkleChannel);
    var scheme = try Verifier.init(allocator, try config());
    defer scheme.deinit(allocator);
    var channel = Engine.Channel{};
    prefix(&channel, try config(), statement);
    try scheme.commit(allocator, roots[0], &((.{log_size} ** path.PREPROCESSED_COLUMNS) ++ (.{provider_log_size} ** 1)), &channel);
    try scheme.commit(allocator, roots[1], &((.{log_size} ** node.N_MAIN_COLUMNS) ++ (.{provider_log_size} ** poseidon.N_MAIN_COLUMNS)), &channel);
    const relations = try relations_mod.Relations.draw(allocator, &channel);
    channel.mixFelts(&claims);
    try scheme.commit(allocator, roots[2], &((.{log_size} ** node.N_INTERACTION_COLUMNS) ++ (.{provider_log_size} ** poseidon.N_INTERACTION_COLUMNS)), &channel);
    const caller_component = try adapter.Component.init(log_size, .{ 0, 0, 0 }, &relations, claims[0..2].*, statement);
    const provider_component = provider(&relations, claims[2..4].*);
    const components = [_]core.air.components.Component{ caller_component.asVerifierComponent(), provider_component.asVerifierComponent() };
    moved = true;
    try core.verifier.verify(Engine.Hasher, Engine.MerkleChannel, allocator, &components, &channel, &scheme, proof);
    return statement;
}

pub fn exercise(comptime Engine: type, allocator: std.mem.Allocator) !Receipt {
    var timer = try std.time.Timer.start();
    const bytes = try produce(Engine, allocator, .none, null);
    defer allocator.free(bytes);
    const produce_ns = timer.lap();
    _ = try verify(Engine, allocator, bytes);
    const fresh_verify_ns = timer.lap();
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    // Valid public header and PCS followed by a hostile commitment count.
    // Refuse it before even the first allocation, including on small laptops.
    const hostile_body = [_]u8{ 0, 1, 3, 0, 1, 0, 0xff, 0xff, 0xff, 0xff, 0x0f };
    var hostile: [header_bytes + hostile_body.len]u8 = undefined;
    @memcpy(hostile[0..header_bytes], bytes[0..header_bytes]);
    @memcpy(hostile[header_bytes..], &hostile_body);
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    if (verify(Engine, failing.allocator(), &hostile)) |_| return error.HostileLengthAccepted else |err| if (err != error.InvalidProofShape) return err;
    for ([_]Mutation{ .squeeze, .height, .link, .root }) |mutation| {
        if (produce(Engine, allocator, mutation, null)) |invalid| {
            allocator.free(invalid);
            return error.ForgedNodeAccepted;
        } else |err| {
            const expected = if (mutation == .squeeze) error.UnbalancedNodeProviderClaims else error.ConstraintsNotSatisfied;
            if (err != expected) return err;
        }
    }
    bytes[path.STATEMENT_BYTES] ^= 1;
    if (verify(Engine, allocator, bytes)) |_| return error.ChangedClaimAccepted else |_| {}
    bytes[path.STATEMENT_BYTES] ^= 1;
    bytes[bytes.len - 1] ^= 1;
    std.debug.print("Checking deliberate proof corruption; a Merkle rejection below is expected.\n", .{});
    if (verify(Engine, allocator, bytes)) |_| return error.ChangedProofAccepted else |_| {}
    return .{ .proof_bytes = bytes.len, .proof_sha256 = digest, .produce_ns = produce_ns, .fresh_verify_ns = fresh_verify_ns };
}

/// Small artifact command shared by CPU and Metal development executables.
/// `verify` accepts only serialized data and returns its authenticated public
/// claim; a consuming VM must also compare that claim with its expected state.
pub fn artifactCommand(comptime Engine: type, allocator: std.mem.Allocator, args: []const []const u8) !void {
    var timer = try std.time.Timer.start();
    const program_mode = args.len == 4 and
        (std.mem.eql(u8, args[0], "produce-program") or std.mem.eql(u8, args[0], "verify-program"));
    if (args.len != 2 and !program_mode) return error.ExpectedProduceOrVerifyAndArtifactPath;
    var supplied: ?word_tree.Witness = null;
    if (program_mode) {
        const elf = try std.fs.cwd().readFileAlloc(allocator, args[1], 8 * 1024 * 1024);
        defer allocator.free(elf);
        supplied = try word_tree.fromElf(allocator, elf, try std.fmt.parseInt(u32, args[2], 0));
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(elf, &digest, .{});
        std.debug.print("Public Ethereum program image: elf_sha256={s}, address={s}\n", .{ std.fmt.bytesToHex(digest, .lower), args[2] });
    }
    const artifact_path = args[args.len - 1];
    if (std.mem.eql(u8, args[0], "produce") or (program_mode and std.mem.eql(u8, args[0], "produce-program"))) {
        const bytes = try produce(Engine, allocator, .none, if (supplied) |*value| value else null);
        defer allocator.free(bytes);
        var file = try std.fs.cwd().createFile(artifact_path, .{ .exclusive = true });
        defer file.close();
        errdefer std.fs.cwd().deleteFile(artifact_path) catch {};
        try file.writeAll(bytes);
        try file.sync();
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        std.debug.print("Produced diagnostic Ethereum path proof: bytes={d}, sha256={s}\n", .{ bytes.len, std.fmt.bytesToHex(digest, .lower) });
    } else if (std.mem.eql(u8, args[0], "verify") or (program_mode and std.mem.eql(u8, args[0], "verify-program"))) {
        const bytes = try std.fs.cwd().readFileAlloc(allocator, artifact_path, max_bytes);
        defer allocator.free(bytes);
        const statement = try verify(Engine, allocator, bytes);
        if (supplied) |expected| if (!std.meta.eql(statement, expected.statement)) return error.ProgramPathMismatch;
        std.debug.print("Verified diagnostic Ethereum path: kind={s}, depth={d}, index={d}, leaf={any}, root={any}\n", .{
            @tagName(statement.kind), statement.depth, statement.index, statement.leaf, statement.root,
        });
    } else return error.ExpectedProduceOrVerifyAndArtifactPath;
    std.debug.print("Artifact request: {d}ns (includes image preparation and file IO; runtime initialization excluded)\n", .{timer.read()});
}
