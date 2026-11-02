//! Diagnostic public-ledger RAM hash STARK. The verifier reconstructs the
//! sponge/tree graph without hashing witness-dependent inputs, then closes its
//! full-I/O requests against the existing universal Poseidon STARK. Public
//! permutation states cost 64 bytes/call. This is NOT private RAM continuation,
//! a CPU/RAM relation, or a production security profile.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const frontend = @import("stwo_riscv_frontend");
const memory = frontend.rv64_air.memory;
const ram = memory.commitment;
const Witness = memory.transition.Witness;
const support = frontend.testing.component_proof.support;
const poseidon = frontend.testing.component_proof.universal_air;
const legacy = frontend.testing.component_proof.poseidon_air;
const Component = frontend.testing.component_proof.universal_component.Component;
const Relations = frontend.testing.component_proof.relations.Relations;
const postcard = @import("interop_postcard");
const B = @import("stwo_cpu_backend").CpuBackend;
const P = frontend.rv64_air.protocol;
const Engine = engine.engine.ProverEngine(B, P.Hasher, P.MerkleChannel, P.Channel);
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const State = [16]M;
const MAX_CALLS = 1 << 16;
const MAX_BYTES = 64 * 1024 * 1024;
const MAX_PAGES = 64;
const CONFIG = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 10, .fold_step = 1 } };
const Suite = enum { diagnostic, receipt };
fn config(suite: Suite) core.pcs.PcsConfig {
    return if (suite == .diagnostic) CONFIG else P.config();
}
fn magic(suite: Suite) u32 {
    return if (suite == .diagnostic) 0x52414d31 else 0x52414d32;
}

fn fixed(a: std.mem.Allocator, log: u32) ![]engine.pcs.ColumnEvaluation {
    const columns = try a.alloc(engine.pcs.ColumnEvaluation, 1);
    errdefer a.free(columns);
    const values = try a.alloc(M, @as(usize, 1) << @intCast(log));
    @memset(values, M.zero());
    values[0] = M.one();
    columns[0] = .{ .log_size = log, .values = values };
    return columns;
}

fn component(log: u32, count: usize, relations: *const Relations, claims: [2]Q) Component {
    // Universal shell constrains every permutation row and authenticates the
    // enabler itself; its adapter samples only first, so active aliases first.
    return .{ .log_size = log, .n_rows = @intCast(count), .is_first_col_idx = 0, .is_active_col_idx = 0, .main_col_offset = 0, .interaction_col_offset = 0, .relations = relations, .claims = claims };
}

fn prefix(channel: *P.Channel, witness: *const Witness, outputs: []const State, log: u32, suite: Suite) void {
    config(suite).mixInto(channel);
    channel.mixU32s(&.{ 0x5256414d, if (suite == .diagnostic) 1 else 2, ram.SCHEMA_VERSION, ram.PAGE_BITS, ram.PAGE_DEPTH, log });
    channel.mixU32s(&witness.before);
    channel.mixU32s(&witness.after);
    channel.mixU64(witness.pages.len);
    for (witness.pages) |*page| {
        channel.mixU64(page.index);
        for ([_]*const ram.Page{ &page.before, &page.after }) |cells| for (cells) |cell| {
            channel.mixU64(cell.value);
            channel.mixU32s(&.{cell.permissions});
        };
    }
    channel.mixU64(witness.sides.len);
    for (witness.sides) |side| {
        channel.mixU32s(&.{side.height});
        channel.mixU64(side.index);
        channel.mixU32s(&side.digest);
    }
    channel.mixU64(outputs.len);
    for (outputs) |state| {
        var words: [16]u32 = undefined;
        for (&words, state) |*word, value| word.* = value.toU32();
        channel.mixU32s(&words);
    }
}

fn expectedClaim(requests: []const ram.PermutationIO, relations: *const Relations) !Q {
    var claim = Q.zero();
    for (requests) |request| {
        var tuple: [32]M = undefined;
        @memcpy(tuple[0..16], &request.input);
        @memcpy(tuple[16..32], &request.output);
        claim = claim.add(try relations.poseidon2_io.combineBase(tuple).inv());
    }
    return claim;
}

fn checkClaims(claims: [2]Q, requests: []const ram.PermutationIO, relations: *const Relations) !void {
    if (!claims[0].isZero() or !claims[1].eql(try expectedClaim(requests, relations))) return error.UnbalancedRamHashClaims;
}

fn callsFromRequests(a: std.mem.Allocator, requests: []const ram.PermutationIO) ![]legacy.Call {
    const calls = try a.alloc(legacy.Call, requests.len);
    for (calls, requests) |*call, request| {
        call.* = .{ .input = undefined, .io = true };
        for (&call.input, request.input) |*word, value| word.* = value.toU32();
    }
    return calls;
}

fn appendWord(a: std.mem.Allocator, bytes: *std.ArrayList(u8), word: u32) !void {
    var encoded: [4]u8 = undefined;
    std.mem.writeInt(u32, &encoded, word, .little);
    try bytes.appendSlice(a, &encoded);
}

fn checkShape(witness: *const Witness) !void {
    if (witness.pages.len == 0 or witness.pages.len > MAX_PAGES or witness.sides.len > witness.pages.len * ram.PAGE_DEPTH)
        return error.InvalidRamHashProofShape;
}

pub fn prove(a: std.mem.Allocator, witness: *const Witness) ![]u8 {
    try checkShape(witness);
    var recorded = try witness.recordHashCalls(a);
    defer recorded.deinit();
    return proveRequests(a, witness, recorded.calls.items, .diagnostic);
}

/// Fixed 70-query/26-bit-PoW suite. This authenticates the public hash graph,
/// not private RAM/CPU execution; the receiver must independently pin context.
pub fn proveReceipt(a: std.mem.Allocator, witness: *const Witness) ![]u8 {
    try checkShape(witness);
    var recorded = try witness.recordHashCalls(a);
    defer recorded.deinit();
    return proveRequests(a, witness, recorded.calls.items, .receipt);
}

/// Diagnostic adversarial-entry surface: a separately supplied public ledger
/// must close against REAL provider outputs, not become host hash authority.
pub fn proveFromPublicLedger(a: std.mem.Allocator, witness: *const Witness, outputs: []const State) ![]u8 {
    try checkShape(witness);
    if (outputs.len == 0 or outputs.len > MAX_CALLS) return error.InvalidRamHashProofShape;
    var replay = try witness.replayHashCalls(a, outputs);
    defer replay.deinit();
    return proveRequests(a, witness, replay.calls.items, .diagnostic);
}

fn proveRequests(a: std.mem.Allocator, witness: *const Witness, requests: []const ram.PermutationIO, suite: Suite) ![]u8 {
    const count = requests.len;
    if (count == 0 or count > MAX_CALLS) return error.InvalidRamHashProofShape;
    const log: u32 = @intCast(@max(4, std.math.log2_int_ceil(usize, count)));
    const outputs = try a.alloc(State, count);
    defer a.free(outputs);
    for (outputs, requests) |*output, request| output.* = request.output;
    const calls = try callsFromRequests(a, requests);
    defer a.free(calls);
    var scheme = try Engine.init(a, config(suite));
    var moved = false;
    defer if (!moved) Engine.deinit(&scheme, a);
    var channel = P.Channel{};
    prefix(&channel, witness, outputs, log, suite);
    try Engine.commit(&scheme, a, try fixed(a, log), null, &channel);
    var main = try poseidon.generateMain(a, calls, log);
    var main_moved = false;
    defer if (!main_moved) main.deinit(a);
    const main_columns = try support.takeColumns(poseidon.N_MAIN_COLUMNS, a, &main.values, log);
    main_moved = true;
    try Engine.commit(&scheme, a, main_columns, null, &channel);
    const relations = try Relations.draw(a, &channel);
    var interaction = try legacy.generateInteraction(a, calls, log, &relations);
    var interaction_moved = false;
    defer if (!interaction_moved) interaction.deinit(a);
    const claims = interaction.claims.sums;
    try checkClaims(claims, requests, &relations);
    channel.mixFelts(&claims);
    const interaction_columns = try support.takeColumns(legacy.N_INTERACTION_COLUMNS, a, &interaction.columns, log);
    interaction_moved = true;
    try Engine.commit(&scheme, a, interaction_columns, null, &channel);
    const value = component(log, count, &relations, claims);
    moved = true;
    var proof = try Engine.prove(a, &.{value.asProverComponent()}, &channel, scheme, .{});
    defer proof.deinit(a);
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(a);
    try appendWord(a, &bytes, magic(suite));
    try appendWord(a, &bytes, @intCast(count));
    for (outputs) |state| for (state) |word| try appendWord(a, &bytes, word.toU32());
    for (claims) |claim| for (claim.toM31Array()) |word| try appendWord(a, &bytes, word.toU32());
    try postcard.serializeProof(P.Hasher, bytes.writer(a), proof.proof);
    if (bytes.items.len > MAX_BYTES) return error.InvalidRamHashProofShape;
    return bytes.toOwnedSlice(a);
}

pub fn verify(a: std.mem.Allocator, witness: *const Witness, expected_before: ram.Digest, expected_after: ram.Digest, expected_pages: []const u64, updates: []const memory.transition.NetUpdate, bytes: []const u8) !void {
    return verifyAtSuite(a, witness, expected_before, expected_after, expected_pages, updates, bytes, .diagnostic);
}

pub fn verifyReceipt(a: std.mem.Allocator, witness: *const Witness, expected_before: ram.Digest, expected_after: ram.Digest, expected_pages: []const u64, updates: []const memory.transition.NetUpdate, bytes: []const u8) !void {
    return verifyAtSuite(a, witness, expected_before, expected_after, expected_pages, updates, bytes, .receipt);
}

fn verifyAtSuite(a: std.mem.Allocator, witness: *const Witness, expected_before: ram.Digest, expected_after: ram.Digest, expected_pages: []const u64, updates: []const memory.transition.NetUpdate, bytes: []const u8, suite: Suite) !void {
    try checkShape(witness);
    try witness.validateOpenings(expected_pages);
    try witness.validateNetUpdates(updates);
    if (!ram.equal(witness.before, expected_before) or !ram.equal(witness.after, expected_after)) return error.RamBoundaryMismatch;
    if (bytes.len < 40 or bytes.len > MAX_BYTES or std.mem.readInt(u32, bytes[0..4], .little) != magic(suite)) return error.InvalidRamHashProofShape;
    const count = std.mem.readInt(u32, bytes[4..8], .little);
    if (count == 0 or count > MAX_CALLS) return error.InvalidRamHashProofShape;
    const header: usize = 8 + @as(usize, count) * 64 + 32;
    if (header >= bytes.len) return error.InvalidRamHashProofShape;
    const log: u32 = @intCast(@max(4, std.math.log2_int_ceil(u32, count)));
    const outputs = try a.alloc(State, count);
    defer a.free(outputs);
    var at: usize = 8;
    for (outputs) |*state| for (state) |*word| {
        const value = std.mem.readInt(u32, bytes[at..][0..4], .little);
        if (value >= core.fields.m31.Modulus) return error.NonCanonicalDigest;
        word.* = M.fromCanonical(value);
        at += 4;
    };
    var replay = try witness.replayHashCalls(a, outputs);
    defer replay.deinit();
    var claims: [2]Q = undefined;
    for (&claims) |*claim| {
        var words: [4]M = undefined;
        for (&words) |*word| {
            const value = std.mem.readInt(u32, bytes[at..][0..4], .little);
            if (value >= core.fields.m31.Modulus) return error.NonCanonicalDigest;
            word.* = M.fromCanonical(value);
            at += 4;
        }
        claim.* = Q.fromM31Array(words);
    }
    const params = config(suite);
    try postcard.proof_preflight.validate(bytes[header..], .{
        .config = .{ .pow_bits = params.pow_bits, .log_blowup_factor = params.fri_config.log_blowup_factor, .n_queries = params.fri_config.n_queries, .log_last_layer_degree_bound = params.fri_config.log_last_layer_degree_bound, .fold_step = params.fri_config.fold_step, .lifting_log_size = params.lifting_log_size },
        .tree_columns = .{ 1, poseidon.N_MAIN_COLUMNS, legacy.N_INTERACTION_COLUMNS, 8 },
        .max_column_log_size = log,
        .hash_size = @sizeOf(P.Hasher.Hash),
        .max_wire_bytes = MAX_BYTES - header,
    });
    var stream = std.io.fixedBufferStream(bytes[header..]);
    var proof = try postcard.deserializeProof(P.Hasher, a, stream.reader());
    var moved = false;
    defer if (!moved) proof.deinit(a);
    if (stream.pos != bytes.len - header or proof.commitment_scheme_proof.commitments.items.len != 4) return error.InvalidRamHashProofShape;
    const roots = proof.commitment_scheme_proof.commitments.items;
    {
        var setup = try Engine.init(a, params);
        defer Engine.deinit(&setup, a);
        var scratch = P.Channel{};
        try Engine.commit(&setup, a, try fixed(a, log), null, &scratch);
        var canonical = try setup.roots(a);
        defer canonical.deinit(a);
        if (!std.meta.eql(canonical.items[0], roots[0])) return error.InvalidRamHashFixedRoot;
    }
    var scheme = try core.pcs.verifier.CommitmentSchemeVerifier(P.Hasher, P.MerkleChannel).init(a, params);
    defer scheme.deinit(a);
    var channel = P.Channel{};
    prefix(&channel, witness, outputs, log, suite);
    try scheme.commit(a, roots[0], &.{log}, &channel);
    try scheme.commit(a, roots[1], &([_]u32{log} ** poseidon.N_MAIN_COLUMNS), &channel);
    const relations = try Relations.draw(a, &channel);
    try checkClaims(claims, replay.calls.items, &relations);
    channel.mixFelts(&claims);
    try scheme.commit(a, roots[2], &([_]u32{log} ** legacy.N_INTERACTION_COLUMNS), &channel);
    const value = component(log, count, &relations, claims);
    moved = true;
    try core.verifier.verify(P.Hasher, P.MerkleChannel, a, &.{value.asVerifierComponent()}, &channel, &scheme, proof);
}
