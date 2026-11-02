//! RV64 recursion tools: wrap one Ethereum batch proof into a circuit leaf,
//! fold leaves to one root, verify the root. `check-transcript` replays the
//! native transcript prefix through the recursion walkers and reports the
//! leaf statement digest; it proves nothing.
const std = @import("std");
const A = @import("rv64_authenticated_execution.zig");
const Request = @import("rv64_ethereum_request.zig");
const Receipt = @import("rv64_ethereum_batch_receipt.zig");
const Key = @import("rv64_execution_verifier_key.zig");
const walk = @import("rv64_recursion/transcript_walk.zig");
const fold_root = @import("rv64_recursion/fold_root.zig");
const leaf_wrap = @import("rv64_recursion/leaf_wrap.zig");
const Chain = @import("rv64_ethereum_chain.zig");
const wire = @import("stwo_proof_wire");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len < 2) return usage();
    const command = args[1];
    if (std.mem.eql(u8, command, "check-transcript")) {
        if (args.len != 4) return usage();
        return checkTranscript(a, args[2], try std.fmt.parseInt(u32, args[3], 10));
    }
    if (std.mem.eql(u8, command, "wrap")) {
        if (args.len < 5) return usage();
        return wrapCommand(a, args[2], args[3], args[4..]);
    }
    if (std.mem.eql(u8, command, "fold")) {
        if (args.len < 5) return usage();
        return foldCommand(a, args[2], try std.fmt.parseInt(usize, args[3], 10), args[4..]);
    }
    if (std.mem.eql(u8, command, "verify-root")) {
        if (args.len != 5) return usage();
        return verifyRootCommand(a, args[2], args[3], args[4]);
    }
    return usage();
}

/// `wrap <ethereum-config.json> <out-dir> <batch-index>...`: wraps each
/// batch proof into a circuit leaf, writing `leaf-NNNNNN.{json,proof}`.
fn wrapCommand(a: std.mem.Allocator, config_path: []const u8, out_dir: []const u8, indices: []const []const u8) !void {
    var loaded = try load(a, config_path);
    defer loaded.deinit();
    const assets = try fold_root.Assets.init(a);
    defer assets.deinit();
    var directory = try std.fs.cwd().makeOpenPath(out_dir, .{});
    defer directory.close();
    for (indices) |text| {
        const index = try std.fmt.parseInt(u32, text, 10);
        var arena_state = std.heap.ArenaAllocator.init(a);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var batch = try loadBatch(a, &loaded, index);
        defer batch.deinit();
        var prepared = try A.Prepared.initWithAuthority(a, batch.public, &loaded.request.policy, &loaded.request.authority);
        defer prepared.deinit();
        var key = try Key.ReceiverKey.fromPrepared(a, &prepared, batch.public, &loaded.request.authority);
        defer key.deinit();
        var proof = try wire.decodeProofBytesBinary(a, batch.proof_bytes);
        defer proof.deinit(a);
        const wrapped = try leaf_wrap.wrap(a, arena, assets, &key, index, batch.public, batch.receipt.claims, &proof);
        defer a.free(wrapped.proof_bytes);
        try directory.writeFile(.{ .sub_path = wrapped.leaf.proof_file, .data = wrapped.proof_bytes });
        const json = try std.json.Stringify.valueAlloc(a, wrapped.leaf, .{ .whitespace = .indent_2 });
        defer a.free(json);
        const name = try std.fmt.allocPrint(arena, "leaf-{d:0>6}.json", .{index});
        try directory.writeFile(.{ .sub_path = name, .data = json });
        const timings_json = try std.json.Stringify.valueAlloc(a, wrapped.timings, .{ .whitespace = .indent_2 });
        defer a.free(timings_json);
        const timings_name = try std.fmt.allocPrint(arena, "leaf-{d:0>6}.timings.json", .{index});
        try directory.writeFile(.{ .sub_path = timings_name, .data = timings_json });
        const t = wrapped.timings;
        std.debug.print("batch {d} wrapped: native verify {d} ms, build {d} ms, pad {d} ms, preprocess {d} ms, prove {d} ms, serialize {d} ms; {d} vars; gates eq {d} qm31 {d} m31u32 {d} xor3 {d} blake_g {d}; proof {d} bytes\n", .{ index, t.native_verify_ns / std.time.ns_per_ms, t.build_ns / std.time.ns_per_ms, t.pad_ns / std.time.ns_per_ms, t.preprocess_ns / std.time.ns_per_ms, t.prove_ns / std.time.ns_per_ms, t.serialize_ns / std.time.ns_per_ms, t.n_vars, t.gate_counts.eq, t.gate_counts.qm31_ops, t.gate_counts.m31_to_u32, t.gate_counts.triple_xor, t.gate_counts.blake_g_gate, wrapped.proof_bytes.len });
    }
}

/// `fold <out-dir> <jobs> <leaf.json>...`: folds the leaves in the given
/// order to one root under the production registry's shared target.
fn foldCommand(a: std.mem.Allocator, out_dir: []const u8, jobs: usize, leaf_paths: []const []const u8) !void {
    try fold_root.admission.validateCount(leaf_paths.len);
    var timer = try std.time.Timer.start();
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const assets = try fold_root.Assets.init(a);
    defer assets.deinit();
    const leaves = try arena.alloc(fold_root.LeafFile, leaf_paths.len);
    const proofs = try arena.alloc([]const u8, leaf_paths.len);
    for (leaf_paths, leaves, proofs) |path, *leaf, *proof| {
        const text = try std.fs.cwd().readFileAlloc(arena, path, 64 << 20);
        leaf.* = try std.json.parseFromSliceLeaky(fold_root.LeafFile, arena, text, .{ .ignore_unknown_fields = true });
        const dir = std.fs.path.dirname(path) orelse ".";
        const proof_path = try std.fs.path.join(arena, &.{ dir, leaf.proof_file });
        proof.* = try std.fs.cwd().readFileAlloc(arena, proof_path, 256 << 20);
    }
    const assets_ns = timer.lap();
    const root = try fold_root.fold(a, assets, leaves, proofs, jobs);
    defer a.free(root.proof_bytes);
    defer a.free(root.packed_json);
    const fold_ns = timer.lap();
    var directory = try std.fs.cwd().makeOpenPath(out_dir, .{});
    defer directory.close();
    try directory.writeFile(.{ .sub_path = "root.proof", .data = root.proof_bytes });
    try directory.writeFile(.{ .sub_path = "root_packed.json", .data = root.packed_json });
    const summary = try std.json.Stringify.valueAlloc(a, .{
        .schema = "rv64-recursion-root-v1",
        .output_digest = root.output_digest,
        .preprocessed_root = root.preprocessed_root,
        .circuit_hash = root.circuit_hash,
        .leaf_circuit_hash = leaves[0].circuit_hash,
        .n_leaves = root.n_leaves,
        .n_layers = root.n_layers,
        .n_reductions = root.n_reductions,
        .jobs = jobs,
        .assets_ns = assets_ns,
        .fold_ns = fold_ns,
        .proof_bytes = root.proof_bytes.len,
    }, .{ .whitespace = .indent_2 });
    defer a.free(summary);
    try directory.writeFile(.{ .sub_path = "root.json", .data = summary });
    std.debug.print("folded {d} leaves in {d} reductions over {d} layers: {d} ms (assets {d} ms), root proof {d} bytes\n", .{ root.n_leaves, root.n_reductions, root.n_layers, fold_ns / std.time.ns_per_ms, assets_ns / std.time.ns_per_ms, root.proof_bytes.len });
}

const RootSummary = struct { output_digest: [8]u32, preprocessed_root: [8]u32, circuit_hash: [8]u32, n_leaves: usize };

/// `verify-root <root-dir> <ethereum-config.json> <trusted-topologies.json>`: verifies the root proof,
/// recomputes its digest from the packed tree, rebinds every revealed leaf
/// statement to its public values, and checks the batch chain adjacency
/// from the independently derived initial state.
fn verifyRootCommand(a: std.mem.Allocator, root_dir: []const u8, config_path: []const u8, trusted_topologies_path: []const u8) !void {
    var timer = try std.time.Timer.start();
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var directory = try std.fs.cwd().openDir(root_dir, .{});
    defer directory.close();
    const summary = try std.json.parseFromSliceLeaky(RootSummary, arena, try directory.readFileAlloc(arena, "root.json", 1 << 20), .{ .ignore_unknown_fields = true });
    // This file is an independently trusted receiver input, like the ELF
    // configuration. Producer leaf metadata never authorizes its own circuit.
    const trusted = try std.json.parseFromSliceLeaky(fold_root.admission.TrustedTopologies, arena, try std.fs.cwd().readFileAlloc(arena, trusted_topologies_path, fold_root.admission.MAX_MANIFEST_BYTES), .{});
    try trusted.validate(summary.n_leaves);
    const root = fold_root.Root{
        .proof_bytes = try directory.readFileAlloc(arena, "root.proof", 256 << 20),
        .output_digest = summary.output_digest,
        .preprocessed_root = summary.preprocessed_root,
        .circuit_hash = summary.circuit_hash,
        .packed_json = try directory.readFileAlloc(arena, "root_packed.json", fold_root.admission.MAX_PACKED_JSON_BYTES),
        .n_leaves = summary.n_leaves,
        .n_layers = 0,
        .n_reductions = 0,
    };
    // The untrusted leaf files supply public statements, not admission hashes.
    const leaves = try arena.alloc(fold_root.LeafFile, summary.n_leaves);
    const admitted = try arena.alloc(fold_root.admission.Leaf, summary.n_leaves);
    for (leaves, admitted, 0..) |*leaf, *hash, i| {
        const name = try std.fmt.allocPrint(arena, "leaf-{d:0>6}.json", .{i});
        leaf.* = try std.json.parseFromSliceLeaky(fold_root.LeafFile, arena, try directory.readFileAlloc(arena, name, fold_root.admission.MAX_LEAF_JSON_BYTES), .{ .ignore_unknown_fields = true });
        if (leaf.batch_index != i) return error.LeafOrderMismatch;
        try trusted.leaves[i].checkLayout(try fold_root.admission.layoutDigest(leaf.public));
        if (leaf.statement_words.len > fold_root.admission.MAX_STATEMENT_WORDS) return error.LeafPreimageShape;
        if (!std.mem.eql(u32, &leaf.circuit_hash, &trusted.leaves[i].circuit_hash)) return error.LeafCircuitHashMismatch;
        const digest = walk.statementDigest(leaf.statement_words);
        if (!std.mem.eql(u32, &digest, &leaf.output_digest)) return error.LeafDigestMismatch;
        hash.* = .{ .circuit_hash = trusted.leaves[i].circuit_hash, .statement_digest = digest };
    }
    const assets = try fold_root.Assets.init(a);
    defer assets.deinit();
    const check = try fold_root.verifyRoot(a, assets, root, admitted);
    const root_ns = timer.lap();
    // Chain adjacency over the leaf statements in order.
    var loaded = try load(a, config_path);
    defer loaded.deinit();
    const cpu = A.frontend.rv64.machine.Cpu.init(loaded.request.loaded.info.entry, loaded.config.symbols.stack_top);
    var cursor = Chain.Cursor{ .root = loaded.request.initial_cache.root(), .pc = cpu.pc, .registers = cpu.regs, .expected_state_policy = loaded.config.state_policy };
    for (leaves, 0..) |leaf, i| {
        const index: u32 = @intCast(i);
        var public = leaf.public;
        public.cpu.statement.program = loaded.request.authority.expectedProgram();
        // Match the native receiver admission, including canonical roots and
        // unchanged RAM when the RAM roster is absent (not Layout checks).
        try public.validateWithAdmittedOpcodes(&loaded.request.policy, &loaded.request.authority.opcodes);
        var prepared = try A.Prepared.initForLayout(a, public.layout(), &loaded.request.policy, &loaded.request.authority);
        defer prepared.deinit();
        try fold_root.checkStatementWords(a, prepared.verificationView(), public, leaf.statement_words);
        if (!std.mem.eql(u32, &walk.statementDigest(leaf.statement_words), &leaf.output_digest)) return error.LeafDigestMismatch;
        try cursor.check(public, index, cursor.steps, loaded.config.max_steps);
        try cursor.advanceVerified(public);
    }
    std.debug.print("root accepted: proof verified, {d} leaf digests recomputed, {d} statements chained to pc 0x{x} after {d} steps; root {d} ms, chain {d} ms\n", .{ check.leaf_hash_checked, summary.n_leaves, cursor.pc, cursor.steps, root_ns / std.time.ns_per_ms, timer.lap() / std.time.ns_per_ms });
}

fn usage() error{Usage} {
    std.debug.print(
        \\usage:
        \\  rv64-recursion check-transcript <ethereum-config.json> <batch-index>
        \\  rv64-recursion wrap <ethereum-config.json> <out-dir> <batch-index>...
        \\  rv64-recursion fold <out-dir> <jobs> <leaf.json>...
        \\  rv64-recursion verify-root <root-dir> <ethereum-config.json> <trusted-topologies.json>
        \\
    , .{});
    return error.Usage;
}

pub const Loaded = struct {
    arena: std.heap.ArenaAllocator,
    request: Request.Request,
    config: Request.Config,
    pub fn deinit(self: *Loaded) void {
        self.request.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
};

/// Parses the Ethereum proving config and derives the independent authority
/// (ELF, input, policy, initial image) exactly as the native receiver does.
pub fn load(a: std.mem.Allocator, config_path: []const u8) !Loaded {
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const raw = try std.fs.cwd().readFileAlloc(arena.allocator(), config_path, 1 << 20);
    const parsed = try std.json.parseFromSliceLeaky(Request.Config, arena.allocator(), raw, .{ .ignore_unknown_fields = true });
    const request = try Request.Request.init(a, parsed);
    return .{ .arena = arena, .request = request, .config = parsed };
}

pub const Batch = struct {
    arena: std.heap.ArenaAllocator,
    receipt: Receipt.Receipt,
    public: A.Public,
    proof_bytes: []const u8,
    pub fn deinit(self: *Batch) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

/// Reads one batch's receipt and proof from the proving output directory
/// and binds the receipt to the independent program authority.
pub fn loadBatch(a: std.mem.Allocator, loaded: *const Loaded, index: u32) !Batch {
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const alloc = arena.allocator();
    var directory = try std.fs.cwd().openDir(loaded.config.output_directory, .{});
    defer directory.close();
    const meta_name = try std.fmt.allocPrint(alloc, "batch-{d:0>6}.json", .{index});
    const proof_name = try std.fmt.allocPrint(alloc, "batch-{d:0>6}.proof", .{index});
    const metadata = try directory.readFileAlloc(alloc, meta_name, 128 * 1024);
    const receipt = try std.json.parseFromSliceLeaky(Receipt.Receipt, alloc, metadata, .{});
    const public = try receipt.bound(&loaded.request.authority);
    const bytes = try directory.readFileAlloc(alloc, proof_name, 128 * 1024 * 1024);
    try Request.pin(bytes, &receipt.proof_sha256);
    return .{ .arena = arena, .receipt = receipt, .public = public, .proof_bytes = bytes };
}

fn checkTranscript(a: std.mem.Allocator, config_path: []const u8, index: u32) !void {
    var timer = try std.time.Timer.start();
    var loaded = try load(a, config_path);
    defer loaded.deinit();
    var batch = try loadBatch(a, &loaded, index);
    defer batch.deinit();
    var prepared = try A.Prepared.initWithAuthority(a, batch.public, &loaded.request.policy, &loaded.request.authority);
    defer prepared.deinit();
    var key = try Key.ReceiverKey.fromPrepared(a, &prepared, batch.public, &loaded.request.authority);
    defer key.deinit();
    var proof = try wire.decodeProofBytesBinary(a, batch.proof_bytes);
    defer proof.deinit(a);
    const commitments = proof.commitment_scheme_proof.commitments.items;
    if (commitments.len != 4 or !std.mem.eql(u8, &commitments[0], &key.root)) return error.AuthenticatedExecutionFixedRootMismatch;
    var replay = try walk.checkParity(a, key.view(), batch.public, batch.receipt.claims, key.root, commitments[1], key.fixed_logs, key.main_logs);
    defer replay.deinit();
    const digest = walk.statementDigest(replay.free.items);
    std.debug.print("batch {d}: transcript parity ok in {d} ms\n  free words {d}, challenge draws {d}, claim felts {d}\n  statement digest ", .{ index, timer.read() / std.time.ns_per_ms, replay.free.items.len, replay.drawn.items.len, replay.claim_felts.items.len });
    for (digest) |word| std.debug.print("{x:0>8}", .{word});
    std.debug.print("\n  trees: fixed {d} columns, main {d}, interaction {d}; sampled {d}/{d}/{d}/{d} columns\n", .{ key.fixed_logs.len, key.main_logs.len, key.interaction_logs.len, proof.commitment_scheme_proof.sampled_values.items[0].len, proof.commitment_scheme_proof.sampled_values.items[1].len, proof.commitment_scheme_proof.sampled_values.items[2].len, proof.commitment_scheme_proof.sampled_values.items[3].len });
}
