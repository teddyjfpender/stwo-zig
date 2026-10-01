//! Rung R11 (design §8.2): acceptance and tamper, the Zig verifier against
//! upstream `verify_circuit` (`crates/circuit_verifier/src/verify.rs` of
//! https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230).
//!
//! Three proofs are verified by the Zig circuit verifier (`verify.zig`):
//!
//! - `multiverifier`: upstream's `test_data/circuit_multiverifier/proof.bin`
//!   (Rust-made), under the request of `vectors/circuit/r7/verify/multiverifier.json`;
//! - `leaf`: the Rust leaf of `four_leaves/leaf.json`, under the canonical
//!   config of the recursive-tree registry (every leaf and node of a
//!   canonical tree shares it) with the digest of its output preimage;
//! - `small-fibonacci`: the Zig circuit prover's proof of the R7 fibonacci
//!   circuit.
//!
//! Each must be accepted untouched and rejected after each tampering: the
//! claimed output digest, the preprocessed root, the circuit hash (the eq
//! columns' log size in the layout, which the circuit hash commits to), a
//! claimed sum, the channel salt, the FRI and interaction PoW nonces, and
//! one FRI witness value. Upstream's verdict on every one of these byte
//! strings is committed under `vectors/circuit/r11/verify/` (oracle
//! `verify-circuit`, rejections included); the Zig verdict must agree and
//! the proof and request must be the ones upstream judged. With
//! `STWO_CIRCUIT_R11_EMIT_DIR` set, the test writes every proof and request
//! for the oracle instead of reading the committed verdicts.

const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const circuit_cpu = @import("stwo_circuit_cpu_integration");
const wire = @import("stwo_circuit_recursion_wire");
const circuit_testing = @import("circuit_testing");
const rust_verifier = @import("rust_verifier.zig");

const QM31 = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const preprocessed = circuit.common.preprocessed;
const verify_request = wire.verify_request;
const Json = std.json.Value;

const emit_env = "STWO_CIRCUIT_R11_EMIT_DIR";
const verdicts_dir = "vectors/circuit/r11/verify/";

pub const Tamper = enum {
    none,
    output_digest,
    preprocessed_root,
    circuit_hash,
    claimed_sum,
    channel_salt,
    pow_nonce,
    interaction_pow_nonce,
    fri_witness,
};

const Base = struct {
    label: []const u8,
    proof: []const u8,
    request: verify_request.VerifyRequest,
};

const Setup = struct {
    arena: std.heap.ArenaAllocator,
    projection: circuit.air_eval.projection.Projection,
    table: circuit.air_eval.component_table.Table,

    fn init(self: *Setup, gpa: std.mem.Allocator) !void {
        self.arena = .init(gpa);
        errdefer self.arena.deinit();
        const bytes = try std.fs.cwd().readFileAlloc(self.arena.allocator(), "vectors/circuit/official/compiled_air_constraints_v1.bin", 8 << 20);
        self.projection = try circuit.air_eval.projection.parse(gpa, bytes);
        errdefer self.projection.deinit();
        self.table = try circuit.air_eval.circuit_components.build(gpa, &self.projection);
    }

    fn deinit(self: *Setup) void {
        self.table.deinit();
        self.projection.deinit();
        self.arena.deinit();
    }
};

fn readFile(arena: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.fs.cwd().readFileAlloc(arena, path, 16 << 20);
}

/// Upstream's multiverifier proof and the request the R7 verdict records.
fn multiverifierBase(arena: std.mem.Allocator) !Base {
    const verdict = try std.json.parseFromSliceLeaky(Json, arena, try readFile(arena, "vectors/circuit/r7/verify/multiverifier.json"), .{});
    var request_text: std.Io.Writer.Allocating = .init(arena);
    try std.json.Stringify.value(verdict.object.get("body").?.object.get("request").?, .{}, &request_text.writer);
    return .{
        .label = "multiverifier",
        .proof = try readFile(arena, "vectors/circuit/official/circuit_multiverifier/proof.bin"),
        .request = (try verify_request.parseVerifyRequest(arena, request_text.written())).request,
    };
}

/// The golden Rust leaf under the recursive-tree registry's canonical config.
fn leafBase(arena: std.mem.Allocator) !Base {
    const registry = (try wire.registry.parseRegistry(arena, try readFile(arena, "vectors/circuit/official/registries/recursive_tree_test.json"))).registry;
    const config = try registry.config((try registry.multiverifier()).config);
    const target = circuit.common.finalize.ComponentSizes.fromLogSizes(config.component_log_sizes);
    const shared = try circuit.statements.multiverifier.foldSharedConfig(arena, target, config.fri_config);
    const columns = try arena.alloc(verify_request.Column, preprocessed.N_PREPROCESSED_COLUMNS);
    for (shared.preprocessed_column_log_sizes.entries, columns) |entry, *column| column.* = .{ .id = entry.id, .log_size = entry.log_size };

    const leaf = (try wire.leaf_proof_json.parseLeafInput(arena, try readFile(arena, "vectors/circuit/official/recursive_tree/four_leaves/leaf.json"))).value;
    return .{
        .label = "leaf",
        .proof = leaf.proof.proof,
        .request = .{
            .pcs_config = shared.pcs_config,
            .preprocessed_column_log_sizes = columns,
            .preprocessed_root = leaf.proof.circuit_preprocessed_root.words,
            .output_digest = try leaf.outputDigest(arena),
        },
    };
}

/// The Zig proof of the R7 fibonacci circuit (default config, internal
/// profile), as R7 proves it.
fn smallFibonacciBase(arena: std.mem.Allocator) !Base {
    const gpa = std.testing.allocator;
    var ctx = try circuit_testing.contexts.build(QM31, gpa, .fibonacci);
    defer ctx.deinit();
    try ctx.finalize(false);
    var pp = try preprocessed.PreprocessedCircuit.preprocessContext(QM31, gpa, &ctx);
    defer pp.deinit(gpa);
    const bundle_bytes = try readFile(arena, circuit_cpu.air.bundle_path);
    var bundle = try circuit_cpu.air.parse(gpa, bundle_bytes);
    defer bundle.deinit();
    var proof = try circuit_cpu.Internal.prove(gpa, ctx.values(), &pp, &bundle, circuit_cpu.prove.defaultPcsConfig(pp.traceLogSize()), .{}, {});
    defer proof.deinit();
    var converted = try circuit_cpu.verifier_proof.prepare(gpa, &proof);
    defer converted.deinit();
    const columns = try arena.create([preprocessed.N_PREPROCESSED_COLUMNS]verify_request.Column);
    var request = rust_verifier.requestFor(&proof, &pp, columns);
    for (columns) |*column| column.id = try arena.dupe(u8, column.id);
    request.preprocessed_column_log_sizes = columns;
    return .{ .label = "small-fibonacci", .proof = try converted.serialize(arena), .request = request };
}

fn bumpQm31(value: *QM31) void {
    var limbs = value.toM31Array();
    limbs[0] = limbs[0].add(M31.one());
    value.* = QM31.fromM31Array(limbs);
}

/// `base` with `tamper` applied: the request, or the proof re-encoded
/// after one value changed.
fn tampered(arena: std.mem.Allocator, base: Base, tamper: Tamper) !Base {
    var out = base;
    switch (tamper) {
        .none => {},
        .output_digest => out.request.output_digest[0] ^= 1,
        .preprocessed_root => out.request.preprocessed_root[0] ^= 1,
        .circuit_hash => {
            const columns = try arena.dupe(verify_request.Column, base.request.preprocessed_column_log_sizes);
            var bumped: usize = 0;
            for (columns) |*column| if (std.mem.startsWith(u8, column.id, "eq_in")) {
                column.log_size += 1;
                bumped += 1;
            };
            try std.testing.expectEqual(@as(usize, 2), bumped);
            out.request.preprocessed_column_log_sizes = columns;
        },
        .claimed_sum, .channel_salt, .pow_nonce, .interaction_pow_nonce, .fri_witness => {
            var layout: preprocessed.ColumnLayout = undefined;
            for (&layout.entries, base.request.preprocessed_column_log_sizes) |*entry, column| entry.* = .{ .id = column.id, .log_size = column.log_size };
            const config = try circuit.statements.circuit_statement.circuitVerifierProofConfig(arena, &layout, base.request.pcs_config);
            const shape = config.shape();
            var decoded = try wire.circuit_serialize.deserializeProof(arena, base.proof, shape);
            const proof = &decoded.proof;
            switch (tamper) {
                .claimed_sum => bumpQm31(&proof.claimed_sums[0]),
                .channel_salt => bumpQm31(&proof.channel_salt),
                .pow_nonce => bumpQm31(&proof.pow_nonce),
                .interaction_pow_nonce => bumpQm31(&proof.interaction_pow_nonce),
                .fri_witness => bumpQm31(&proof.fri.witness[0][0]),
                else => unreachable,
            }
            out.proof = try wire.circuit_serialize.serializeProofAlloc(arena, proof, shape);
            try std.testing.expectEqual(base.proof.len, out.proof.len);
        },
    }
    return out;
}

fn sha256Hex(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

/// Upstream's committed verdict on exactly these bytes and this request.
fn expectUpstreamVerdict(arena: std.mem.Allocator, label: []const u8, case: Base, accepted: bool) !void {
    const path = try std.fmt.allocPrint(arena, verdicts_dir ++ "{s}.json", .{label});
    const verdict = try std.json.parseFromSliceLeaky(Json, arena, try readFile(arena, path), .{});
    const body = verdict.object.get("body").?;
    var request_text: std.Io.Writer.Allocating = .init(arena);
    try std.json.Stringify.value(body.object.get("request").?, .{}, &request_text.writer);
    var ours: std.Io.Writer.Allocating = .init(arena);
    try verify_request.writeVerifyRequest(&ours.writer, case.request);
    try std.testing.expectEqualStrings(request_text.written(), ours.written());
    try std.testing.expectEqualStrings(body.object.get("proof_sha256").?.string, &sha256Hex(case.proof));
    try std.testing.expectEqual(@as(i64, @intCast(case.proof.len)), body.object.get("proof_bytes").?.integer);
    if (body.object.get("accepted").?.bool != accepted) {
        std.debug.print("R11 {s}: upstream accepted = {}, expected {}\n", .{ label, !accepted, accepted });
        return error.UpstreamVerdictDiffers;
    }
}

fn checkBase(setup: *const Setup, arena: std.mem.Allocator, base: Base) !void {
    const gpa = std.heap.smp_allocator;
    const emitting = std.process.hasEnvVarConstant(emit_env);
    for (std.enums.values(Tamper)) |tamper| {
        const case = try tampered(arena, base, tamper);
        const label = try std.fmt.allocPrint(arena, "{s}-{s}", .{ base.label, @tagName(tamper) });
        const verdict = try circuit_cpu.verify.verifyProofBytes(gpa, &setup.table, &case.request, case.proof);
        const want = tamper == .none;
        switch (verdict) {
            .accepted => |digest| std.debug.print("R11 {s}: accepted (output digest {x:0>8})\n", .{ label, digest[0] }),
            .rejected => |why| std.debug.print("R11 {s}: rejected at {s} ({s})\n", .{ label, @tagName(why.stage), @errorName(why.reason) }),
        }
        if (verdict.isAccepted() != want) return error.ZigVerdictDiffers;
        if (emitting) {
            try rust_verifier.emitTo(arena, emit_env, label, case.proof, case.request);
        } else {
            try expectUpstreamVerdict(arena, label, case, want);
        }
    }
}

test "R11: upstream's multiverifier proof is accepted, and rejected after each tampering, by both verifiers" {
    var setup: Setup = undefined;
    try setup.init(std.testing.allocator);
    defer setup.deinit();
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    try checkBase(&setup, arena.allocator(), try multiverifierBase(arena.allocator()));
}

test "R11: the Rust golden leaf is accepted, and rejected after each tampering, by both verifiers" {
    var setup: Setup = undefined;
    try setup.init(std.testing.allocator);
    defer setup.deinit();
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    try checkBase(&setup, arena.allocator(), try leafBase(arena.allocator()));
}

test "R11: a Zig circuit proof is accepted, and rejected after each tampering, by both verifiers" {
    var setup: Setup = undefined;
    try setup.init(std.testing.allocator);
    defer setup.deinit();
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    try checkBase(&setup, arena.allocator(), try smallFibonacciBase(arena.allocator()));
}
