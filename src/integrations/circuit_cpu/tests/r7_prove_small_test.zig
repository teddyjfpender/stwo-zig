//! Rung R7: the small circuits of `crates/circuit_prover/src/prover_test.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230) proved by the Zig circuit
//! prover, compared with the oracle's `prove-small` checkpoint
//! (`vectors/circuit/r7/prove_small.json`): the channel digest after every
//! transcript step, the lookup elements, both nonces, the claimed sums,
//! every commitment and FRI layer root, the last layer, and the per-column
//! and per-component digests of all three committed trees.
//!
//! The circuits are built with the Zig builder as the oracle's
//! `contexts.rs` transcribes them; each one's value table is checked against
//! the oracle's `values_sha256` before it is proved.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const cairo = @import("stwo_cairo_frontend");
const circuit_cpu = @import("stwo_circuit_cpu_integration");
const rust_verifier = @import("rust_verifier.zig");
const circuit_testing = @import("circuit_testing");
const contexts = circuit_testing.contexts;

const QM31 = core.fields.qm31.QM31;
const component_list = circuit.common.component_list;
const preprocessed = circuit.common.preprocessed;
const checkpoint = cairo.conformance.checkpoint;
const PcsConfigV2 = core.pcs.config_v2.PcsConfigV2;
const FriConfigV2 = core.pcs.config_v2.FriConfigV2;
const Step = circuit_cpu.prove.Step;

const fixture_path = "vectors/circuit/r7/prove_small.json";
const profiles_path = "vectors/circuit/r7/prove_profiles.json";
const N_RESERVED = component_list.N_RESERVED;

const preprocessed_domains = checkpoint.Domains{
    .column = "STWO_CIRCUIT_PREPROCESSED_COLUMN_V1\x00",
    .accumulator = "STWO_CIRCUIT_PREPROCESSED_ACCUMULATOR_V1\x00",
};
const base_domains = checkpoint.Domains{
    .column = "STWO_CIRCUIT_BASE_COLUMN_V1\x00",
    .accumulator = "STWO_CIRCUIT_BASE_ACCUMULATOR_V1\x00",
};
const interaction_domains = checkpoint.Domains{
    .column = "STWO_CIRCUIT_INTERACTION_COLUMN_V1\x00",
    .accumulator = "STWO_CIRCUIT_INTERACTION_ACCUMULATOR_V1\x00",
};

// The contexts of `tools/stwo-circuit-oracle-rs/src/contexts.rs`, shared
// with the frontend's R5 rung.

const TestContext = contexts.TestContext;

// ---------------------------------------------------------------------------
// The observer: step digests, lookup elements and tree digests.

const Observer = struct {
    allocator: std.mem.Allocator,
    steps: std.ArrayListUnmanaged(struct { Step, [32]u8 }) = .empty,
    z: QM31 = undefined,
    alpha: QM31 = undefined,
    trees: [3]std.ArrayListUnmanaged(checkpoint.Component) = .{ .empty, .empty, .empty },
    accumulators: [3]checkpoint.Digest = undefined,
    /// Compact storage drops the committed evaluations before `onTraces`;
    /// the proof bytes still bind them (roots and decommitted values).
    digest_traces: bool = true,
    timer: ?*std.time.Timer = null,
    last_step_ns: u64 = 0,
    interaction_grind_ns: u64 = 0,

    fn deinit(self: *Observer) void {
        self.steps.deinit(self.allocator);
        for (&self.trees) |*tree| {
            for (tree.items) |component| self.allocator.free(component.columns);
            tree.deinit(self.allocator);
        }
    }

    pub fn onStep(self: *Observer, which: Step, digest: [32]u8) void {
        self.steps.append(self.allocator, .{ which, digest }) catch @panic("out of memory");
        if (self.timer) |timer| {
            const now = timer.read();
            if (which == .mix_interaction_pow_nonce) self.interaction_grind_ns = now - self.last_step_ns;
            self.last_step_ns = now;
        }
    }

    pub fn onLookupElements(self: *Observer, z: QM31, alpha: QM31) void {
        self.z = z;
        self.alpha = alpha;
    }

    pub fn onTraces(
        self: *Observer,
        pp: []const prover.pcs.ColumnEvaluation,
        base: []const prover.pcs.ColumnEvaluation,
        interaction: []const prover.pcs.ColumnEvaluation,
    ) !void {
        if (!self.digest_traces) return;
        const one = [_]usize{pp.len};
        self.accumulators[0] = try self.digestTree(0, preprocessed_domains, pp, &.{"preprocessed"}, &one);
        var base_widths: [component_list.N_COMPONENTS]usize = undefined;
        var interaction_widths: [component_list.N_COMPONENTS]usize = undefined;
        for (component_list.component_facts.toArray(), &base_widths, &interaction_widths) |facts, *b, *i| {
            b.* = facts.trace_columns;
            i.* = facts.interaction_columns;
        }
        self.accumulators[1] = try self.digestTree(1, base_domains, base, &component_list.COMPONENT_NAMES, &base_widths);
        self.accumulators[2] = try self.digestTree(2, interaction_domains, interaction, &component_list.COMPONENT_NAMES, &interaction_widths);
    }

    fn digestTree(
        self: *Observer,
        tree: usize,
        domains: checkpoint.Domains,
        columns: []const prover.pcs.ColumnEvaluation,
        labels: []const []const u8,
        widths: []const usize,
    ) !checkpoint.Digest {
        var accumulator = checkpoint.initial_accumulator;
        var cursor: usize = 0;
        for (labels, widths, 0..) |label, width, ordinal| {
            const records = try self.allocator.alloc(checkpoint.Column, width);
            for (records, columns[cursor..][0..width], 0..) |*record, column, index| {
                const words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(column.values));
                record.* = .{
                    .ordinal = @intCast(index),
                    .row_count = column.values.len,
                    .sha256 = try checkpoint.digestColumnIn(domains, @intCast(ordinal), label, @intCast(index), @alignCast(words)),
                };
            }
            cursor += width;
            accumulator = try checkpoint.extendAccumulatorIn(domains, accumulator, @intCast(ordinal), label, records);
            try self.trees[tree].append(self.allocator, .{
                .ordinal = @intCast(ordinal),
                .label = label,
                .columns = records,
                .accumulator = accumulator,
            });
        }
        try std.testing.expectEqual(columns.len, cursor);
        return accumulator;
    }
};

// ---------------------------------------------------------------------------
// Comparison helpers over the parsed JSON.

const Json = std.json.Value;

fn field(value: Json, name: []const u8) Json {
    return value.object.get(name) orelse std.debug.panic("fixture is missing {s}", .{name});
}

fn expectHex(expected: Json, actual: []const u8) !void {
    try std.testing.expectEqualStrings(expected.string, &std.fmt.bytesToHex(actual[0..32].*, .lower));
}

fn expectQm31(expected: Json, actual: QM31) !void {
    const limbs = actual.toM31Array();
    for (expected.array.items, limbs) |want, got| try std.testing.expectEqual(@as(u32, @intCast(want.integer)), got.toU32());
}

fn expectU64(expected: Json, actual: u64) !void {
    const hi: u64 = @intCast(field(expected, "hi").integer);
    const lo: u64 = @intCast(field(expected, "lo").integer);
    try std.testing.expectEqual((hi << 32) | lo, actual);
}

fn expectTree(expected_components: Json, expected_accumulator: Json, actual: []const checkpoint.Component, accumulator: checkpoint.Digest) !void {
    try std.testing.expectEqual(expected_components.array.items.len, actual.len);
    for (expected_components.array.items, actual) |want, got| {
        try std.testing.expectEqualStrings(field(want, "label").string, got.label);
        const columns = field(want, "columns").array.items;
        try std.testing.expectEqual(columns.len, got.columns.len);
        for (columns, got.columns) |column, record| {
            try std.testing.expectEqual(@as(u64, 1) << @intCast(field(column, "log_size").integer), record.row_count);
            expectHex(field(column, "sha256"), &record.sha256) catch |err| {
                std.debug.print("column {s}[{d}] differs\n", .{ got.label, record.ordinal });
                return err;
            };
        }
        try expectHex(field(want, "accumulator_sha256"), &got.accumulator);
    }
    try expectHex(expected_accumulator, &accumulator);
}

fn loadBundle(allocator: std.mem.Allocator) !circuit_cpu.air.Bundle {
    const bytes = try std.fs.cwd().readFileAlloc(allocator, circuit_cpu.air.bundle_path, 1 << 20);
    defer allocator.free(bytes);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    try std.testing.expectEqualStrings(circuit_cpu.air.bundle_sha256, &std.fmt.bytesToHex(digest, .lower));
    return circuit_cpu.air.parse(allocator, bytes);
}

/// The fixture a proof is compared with: `prove-small` (the upstream
/// tests' default config, internal profile) or `prove-profiles` (the circuit
/// FRI config with 26 PoW bits, on each channel profile).
const Lane = enum { small, internal, root };

fn laneProver(comptime lane: Lane) type {
    return switch (lane) {
        .small, .internal => circuit_cpu.Internal,
        .root => circuit_cpu.Root,
    };
}

fn expectedProof(lane: Lane, which: TestContext, parsed: Json) !Json {
    const proofs = switch (lane) {
        .small => field(field(parsed, "body"), "proofs"),
        .internal, .root => for (field(field(parsed, "body"), "profiles").array.items) |profile| {
            if (std.mem.eql(u8, field(profile, "profile").string, @tagName(lane))) break field(profile, "proofs");
        } else return error.MissingFixture,
    };
    for (proofs.array.items) |proof| {
        if (std.mem.eql(u8, field(proof, "name").string, @tagName(which))) return proof;
    }
    return error.MissingFixture;
}

fn proveAndCompare(comptime lane: Lane, comptime which: TestContext) !void {
    return proveAndCompareLanes(&.{lane}, which, null);
}

/// The storage of a cached run: the shared tree's, and every proof's.
/// Neither changes a byte.
const Cached = struct {
    commitment: circuit_cpu.prove.Options = .{},
    proofs: circuit_cpu.prove.Options = .{},
};

/// Proves `which` on each of `lanes` (which share a PCS config) and compares
/// every proof with its fixture. `cached` commits the preprocessed tree and
/// builds the twiddle tower once, then every proof leases them
/// (`prove.Options.preprocessed_commitment`, `twiddle_tower`), as a fold
/// tree's reductions do.
fn proveAndCompareLanes(comptime lanes: []const Lane, comptime which: TestContext, comptime cached: ?Cached) !void {
    const allocator = std.testing.allocator;
    var ctx = try contexts.build(QM31, allocator, which);
    defer ctx.deinit();
    try ctx.finalize(false);
    var pp = try preprocessed.PreprocessedCircuit.preprocessContext(QM31, allocator, &ctx);
    defer pp.deinit(allocator);
    try std.testing.expect(try ctx.isCircuitValid());

    const pcs_config = switch (lanes[0]) {
        .small => circuit_cpu.prove.defaultPcsConfig(pp.traceLogSize()),
        .internal, .root => PcsConfigV2.fromFriAndTraceSize(try FriConfigV2.init(26, 0, 1, 70, 4), pp.traceLogSize()),
    };
    var tower: ?circuit_cpu.prove.TwiddleTower = if (cached != null) try circuit_cpu.prove.twiddleTower(allocator, pcs_config) else null;
    defer if (tower) |*t| t.deinit(allocator);
    var commitment: ?circuit_cpu.prove.PreprocessedCommitment = if (cached) |storage| blk: {
        var commit_options = storage.commitment;
        commit_options.twiddle_tower = &tower.?;
        break :blk try circuit_cpu.prove.PreprocessedCommitment.build(allocator, &pp, pcs_config, commit_options);
    } else null;
    defer if (commitment) |*c| c.deinit(allocator);
    var options: circuit_cpu.prove.Options = if (cached) |storage| storage.proofs else .{};
    options.preprocessed_commitment = if (commitment) |*c| c else null;
    options.twiddle_tower = if (tower) |*t| t else null;
    const compact = if (cached) |storage|
        storage.commitment.compact_polynomial_min_log != null or storage.proofs.compact_polynomial_min_log != null
    else
        false;
    inline for (lanes) |lane| try proveLaneAndCompare(lane, which, &ctx, &pp, pcs_config, options, !compact);
}

fn proveLaneAndCompare(
    comptime lane: Lane,
    comptime which: TestContext,
    ctx: anytype,
    pp: *const preprocessed.PreprocessedCircuit,
    pcs_config: PcsConfigV2,
    options: circuit_cpu.prove.Options,
    digest_traces: bool,
) !void {
    const allocator = std.testing.allocator;
    const bytes = try std.fs.cwd().readFileAlloc(allocator, if (lane == .small) fixture_path else profiles_path, 16 << 20);
    defer allocator.free(bytes);
    var parsed = try std.json.parseFromSlice(Json, allocator, bytes, .{});
    defer parsed.deinit();
    const expected = try expectedProof(lane, which, parsed.value);

    try std.testing.expectEqualStrings(field(expected, "values_sha256").string, &std.fmt.bytesToHex(circuit_testing.circuit_summary.valuesSha256(ctx.values()), .lower));
    try std.testing.expectEqual(@as(u32, @intCast(field(expected, "trace_log_size").integer)), pp.traceLogSize());

    const pcs_json = field(expected, "pcs_config");
    const fri = field(pcs_json, "fri_config");
    inline for (.{ "pow_bits", "log_blowup_factor", "log_last_layer_degree_bound", "n_queries", "fold_step" }) |name|
        try std.testing.expectEqual(@as(u32, @intCast(field(fri, name).integer)), @field(pcs_config.fri_config, name));
    try std.testing.expectEqual(@as(u32, @intCast(field(pcs_json, "trace_lifting_log_size").integer)), pcs_config.trace_lifting_log_size);
    try std.testing.expectEqual(@as(u32, @intCast(field(pcs_json, "preprocessed_lifting_log_size").integer)), pcs_config.preprocessed_lifting_log_size);

    var bundle = try loadBundle(allocator);
    defer bundle.deinit();
    var observer = Observer{ .allocator = allocator, .digest_traces = digest_traces };
    defer observer.deinit();
    // `STWO_CIRCUIT_STAGE_PROFILE=1` reports the interaction grind (the
    // step before the lookup draw) and the FRI grind (`proof_of_work`).
    const profile = std.process.hasEnvVarConstant("STWO_CIRCUIT_STAGE_PROFILE");
    var recorder = prover.stage_profile.Recorder.init(allocator, "cpu", @tagName(which));
    defer recorder.deinit();
    var timer = try std.time.Timer.start();
    observer.timer = &timer;
    var prove_options = options;
    prove_options.recorder = if (profile) &recorder else null;
    var proof = try laneProver(lane).prove(allocator, ctx.values(), pp, &bundle, pcs_config, prove_options, &observer);
    defer proof.deinit();
    if (profile) {
        var snapshot = try recorder.snapshot(allocator);
        defer snapshot.deinit(allocator);
        const fri_grind = for (snapshot.stages) |stage| {
            if (std.mem.eql(u8, stage.id, "proof_of_work")) break stage.seconds;
        } else 0;
        std.debug.print("{s}/{s}: interaction grind {d:.3} s (nonce 0x{x}), FRI grind {d:.3} s at {d} bits (nonce 0x{x})\n", .{
            @tagName(lane),
            @tagName(which),
            @as(f64, @floatFromInt(observer.interaction_grind_ns)) / std.time.ns_per_s,
            proof.interaction_pow_nonce,
            fri_grind,
            pcs_config.fri_config.pow_bits,
            proof.stark_proof.proof.commitment_scheme_proof.proof_of_work,
        });
    }

    // Component log sizes.
    for (field(expected, "component_log_sizes").array.items, proof.component_log_sizes.toArray()) |pair, log_size| {
        try std.testing.expectEqual(@as(u32, @intCast(pair.array.items[1].integer)), log_size);
    }
    // Transcript.
    const steps = field(expected, "steps").array.items;
    try std.testing.expectEqual(steps.len, observer.steps.items.len);
    for (steps, observer.steps.items) |want, got| {
        try std.testing.expectEqualStrings(field(want, "step").string, @tagName(got[0]));
        expectHex(field(want, "channel_digest"), &got[1]) catch |err| {
            std.debug.print("{s}: transcript differs at {s}\n", .{ @tagName(which), @tagName(got[0]) });
            return err;
        };
    }
    const stark = &proof.stark_proof.proof.commitment_scheme_proof;
    try expectHex(field(expected, "preprocessed_root"), &stark.commitments.items[0]);
    try expectHex(field(expected, "circuit_hash"), &proof.circuit_hash);
    const outputs = field(expected, "output_values").array.items;
    try std.testing.expectEqual(outputs.len, proof.output_values.len);
    for (outputs, proof.output_values) |want, got| try expectQm31(want, got);
    try expectU64(field(expected, "interaction_pow_nonce"), proof.interaction_pow_nonce);
    try expectQm31(field(expected, "interaction_z"), observer.z);
    try expectQm31(field(expected, "interaction_alpha"), observer.alpha);
    for (field(expected, "claimed_sums").array.items, proof.claimed_sums.toArray()) |pair, got| {
        try expectQm31(pair.array.items[1], got);
    }
    const commitments = field(expected, "commitments").array.items;
    try std.testing.expectEqual(commitments.len, stark.commitments.items.len);
    for (commitments, stark.commitments.items) |want, got| try expectHex(want, &got);
    const fri_record = field(expected, "fri");
    try expectHex(field(fri_record, "first_layer_root"), &stark.fri_proof.first_layer.commitment);
    const inner = field(fri_record, "inner_layer_roots").array.items;
    try std.testing.expectEqual(inner.len, stark.fri_proof.inner_layers.len);
    for (inner, stark.fri_proof.inner_layers) |want, layer| try expectHex(want, &layer.commitment);
    const last_layer = field(fri_record, "last_layer_poly").array.items;
    try std.testing.expectEqual(last_layer.len, stark.fri_proof.last_layer_poly.coeffs.len);
    for (last_layer, stark.fri_proof.last_layer_poly.coeffs) |want, got| try expectQm31(want, got);
    try expectU64(field(expected, "fri_pow_nonce"), stark.proof_of_work);
    // Committed trees.
    if (digest_traces) {
        try expectTree(field(expected, "preprocessed_columns"), field(expected, "preprocessed_accumulator_sha256"), observer.trees[0].items, observer.accumulators[0]);
        try expectTree(field(expected, "base_columns"), field(expected, "base_accumulator_sha256"), observer.trees[1].items, observer.accumulators[1]);
        try expectTree(field(expected, "interaction_columns"), field(expected, "interaction_accumulator_sha256"), observer.trees[2].items, observer.accumulators[2]);
    }

    // CircuitSerialize bytes, for circuits whose outputs are a digest.
    if (expected.object.get("circuit_serialize")) |serialized| {
        try std.testing.expectEqual(N_RESERVED, proof.output_values.len);
        var verifier_proof = try circuit_cpu.verifier_proof.prepare(allocator, &proof);
        defer verifier_proof.deinit();
        const encoded = try verifier_proof.serialize(allocator);
        defer allocator.free(encoded);
        try std.testing.expectEqual(@as(usize, @intCast(field(serialized, "bytes").integer)), encoded.len);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(encoded, &digest, .{});
        try expectHex(field(serialized, "sha256"), &digest);
        const label = @tagName(lane) ++ "-" ++ @tagName(which);
        try rust_verifier.emit(allocator, label, encoded, &proof, pp);
        // Upstream's `verify_circuit` is the circuit verifier, on the M31
        // channel. A root-profile proof is byte-identical to upstream's own
        // (checked above), which upstream's native stwo verifier accepted.
        if (lane != .root) try rust_verifier.expectAccepted(allocator, label, &digest);
        if (lane != .small) try std.testing.expect(field(expected, "native_verified").bool);
    } else try std.testing.expect(proof.output_values.len != N_RESERVED);
}

test "R7: fibonacci proof matches prove_circuit_assignment" {
    try proveAndCompare(.small, .fibonacci);
}

test "R7: permutation proof matches prove_circuit_assignment" {
    try proveAndCompare(.small, .permutation);
}

test "R7: blake proof matches prove_circuit_assignment" {
    try proveAndCompare(.small, .blake);
}

test "R7: triple_xor proof matches prove_circuit_assignment" {
    try proveAndCompare(.small, .triple_xor);
}

test "R7: m31_to_u32 proof matches prove_circuit_assignment" {
    try proveAndCompare(.small, .m31_to_u32);
}

test "R7: blake_g_gate proof matches prove_circuit_assignment" {
    try proveAndCompare(.small, .blake_g_gate);
}

test "R7 profiles: internal fibonacci under the 26-bit circuit FRI config" {
    try proveAndCompare(.internal, .fibonacci);
}

test "R7 profiles: internal blake_g_gate under the 26-bit circuit FRI config" {
    try proveAndCompare(.internal, .blake_g_gate);
}

test "R7 profiles: root fibonacci under the 26-bit circuit FRI config" {
    try proveAndCompare(.root, .fibonacci);
}

test "R7 profiles: root blake_g_gate under the 26-bit circuit FRI config" {
    try proveAndCompare(.root, .blake_g_gate);
}

test "R7 cached: one compact preprocessed tree serves compact fibonacci proofs" {
    const compact: circuit_cpu.prove.Options = .{ .compact_polynomial_min_log = 4 };
    try proveAndCompareLanes(&.{ .small, .small }, .fibonacci, .{ .commitment = compact, .proofs = compact });
}

test "R7 cached: one evaluations-only tree serves the internal and root profiles, as folds do" {
    const evaluations: circuit_cpu.prove.Options = .{ .evaluations_only = true };
    try proveAndCompareLanes(&.{ .internal, .root }, .blake_g_gate, .{ .commitment = evaluations, .proofs = evaluations });
}

test "R7 cached: compacting proofs never compact an evaluations-only lease" {
    try proveAndCompareLanes(&.{ .small, .small }, .blake_g_gate, .{
        .commitment = .{ .evaluations_only = true },
        .proofs = .{ .compact_polynomial_min_log = 4 },
    });
}

test "R7: evaluations-only storage and compact storage are exclusive" {
    const allocator = std.testing.allocator;
    var ctx = try contexts.build(QM31, allocator, .fibonacci);
    defer ctx.deinit();
    try ctx.finalize(false);
    var pp = try preprocessed.PreprocessedCircuit.preprocessContext(QM31, allocator, &ctx);
    defer pp.deinit(allocator);
    try std.testing.expectError(error.ConflictingStorageOptions, circuit_cpu.prove.PreprocessedCommitment.build(
        allocator,
        &pp,
        circuit_cpu.prove.defaultPcsConfig(pp.traceLogSize()),
        .{ .evaluations_only = true, .compact_polynomial_min_log = 4 },
    ));
}
