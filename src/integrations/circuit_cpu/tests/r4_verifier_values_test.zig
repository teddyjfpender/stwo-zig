//! Rung R4, value mode (design §8.2): the multiverifier of
//! `test_verify_cairo_proof_and_multiverifier_proof`
//! (`crates/circuit_multiverifier/src/verify_test.rs`,
//! https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230) over the committed proofs
//! `test_data/circuit_multiverifier/{proof,proof_cairo}.bin`.
//!
//! The frontend's `circuit-parity-r4` checks the same stages in topology
//! mode; here the proofs are decoded (`CircuitSerialize`), guessed and
//! verified in value mode. Every stage's gate summary, the value table
//! digest and the output digest must equal the oracle's `verifier-stages`
//! checkpoint, and the circuit must be satisfied: the Zig in-circuit
//! verifier accepts both upstream proofs.
//!
//! The same builder also reproduces the circuit behind `proof.bin` itself (a
//! multiverifier of two copies of the Cairo verifier proof), whose digests
//! `vectors/circuit/r7/multiverifier_inputs.json` pins: that is the circuit
//! the R7 multiverifier rung proves.

const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const circuit_cpu = @import("stwo_circuit_cpu_integration");
const wire = @import("stwo_circuit_recursion_wire").circuit_serialize;
const testing = @import("circuit_testing");

const QM31 = core.fields.qm31.QM31;
const builder = circuit.builder;
const fixture = testing.fixture_json;
const circuit_summary = testing.circuit_summary;
const verifier_stages = testing.verifier_stages;
const circuit_hash = circuit.common.circuit_hash;
const multiverifier = circuit.statements.multiverifier;
const Value = std.json.Value;

const multiverifier_proof_path = "vectors/circuit/official/circuit_multiverifier/proof.bin";
const cairo_proof_path = "vectors/circuit/official/circuit_multiverifier/proof_cairo.bin";
const r7_inputs_path = "vectors/circuit/r7/multiverifier_inputs.json";

/// `PRIVACY_CAIRO_VERIFIER_PREPROCESSED_ROOT` of
/// `crates/circuit_multiverifier/src/test_utils.rs`; its circuit hash is
/// checked against the checkpoint's preimage below.
const privacy_cairo_verifier_preprocessed_root = [8]u32{ 2148584466, 2382698151, 457595934, 1170971019, 2577130673, 1560042363, 4279004765, 3806063892 };

const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    table: circuit.air_eval.component_table.Table,
    projection: circuit.air_eval.projection.Projection,
    shared: multiverifier.SharedConfig,
    multiverifier_proof: circuit.stark_verifier.proof.Proof(QM31),
    cairo_proof: circuit.stark_verifier.proof.Proof(QM31),

    fn deinit(self: *Fixture, gpa: std.mem.Allocator) void {
        self.table.deinit();
        self.projection.deinit();
        self.shared.deinit(gpa);
        self.arena.deinit();
    }
};

fn loadFixture(gpa: std.mem.Allocator) !*Fixture {
    const self = try gpa.create(Fixture);
    errdefer gpa.destroy(self);
    self.arena = .init(gpa);
    errdefer self.arena.deinit();
    const a = self.arena.allocator();

    const projection_bytes = try std.fs.cwd().readFileAlloc(a, verifier_stages.projection_path, 8 << 20);
    self.projection = try circuit.air_eval.projection.parse(gpa, projection_bytes);
    errdefer self.projection.deinit();
    self.table = try circuit.air_eval.circuit_components.build(gpa, &self.projection);
    errdefer self.table.deinit();
    self.shared = try verifier_stages.privacySharedConfig(gpa);
    errdefer self.shared.deinit(gpa);

    const config = try circuit_cpu.verifier_proof.proofConfig(self.shared.preprocessed_column_log_sizes.entries.len, self.shared.pcs_config);
    self.multiverifier_proof = try decode(a, multiverifier_proof_path, config);
    self.cairo_proof = try decode(a, cairo_proof_path, config);
    return self;
}

fn decode(a: std.mem.Allocator, path: []const u8, config: wire.ProofConfig) !circuit.stark_verifier.proof.Proof(QM31) {
    const bytes = try std.fs.cwd().readFileAlloc(a, path, 1 << 20);
    var decoded = try wire.deserializeProof(a, bytes, config);
    try std.testing.expectEqual(bytes.len, decoded.consumed);
    return circuit_cpu.verifier_proof.circuitVerifierValues(a, &decoded.proof, config);
}

fn words(value: []const Value) ![8]u32 {
    if (value.len != 8) return error.FixtureShape;
    var out: [8]u32 = undefined;
    for (&out, value) |*word, item| word.* = try fixture.unsigned(u32, item);
    return out;
}

/// The circuit's output digest: the values of its output wires but `u`.
fn outputDigest(ctx: *const builder.Context(QM31)) ![8]u32 {
    var out: [8]u32 = undefined;
    var at: usize = 0;
    for (ctx.circuit.output.items) |wire_idx| {
        if (wire_idx == builder.context.u_var_idx) continue;
        if (at == out.len) return error.TooManyOutputs;
        out[at] = builder.ivalue.unpackU32(QM31, ctx.get(.{ .idx = wire_idx }));
        at += 1;
    }
    if (at != out.len) return error.TooFewOutputs;
    return out;
}

test "R4: the multiverifier accepts proof.bin and proof_cairo.bin, stage by stage (values)" {
    const gpa = std.testing.allocator;
    var document = try fixture.load(gpa, verifier_stages.fixture_path, 1 << 20);
    defer document.deinit();
    const body = try fixture.checkpointBody(document.root(), "r4", "verifier-stages");
    const f = try loadFixture(gpa);
    defer {
        f.deinit(gpa);
        gpa.destroy(f);
    }

    // The preimage: [circuit_hash, output_digest] of the multiverifier child,
    // then of the Cairo verifier child.
    const preimage = try fixture.array(try fixture.field(body, "preimage_words"));
    try std.testing.expectEqual(@as(usize, 32), preimage.len);
    const multiverifier_root = try verifier_stages.words8(try fixture.field(body, "preprocessed_root"));
    const log_sizes = try circuit.statements.circuit_statement.circuitComponentLogSizes(&f.shared.preprocessed_column_log_sizes);
    const cairo_hash = try circuit_hash.hostCircuitHash(
        log_sizes,
        verifier_stages.privacy_log_blowup_factor,
        circuit_hash.bytesFromLeU32s(8, privacy_cairo_verifier_preprocessed_root),
    );
    try std.testing.expectEqual(try words(preimage[16..24]), circuit_hash.leU32sFromBytes(8, &cairo_hash));

    const inputs = [_]multiverifier.MultiverifierInput(QM31){
        .{
            .proof = &f.multiverifier_proof,
            .preprocessed_root = builder.blake.hashValue(QM31, multiverifier_root),
            .output_digest = builder.blake.hashValue(QM31, try words(preimage[8..16])),
        },
        .{
            .proof = &f.cairo_proof,
            .preprocessed_root = builder.blake.hashValue(QM31, privacy_cairo_verifier_preprocessed_root),
            .output_digest = builder.blake.hashValue(QM31, try words(preimage[24..32])),
        },
    };
    var ctx = try verifier_stages.buildAndCompare(QM31, gpa, &f.table, &inputs, &f.shared, body);
    defer ctx.deinit();

    try std.testing.expectEqual(try fixture.digest(try fixture.field(body, "values_sha256")), circuit_summary.valuesSha256(ctx.values()));
    try std.testing.expect(try ctx.isCircuitValid());
    try std.testing.expectEqual(try verifier_stages.words8(try fixture.field(body, "output_digest")), try outputDigest(&ctx));
}

test "R4: the multiverifier of two Cairo verifier proofs is the circuit proof.bin proves" {
    const gpa = std.testing.allocator;
    var document = try fixture.load(gpa, r7_inputs_path, 1 << 20);
    defer document.deinit();
    const body = try fixture.checkpointBody(document.root(), "r7", "multiverifier-inputs");
    const f = try loadFixture(gpa);
    defer {
        f.deinit(gpa);
        gpa.destroy(f);
    }

    var stages_document = try fixture.load(gpa, verifier_stages.fixture_path, 1 << 20);
    defer stages_document.deinit();
    const preimage = try fixture.array(try fixture.field(try fixture.checkpointBody(stages_document.root(), "r4", "verifier-stages"), "preimage_words"));
    const cairo_input: multiverifier.MultiverifierInput(QM31) = .{
        .proof = &f.cairo_proof,
        .preprocessed_root = builder.blake.hashValue(QM31, privacy_cairo_verifier_preprocessed_root),
        .output_digest = builder.blake.hashValue(QM31, try words(preimage[24..32])),
    };
    var ctx = try multiverifier.buildMultiverifierCircuit(QM31, gpa, &f.table, &.{ cairo_input, cairo_input }, &f.shared, circuit.stark_verifier.verify.NoStages{});
    defer ctx.deinit();
    try circuit.common.finalize.padToTargets(QM31, &ctx, verifier_stages.privacy_target_sizes);

    try circuit_summary.expectGateSummary(try fixture.field(body, "circuit"), circuit_summary.gateSummary(&ctx.circuit));
    try std.testing.expectEqual(try fixture.unsigned(usize, try fixture.field(body, "n_values")), ctx.values().len);
    try std.testing.expectEqual(try fixture.digest(try fixture.field(body, "values_sha256")), circuit_summary.valuesSha256(ctx.values()));
    try std.testing.expect(try ctx.isCircuitValid());
}
