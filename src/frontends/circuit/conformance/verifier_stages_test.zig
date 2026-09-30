//! Rung R4, topology mode (design §8.2): the in-circuit STARK verifier,
//! stage by stage, in the multiverifier of
//! `crates/circuit_multiverifier/src/verify_test.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230), built over empty proofs.
//!
//! Every stage's gate summary must equal the oracle's, which the oracle
//! asserted equal in value and topology mode, and the padded circuit's
//! preprocessed root must be `MULTIVERIFIER_PREPROCESSED_ROOT`. The value
//! half (the committed proofs, the value digest and the output digest) runs
//! in `src/integrations/circuit_cpu`, which can decode `CircuitSerialize`.

const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("circuit_frontend");
const testing = @import("circuit_testing");

const builder = circuit.builder;
const fixture = testing.fixture_json;
const verifier_stages = testing.verifier_stages;
const circuit_hash = circuit.common.circuit_hash;

test "R4: multiverifier verifier stages and preprocessed root match the oracle (topology)" {
    const gpa = std.testing.allocator;
    var document = try fixture.load(gpa, verifier_stages.fixture_path, 1 << 20);
    defer document.deinit();
    const body = try fixture.checkpointBody(document.root(), "r4", "verifier-stages");
    try std.testing.expectEqual(verifier_stages.privacy_trace_log_size, try fixture.unsigned(u32, try fixture.field(body, "pcs_config_trace_log_size")));
    try std.testing.expectEqual(verifier_stages.privacy_log_blowup_factor, try fixture.unsigned(u32, try fixture.field(body, "log_blowup_factor")));

    const projection_bytes = try std.fs.cwd().readFileAlloc(gpa, verifier_stages.projection_path, 8 << 20);
    defer gpa.free(projection_bytes);
    var projection = try circuit.air_eval.projection.parse(gpa, projection_bytes);
    defer projection.deinit();
    var table = try circuit.air_eval.circuit_components.build(gpa, &projection);
    defer table.deinit();

    var shared = try verifier_stages.privacySharedConfig(gpa);
    defer shared.deinit(gpa);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const empty = try circuit.stark_verifier.proof.emptyProof(arena.allocator(), shared.proof_config);
    const input: circuit.statements.multiverifier.MultiverifierInput(builder.NoValue) = .{
        .proof = &empty,
        .preprocessed_root = undefined,
        .output_digest = undefined,
    };
    var ctx = try verifier_stages.buildAndCompare(builder.NoValue, gpa, &table, &.{ input, input }, &shared, body);
    defer ctx.deinit();

    var pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(gpa, &ctx.circuit);
    defer pp.deinit(gpa);
    try std.testing.expect(pp.layout().eql(&shared.preprocessed_column_log_sizes));
    const root = try pp.preprocessedRoot(gpa, verifier_stages.privacy_log_blowup_factor);
    const expected_root = circuit_hash.bytesFromLeU32s(8, try verifier_stages.words8(try fixture.field(body, "preprocessed_root")));
    try std.testing.expectEqualSlices(u8, &expected_root, &root);

    // The host preimage: each child's circuit hash is the host hash of its
    // root under the shared config; the first child is a multiverifier.
    const preimage = try fixture.array(try fixture.field(body, "preimage_words"));
    try std.testing.expectEqual(@as(usize, 32), preimage.len);
    const log_sizes = try circuit.statements.circuit_statement.circuitComponentLogSizes(&shared.preprocessed_column_log_sizes);
    const child_hash = try circuit_hash.hostCircuitHash(log_sizes, verifier_stages.privacy_log_blowup_factor, expected_root);
    for (circuit_hash.leU32sFromBytes(8, &child_hash), preimage[0..8]) |word, expected| {
        try std.testing.expectEqual(try fixture.unsigned(u32, expected), word);
    }
}
