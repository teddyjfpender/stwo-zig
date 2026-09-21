//! Actual PCS proof of the two opt-in AIRs on genuine 40-word execution.
//! This component gate has explicit unclosed external LogUp claims. It is
//! not a segment wrapper or proof that the external graph/claim/hash/range
//! components have been admitted. The companion test checks their packet
//! graph equations and exact shared tuple boundary separately.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const postcard = @import("interop_postcard");
const support = @import("universal_typed_component_proof_test_support.zig");
const fixture_mod = @import("recursive_common_ethereum_initial_input_lane_v1_test.zig");
const graph_mod = @import("recursive_common_ethereum_initial_input_packet_v1_test.zig");
const Air = frontend.recursion.air.ethereum_initial_input_packet_v1;
const Lane = Air.lane;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const r = frontend.recursion.air;
const Engine = frontend.recursion.engine.ProverEngineForBackend(@import("stwo_cpu_backend").CpuBackend);
const manifest_mod = r.universal_adapter_manifest;
const LaneComponent = r.universal_typed_component.Component(Lane, Lane.Relation);
const PacketComponent = r.universal_typed_component.Component(Air, Air.Relation);
const LOG: u32 = 6;
const ROWS = 64;
const PP = Lane.PREPROCESSED_COLUMN_COUNT + Air.PREPROCESSED_COLUMN_COUNT;
const MAIN = Lane.PHYSICAL_MAIN_COLUMN_COUNT + Air.PHYSICAL_MAIN_COLUMN_COUNT;
const INTERACTION = Lane.INTERACTION_COLUMN_COUNT + Air.INTERACTION_COLUMN_COUNT;
const CONFIG = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 3, .fold_step = 1 } };
const a = std.testing.allocator;
// Test-only roster slots. The manifest commits the new AIR identities; this
// does not select those AIRs for any production roster or circuit profile.
const LANE_KEY: manifest_mod.ComponentKey = .vm_public_claim_input;
const PACKET_KEY: manifest_mod.ComponentKey = .vm_public_logup_input;
const Encoded = struct { bytes: []u8, claims: [2]QM31 };
fn manifest() !manifest_mod.Manifest {
    var b = manifest_mod.Builder{};
    _ = try b.append(LaneComponent.manifestGeometry(LANE_KEY, LOG));
    _ = try b.append(PacketComponent.manifestGeometry(PACKET_KEY, LOG));
    return b.seal();
}
fn claimVector(m: *const manifest_mod.Manifest, values: [2]QM31) !manifest_mod.ClaimVector {
    var result = try manifest_mod.ClaimVector.init(m);
    try result.bind(LANE_KEY, values[0]);
    try result.bind(PACKET_KEY, values[1]);
    try result.sealClaims(m);
    return result;
}
fn preprocessing(graph: *const graph_mod.TestGraph) ![]M31 {
    const storage = try a.alloc(M31, PP * ROWS);
    @memset(storage, M31.zero());
    const shape = try Lane.Shape.init(40);
    for (0..ROWS) |index| {
        const destination = r.framework_interaction.committedRow(index, LOG);
        for (try shape.preprocessing(@intCast(index)), 0..) |word, column| storage[column * ROWS + destination] = word;
        if (index < Air.ROW_COUNT) for (graph.preprocessing[index], 0..) |word, column| {
            storage[(Lane.PREPROCESSED_COLUMN_COUNT + column) * ROWS + destination] = word;
        };
    }
    return storage;
}
fn produce() !Encoded {
    const fixture = try fixture_mod.Fixture.init();
    var graph = try graph_mod.TestGraph.init(&fixture);
    defer graph.circuit.deinit();
    var packet_rows: [ROWS]Air.Row = @splat(@splat(M31.zero()));
    @memcpy(packet_rows[0..Air.ROW_COUNT], &graph.rows());
    const m = try manifest();
    var scheme = try Engine.init(a, CONFIG);
    var moved = false;
    defer if (!moved) Engine.deinit(&scheme, a);
    var channel = Engine.Channel{};
    try support.commitTree(PP, &scheme, a, try preprocessing(&graph), LOG, &channel);
    try Engine.flushPendingCommit(&scheme, a, &channel);
    const main = try a.alloc(M31, MAIN * ROWS);
    @memset(main, M31.zero());
    for (0..ROWS) |index| {
        const destination = r.framework_interaction.committedRow(index, LOG);
        for (fixture.rows[index][0..Lane.PHYSICAL_MAIN_COLUMN_COUNT], 0..) |word, column| main[column * ROWS + destination] = word;
        for (packet_rows[index][0..Air.PHYSICAL_MAIN_COLUMN_COUNT], 0..) |word, column| main[(Lane.PHYSICAL_MAIN_COLUMN_COUNT + column) * ROWS + destination] = word;
    }
    try support.commitTree(MAIN, &scheme, a, main, LOG, &channel);
    try Engine.flushPendingCommit(&scheme, a, &channel);
    try m.mixStatementPrefix(&channel);
    const relations = try r.universal_challenges.UniversalRelations.draw(a, &channel);
    var lane_definition = try Lane.build(a);
    defer lane_definition.deinit();
    const lane_plan = try Lane.Relation.authenticate(&lane_definition);
    var definition = try Air.build(a);
    defer definition.deinit();
    const plan = try Air.Relation.authenticate(&definition);
    var lane_interaction = try r.framework_interaction.Runtime(Lane.Relation.Runtime).generatePrepared(a, &lane_plan, &fixture.rows, LOG, &relations);
    defer lane_interaction.deinit(a);
    var packet_interaction = try r.framework_interaction.Runtime(Air.Relation.Runtime).generatePrepared(a, &plan, &packet_rows, LOG, &relations);
    defer packet_interaction.deinit(a);
    const claims = [2]QM31{ lane_interaction.claimed_sum, packet_interaction.claimed_sum };
    var cv = try claimVector(&m, claims);
    try cv.mixInteractionClaims(&m, &channel);
    const interaction = try a.alloc(M31, INTERACTION * ROWS);
    for (lane_interaction.columns, 0..) |column, index| @memcpy(interaction[index * ROWS ..][0..ROWS], column);
    for (packet_interaction.columns, 0..) |column, index| @memcpy(interaction[(Lane.INTERACTION_COLUMN_COUNT + index) * ROWS ..][0..ROWS], column);
    try support.commitTree(INTERACTION, &scheme, a, interaction, LOG, &channel);
    try Engine.flushPendingCommit(&scheme, a, &channel);
    const lane_component = try LaneComponent.init(&lane_definition, lane_plan, &m, LANE_KEY, LOG, .{}, &relations, claims[0]);
    const packet_component = try PacketComponent.init(&definition, plan, &m, PACKET_KEY, LOG, .{}, &relations, claims[1]);
    var gate = try manifest_mod.ProofGate.init(&m);
    try gate.append(&m, try lane_component.binding(&m));
    try gate.append(&m, try packet_component.binding(&m));
    try gate.sealGate(&m);
    moved = true;
    var extended = try Engine.prove(a, try gate.proverSlice(), &channel, scheme, .{});
    defer extended.aux.deinit(a);
    defer extended.proof.deinit(a);
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(a);
    try postcard.serializeProof(Engine.Hasher, bytes.writer(a), extended.proof);
    return .{ .bytes = try bytes.toOwnedSlice(a), .claims = claims };
}
fn verify(encoded: Encoded) !void {
    var stream = std.io.fixedBufferStream(encoded.bytes);
    var proof = try postcard.deserializeProof(Engine.Hasher, a, stream.reader());
    var moved = false;
    defer if (!moved) proof.deinit(a);
    if (stream.pos != encoded.bytes.len) return error.NoncanonicalProof;
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4) return error.InvalidProofShape;
    // Reconstruct fixed PP from shape and a fresh graph; all proving owners
    // were destroyed by produce(). No recorded proof root is an authority.
    const fixture = try fixture_mod.Fixture.init();
    var graph = try graph_mod.TestGraph.init(&fixture);
    defer graph.circuit.deinit();
    var pp = try Engine.init(a, CONFIG);
    defer Engine.deinit(&pp, a);
    var scratch = Engine.Channel{};
    try support.commitTree(PP, &pp, a, try preprocessing(&graph), LOG, &scratch);
    try Engine.flushPendingCommit(&pp, a, &scratch);
    var expected = try pp.roots(a);
    defer expected.deinit(a);
    if (!std.meta.eql(expected.items[0], roots[0])) return error.PreprocessedRootMismatch;
    const m = try manifest();
    var scheme = try core.pcs.verifier.CommitmentSchemeVerifier(Engine.Hasher, Engine.MerkleChannel).init(a, CONFIG);
    defer scheme.deinit(a);
    var channel = Engine.Channel{};
    try scheme.commit(a, roots[0], &([_]u32{LOG} ** PP), &channel);
    try scheme.commit(a, roots[1], &([_]u32{LOG} ** MAIN), &channel);
    try m.mixStatementPrefix(&channel);
    const relations = try r.universal_challenges.UniversalRelations.draw(a, &channel);
    var cv = try claimVector(&m, encoded.claims);
    try cv.mixInteractionClaims(&m, &channel);
    try scheme.commit(a, roots[2], &([_]u32{LOG} ** INTERACTION), &channel);
    var lane_definition = try Lane.build(a);
    defer lane_definition.deinit();
    var definition = try Air.build(a);
    defer definition.deinit();
    const lane_component = try LaneComponent.init(&lane_definition, try Lane.Relation.authenticate(&lane_definition), &m, LANE_KEY, LOG, .{}, &relations, encoded.claims[0]);
    const packet_component = try PacketComponent.init(&definition, try Air.Relation.authenticate(&definition), &m, PACKET_KEY, LOG, .{}, &relations, encoded.claims[1]);
    var gate = try manifest_mod.ProofGate.init(&m);
    try gate.append(&m, try lane_component.binding(&m));
    try gate.append(&m, try packet_component.binding(&m));
    try gate.sealGate(&m);
    moved = true;
    try core.verifier.verify(Engine.Hasher, Engine.MerkleChannel, a, try gate.verifierSlice(), &channel, &scheme, proof);
}
test "Ethereum initial input packet and genuine lane serialize destroy and freshly verify PCS proof" {
    const encoded = try produce();
    defer a.free(encoded.bytes);
    try verify(encoded);
    var changed = encoded;
    changed.claims[1] = changed.claims[1].add(QM31.one());
    if (verify(changed)) |_| return error.ExpectedChangedClaimRejection else |_| {}
    std.debug.print("INITIAL_INPUT_PACKET_PCS native_verified=true bytes={d} changed_claim_rejected=true external_closure_required=true\n", .{encoded.bytes.len});
}
