//! Complete component STARK gate. The isolated provider has a public LogUp
//! claim; caller closure belongs to the admitted recursive parent profile.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const wire = @import("stwo_proof_wire");
pub const Engine = prover.engine.ProverEngine(@import("stwo_cpu_backend").CpuBackend, wire.Hasher, core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel, core.channel.blake2s.Blake2sChannel);
const air = @import("stwo_riscv_frontend").testing.component_proof.universal_air;
const legacy = @import("stwo_riscv_frontend").testing.component_proof.poseidon_air;
const Component = @import("stwo_riscv_frontend").testing.component_proof.universal_component.Component;
const relations_mod = @import("stwo_riscv_frontend").testing.component_proof.relations;
const support = @import("stwo_riscv_frontend").testing.component_proof.support;
const QM31 = core.fields.qm31.QM31;
const LOG: u32 = 4;
const CALLS = [_]legacy.Call{
    legacy.Call.narrow(123, 456),
    .{ .input = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }, .wide = true },
    .{ .input = .{ 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 }, .io = true },
};
const CONFIG = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 3, .fold_step = 1 } };
pub const Encoded = struct { bytes: []u8, claims: [2]QM31 };
fn component(comptime trace_log: u32, relations: *const relations_mod.Relations, claims: [2]QM31) Component {
    return .{ .log_size = trace_log, .n_rows = CALLS.len, .is_first_col_idx = 0, .is_active_col_idx = 0, .main_col_offset = 0, .interaction_col_offset = 0, .relations = relations, .claims = claims };
}
pub fn produce(allocator: std.mem.Allocator) !Encoded {
    return produceWithEngine(Engine, allocator);
}

pub fn produceWithEngine(comptime SelectedEngine: type, allocator: std.mem.Allocator) !Encoded {
    return produceWithEngineAtLog(SelectedEngine, allocator, LOG);
}

pub fn produceWithEngineAtLog(comptime SelectedEngine: type, allocator: std.mem.Allocator, comptime trace_log: u32) !Encoded {
    var scheme = try SelectedEngine.init(allocator, CONFIG);
    var moved = false;
    defer if (!moved) SelectedEngine.deinit(&scheme, allocator);
    scheme.setCoefficientRetentionPolicy(.never);
    var channel = SelectedEngine.Channel{};
    CONFIG.mixInto(&channel);
    try SelectedEngine.commit(&scheme, allocator, try support.generateSelectors(allocator, trace_log, CALLS.len), null, &channel);
    var main = try air.generateMain(allocator, &CALLS, trace_log);
    var main_moved = false;
    defer if (!main_moved) main.deinit(allocator);
    const main_columns = try support.takeColumns(air.N_MAIN_COLUMNS, allocator, &main.values, trace_log);
    main_moved = true;
    try SelectedEngine.commit(&scheme, allocator, main_columns, null, &channel);
    const relations = try relations_mod.Relations.draw(allocator, &channel);
    var interaction = try legacy.generateInteraction(allocator, &CALLS, trace_log, &relations);
    var interaction_moved = false;
    defer if (!interaction_moved) interaction.deinit(allocator);
    channel.mixFelts(&interaction.claims.sums);
    const interaction_columns = try support.takeColumns(air.N_INTERACTION_COLUMNS, allocator, &interaction.columns, trace_log);
    interaction_moved = true;
    try SelectedEngine.commit(&scheme, allocator, interaction_columns, null, &channel);
    const value = component(trace_log, &relations, interaction.claims.sums);
    moved = true;
    const handle = value.asProverComponent();
    var extended = try SelectedEngine.prove(allocator, &.{handle}, &channel, scheme, .{});
    defer extended.aux.deinit(allocator);
    defer extended.proof.deinit(allocator);
    return .{ .bytes = try wire.encodeProofBytesBinary(allocator, extended.proof), .claims = interaction.claims.sums };
}
pub fn verify(allocator: std.mem.Allocator, encoded: Encoded) !void {
    return verifyAtLog(allocator, encoded, LOG);
}

pub fn verifyAtLog(allocator: std.mem.Allocator, encoded: Encoded, comptime trace_log: u32) !void {
    var proof = try wire.decodeProofBytesBinary(allocator, encoded.bytes);
    var moved = false;
    defer if (!moved) proof.deinit(allocator);
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4) return error.InvalidProofShape;
    // Recompute the fixed selectors; no producer root or PCS owner survives.
    var pp = try Engine.init(allocator, CONFIG);
    defer Engine.deinit(&pp, allocator);
    var scratch = Engine.Channel{};
    try Engine.commit(&pp, allocator, try support.generateSelectors(allocator, trace_log, CALLS.len), null, &scratch);
    var expected = try pp.roots(allocator);
    defer expected.deinit(allocator);
    try std.testing.expectEqualDeep(expected.items[0], roots[0]);
    var scheme = try core.pcs.verifier.CommitmentSchemeVerifier(Engine.Hasher, Engine.MerkleChannel).init(allocator, CONFIG);
    defer scheme.deinit(allocator);
    var channel = Engine.Channel{};
    CONFIG.mixInto(&channel);
    try scheme.commit(allocator, roots[0], &.{ trace_log, trace_log }, &channel);
    try scheme.commit(allocator, roots[1], &([_]u32{trace_log} ** air.N_MAIN_COLUMNS), &channel);
    const relations = try relations_mod.Relations.draw(allocator, &channel);
    channel.mixFelts(&encoded.claims);
    try scheme.commit(allocator, roots[2], &([_]u32{trace_log} ** air.N_INTERACTION_COLUMNS), &channel);
    const value = component(trace_log, &relations, encoded.claims);
    moved = true;
    try core.verifier.verify(Engine.Hasher, Engine.MerkleChannel, allocator, &.{value.asVerifierComponent()}, &channel, &scheme, proof);
}
test "recursive universal degree3 Poseidon serializes destroys and freshly verifies all modes" {
    const allocator = std.testing.allocator;
    const encoded = try produce(allocator);
    defer allocator.free(encoded.bytes);
    try verify(allocator, encoded);
    var changed = encoded;
    changed.claims[0] = changed.claims[0].add(QM31.one());
    if (verify(allocator, changed)) |_| return error.ExpectedClaimRejection else |_| {}
}
