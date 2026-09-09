//! Isolated fixed-program component proof; dynamic caller cancellation remains
//! a full-profile gate. Tree0 is rebuilt from independently supplied fixed rows.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const wire = @import("stwo_proof_wire");
const Engine = prover.engine.ProverEngine(@import("stwo_cpu_backend").CpuBackend, wire.Hasher, core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel, core.channel.blake2s.Blake2sChannel);
const air = @import("commitment.zig");
const interaction = @import("interaction.zig");
const fixed = @import("fixed_table_v1.zig");
const Component = @import("../component.zig").RiscVTraceComponent;
const relations_mod = @import("../relation_challenges.zig");
const support = @import("../../prover/memory_provider_shards/proof_harness.zig");
const QM31 = core.fields.qm31.QM31;
const LOG: u32 = 4;
const ROWS = [_]air.Row{
    .{ .addr = 4, .values = .{ 1, 2, 3, 4 }, .multiplicity = 2, .root = 31 },
    .{ .addr = 8, .values = .{ 5, 6, 7, 8 }, .multiplicity = 1, .root = 31 },
    .{ .addr = 12, .values = .{ 9, 10, 11, 12 }, .multiplicity = 0, .root = 31 },
};
const CONFIG = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 3, .fold_step = 1 } };
const Encoded = struct { bytes: []u8, claims: [interaction.N_SUMS]QM31 };
fn component(relations: *const relations_mod.Relations, claims: [interaction.N_SUMS]QM31) Component {
    return .{ .desc = .{ .family = .base_alu_reg, .log_size = LOG, .n_rows = ROWS.len, .n_columns = air.N_MAIN_COLUMNS }, .initial_pc = 0, .total_steps = 3, .kind = .program, .is_first_col_idx = 0, .is_active_col_idx = 1, .fixed_program_columns = .{ 2, 3, 4, 5, 6, 7 }, .main_col_offset = 0, .interaction_col_offset = 0, .relations = relations, .program_claims = claims };
}
fn preprocessed(allocator: std.mem.Allocator, rows: []const air.Row) ![]prover.pcs.ColumnEvaluation {
    const selectors = try support.generateSelectors(allocator, LOG, @intCast(rows.len));
    defer allocator.free(selectors);
    errdefer for (selectors) |column| allocator.free(@constCast(column.values));
    const fixed_rows = try allocator.dupe(air.Row, rows);
    defer allocator.free(fixed_rows);
    for (fixed_rows) |*row| row.multiplicity = 0;
    var table = try fixed.ColumnsV1.init(allocator, fixed_rows, LOG);
    errdefer table.deinit(allocator);
    const result = try allocator.alloc(prover.pcs.ColumnEvaluation, 2 + fixed.COLUMN_COUNT);
    @memcpy(result[0..2], selectors);
    for (table.values, result[2..]) |column, *value| value.* = .{ .log_size = LOG, .values = column };
    return result;
}
fn produce(allocator: std.mem.Allocator) !Encoded {
    var scheme = try Engine.init(allocator, CONFIG);
    var moved = false;
    defer if (!moved) Engine.deinit(&scheme, allocator);
    scheme.setCoefficientRetentionPolicy(.never);
    var channel = Engine.Channel{};
    CONFIG.mixInto(&channel);
    try Engine.commit(&scheme, allocator, try preprocessed(allocator, &ROWS), null, &channel);
    var main = try air.generateMain(allocator, &ROWS, LOG);
    var main_moved = false;
    defer if (!main_moved) main.deinit(allocator);
    const main_columns = try support.takeColumns(air.N_MAIN_COLUMNS, allocator, &main.values, LOG);
    main_moved = true;
    try Engine.commit(&scheme, allocator, main_columns, null, &channel);
    const relations = try relations_mod.Relations.draw(allocator, &channel);
    var generated = try interaction.generateWithPolicy(.fixed_decoded_table_v1, allocator, &ROWS, LOG, &relations);
    var interaction_moved = false;
    defer if (!interaction_moved) generated.deinit(allocator);
    channel.mixFelts(&generated.claims.sums);
    const interaction_columns = try support.takeColumns(interaction.N_COLUMNS, allocator, &generated.columns, LOG);
    interaction_moved = true;
    try Engine.commit(&scheme, allocator, interaction_columns, null, &channel);
    const value = component(&relations, generated.claims.sums);
    moved = true;
    var extended = try Engine.prove(allocator, &.{value.asProverComponent()}, &channel, scheme, .{});
    defer extended.aux.deinit(allocator);
    defer extended.proof.deinit(allocator);
    return .{ .bytes = try wire.encodeProofBytesBinary(allocator, extended.proof), .claims = generated.claims.sums };
}
fn verify(allocator: std.mem.Allocator, encoded: Encoded, admitted_rows: []const air.Row) !void {
    var proof = try wire.decodeProofBytesBinary(allocator, encoded.bytes);
    var moved = false;
    defer if (!moved) proof.deinit(allocator);
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4) return error.InvalidProofShape;
    // Recompute the fixed selectors; no producer root or PCS owner survives.
    var pp = try Engine.init(allocator, CONFIG);
    defer Engine.deinit(&pp, allocator);
    var scratch = Engine.Channel{};
    try Engine.commit(&pp, allocator, try preprocessed(allocator, admitted_rows), null, &scratch);
    var expected = try pp.roots(allocator);
    defer expected.deinit(allocator);
    if (!std.meta.eql(expected.items[0], roots[0])) return error.FixedProgramPreprocessedRootMismatch;
    var scheme = try core.pcs.verifier.CommitmentSchemeVerifier(Engine.Hasher, Engine.MerkleChannel).init(allocator, CONFIG);
    defer scheme.deinit(allocator);
    var channel = Engine.Channel{};
    CONFIG.mixInto(&channel);
    try scheme.commit(allocator, roots[0], &([_]u32{LOG} ** (2 + fixed.COLUMN_COUNT)), &channel);
    try scheme.commit(allocator, roots[1], &([_]u32{LOG} ** air.N_MAIN_COLUMNS), &channel);
    const relations = try relations_mod.Relations.draw(allocator, &channel);
    channel.mixFelts(&encoded.claims);
    try scheme.commit(allocator, roots[2], &([_]u32{LOG} ** interaction.N_COLUMNS), &channel);
    const value = component(&relations, encoded.claims);
    moved = true;
    try core.verifier.verify(Engine.Hasher, Engine.MerkleChannel, allocator, &.{value.asVerifierComponent()}, &channel, &scheme, proof);
}
test "Ethereum fixed program table serializes destroys and freshly verifies complete component proof" {
    const allocator = std.testing.allocator;
    const encoded = try produce(allocator);
    defer allocator.free(encoded.bytes);
    try verify(allocator, encoded, &ROWS);
    var changed_rows = ROWS;
    changed_rows[0].values[0] += 1;
    if (verify(allocator, encoded, &changed_rows)) |_| return error.ExpectedTableRejection else |_| {}
    var changed = encoded;
    changed.claims[0] = changed.claims[0].add(QM31.one());
    if (verify(allocator, changed, &ROWS)) |_| return error.ExpectedClaimRejection else |_| {}
}
