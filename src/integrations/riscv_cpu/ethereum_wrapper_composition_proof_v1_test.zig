//! Complete small heterogeneous STARK regression for Ethereum's composition
//! admission. Active rows exercise q1 polynomial extension and q2 coefficient
//! recovery; this is not an Ethereum block or child-verification proof.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const postcard = @import("interop_postcard");
const admission = @import("ethereum_wrapper_composition_v1.zig");
const support = @import("universal_typed_component_proof_test_support.zig");
const recursion = frontend.recursion;
const air = recursion.air;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Engine = recursion.engine.ProverEngineForBackend(@import("stwo_cpu_backend").CpuBackend);
const VerifierScheme = core.pcs.verifier.CommitmentSchemeVerifier(recursion.engine.Hasher, recursion.engine.MerkleChannel);
const manifest_mod = air.universal_adapter_manifest;
const ControlAir = air.ethereum_publication_control_v1;
const MerkleAir = air.merkle_path;
const Control = air.universal_typed_component.Component(ControlAir, ControlAir.Relation);
const Merkle = air.universal_typed_component.Component(MerkleAir, air.merkle_path_relation);
const ControlRuntime = air.framework_interaction.Runtime(ControlAir.Relation.Runtime);
const MerkleRuntime = air.framework_interaction.Runtime(air.merkle_path_relation.Runtime);
const LOG: u32 = 4;
const SIZE: usize = 1 << LOG;
const PP = ControlAir.PREPROCESSED_COLUMN_COUNT + MerkleAir.PREPROCESSED_COLUMN_COUNT;
const MAIN = ControlAir.PHYSICAL_MAIN_COLUMN_COUNT + MerkleAir.PHYSICAL_MAIN_COLUMN_COUNT;
const INTERACTION = ControlAir.INTERACTION_COLUMN_COUNT + MerkleAir.INTERACTION_COLUMN_COUNT;
const CONFIG = core.pcs.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 3, .fold_step = 1 },
};
const Encoded = struct { bytes: []u8, claims: [2]QM31 };

fn manifestValue() !manifest_mod.Manifest {
    var builder = manifest_mod.Builder{};
    _ = try builder.append(Control.manifestGeometry(.vm_public_logup_control, LOG));
    _ = try builder.append(Merkle.manifestGeometry(.merkle_path, LOG));
    return builder.seal();
}

fn controlRow() !ControlAir.Relation.Row {
    var pp = [_]u32{0} ** ControlAir.PREPROCESSED_COLUMN_COUNT;
    pp[9] = 1;
    pp[10] = 1;
    pp[11] = 0;
    pp[12] = 295;
    return ControlAir.rawWordRow(M31.fromCanonical(0x12345678), M31.fromCanonical(0x5678), M31.fromCanonical(0x1234), true, 738, pp);
}

fn claimsValue(manifest: *const manifest_mod.Manifest, values: [2]QM31) !manifest_mod.ClaimVector {
    var result = try manifest_mod.ClaimVector.init(manifest);
    try result.bind(.vm_public_logup_control, values[0]);
    try result.bind(.merkle_path, values[1]);
    try result.sealClaims(manifest);
    return result;
}

fn preprocessed(allocator: std.mem.Allocator) ![]M31 {
    const values = try allocator.alloc(M31, PP * SIZE);
    errdefer allocator.free(values);
    @memset(values, M31.zero());
    const row = try controlRow();
    for (0..ControlAir.PREPROCESSED_COLUMN_COUNT) |column|
        values[column * SIZE + air.framework_interaction.committedRow(0, LOG)] = row[ControlAir.PHYSICAL_MAIN_COLUMN_COUNT + column];
    return values;
}

fn commitSourceTree(
    comptime count: usize,
    allocator: std.mem.Allocator,
    value_allocator: ?std.mem.Allocator,
    manifest: *const manifest_mod.Manifest,
    tree_index: usize,
    values: []M31,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
) !void {
    if (value_allocator) |selected| {
        defer allocator.free(values);
        const Storage = @import("recursive_binary_outer_support.zig").TreeStorageForManifest(manifest_mod);
        var storage = try Storage.initWithValueAllocator(allocator, selected, manifest, tree_index);
        defer storage.deinit();
        try std.testing.expectEqual(values.len, storage.storage.len);
        @memcpy(storage.storage, values);
        try storage.commitWithEngine(Engine, scheme, channel);
        try std.testing.expectEqual(@as(usize, 0), storage.storage.len);
        return;
    }
    return support.commitTree(count, scheme, allocator, values, LOG, channel);
}

fn produce(allocator: std.mem.Allocator, normalize: bool, retained_allocator: ?std.mem.Allocator) !Encoded {
    const manifest = try manifestValue();
    var scheme = try Engine.init(allocator, CONFIG);
    scheme.setCoefficientRetentionPolicy(.never);
    scheme.setRetainedColumnAllocator(retained_allocator);
    var moved = false;
    defer if (!moved) Engine.deinit(&scheme, allocator);
    var channel = Engine.Channel{};
    try commitSourceTree(PP, allocator, retained_allocator, &manifest, manifest_mod.PREPROCESSED_TREE_INDEX, try preprocessed(allocator), &scheme, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    const control_row = try controlRow();
    const merkle_row = try air.merkle_path_witness.logicalRow(support.fixtureInvocation(1));
    const main = try allocator.alloc(M31, MAIN * SIZE);
    @memset(main, M31.zero());
    const first = air.framework_interaction.committedRow(0, LOG);
    for (control_row[0..ControlAir.PHYSICAL_MAIN_COLUMN_COUNT], 0..) |value, column| main[column * SIZE + first] = value;
    for (merkle_row[0..MerkleAir.PHYSICAL_MAIN_COLUMN_COUNT], 0..) |value, column| main[(ControlAir.PHYSICAL_MAIN_COLUMN_COUNT + column) * SIZE + first] = value;
    try commitSourceTree(MAIN, allocator, retained_allocator, &manifest, manifest_mod.MAIN_TREE_INDEX, main, &scheme, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    try manifest.mixStatementPrefix(&channel);
    const relations = try air.universal_challenges.UniversalRelations.draw(allocator, &channel);
    var control_definition = try ControlAir.build(allocator);
    defer control_definition.deinit();
    const control_plan = try ControlAir.Relation.authenticate(&control_definition);
    var merkle_definition = try MerkleAir.build(allocator);
    defer merkle_definition.deinit();
    const merkle_plan = try air.merkle_path_relation.authenticate(&merkle_definition);
    var control_interaction = try ControlRuntime.generatePrepared(allocator, &control_plan, &.{control_row}, LOG, &relations);
    defer control_interaction.deinit(allocator);
    var merkle_interaction = try MerkleRuntime.generatePrepared(allocator, &merkle_plan, &.{merkle_row}, LOG, &relations);
    defer merkle_interaction.deinit(allocator);
    const claim_values = [2]QM31{ control_interaction.claimed_sum, merkle_interaction.claimed_sum };
    try std.testing.expect(!claim_values[0].isZero() and !claim_values[1].isZero());
    var claims = try claimsValue(&manifest, claim_values);
    try claims.mixInteractionClaims(&manifest, &channel);
    const interactions = try allocator.alloc(M31, INTERACTION * SIZE);
    for (control_interaction.columns, 0..) |column, index| @memcpy(interactions[index * SIZE ..][0..SIZE], column);
    for (merkle_interaction.columns, 0..) |column, index| @memcpy(interactions[(ControlAir.INTERACTION_COLUMN_COUNT + index) * SIZE ..][0..SIZE], column);
    try commitSourceTree(INTERACTION, allocator, retained_allocator, &manifest, manifest_mod.INTERACTION_TREE_INDEX, interactions, &scheme, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    for (scheme.trees.items) |tree| try std.testing.expect(tree.coefficients == null);
    const control = try Control.init(&control_definition, control_plan, &manifest, .vm_public_logup_control, LOG, .{ M31.one(), M31.zero() }, &relations, claim_values[0]);
    const merkle = try Merkle.init(&merkle_definition, merkle_plan, &manifest, .merkle_path, LOG, .{}, &relations, claim_values[1]);
    try std.testing.expectEqual(LOG + 2, control.maxConstraintLogDegreeBound());
    try std.testing.expectEqual(LOG + 1, merkle.maxConstraintLogDegreeBound());
    var gate = try manifest_mod.ProofGate.init(&manifest);
    try gate.append(&manifest, try control.binding(&manifest));
    try gate.append(&manifest, try merkle.binding(&manifest));
    if (normalize) try admission.admitGate(&manifest, &gate);
    try gate.sealGate(&manifest);
    moved = true;
    var extended = try Engine.prove(allocator, try gate.proverSlice(), &channel, scheme, .{});
    defer extended.aux.deinit(allocator);
    defer extended.proof.deinit(allocator);
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try postcard.serializeProof(recursion.engine.Hasher, bytes.writer(allocator), extended.proof);
    return .{ .bytes = try bytes.toOwnedSlice(allocator), .claims = claim_values };
}

fn verifyEncoded(allocator: std.mem.Allocator, encoded: Encoded, normalize: bool) !void {
    // Every producer allocation and typed definition is gone on entry.
    var stream = std.io.fixedBufferStream(encoded.bytes);
    var proof = try postcard.deserializeProof(recursion.engine.Hasher, allocator, stream.reader());
    var moved = false;
    defer if (!moved) proof.deinit(allocator);
    if (stream.pos != encoded.bytes.len) return error.TrailingProofBytes;
    const manifest = try manifestValue();
    const commitments = proof.commitment_scheme_proof.commitments.items;
    try std.testing.expectEqual(@as(usize, 4), commitments.len);
    try std.testing.expectEqualDeep(CONFIG, proof.commitment_scheme_proof.config);
    // Fresh deterministic preprocessing, not a root handed out by producer.
    const expected_root = blk: {
        var pp_scheme = try Engine.init(allocator, CONFIG);
        defer Engine.deinit(&pp_scheme, allocator);
        pp_scheme.setCoefficientRetentionPolicy(.never);
        var pp_channel = Engine.Channel{};
        try support.commitTree(PP, &pp_scheme, allocator, try preprocessed(allocator), LOG, &pp_channel);
        try Engine.flushPendingCommit(&pp_scheme, allocator, &pp_channel);
        break :blk pp_scheme.trees.items[0].root();
    };
    try std.testing.expectEqualDeep(expected_root, commitments[0]);
    var scheme = try VerifierScheme.init(allocator, CONFIG);
    defer scheme.deinit(allocator);
    var channel = Engine.Channel{};
    try scheme.commit(allocator, commitments[0], &([_]u32{LOG} ** PP), &channel);
    try scheme.commit(allocator, commitments[1], &([_]u32{LOG} ** MAIN), &channel);
    try manifest.mixStatementPrefix(&channel);
    const relations = try air.universal_challenges.UniversalRelations.draw(allocator, &channel);
    var claims = try claimsValue(&manifest, encoded.claims);
    try claims.mixInteractionClaims(&manifest, &channel);
    try scheme.commit(allocator, commitments[2], &([_]u32{LOG} ** INTERACTION), &channel);
    var control_definition = try ControlAir.build(allocator);
    defer control_definition.deinit();
    const control_plan = try ControlAir.Relation.authenticate(&control_definition);
    var merkle_definition = try MerkleAir.build(allocator);
    defer merkle_definition.deinit();
    const merkle_plan = try air.merkle_path_relation.authenticate(&merkle_definition);
    const control = try Control.init(&control_definition, control_plan, &manifest, .vm_public_logup_control, LOG, .{ M31.one(), M31.zero() }, &relations, encoded.claims[0]);
    const merkle = try Merkle.init(&merkle_definition, merkle_plan, &manifest, .merkle_path, LOG, .{}, &relations, encoded.claims[1]);
    var gate = try manifest_mod.ProofGate.init(&manifest);
    try gate.append(&manifest, try control.binding(&manifest));
    try gate.append(&manifest, try merkle.binding(&manifest));
    if (normalize) try admission.admitGate(&manifest, &gate);
    try gate.sealGate(&manifest);
    moved = true;
    try core.verifier.verify(recursion.engine.Hasher, recursion.engine.MerkleChannel, allocator, try gate.verifierSlice(), &channel, &scheme, proof);
}

test "Ethereum composition profile small heterogeneous proof serializes destroys and freshly verifies" {
    const allocator = std.testing.allocator;
    const encoded = try produce(allocator, true, null);
    defer allocator.free(encoded.bytes);
    try std.testing.expect(encoded.bytes.len != 0);
    try verifyEncoded(allocator, encoded, true);
}

test "Ethereum composition profile small heterogeneous proof rejects inconsistent split admission" {
    const allocator = std.testing.allocator;
    // Retain the original complete-proof failure as a cheap reproducer.
    try std.testing.expectError(error.ConstraintsNotSatisfied, produce(allocator, false, null));
    const encoded = try produce(allocator, true, null);
    defer allocator.free(encoded.bytes);
    if (verifyEncoded(allocator, encoded, false)) |_| return error.ExpectedCompositionAdmissionFailure else |_| {}
}

test "Ethereum composition profile mapped proof preserves bytes after scratch destruction" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);
    const ordinary = try produce(allocator, true, null);
    defer allocator.free(ordinary.bytes);
    const mapped = blk: {
        var backing = try @import("stwo_prover_engine").mmap_alloc.FileBackedAllocator.init(path);
        defer backing.deinit();
        const result = try produce(allocator, true, backing.allocator());
        errdefer allocator.free(result.bytes);
        try std.testing.expect(backing.total_bytes.load(.monotonic) > 0);
        try std.testing.expectEqual(@as(usize, 0), backing.live_bytes.load(.monotonic));
        break :blk result;
    };
    defer allocator.free(mapped.bytes);
    try std.testing.expectEqualSlices(u8, ordinary.bytes, mapped.bytes);
    try std.testing.expectEqualDeep(ordinary.claims, mapped.claims);
    try verifyEncoded(allocator, mapped, true);
}
