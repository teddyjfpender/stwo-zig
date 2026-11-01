//! Actual original ALU MAIN arithmetic over real wide PCS/FRI, not a closed VM proof.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const frontend = @import("stwo_riscv_frontend").rv64_air;
const Component = frontend.main_only.component.Component;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const P = engine.air.component_prover.ForField(O);
const CP = core.pcs.ForField(O);
const CPU = @import("stwo_cpu_backend").CpuBackend;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const Channel = core.channel.raw_mod_m31.Om31Channel;
const MC = struct {
    pub fn mixRoot(c: *Channel, root: H.Hash) void {
        core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel.mixRoot(&c.inner, root);
    }
};
const Prover = engine.engine.ForField(O).ProverEngine(CPU, H, MC, Channel);
const a = std.testing.allocator;
fn component() Component {
    return .{ .log_size = 5, .public = .{ .alu = {} }, .offsets = .{ 0, 0 } };
}
fn config() !CP.PcsConfig {
    var cfg = CP.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.ForField(O).FriConfig.init(0, 1, 12) };
    cfg.fri_config.fold_step = 1;
    return cfg;
}
fn produce(invalid: bool) !Prover.ExtendedProof {
    const cfg = try config();
    var channel = Channel.init();
    cfg.mixInto(&channel);
    var scheme = try Prover.init(a, cfg);
    var owns = true;
    errdefer if (owns) scheme.deinit(a);
    try scheme.commit(a, &.{}, &channel);
    const alu = frontend.word16_v1.alu_experiment;
    var values: [47][32]M = undefined;
    // Vary carries/signs/inverses across actual valid rows: composition is not
    // accidentally the identically-zero constant-trace special case.
    for (0..32) |i| {
        const x: u64 = if (i % 2 == 0) std.math.maxInt(u64) - i * 17 else i * 77731;
        const row = try alu.equations.witness(.add, x, i * 9079 + 2671);
        const logical = alu.lookup.rowToColumnsFor(core.fields.qm31.QM31, row);
        for (logical, 0..) |v, c| {
            const coordinates = v.toM31Array();
            try std.testing.expect(coordinates[1].isZero() and coordinates[2].isZero() and coordinates[3].isZero());
            values[c][i] = coordinates[0];
        }
    }
    @memset(&values[46], M.one());
    if (invalid) values[alu.equations.columns.sum][7] = values[alu.equations.columns.sum][7].add(M.one());
    var columns: [47]engine.pcs.ColumnEvaluation = undefined;
    for (&columns, &values) |*c, *v| c.* = .{ .log_size = 5, .values = v };
    try scheme.commit(a, &columns, &channel);
    try scheme.commit(a, &.{}, &channel);
    const air = component();
    const components = [_]P.ComponentProver{air.asProverComponent()};
    owns = false;
    return Prover.prove(a, &components, &channel, scheme, .{});
}
fn verify(proof: core.proof.ForField(O).StarkProof(H)) !void {
    var owned = proof;
    var owns = true;
    defer if (owns) owned.deinit(a);
    if (proof.commitment_scheme_proof.commitments.items.len != 4) return error.InvalidStructure;
    const cfg = try config();
    var channel = Channel.init();
    cfg.mixInto(&channel);
    var receiver = try CP.verifier.CommitmentSchemeVerifier(H, MC).init(a, cfg);
    defer receiver.deinit(a);
    try receiver.commit(a, proof.commitment_scheme_proof.commitments.items[0], &.{}, &channel);
    const logs = [_]u32{5} ** 47;
    try receiver.commit(a, proof.commitment_scheme_proof.commitments.items[1], &logs, &channel);
    try receiver.commit(a, proof.commitment_scheme_proof.commitments.items[2], &.{}, &channel);
    const air = component();
    const verifier = air.asVerifierComponent();
    owns = false;
    try core.verifier.ForField(O).verify(H, MC, a, &.{verifier}, &channel, &receiver, proof);
}
test "OM31 original ALU MAIN actual packed domain STARK and fresh wide receiver accept" {
    var proof = try produce(false);
    defer proof.aux.deinit(a);
    var high_main = false;
    var high_composition = false;
    for (proof.proof.commitment_scheme_proof.sampled_values.items[1]) |column| for (column) |v| {
        high_main = high_main or !v.c1.isZero();
    };
    for (proof.proof.commitment_scheme_proof.sampled_values.items[3]) |column| for (column) |v| {
        high_composition = high_composition or !v.c1.isZero();
    };
    try std.testing.expect(high_main and high_composition);
    try verify(proof.proof);
}
test "OM31 original ALU MAIN actual receiver rejects high-half opening mutation" {
    var proof = try produce(false);
    defer proof.aux.deinit(a);
    const sampled = &proof.proof.commitment_scheme_proof.sampled_values.items[1][0][0];
    sampled.* = sampled.add(O.basis());
    verify(proof.proof) catch |err| switch (err) {
        error.OodsNotMatching, error.RootMismatch, error.FirstLayerEvaluationsInvalid => return,
        else => return err,
    };
    return error.ExpectedRejection;
}
test "OM31 original ALU MAIN invalid arithmetic trace cannot produce an accepted proof" {
    var proof = produce(true) catch |err| switch (err) {
        error.ConstraintsNotSatisfied, error.InvalidLastLayerDegree => return,
        else => return err,
    };
    defer proof.aux.deinit(a);
    verify(proof.proof) catch |err| switch (err) {
        error.OodsNotMatching, error.LastLayerDegreeInvalid => return,
        else => return err,
    };
    return error.ExpectedRejection;
}
