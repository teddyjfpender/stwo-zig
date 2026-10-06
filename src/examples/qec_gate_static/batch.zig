//! Sixty-four-shot fixed-circuit proof with verifier-rebuilt SHAKE table root.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const proof_wire = @import("stwo_proof_wire");
const input = @import("input.zig");
const batch_input = @import("batch_input.zig");
const component = @import("batch_component.zig");
const Hasher = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const MerkleChannel = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel;
const Channel = core.channel.blake2s.Blake2sChannel;
const Proof = core.proof.StarkProof(Hasher);

pub const Output = struct {
    statement: batch_input.Statement,
    proof: Proof,
};

pub fn prove(allocator: std.mem.Allocator, config: core.pcs.PcsConfig, program: *const input.Program, s: batch_input.Statement) !Output {
    try batch_input.validate(program, s);
    var channel = Channel{};
    config.mixInto(&channel);
    var scheme = try prover.pcs.CommitmentSchemeProver(CpuBackend, Hasher, MerkleChannel).init(allocator, config);
    const fixed = try batch_input.generateFixed(allocator, program, s);
    const main = batch_input.generateMain(allocator, program, s, fixed) catch |err| {
        batch_input.deinitColumns(allocator, fixed);
        return err;
    };
    scheme.commitOwned(allocator, fixed, &channel) catch |err| {
        batch_input.deinitColumns(allocator, main);
        return err;
    };
    try scheme.commitOwned(allocator, main, &channel);
    mixStatement(&channel, s);
    const air = component.Component{ .program = program, .statement = s };
    const components = [_]prover.air.component_prover.ComponentProver{air.asProverComponent()};
    const result = try prover.prove.proveEx(
        CpuBackend,
        Hasher,
        MerkleChannel,
        allocator,
        &components,
        &channel,
        scheme,
        false,
    );
    var aux = result.aux;
    aux.deinit(allocator);
    return .{ .statement = s, .proof = result.proof };
}

pub fn verify(allocator: std.mem.Allocator, config: core.pcs.PcsConfig, program: *const input.Program, s: batch_input.Statement, proof_in: Proof) !void {
    var proof = proof_in;
    var moved = false;
    defer if (!moved) proof.deinit(allocator);
    try batch_input.validate(program, s);
    if (proof.commitment_scheme_proof.commitments.items.len < 2) return error.InvalidProofShape;
    const expected_root = try expectedFixedRoot(allocator, config, program, s);
    if (!std.mem.eql(u8, &expected_root, &proof.commitment_scheme_proof.commitments.items[0]))
        return error.FixedChallengeRootMismatch;
    var channel = Channel{};
    config.mixInto(&channel);
    var scheme = try core.pcs.verifier.CommitmentSchemeVerifier(Hasher, MerkleChannel).init(allocator, config);
    defer scheme.deinit(allocator);
    const qubits = program.final_columns.len;
    const fixed_logs = try allocator.alloc(u32, qubits * 2);
    defer allocator.free(fixed_logs);
    @memset(fixed_logs, s.log_rows);
    try scheme.commit(allocator, proof.commitment_scheme_proof.commitments.items[0], fixed_logs, &channel);
    const main_logs = try allocator.alloc(u32, program.gates.len);
    defer allocator.free(main_logs);
    @memset(main_logs, s.log_rows);
    try scheme.commit(allocator, proof.commitment_scheme_proof.commitments.items[1], main_logs, &channel);
    mixStatement(&channel, s);
    const air = component.Component{ .program = program, .statement = s };
    const components = [_]core.air.components.Component{air.asVerifierComponent()};
    moved = true;
    try core.verifier.verify(Hasher, MerkleChannel, allocator, &components, &channel, &scheme, proof);
}

fn expectedFixedRoot(allocator: std.mem.Allocator, config: core.pcs.PcsConfig, program: *const input.Program, s: batch_input.Statement) !Hasher.Hash {
    const fixed = try batch_input.generateFixed(allocator, program, s);
    defer batch_input.deinitColumns(allocator, fixed);
    var twiddles = prover.poly.twiddle_source.TwiddleSource.initOwned(allocator);
    defer twiddles.deinit(allocator);
    var prepared = try prover.pcs.column_preparation.prepareColumnsForCommitBorrowedForBackend(
        prover.pcs.HostMerkleBackend,
        allocator,
        fixed,
        config.fri_config.log_blowup_factor,
        .never,
        &twiddles,
    );
    var tree = prover.pcs.CommitmentTreeProver(Hasher).initPrepared(allocator, &prepared, null) catch |err| {
        prepared.deinit(allocator);
        return err;
    };
    defer tree.deinit(allocator);
    return tree.root();
}

fn mixStatement(channel: *Channel, s: batch_input.Statement) void {
    channel.mixU32s(&.{ s.log_rows, s.width, s.gate_count, s.batch_index });
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, s.circuit_hash[i * 4 ..][0..4], .little);
    channel.mixU32s(&words);
}

test "64-shot gate witness satisfies each fixed and terminal relation" {
    const bytes = @embedFile("fixtures/iadd256.kmx");
    var program = try input.parse(std.testing.allocator, bytes);
    defer program.deinit();
    const s = batch_input.statement(&program);
    const fixed = try batch_input.generateFixed(std.testing.allocator, &program, s);
    defer batch_input.deinitColumns(std.testing.allocator, fixed);
    const main = try batch_input.generateMain(std.testing.allocator, &program, s, fixed);
    defer batch_input.deinitColumns(std.testing.allocator, main);
    const fixed_row = try std.testing.allocator.alloc(core.fields.m31.M31, fixed.len);
    defer std.testing.allocator.free(fixed_row);
    const main_row = try std.testing.allocator.alloc(core.fields.m31.M31, main.len);
    defer std.testing.allocator.free(main_row);
    const air = component.Component{ .program = &program, .statement = s };
    for (0..64) |row| {
        for (fixed, fixed_row) |col, *value| value.* = col.values[row];
        for (main, main_row) |col, *value| value.* = col.values[row];
        const constraints = try air.constraintsAt(core.fields.m31.M31, std.testing.allocator, fixed_row, main_row);
        defer std.testing.allocator.free(constraints);
        for (constraints) |value| try std.testing.expect(value.isZero());
    }
}

test "iadd8 first 64 distinct SHAKE shots prove and freshly verify" {
    const bytes = @embedFile("fixtures/iadd8.kmx");
    var source = try input.parse(std.testing.allocator, bytes);
    defer source.deinit();
    const s = batch_input.statement(&source);
    const config = core.pcs.PcsConfig{
        .pow_bits = 0,
        .fri_config = try core.fri.FriConfig.init(0, 2, 3),
    };
    var output = try prove(std.testing.allocator, config, &source, s);
    defer output.proof.deinit(std.testing.allocator);
    const wire = try proof_wire.encodeProofBytes(std.testing.allocator, output.proof);
    defer std.testing.allocator.free(wire);
    try verify(std.testing.allocator, config, &source, s, try proof_wire.decodeProofBytes(std.testing.allocator, wire));
}

test "iadd256 first 64 distinct SHAKE shots prove and freshly verify" {
    if (@import("builtin").mode != .ReleaseFast) return error.SkipZigTest;
    const bytes = @embedFile("fixtures/iadd256.kmx");
    var source = try input.parse(std.testing.allocator, bytes);
    defer source.deinit();
    const s = batch_input.statement(&source);
    const config = core.pcs.PcsConfig{
        .pow_bits = 26,
        .fri_config = try core.fri.FriConfig.init(0, 2, 70),
    };
    var prove_timer = try std.time.Timer.start();
    var output = try prove(std.testing.allocator, config, &source, s);
    defer output.proof.deinit(std.testing.allocator);
    const prove_ns = prove_timer.read();
    const wire = try proof_wire.encodeProofBytes(std.testing.allocator, output.proof);
    defer std.testing.allocator.free(wire);
    var independent = try input.parse(std.testing.allocator, bytes);
    defer independent.deinit();
    var verify_timer = try std.time.Timer.start();
    try verify(std.testing.allocator, config, &independent, s, try proof_wire.decodeProofBytes(std.testing.allocator, wire));
    const verify_ns = verify_timer.read();
    independent.first_batch[0].target ^= 1;
    try std.testing.expectError(
        error.FixedChallengeRootMismatch,
        verify(std.testing.allocator, config, &independent, s, try proof_wire.decodeProofBytes(std.testing.allocator, wire)),
    );
    std.debug.print("QEC_GATE_BATCH_DIAGNOSTIC width=256 shots=64 repetitions=1 gates={d} trace_rows=64 fixed_columns={d} main_columns={d} trace_cells={d} prove_ns={d} verify_ns={d} json_wire_bytes={d} security=pow26_queries70\n", .{
        source.gates.len,                                       source.final_columns.len * 2, source.gates.len,
        (source.final_columns.len * 2 + source.gates.len) * 64, prove_ns,                     verify_ns,
        wire.len,
    });
}
