//! Experimental static-wiring CX/CCX STARK for one public shot and repetition.
//! The QEC benchmark's 64-shot batches and repeated execution are not covered.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const proof_wire = @import("stwo_proof_wire");
pub const input = @import("qec_gate_static/input.zig");
pub const component = @import("qec_gate_static/component.zig");
pub const batch = @import("qec_gate_static/batch.zig");

test {
    _ = batch;
}

pub const Hasher = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
pub const MerkleChannel = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel;
pub const Channel = core.channel.blake2s.Blake2sChannel;
pub const Proof = core.proof.StarkProof(Hasher);

pub const Output = struct {
    statement: input.Statement,
    proof: Proof,
};

pub fn prove(allocator: std.mem.Allocator, config: core.pcs.PcsConfig, program: *const input.Program, statement: input.Statement) !Output {
    try validate(program, statement);
    var channel = Channel{};
    config.mixInto(&channel);
    var scheme = try prover.pcs.CommitmentSchemeProver(CpuBackend, Hasher, MerkleChannel).init(allocator, config);
    const preprocessed = try allocator.alloc(prover.pcs.ColumnEvaluation, 0);
    try scheme.commitOwned(allocator, preprocessed, &channel);
    const main = try input.generate(allocator, program, statement);
    try scheme.commitOwned(allocator, main, &channel);
    mixStatement(&channel, statement);
    const air = component.Component{ .program = program, .statement = statement };
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
    return .{ .statement = statement, .proof = result.proof };
}

pub fn verify(allocator: std.mem.Allocator, config: core.pcs.PcsConfig, program: *const input.Program, statement: input.Statement, proof_in: Proof) !void {
    var proof = proof_in;
    var moved = false;
    defer if (!moved) proof.deinit(allocator);
    try validate(program, statement);
    if (proof.commitment_scheme_proof.commitments.items.len < 2) return error.InvalidProofShape;
    var channel = Channel{};
    config.mixInto(&channel);
    var scheme = try core.pcs.verifier.CommitmentSchemeVerifier(Hasher, MerkleChannel).init(allocator, config);
    defer scheme.deinit(allocator);
    try scheme.commit(allocator, proof.commitment_scheme_proof.commitments.items[0], &.{}, &channel);
    const logs = try allocator.alloc(u32, program.columnCount());
    defer allocator.free(logs);
    @memset(logs, statement.log_rows);
    try scheme.commit(allocator, proof.commitment_scheme_proof.commitments.items[1], logs, &channel);
    mixStatement(&channel, statement);
    const air = component.Component{ .program = program, .statement = statement };
    const components = [_]core.air.components.Component{air.asVerifierComponent()};
    moved = true;
    try core.verifier.verify(Hasher, MerkleChannel, allocator, &components, &channel, &scheme, proof);
}

fn validate(program: *const input.Program, statement: input.Statement) !void {
    if (statement.log_rows < 4 or statement.log_rows > 16 or statement.width != program.width or
        statement.gate_count != program.gates.len or
        statement.target != program.challenge.target or statement.offset != program.challenge.offset or
        !std.mem.eql(u8, &statement.circuit_hash, &program.hash)) return error.InvalidStatement;
}

fn mixStatement(channel: *Channel, statement: input.Statement) void {
    channel.mixU32s(&.{ statement.log_rows, statement.width, statement.gate_count });
    var hash_words: [8]u32 = undefined;
    for (&hash_words, 0..) |*word, i| word.* = std.mem.readInt(u32, statement.circuit_hash[i * 4 ..][0..4], .little);
    channel.mixU32s(&hash_words);
    var target_bytes: [32]u8 = undefined;
    var offset_bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &target_bytes, statement.target, .little);
    std.mem.writeInt(u256, &offset_bytes, statement.offset, .little);
    var target_words: [8]u32 = undefined;
    var offset_words: [8]u32 = undefined;
    for (0..8) |i| {
        target_words[i] = std.mem.readInt(u32, target_bytes[i * 4 ..][0..4], .little);
        offset_words[i] = std.mem.readInt(u32, offset_bytes[i * 4 ..][0..4], .little);
    }
    channel.mixU32s(&target_words);
    channel.mixU32s(&offset_words);
}

test "public iadd8 first SHAKE shot proves and independently decodes/verifies" {
    const bytes = @embedFile("qec_gate_static/fixtures/iadd8.kmx");
    var source = try input.parse(std.testing.allocator, bytes);
    defer source.deinit();
    const statement = input.statement(&source, input.firstChallenge(bytes, source.width));
    const config = core.pcs.PcsConfig{
        .pow_bits = 0,
        .fri_config = try core.fri.FriConfig.init(0, 2, 3),
    };
    var output = try prove(std.testing.allocator, config, &source, statement);
    defer output.proof.deinit(std.testing.allocator);
    const wire = try proof_wire.encodeProofBytes(std.testing.allocator, output.proof);
    defer std.testing.allocator.free(wire);
    var independent = try input.parse(std.testing.allocator, bytes);
    defer independent.deinit();
    try verify(std.testing.allocator, config, &independent, statement, try proof_wire.decodeProofBytes(std.testing.allocator, wire));
    var changed = statement;
    changed.offset +%= 1;
    try std.testing.expectError(error.InvalidStatement, verify(std.testing.allocator, config, &independent, changed, try proof_wire.decodeProofBytes(std.testing.allocator, wire)));
}

test "public iadd256 one-shot static-gate proof diagnostic" {
    if (@import("builtin").mode != .ReleaseFast) return error.SkipZigTest;
    const bytes = @embedFile("qec_gate_static/fixtures/iadd256.kmx");
    var program = try input.parse(std.testing.allocator, bytes);
    defer program.deinit();
    const statement = input.statement(&program, program.challenge);
    const config = core.pcs.PcsConfig{
        .pow_bits = 0,
        .fri_config = try core.fri.FriConfig.init(0, 2, 3),
    };
    var prove_timer = try std.time.Timer.start();
    var output = try prove(std.testing.allocator, config, &program, statement);
    defer output.proof.deinit(std.testing.allocator);
    const prove_ns = prove_timer.read();
    const wire = try proof_wire.encodeProofBytes(std.testing.allocator, output.proof);
    defer std.testing.allocator.free(wire);
    var verifier_program = try input.parse(std.testing.allocator, bytes);
    defer verifier_program.deinit();
    var verify_timer = try std.time.Timer.start();
    try verify(std.testing.allocator, config, &verifier_program, statement, try proof_wire.decodeProofBytes(std.testing.allocator, wire));
    const verify_ns = verify_timer.read();
    std.debug.print("QEC_GATE_STATIC_DIAGNOSTIC width={d} shots=1 repetitions=1 gates={d} trace_rows={d} trace_columns={d} trace_cells={d} prove_ns={d} verify_ns={d} json_wire_bytes={d} security=development_pow0_queries3\n", .{
        program.width,         program.gates.len,                                                       @as(usize, 1) << @intCast(statement.log_rows),
        program.columnCount(), (@as(usize, 1) << @intCast(statement.log_rows)) * program.columnCount(), prove_ns,
        verify_ns,             wire.len,
    });

    const stronger = core.pcs.PcsConfig{
        .pow_bits = 26,
        .fri_config = try core.fri.FriConfig.init(0, 2, 70),
    };
    prove_timer.reset();
    var stronger_output = try prove(std.testing.allocator, stronger, &program, statement);
    defer stronger_output.proof.deinit(std.testing.allocator);
    const stronger_prove_ns = prove_timer.read();
    const stronger_wire = try proof_wire.encodeProofBytes(std.testing.allocator, stronger_output.proof);
    defer std.testing.allocator.free(stronger_wire);
    verify_timer.reset();
    try verify(std.testing.allocator, stronger, &verifier_program, statement, try proof_wire.decodeProofBytes(std.testing.allocator, stronger_wire));
    const stronger_verify_ns = verify_timer.read();
    std.debug.print("QEC_GATE_STATIC_DIAGNOSTIC width={d} shots=1 repetitions=1 gates={d} trace_rows={d} trace_columns={d} trace_cells={d} prove_ns={d} verify_ns={d} json_wire_bytes={d} security=pow26_queries70\n", .{
        program.width,         program.gates.len,                                                       @as(usize, 1) << @intCast(statement.log_rows),
        program.columnCount(), (@as(usize, 1) << @intCast(statement.log_rows)) * program.columnCount(), stronger_prove_ns,
        stronger_verify_ns,    stronger_wire.len,
    });
}
