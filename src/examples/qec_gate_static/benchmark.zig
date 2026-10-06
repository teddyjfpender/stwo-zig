//! Isolated-process measurement of the public 64-shot gate AIR ladder.

const std = @import("std");
const core = @import("stwo_core");
const proof_wire = @import("stwo_proof_wire");
const input = @import("input.zig");
const repeat_program = @import("repeat_program.zig");
const batch_input = @import("batch_input.zig");
const batch = @import("batch.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len != 2) return error.ExpectedRepetitionCount;
    const repetitions = try std.fmt.parseInt(u32, args[1], 10);
    if (repetitions != 1 and repetitions != 2 and repetitions != 4) return error.InvalidRepetitionCount;

    const bytes = @embedFile("fixtures/iadd256.kmx");
    var source = try input.parse(allocator, bytes);
    defer source.deinit();
    var repeated = try repeat_program.repeatProgram(allocator, &source, repetitions);
    defer repeated.deinit();
    const statement = batch_input.statement(&repeated);
    const config = core.pcs.PcsConfig{
        .pow_bits = 26,
        .fri_config = try core.fri.FriConfig.init(0, 2, 70),
    };
    var timer = try std.time.Timer.start();
    var output = try batch.prove(allocator, config, &repeated, statement);
    defer output.proof.deinit(allocator);
    const prove_ns = timer.read();
    const wire = try proof_wire.encodeProofBytes(allocator, output.proof);
    defer allocator.free(wire);
    var proof_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(wire, &proof_hash, .{});

    var verifier_source = try input.parse(allocator, bytes);
    defer verifier_source.deinit();
    var verifier_program = try repeat_program.repeatProgram(allocator, &verifier_source, repetitions);
    defer verifier_program.deinit();
    timer.reset();
    try batch.verify(allocator, config, &verifier_program, statement, try proof_wire.decodeProofBytes(allocator, wire));
    const verify_ns = timer.read();

    std.debug.print(
        "QEC_GATE_BATCH_RECEIPT host_proof=true width=256 shots=64 repetitions={d} gates={d} trace_rows=64 fixed_columns={d} main_columns={d} trace_cells={d} prove_ns={d} verify_ns={d} json_wire_bytes={d} proof_sha256={s} pow_nonce={d} security=pow26_queries70 verified=true\n",
        .{
            repetitions,                                                repeated.gates.len,                                 repeated.final_columns.len * 2, repeated.gates.len,
            (repeated.final_columns.len * 2 + repeated.gates.len) * 64, prove_ns,                                           verify_ns,                      wire.len,
            std.fmt.bytesToHex(proof_hash, .lower),                     output.proof.commitment_scheme_proof.proof_of_work,
        },
    );
}
