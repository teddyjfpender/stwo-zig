//! Failure-path ownership tests for Tree-1 profiling scopes.

const std = @import("std");
const stage_profile = @import("stwo_prover_api").stage_profile;
const program_commitment = @import("../air/program/commitment.zig");
const commitment_witness = @import("commitment_witness.zig");
const subject = @import("main_trace.zig");
const proof_workspace = @import("proof_workspace.zig");
const statement_geometry = @import("statement_geometry.zig");

const CommitmentWitness = commitment_witness.CommitmentWitness;
const Geometry = statement_geometry.Geometry;
const ProofWorkspace = proof_workspace.ProofWorkspace;

fn expectScopeClosedAsRoot(
    recorder: *stage_profile.Recorder,
    closed_scope_id: []const u8,
) !void {
    var probe = try stage_profile.StageScope.begin(
        recorder,
        "riscv_scope_lifecycle_probe",
        "RISC-V scope lifecycle probe",
    );
    probe.end();

    var profile = try recorder.snapshot(std.testing.allocator);
    defer profile.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), profile.stages.len);
    try std.testing.expectEqualStrings(closed_scope_id, profile.stages[0].id);
    try std.testing.expect(profile.stages[0].children == null);
    try std.testing.expectEqualStrings(
        "riscv_scope_lifecycle_probe",
        profile.stages[1].id,
    );
    try std.testing.expect(profile.stages[1].children == null);
}

test "main trace profiling: infrastructure failure closes its scope" {
    const allocator = std.testing.allocator;
    var recorder = stage_profile.Recorder.init(allocator, "zig", "riscv");
    defer recorder.deinit();

    const workspace = try ProofWorkspace.create(allocator);
    defer workspace.destroy(allocator);
    var columns = try subject.Columns.init(
        allocator,
        program_commitment.N_MAIN_COLUMNS,
        0,
        null,
        null,
    );
    defer columns.deinit(allocator);

    var program = try program_commitment.build(
        allocator,
        &.{.{ .pc = 0, .word = 0x00000013 }},
        &.{},
    );
    defer program.deinit(allocator);
    const witness: CommitmentWitness = .{
        .boundary = null,
        .program = commitment_witness.ProgramWitnessV1.fromOwned(program),
        .poseidon_calls = .empty,
        .merkle_rows = .empty,
    };
    const geometry: Geometry = .{
        .program_log_size = 4,
        .merkle_log_size = 4,
        .poseidon_log_size = 4,
        .clock_update_log = 4,
        .merkle_infra_index = 0,
        .poseidon_infra_index = 0,
        .clock_infra_index = 0,
    };
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );

    try std.testing.expectError(
        error.OutOfMemory,
        subject.generateInfrastructure(
            failing.allocator(),
            workspace,
            &columns,
            &witness,
            geometry,
            null,
            &recorder,
        ),
    );
    try expectScopeClosedAsRoot(
        &recorder,
        "riscv_infrastructure_trace_generation",
    );
}

test "main trace profiling: abandoned opcode generation closes its scope" {
    const allocator = std.testing.allocator;
    var recorder = stage_profile.Recorder.init(allocator, "zig", "riscv");
    defer recorder.deinit();
    const workspace = try ProofWorkspace.create(allocator);
    defer workspace.destroy(allocator);
    workspace.opcode_error = error.InjectedOpcodeGenerationFailure;

    var generation: subject.OpcodeGeneration = .{
        .thread = null,
        .scope = try stage_profile.StageScope.begin(
            &recorder,
            "riscv_opcode_trace_generation",
            "RISC-V opcode trace generation (overlapped)",
        ),
        .joined = false,
        .finished = false,
    };
    generation.abandon(workspace, allocator);
    // Cleanup paths can overlap after `finish` reports an opcode error. Closing
    // twice must remain a no-op after the first balanced pop.
    generation.abandon(workspace, allocator);

    try std.testing.expect(generation.joined);
    try std.testing.expect(generation.scope.ended);
    try expectScopeClosedAsRoot(
        &recorder,
        "riscv_opcode_trace_generation",
    );
}
