const std = @import("std");
const core = @import("stwo_core");
const E = @import("execution.zig");
const P = @import("protocol.zig");
const F = @import("fixture.zig");
const Attack = @import("adversarial_fixture.zig");
const Q = P.Q;
const S = @import("../word16_execution/sources.zig");
const Cell = @import("stwo_riscv_frontend").rv64_air.memory.closed_ram.types.Cell;
const a = std.testing.allocator;
fn rejected(result: anyerror!void) !void {
    if (result) |_| return error.ExpectedGlobalProofRejection else |_| {}
}
fn verify(case: *const F.Case, bundle: *const E.Bundle) !void {
    const keys = case.keys();
    return E.verify(a, &keys, case.expected(), bundle);
}
test "global execution binds actual stage1 roots physical claims and complete ordered inventory" {
    var case = try F.Case.init(a);
    defer case.deinit();
    try verify(&case, &case.bundle);
    for (0..2) |tree| {
        const roots = try a.dupe(P.Receipt, case.bundle.manifest.roots);
        defer a.free(roots);
        if (tree == 0) roots[0].fixed.bytes[0] ^= 1 else roots[0].main.bytes[0] ^= 1;
        var manifest = try P.Manifest.init(a, case.bundle.manifest.specs, roots);
        defer manifest.deinit();
        const view = E.Bundle{ .manifest = manifest, .proofs = case.bundle.proofs };
        try std.testing.expectError(error.GlobalStage1RootMismatch, verify(&case, &view));
    }
    {
        const roots = try a.dupe(P.Receipt, case.bundle.manifest.roots);
        defer a.free(roots);
        std.mem.swap(P.Receipt, &roots[0], &roots[1]);
        var manifest = try P.Manifest.init(a, case.bundle.manifest.specs, roots);
        defer manifest.deinit();
        const view = E.Bundle{ .manifest = manifest, .proofs = case.bundle.proofs };
        try std.testing.expectError(error.GlobalStage1RootMismatch, verify(&case, &view));
    }
    {
        const roots = case.bundle.manifest.roots;
        defer case.bundle.manifest.roots = roots;
        case.bundle.manifest.roots = roots[0..1];
        try std.testing.expectError(error.IncompleteGlobalExecutionManifest, verify(&case, &case.bundle));
    }
    {
        const first = case.bundle.proofs[0].claims.ls.ram;
        const second = case.bundle.proofs[1].claims.ls.ram;
        defer {
            case.bundle.proofs[0].claims.ls.ram = first;
            case.bundle.proofs[1].claims.ls.ram = second;
        }
        case.bundle.proofs[0].claims.ls.ram = first.add(Q.one());
        case.bundle.proofs[1].claims.ls.ram = second.sub(Q.one());
        try S.validateOpenForGlobalRam(case.bundle.proofs[0].claims);
        try S.validateOpenForGlobalRam(case.bundle.proofs[1].claims);
        try rejected(verify(&case, &case.bundle));
    }
    {
        const first = case.bundle.proofs[0].claims.cpu;
        const second = case.bundle.proofs[1].claims.cpu;
        defer {
            case.bundle.proofs[0].claims.cpu = first;
            case.bundle.proofs[1].claims.cpu = second;
        }
        case.bundle.proofs[0].claims.cpu = first.add(Q.one());
        case.bundle.proofs[1].claims.cpu = second.sub(Q.one());
        try std.testing.expectError(error.UnclosedLocalExecutionRelations, verify(&case, &case.bundle));
    }
    {
        const before = case.bundle.proofs[0].claims.initial;
        defer case.bundle.proofs[0].claims.initial = before;
        case.bundle.proofs[0].claims.initial.owner = Q.one();
        case.bundle.proofs[0].claims.initial.selection = Q.one().neg();
        try std.testing.expectError(error.NonzeroOmittedMemoryClaim, verify(&case, &case.bundle));
    }
}
test "global execution independently admits genesis policy program budget epoch and continuation" {
    var case = try F.Case.init(a);
    defer case.deinit();
    const keys = case.keys();
    {
        var expected = case.expected();
        expected.program_identity[0] ^= 1;
        try std.testing.expectError(error.GlobalExecutionProgramMismatch, E.verify(a, &keys, expected, &case.bundle));
        expected = case.expected();
        expected.admission.max_prefix_steps = 1;
        try std.testing.expectError(error.ExecutionPrefixBudgetExceeded, E.verify(a, &keys, expected, &case.bundle));
        expected = case.expected();
        expected.total_steps += 1;
        expected.max_total_steps += 1;
        try std.testing.expectError(error.GlobalExecutionCoverageMismatch, E.verify(a, &keys, expected, &case.bundle));
    }
    {
        const original = case.bundle.proofs[1].request.epoch;
        defer case.bundle.proofs[1].request.epoch = original;
        case.bundle.proofs[1].request.epoch = 1;
        try std.testing.expectError(error.InvalidGlobalExecutionEpoch, verify(&case, &case.bundle));
    }
    {
        const original = case.bundle.proofs[1].request.cpu.initial_pc;
        defer case.bundle.proofs[1].request.cpu.initial_pc = original;
        case.bundle.proofs[1].request.cpu.initial_pc ^= 4;
        try std.testing.expectError(error.GlobalCpuBoundaryMismatch, verify(&case, &case.bundle));
    }
    {
        const original = case.bundle.proofs[1].request.cpu.initial_registers[1];
        defer case.bundle.proofs[1].request.cpu.initial_registers[1] = original;
        case.bundle.proofs[1].request.cpu.initial_registers[1] ^= 1;
        try std.testing.expectError(error.GlobalCpuBoundaryMismatch, verify(&case, &case.bundle));
    }
    {
        const original = case.bundle.proofs[1].request.memory.initial;
        defer case.bundle.proofs[1].request.memory.initial = original;
        case.bundle.proofs[1].request.memory.initial = case.bundle.proofs[0].request.memory.initial;
        try std.testing.expectError(error.RepeatedGlobalInitialization, verify(&case, &case.bundle));
    }
    {
        const original = case.bundle.proofs[0].request.memory.terminal;
        defer case.bundle.proofs[0].request.memory.terminal = original;
        case.bundle.proofs[0].request.memory.terminal = case.bundle.proofs[1].request.memory.terminal;
        try std.testing.expectError(error.PrematureGlobalTeardown, verify(&case, &case.bundle));
    }
    {
        const original = case.bundle.proofs[0].request.memory.initial[0];
        defer @constCast(case.bundle.proofs[0].request.memory.initial)[0] = original;
        @constCast(case.bundle.proofs[0].request.memory.initial)[0].state.value ^= 1;
        try std.testing.expectError(error.UntrustedGlobalMemoryInitialization, verify(&case, &case.bundle));
        @constCast(case.bundle.proofs[0].request.memory.initial)[0] = original;
        @constCast(case.bundle.proofs[0].request.memory.initial)[0].state.rights ^= 1;
        try std.testing.expectError(error.UntrustedGlobalMemoryInitialization, verify(&case, &case.bundle));
    }
    {
        const initial = [_]Cell{ case.bundle.proofs[0].request.memory.initial[0], case.bundle.proofs[0].request.memory.initial[0] };
        const terminal = [_]Cell{ case.bundle.proofs[1].request.memory.terminal[0], case.bundle.proofs[1].request.memory.terminal[0] };
        var proofs = [_]E.Encoded{ case.bundle.proofs[0], case.bundle.proofs[1] };
        proofs[0].request.memory.initial = &initial;
        proofs[1].request.memory.terminal = &terminal;
        const view = E.Bundle{ .manifest = case.bundle.manifest, .proofs = &proofs };
        try std.testing.expectError(error.GlobalTouchedSetMismatch, verify(&case, &view));
    }
}
test "real locally valid load-to-x0 fork proofs fail only global RAM closure" {
    var honest = try Attack.Case.init(a, false);
    defer honest.deinit();
    const keys = honest.keys();
    try E.verify(a, &keys, honest.expected(), &honest.bundle);
    const OldExecution = @import("../word16_execution/execution.zig");
    const first = honest.bundle.proofs[0];
    const first_closed = OldExecution.Encoded{ .bytes = first.bytes, .request = first.request, .claims = first.claims };
    try std.testing.expectError(error.InvalidMemoryStatement, OldExecution.verify(a, honest.setup, honest.expected().admission, first_closed));
    const second = honest.bundle.proofs[1];
    const second_closed = OldExecution.Encoded{ .bytes = second.bytes, .request = second.request, .claims = second.claims };
    var rebase = honest.expected().admission;
    rebase.initial_pc = second.request.cpu.initial_pc;
    rebase.initial_registers = second.request.cpu.initial_registers;
    try std.testing.expectError(error.UnqualifiedCrossBatchMemoryScope, OldExecution.verify(a, honest.setup, rebase, second_closed));

    var forked = try Attack.Case.init(a, true);
    defer forked.deinit();
    for (forked.bundle.proofs) |proof| try S.validateOpenForGlobalRam(proof.claims);
    var debt = Q.zero();
    for (forked.bundle.proofs) |proof| {
        debt = debt.add(proof.claims.ls.ram).add(proof.claims.initial.ram).add(proof.claims.terminal.ram);
    }
    try std.testing.expect(!debt.isZero());
    const fork_keys = forked.keys();
    try std.testing.expectError(error.UnclosedGlobalExecutionRam, E.verify(a, &fork_keys, forked.expected(), &forked.bundle));
}
