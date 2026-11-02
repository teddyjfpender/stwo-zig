const std = @import("std");
const F = @import("fixture.zig");
const E = @import("execution.zig");
const R = @import("roster.zig");
const a = std.testing.allocator;
test "Actual CPU SD ADD ADDI DOUBLE join independently sized RCB truth and global RAM proofs" {
    var c = try F.Case.init(a, .none);
    defer c.deinit();
    const keys = c.keys();
    try E.verify(a, &keys, c.truthKeys(), c.expected(), &c.bundle);
    var s0 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, c.setups[0].materials.geometry, .{ 5, 5 });
    defer s0.deinit();
    var s1 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, c.setups[1].materials.geometry, .{ 5, 5 });
    defer s1.deinit();
    var ta = try R.TruthSetup.init(a, .add, c.truths[0].logs);
    defer ta.deinit();
    var td = try R.TruthSetup.init(a, .double, c.truths[1].logs);
    defer td.deinit();
    try E.verify(a, &.{ &s0, &s1 }, .{ &ta, &td }, c.expected(), &c.bundle);
    const PublicGuard = struct {
        fn verify(ctx: *anyopaque) !void {
            const case_ptr: *F.Case = @ptrCast(@alignCast(ctx));
            const verify_keys = case_ptr.keys();
            try E.verify(a, &verify_keys, case_ptr.truthKeys(), case_ptr.expected(), &case_ptr.bundle);
        }
    };
    try @import("../boundary_guard_fixture.zig").check(&c.bundle.cpus[0].request.base.memory, &c.bundle.cpus[c.bundle.cpus.len - 1].request.base.memory, .{ .context = &c, .verify = PublicGuard.verify });
}
test "Actual valid local secp proofs reject false output and fabricated cross epoch predecessor" {
    var output = try F.Case.init(a, .wrong_output);
    defer output.deinit();
    const keys = output.keys();
    try std.testing.expectError(error.UnclosedSecpWire, E.verify(a, &keys, output.truthKeys(), output.expected(), &output.bundle));
    var reset = try F.Case.init(a, .false_reset);
    defer reset.deinit();
    const rr = reset.keys();
    try std.testing.expectError(error.UnclosedSecpRam, E.verify(a, &rr, reset.truthKeys(), reset.expected(), &reset.bundle));
}

test "Actual CPU owner debt rejects substituted pointer and substituted service kind" {
    for ([_]F.Case.Mutation{ .wrong_pointer, .wrong_kind }) |mutation| {
        var c = try F.Case.init(a, mutation);
        defer c.deinit();
        const keys = c.keys();
        try std.testing.expectError(error.UnclosedSecpCpuRelations, E.verify(a, &keys, c.truthKeys(), c.expected(), &c.bundle));
    }
}
test "Secp receiver binds complete expected roots typed roles and every physical claim" {
    const G = @import("../protocol.zig");
    var c = try F.Case.init(a, .none);
    defer c.deinit();
    const keys = c.keys();
    const receipts = try a.dupe(G.Receipt, c.bundle.manifest.roots);
    defer a.free(receipts);
    receipts[3].main.bytes[0] ^= 1;
    var wrong = try G.Manifest.init(a, c.bundle.manifest.specs, receipts);
    defer wrong.deinit();
    var candidate = c.bundle;
    candidate.manifest = wrong;
    if (E.verify(a, &keys, c.truthKeys(), c.expected(), &candidate)) |_| return error.AcceptedWrongTruthRoot else |_| {}
    var missing = try G.Manifest.init(a, c.bundle.manifest.specs[0..3], c.bundle.manifest.roots[0..3]);
    defer missing.deinit();
    candidate = c.bundle;
    candidate.manifest = missing;
    try std.testing.expectError(error.IncompleteGlobalExecutionManifest, E.verify(a, &keys, c.truthKeys(), c.expected(), &candidate));
    const swapped = [2]*const R.TruthSetup{ c.truths[1], c.truths[0] };
    try std.testing.expectError(error.InvalidSecpTruthKind, E.verify(a, &keys, swapped, c.expected(), &c.bundle));
    c.bundle.truths[0].claims[0] = c.bundle.truths[0].claims[0].add(G.Q.one());
    c.bundle.truths[1].claims[0] = c.bundle.truths[1].claims[0].sub(G.Q.one());
    if (E.verify(a, &keys, c.truthKeys(), c.expected(), &c.bundle)) |_| return error.AcceptedBalancedSecpClaims else |_| {}
}

fn zeroInputWord(_: *const anyopaque, address: u64) !u64 {
    if (address < F.ADDRESS or address > F.ADDRESS + 184 or address & 7 != 0) return error.UntrustedSecpAddress;
    return 0;
}

test "locally valid noncanonical secp operand proofs fail the actual closed Word16 Wire receiver" {
    const S = @import("stwo_riscv_frontend").rv64_air.crypto.secp256k1;
    inline for (.{ .lhs, .rhs }) |fault| {
        var c = try F.Captured.init(a);
        defer c.deinit();
        for (c.advice.events) |events| for (events) |*event| {
            event.before.value = 0;
            event.after.value = 0;
        };
        for (c.advice.initial) |*cell| cell.state.value = 0;
        for (c.advice.terminal) |*cell| cell.state.value = 0;
        for (c.advice.calls) |*families| for (families) |calls| for (calls) |*call| {
            @memset(&call.before, 0);
            @memset(&call.after, 0);
            for (&call.predecessors) |*state| state.value = 0;
        };
        var expected = F.expectedFor(c.program.identity);
        expected.admission.image.initial_word = zeroInputWord;
        expected.admission.image_identity = @splat(0x6e);
        var s0 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, try c.native[0].geometry(), .{ 5, 5 });
        defer s0.deinit();
        var s1 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, try c.native[1].geometry(), .{ 5, 5 });
        defer s1.deinit();
        var ta = try R.TruthSetup.init(a, .add, .{ try S.layout.logSize(.product, &S.program.add, 1), try S.layout.logSize(.linear, &S.program.add, 1) });
        defer ta.deinit();
        var td = try R.TruthSetup.init(a, .double, .{ try S.layout.logSize(.product, &S.program.double, 1), try S.layout.logSize(.linear, &S.program.double, 1) });
        defer td.deinit();
        // MAIN contains an operand byte256 in a zero-product row. The honest
        // BYTE metadata/counts remain unchanged, and the dishonest prover
        // computes Wire debt from the actual committed field coordinates.
        var bundle = try E.testing.produceWithOperandFault(fault, a, &.{ &s0, &s1 }, .{ &ta, &td }, &.{ &c.native[0], &c.native[1] }, &c.advice, expected);
        defer bundle.deinit(a);
        // verify reaches the final closed Wire check only after verifying all
        // four physical proofs, their MAIN roots, claims and manifest binding.
        try std.testing.expectError(error.UnclosedSecpWire, E.verify(a, &.{ &s0, &s1 }, .{ &ta, &td }, expected, &bundle));
        var debt = @import("../protocol.zig").Q.zero();
        for (bundle.cpus) |cpu| for (cpu.claims.bridges) |bridge| {
            debt = debt.add(bridge.wire);
        };
        for (bundle.truths) |truth| for (truth.claims) |claim| {
            debt = debt.add(claim);
        };
        try std.testing.expect(!debt.isZero());
        bundle.truths[0].claims[0] = bundle.truths[0].claims[0].sub(debt);
        if (E.verify(a, &.{ &s0, &s1 }, .{ &ta, &td }, expected, &bundle)) |_| return error.AcceptedRebalancedOperandClaim else |_| {}
    }
}
