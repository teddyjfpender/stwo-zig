const std = @import("std");
const core = @import("stwo_core");
const F = @import("resident_native_plan_test_v1.zig");
const Program = @import("resident_native_program_v1.zig");
const PCS = @import("resident_native_pcs_v1.zig");
const Memory = @import("resident_native_memory_v1.zig");
const Terminal = @import("resident_native_terminal_v1.zig");
const Claim = @import("../../frontends/riscv/prover/block_v5_native_projection_fused_proof_v1.zig").Claim;
const Access = @import("../../frontends/riscv/prover/block_v5_opcode_memory_sidecar_proof_v1.zig").Claim;
const cuda = @import("stwo_cuda_backend");
fn forceBind4(a: std.mem.Allocator, tx: *cuda.runtime.proof_transaction.ResidentProofTransaction, p: *const Program.ForCommitments(4).Owned, pcs: *const PCS.ForCommitments(4).Plans, t: *const Terminal.ForCommitments(4).Bundle) !void {
    var v = try Memory.ForCommitments(4).bind(a, tx, p, pcs, t, 24);
    _ = try v.producer();
    _ = try v.composition();
    v.deinit();
}
fn forceBind5(a: std.mem.Allocator, tx: *cuda.runtime.proof_transaction.ResidentProofTransaction, p: *const Program.ForCommitments(5).Owned, pcs: *const PCS.ForCommitments(5).Plans, t: *const Terminal.ForCommitments(5).Bundle) !void {
    var v = try Memory.ForCommitments(5).bind(a, tx, p, pcs, t, 24);
    _ = try v.producer();
    _ = try v.composition();
    v.deinit();
}
test "resident native arena terminal original four five tree independent plans" {
    const a = std.testing.allocator;
    _ = &forceBind4;
    _ = &forceBind5;
    inline for (.{ 4, 5 }) |N| {
        const T = Terminal.ForCommitments(N);
        const Mem = Memory.ForCommitments(N);
        const p = try F.fixture(N, a, true);
        defer p.deinit();
        var pcs = try PCS.ForCommitments(N).Plans.init(a, p, 96 << 30);
        defer pcs.deinit();
        var terminal = try T.init(a, p, &pcs);
        defer terminal.deinit(a);
        try terminal.validate(pcs.decommit.topology.assembly_capacity_words);
        const expected = N * 8 + p.view().profile.projections.len * 4 + p.view().profile.slots.len * 38;
        try std.testing.expectEqual(expected, terminal.section(.trace_commitments).words);
        var memory = try Mem.Plan.init(a, p, &pcs, &terminal, 32, 96, &.{}, 96 << 30);
        defer memory.deinit();
        try std.testing.expectError(error.ResidentNativeResourceLimit, Mem.Plan.init(a, p, &pcs, &terminal, 32, 96, &.{}, 1));
        try std.testing.expectEqual(N, pcs.decommit.topology.trace_openings.len);
        const words = try a.alloc(u32, terminal.total_words);
        defer a.free(words);
        @memset(words, 0);
        @memcpy(words[0..terminal.static_header.len], terminal.static_header);
        try std.testing.expectError(error.InvalidResidentNativeVerdict, T.validateEnvelope(terminal, words));
        words[15] = 0;
        try T.validateEnvelope(terminal, words);
        words[4] = if (N == 4) 5 else 4;
        try std.testing.expectError(error.InvalidResidentNativeTerminal, T.validateEnvelope(terminal, words));
        const claims = try a.alloc(Claim, p.view().profile.projections.len);
        defer a.free(claims);
        const access = try a.alloc(Access, p.view().profile.slots.len);
        defer a.free(access);
        const raw = try a.alloc(u32, claims.len * 4 + access.len * 38);
        defer a.free(raw);
        @memset(raw, 0);
        try T.decodeClaims(p, raw, claims, access);
        for (claims, p.view().profile.projections) |c, s| try std.testing.expectEqual(s.n_rows, c.row_count);
        raw[0] = core.fields.m31.Modulus;
        try std.testing.expectError(error.InvalidFieldElement, T.decodeClaims(p, raw, claims, access));
        raw[0] = 0;
        if (N == 5) {
            raw[claims.len * 4 + 37] = 1;
            try std.testing.expectError(error.InvalidResidentNativeActiveCount, T.decodeClaims(p, raw, claims, access));
        }
        std.mem.doNotOptimizeAway(&T.Proof.decode);
        std.debug.print("native arena trees={d} slots={d} bytes={d} terminalwords={d}\n", .{ N, memory.requirements.len, memory.placement.total_words * 4, terminal.total_words });
    }
}

test "resident native arena actual frame and original high-gap clock metadata" {
    const a = std.testing.allocator;
    inline for (.{ 4, 5 }) |N| {
        const p = if (N == 4) try F.envelopeFixture(4, a, true) else try F.clockMetadataFixture(a);
        defer p.deinit();
        var pcs = try PCS.ForCommitments(N).Plans.init(a, p, 96 << 30);
        defer pcs.deinit();
        var terminal = try Terminal.ForCommitments(N).init(a, p, &pcs);
        defer terminal.deinit(a);
        var memory = try Memory.ForCommitments(N).Plan.init(a, p, &pcs, &terminal, 32, if (N == 4) 0 else 96, &.{}, 96 << 30);
        defer memory.deinit();
        if (N == 4) {
            try std.testing.expectEqual(@as(usize, 0), p.view().physical_claim_count);
            try std.testing.expectEqual(@as(usize, 1), p.view().components.len);
            try std.testing.expectEqual(Program.Kind.frame, p.view().components[0].kind);
        } else {
            var has_clock = false;
            for (p.view().components) |c| {
                if (c.kind == .clock) has_clock = true;
            }
            try std.testing.expect(has_clock);
        }
        std.debug.print("native envelope trees={d} components={d} physicalclaims={d} samples={d}\n", .{ N, p.view().components.len, p.view().physical_claim_count, pcs.proof_layout.sample_total });
    }
}

test "resident native arena production gate remains closed" {
    const Prover = @import("resident_native_prover_v1.zig");
    try std.testing.expectError(error.UnqualifiedResidentNativeController, Prover.requireQualification(false));
    try Prover.requireQualification(true);
}
