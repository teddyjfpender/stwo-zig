//! Sail-compatible RV32M high-multiply proof and malicious-witness coverage.

const std = @import("std");
const pcs = @import("stwo_core").pcs;
const riscv_cpu = @import("../../integrations/riscv_cpu/mod.zig");
const relation_export = @import("../../frontends/riscv/air/relation_export.zig");
const public_values = @import("../../frontends/riscv/diagnostics/public_values.zig");
const orchestration = @import("../../frontends/riscv/prover/orchestration.zig");
const witness_hook = @import("../../frontends/riscv/prover/test_witness_hook.zig");
const runner = @import("../../frontends/riscv/runner/mod.zig");

const TEST_PCS_CONFIG = pcs.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
    },
};

const Fixture = struct {
    allocator: std.mem.Allocator,
    elf: []u8,
    run: runner.RunResult,
    public: public_values.OwnedPublicData,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const elf = try std.fs.cwd().readFileAlloc(
            allocator,
            "vectors/riscv_elfs/mul_div.elf",
            64 * 1024 * 1024,
        );
        errdefer allocator.free(elf);
        var run = try runner.runWithInput(allocator, elf, &.{}, 1_000_000);
        errdefer run.deinit();
        const public = try public_values.derive(allocator, &run);
        return .{
            .allocator = allocator,
            .elf = elf,
            .run = run,
            .public = public,
        };
    }

    fn deinit(self: *Fixture) void {
        self.public.deinit(self.allocator);
        self.run.deinit();
        self.allocator.free(self.elf);
        self.* = undefined;
    }
};

test "signed high-multiply relation closes and proves through the CPU-SIMD engine" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    var family_rows: usize = 0;
    for (fixture.run.execution_trace.rows.items) |row| {
        const family = try @import("../../frontends/riscv/runner/trace.zig")
            .proofOpcodeFamily(row.opcode);
        if (family == .mulh) family_rows += 1;
    }
    try std.testing.expectEqual(@as(usize, 3), family_rows);

    const diagnostic = try riscv_cpu.diagnoseRiscVRelations(
        fixture.allocator,
        TEST_PCS_CONFIG,
        &fixture.run.execution_trace,
        &fixture.run.state_chain_tracker,
        &fixture.run.rw_memory,
        fixture.public.data,
    );
    try diagnostic.bundle.validate();

    const mulh = diagnostic.bundle.components[@intFromEnum(relation_export.Component.mulh)];
    try std.testing.expect(!mulh.absent);
    try std.testing.expect(mulh.nonzero.entries > 0);
    inline for (.{ relation_export.Domain.range_check_8_11, relation_export.Domain.range_check_m31 }) |domain| {
        const domain_index = @intFromEnum(domain);
        try std.testing.expect(!mulh.domain_sums[domain_index].isZero());
        try std.testing.expect(diagnostic.bundle.aggregate.domain_sums[domain_index].isZero());
    }

    const proof = try riscv_cpu.proveRiscVWithPublicData(
        fixture.allocator,
        TEST_PCS_CONFIG,
        &fixture.run.execution_trace,
        &fixture.run.state_chain_tracker,
        &fixture.run.rw_memory,
        null,
        fixture.public.data,
    );
    defer proof.deinitAfterProofMoved(fixture.allocator);
    try riscv_cpu.verifyRiscV(
        fixture.allocator,
        TEST_PCS_CONFIG,
        proof.statement,
        proof.proof,
        proof.interaction_claim,
    );
}

fn expectMutationRejected(fixture: *const Fixture, cell: witness_hook.Cell) !void {
    var channel = riscv_cpu.CpuProverEngine.Channel{};
    const output = orchestration.runRiscVWithEngineAndPublicDataUsingChannel(
        riscv_cpu.CpuProverEngine,
        .prove,
        fixture.allocator,
        TEST_PCS_CONFIG,
        &fixture.run.execution_trace,
        &fixture.run.state_chain_tracker,
        &fixture.run.rw_memory,
        null,
        fixture.public.data,
        &channel,
        .{ .main = cell },
    ) catch |err| {
        try std.testing.expectEqual(error.ConstraintsNotSatisfied, err);
        return;
    };
    defer output.deinitAfterProofMoved(fixture.allocator);
    try std.testing.expect(std.meta.isError(riscv_cpu.verifyRiscV(
        fixture.allocator,
        TEST_PCS_CONFIG,
        output.statement,
        output.proof,
        output.interaction_claim,
    )));
}

test "signed high-multiply rejects forged committed witness cells" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    const target: witness_hook.Target = .{ .opcode = .{ .family = .mulh } };
    const cases = [_]witness_hook.Cell{
        .{ .target = target, .column = 32, .logical_row = 0 }, // low product
        .{ .target = target, .column = 36, .logical_row = 0 }, // rs1 sign
        .{ .target = target, .column = 38, .logical_row = 0 }, // MULH selector
    };
    for (cases) |cell| try expectMutationRejected(&fixture, cell);
}
