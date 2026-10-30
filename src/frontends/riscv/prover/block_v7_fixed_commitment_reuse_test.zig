//! Actual PCS ownership and hostile substitution checks for commit-once setup.
const std = @import("std");
const M = @import("stwo_core").fields.m31.M31;
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Rows = @import("../recursion/air/blake3_parent_row_storage.zig");
const Fixed = @import("../recursion/blake3_parent_fixed_key_v1.zig").ForBackend(Cpu);
const Protocol = @import("../recursion/blake3_execution_parent_protocol.zig");
const Plan = @import("../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Cpu, Protocol);

test "retained fixed commitment rejects substitutions and survives source owner destruction" {
    const a = std.testing.allocator;
    var rows: Rows.Prepared = .{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = 0 };
    inline for (0..Rows.Airs.len) |i| rows.fixed[i] = &.{};
    defer rows.deinit();
    inline for (Rows.Airs, 0..) |Air, i| {
        rows.fixed[i] = try a.alloc(Rows.FixedRow(Air), 1);
        rows.fixed[i][0] = @splat(M.zero());
        rows.main[i] = try a.alloc(@import("stwo_prover_engine").pcs.ColumnEvaluation, Air.PHYSICAL_MAIN_COLUMN_COUNT);
        for (rows.main[i]) |*column| column.* = .{ .log_size = 1, .values = &.{} };
        for (rows.main[i]) |*column| {
            const values = try a.alloc(M, 2);
            @memset(values, M.zero());
            column.values = values;
        }
    }
    const context: Protocol.Context = .{ .child_key_id = @splat(1), .child_config = Protocol.Profile.diagnostic_q8_pow0.config(), .graph_ids = @splat(@splat(2)), .transcript_plan_id = @splat(3) };
    var committed = try Fixed.deriveCommitted(a, rows.fixed, context, .diagnostic_q8_pow0);
    var owns = true;
    defer if (owns) committed.deinit();
    const original_key = try Fixed.derive(a, rows.fixed, context, .diagnostic_q8_pow0);
    try std.testing.expectEqualDeep(original_key, committed.key);
    const admission = try Protocol.Admission.init(original_key, try original_key.identity());
    rows.fixed[0][0][0] = M.one();
    try std.testing.expectError(error.InvalidBlake3ParentRows, Plan.initFromFixedCommitment(a, &rows, admission, &committed));
    rows.fixed[0][0][0] = M.zero();
    committed.key.context.child_key_id[0] ^= 1;
    try std.testing.expectError(error.InvalidBlake3ParentFixedCommitment, Plan.initFromFixedCommitment(a, &rows, admission, &committed));
    committed.key.context.child_key_id[0] ^= 1;
    committed.key.preprocessed_root[0] ^= 1;
    try std.testing.expectError(error.UntrustedBlake3ParentRoot, Plan.initFromFixedCommitment(a, &rows, admission, &committed));
    committed.key.preprocessed_root[0] ^= 1;
    const plan = try Plan.initFromFixedCommitment(a, &rows, admission, &committed);
    defer plan.deinit();
    committed.deinit();
    owns = false;
    try std.testing.expectEqualDeep(original_key.preprocessed_root, plan.fixed_commitment.root());
    try plan.validateRows(&rows);
    // Fixed setup alone is not a proof of these dummy MAIN rows.
}
