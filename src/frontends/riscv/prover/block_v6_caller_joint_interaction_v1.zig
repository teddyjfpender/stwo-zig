//! Isolated original caller interaction construction for joint-proof qualification.
//! Equations and primitive generators are the original B5CF1 authority. The
//! orchestration preserves its exact partition order and physical claim census.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Column = engine.pcs.ColumnEvaluation;
const Schedule = @import("block_v5_caller_fused_schedule_v1.zig").Schedule;
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Program = @import("block_v5_program_extension_proof_v1.zig");
const Algebra = @import("block_v5_precompile_lookup_algebra_v1.zig");
const External = @import("block_v5_external_memory_sidecar_proof_v1.zig");
const Selected = @import("block_v5_committed_projection_columns_v1.zig");
const Range = @import("block_execution_byte_range_v2.zig");
const Transition = @import("block_execution_transition_interaction_v2.zig");
const UniversalMemory = @import("block_v5_opcode_memory_interaction_v1.zig");
const WordTransition = @import("block_v5_word_execution_transition_v1.zig");
const Word = @import("block_v5_word_memory_protocol_v1.zig");

const Fused = @import("block_v5_caller_fused_proof_v1.zig");
pub const Generated = struct {
    claims: Fused.ClaimFrames,
    columns: []Column,
    pub fn deinit(self: *Generated, a: std.mem.Allocator) void {
        self.claims.deinit(a);
        for (self.columns) |column| a.free(column.values);
        a.free(self.columns);
        self.* = undefined;
    }
};
pub fn generate(a: std.mem.Allocator, columns: *const Selected.Columns, schedule: *const Schedule, inputs: []const External.Input, snapshots: anytype, relations: *const Profile.Relations, word: *const Word.Challenges) !Generated {
    if (inputs.len != schedule.memory.len or snapshots.len != inputs.len) return error.InvalidJointCallerInputs;
    var claims = Fused.ClaimFrames{ .program_claims = try a.alloc(Program.Claim, schedule.program.len), .state_claims = &.{}, .table_claims = &.{}, .memory_claims = &.{} };
    errdefer claims.deinit(a);
    claims.state_claims = try a.alloc(Program.Claim, schedule.program.len);
    claims.table_claims = try a.alloc(Algebra.Claim, schedule.tables.len);
    claims.memory_claims = try a.alloc(External.Claim, schedule.memory.len);
    var interaction: std.ArrayList(Column) = .empty;
    errdefer {
        for (interaction.items) |column| a.free(column.values);
        interaction.deinit(a);
    }
    inline for (.{ .program, .state }, 0..) |projection, part| for (schedule.program, 0..) |slot, i| {
        const generated = try Fused.generateProgram(a, columns.fixed, columns.main, slot, &relations.sha, projection);
        const claim = Program.Claim{ .sum = generated.claim, .fetch_count = slot.active_calls };
        if (part == 0) claims.program_claims[i] = claim else claims.state_claims[i] = claim;
        try Fused.appendOwned(a, &interaction, slot.log_size, generated.columns);
    };
    for (schedule.tables, claims.table_claims) |slot, *claim| {
        const generated = try Algebra.generate(a, columns.fixed, columns.main, slot, relations, schedule.owner);
        claim.* = .{ .sum = generated.claim, .row_count = slot.n_rows };
        try Fused.appendOwned(a, &interaction, slot.log_size, generated.columns);
    }
    for (inputs, schedule.memory, claims.memory_claims, snapshots) |input, slot, *claim, snapshot| {
        if (!std.meta.eql(input.descriptor, slot) or !std.meta.eql(input.trace.descriptor, slot)) return error.UntrustedV5CallerCompositeInputs;
        const rows = try a.alloc(Transition.Row, input.trace.domainSize());
        defer a.free(rows);
        const memory_rows = try a.alloc(UniversalMemory.Row, input.trace.domainSize());
        defer a.free(memory_rows);
        for (rows, memory_rows, 0..) |*row, *memory_row, i| {
            row.* = try input.trace.row(i);
            memory_row.* = try UniversalMemory.rowFromPair(try input.trace.pairAt(i));
        }
        var t = try WordTransition.generate(a, word, rows, slot.log_size);
        defer t.deinit(a);
        var b = try Range.generate(a, input.trace, word.universal_prefix.get(.range_check_8_8), snapshot);
        defer b.deinit(a);
        var m = try UniversalMemory.generate(a, word.universal_prefix.get(.memory_access), memory_rows, slot.log_size);
        defer m.deinit(a);
        claim.* = .{ .transition_sum = t.claim, .universal_sum = m.claim, .range_claims = b.claims, .active_count = t.count };
        try Fused.appendCopies(a, &interaction, slot.log_size, &t.columns);
        try Fused.appendCopies(a, &interaction, slot.log_size, &b.columns);
        try Fused.appendCopies(a, &interaction, slot.log_size, &m.columns);
    }

    return .{ .claims = claims, .columns = try interaction.toOwnedSlice(a) };
}
