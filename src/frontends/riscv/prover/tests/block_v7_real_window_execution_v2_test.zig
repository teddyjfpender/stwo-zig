const std = @import("std");
const core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const Run = @import("../block_v7_real_window_execution_v2.zig");
const Guest = @import("block_v7_keccak_execution_test_support.zig");
const Receive = @import("../block_v7_execution_receiver_v1.zig");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Q = core.fields.qm31.QM31;
const Consumer = struct {
    pub const Result = void;
    pub fn consume(fixture: Run.Fixture) !void {
        try std.testing.expectEqual(.declared_window, fixture.original.scope);
        try std.testing.expect(fixture.input.memory == .window_joint);
        if (fixture.trusted.window.?.selection != null) {
            const selected = try fixture.trusted.window.?.cloneAlloc(fixture.allocator);
            defer {
                selected.deinit();
                fixture.allocator.destroy(selected);
            }
            for (selected.initial.intervals) |*row| if (row.allowed) {
                row.value ^= 1;
                break;
            };
            var untrusted = fixture.trusted;
            untrusted.window = selected;
            try std.testing.expectError(error.UntrustedV7SparseInitialization, Receive.For(Cpu).verify(fixture.allocator, untrusted, fixture.input, .{}));
        }
        const proof = @constCast(fixture.input.memory.window_joint);
        // Build the new shared-PCS memory context through independent original
        // fixed-root admission. It is an OPEN context, not a union proof or
        // replacement for the complete recursive verification below.
        const UnionMemory = @import("../block_v7_complete_union_memory_v1.zig").ForMode(true);
        const context = try UnionMemory.verifier(Cpu, fixture.allocator, .{
            .policy = fixture.policy,
            .epoch = fixture.input.epoch,
            .entries = fixture.input.entries,
            .roots = proof.roots,
            .interval_log = proof.interval_log,
            .claims = proof.claims(),
        }, .{});
        defer context.deinit();
        try std.testing.expect(context.verifiers.len != 0);
        try std.testing.expectEqualDeep(proof.claims(), context.claims);
        const drawn = try fixture.input.epoch.draw(fixture.allocator);
        var original_channel = drawn.channel;
        var union_channel = drawn.channel;
        const Protocol = @import("../block_v7_window_memory_joint_protocol_v1.zig");
        try Protocol.recordAfterChallenges(&original_channel, context.pin, &context.layout, proof.claims());
        try context.recordAfterChallenges(&union_channel);
        try std.testing.expectEqualDeep(original_channel.digestBytes(), union_channel.digestBytes());
        try std.testing.expectEqual(@as(usize, 31), proof.ram[0].sums.len);
        // Keep the two-plane aggregate unchanged. Transcript binding must still
        // reject this fully decoded physical-claim substitution.
        proof.ram[0].sums[29] = proof.ram[0].sums[29].add(Q.one());
        proof.ram[0].sums[30] = proof.ram[0].sums[30].sub(Q.one());
        defer {
            proof.ram[0].sums[29] = proof.ram[0].sums[29].sub(Q.one());
            proof.ram[0].sums[30] = proof.ram[0].sums[30].add(Q.one());
        }
        const failure = Receive.For(Cpu).verify(fixture.allocator, fixture.trusted, fixture.input, .{});
        if (failure) |_| return error.AcceptedForgedWindowPhysicalClaims else |err| {
            try std.testing.expect(err == error.OodsNotMatching or err == error.ConstraintsNotSatisfied);
        }
    }
};
test "new v7 genuine nonterminal Keccak execution binds complete admitted endpoint" {
    try @import("../block_v7_real_window_execution_test_support_v2.zig").runTiny(Consumer);
}

test "sparse new v7 genuine nonterminal execution verifies original sources and rejects forged initialization" {
    try @import("../block_v7_real_window_execution_test_support_v2.zig").runTinyWithSparse(Consumer, true);
}
