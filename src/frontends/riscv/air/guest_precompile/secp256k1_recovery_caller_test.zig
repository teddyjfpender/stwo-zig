const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const abi = @import("../../isa/ethereum_signer_recovery.zig");
const custom0 = @import("../../isa/custom0.zig");
const affine = @import("secp256k1_affine.zig");
const caller = @import("secp256k1_recovery_caller.zig");
const call_buffer = @import("../../runner/guest_precompile/secp256k1_recover_call_buffer.zig");
const runner = @import("../../runner/guest_precompile/secp256k1_recover_v1.zig");
const direct = @import("secp256k1_recovery_direct.zig");
const fixture = @import("secp256k1_affine_test.zig").csp_input;
const recovery = @import("secp256k1_recovery.zig");
const relations_mod = @import("secp256k1_relations.zig");

const Sink = struct {
    failures: usize = 0,

    pub fn add(self: *Sink, value: anytype, degree: u8) void {
        _ = degree;
        const lifted = if (@TypeOf(value) == M31) QM31.fromBase(value) else value;
        self.failures += @intFromBool(!lifted.isZero());
    }
};

test "secp256k1 recovery caller: exact row vanishes and preflight binds instruction" {
    var tape = try recoveryTape();
    defer tape.deinit();
    const record = recordFor(&tape.recoveries.items[0]);
    const row = caller.rowFromRecord(record);
    var sink = Sink{};
    caller.evaluateDirect(M31, &row, &sink);
    try std.testing.expectEqual(@as(usize, 0), sink.failures);

    const execution = runner.ExecutionRow{
        .execution_clock = record.execution_clock,
        .pc = record.pc,
        .inst_word = custom0.encodeSecp256k1Recover(record.pointer_register),
        .call_index = 0,
    };
    try caller.preflight(&.{record}, &.{execution}, record.execution_clock);
    var forged = execution;
    forged.inst_word = custom0.encodeKeccakf(record.pointer_register);
    try std.testing.expectError(
        error.ProgramMismatch,
        caller.preflight(&.{record}, &.{forged}, record.execution_clock),
    );
}

test "secp256k1 recovery caller: arithmetic tuple cancels exactly" {
    var tape = try recoveryTape();
    defer tape.deinit();
    const record = recordFor(&tape.recoveries.items[0]);
    const caller_row = caller.rowFromRecord(record);
    const recovery_row = try direct.rowFromRecord(&tape, &tape.recoveries.items[0]);
    const relations = relations_mod.Relations.dummy();
    const caller_pairs = caller.rowPairs(M31, &caller_row, &relations);
    const recovery_pairs = direct.rowPairs(M31, &recovery_row, &relations);
    const caller_event = caller_pairs[caller.batch_count - 1];
    const recovery_event = recovery_pairs[direct.batch_count - 1];
    try std.testing.expect(caller_event.n1.eql(recovery_event.n2.neg()));
    try std.testing.expect(caller_event.d1.eql(recovery_event.d2));
}

test "secp256k1 recovery caller: status recid output and old-memory mutations reject" {
    var tape = try recoveryTape();
    defer tape.deinit();
    const record = recordFor(&tape.recoveries.items[0]);
    const relations = relations_mod.Relations.dummy();
    const row = caller.rowFromRecord(record);
    const baseline = caller.rowPairs(M31, &row, &relations);

    var forged = row;
    forged[caller.Layout.status_bytes] = M31.zero();
    var sink = Sink{};
    caller.evaluateDirect(M31, &forged, &sink);
    try std.testing.expect(sink.failures != 0);
    try std.testing.expect(!baseline[caller.batch_count - 1].d1.eql(
        caller.rowPairs(M31, &forged, &relations)[caller.batch_count - 1].d1,
    ));

    forged = row;
    forged[caller.Layout.recovery_id_bytes + 1] = M31.one();
    sink = .{};
    caller.evaluateDirect(M31, &forged, &sink);
    try std.testing.expect(sink.failures != 0);

    forged = row;
    forged[caller.Layout.public_key_big_endian + 9] =
        forged[caller.Layout.public_key_big_endian + 9].add(M31.one());
    try std.testing.expect(!baseline[caller.batch_count - 1].d1.eql(
        caller.rowPairs(M31, &forged, &relations)[caller.batch_count - 1].d1,
    ));

    forged = row;
    forged[caller.Layout.outputPreviousByte(3, 2)] =
        forged[caller.Layout.outputPreviousByte(3, 2)].add(M31.one());
    const forged_pairs = caller.rowPairs(M31, &forged, &relations);
    const output_consume_batch = (6 + 3 * abi.input_word_count + 3 * 3) / 2;
    try std.testing.expect(!baseline[output_consume_batch].d1.eql(
        forged_pairs[output_consume_batch].d1,
    ));
}

fn recordFor(recovery_record: *const affine.RecoveryRecord) call_buffer.Record {
    return .{
        .execution_clock = 3,
        .pc = 0x1000,
        .io_ptr = 0x2000,
        .pointer_register = 5,
        .pointer_previous_clock = 0,
        .digest_big_endian = recovery_record.digest_big_endian,
        .r_big_endian = reverse(recovery_record.r),
        .s_big_endian = reverse(recovery_record.s),
        .recovery_id = recovery_record.recovery_id,
        .public_key_xy_big_endian = fixture[33..97].*,
        .status = abi.success_status,
        .input_previous_clocks = .{0} ** abi.input_word_count,
        .output_previous_words = .{0xa5a5_5a5a} ** abi.output_word_count,
        .output_previous_clocks = .{0} ** abi.output_word_count,
    };
}

fn recoveryTape() !affine.Tape {
    var tape = affine.Tape.init(std.testing.allocator);
    errdefer tape.deinit();
    for (0..2) |recovery_id| {
        recovery.recover(
            &tape,
            fixture[0..32].*,
            fixture[97..129].*,
            fixture[129..161].*,
            @intCast(recovery_id),
            fixture[33..97].*,
        ) catch |err| switch (err) {
            error.RecoveredPublicKeyMismatch => continue,
            else => return err,
        };
        return tape;
    }
    return error.InvalidFixture;
}

fn reverse(value: [32]u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (value, 0..) |byte, index| result[value.len - 1 - index] = byte;
    return result;
}
