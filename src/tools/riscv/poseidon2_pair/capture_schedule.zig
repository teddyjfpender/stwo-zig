//! Allocation-free, canonical C-013 attempt schedule.
//!
//! The frozen M6 protocol fixes six call counts, three workload shapes, ten
//! excluded warmups per arm, and three measured AB/BA rounds with ten pairs
//! per round. This module turns that prose into one deterministic launch
//! order. A future orchestrator consumes this iterator; it may not retry,
//! delete, reorder, or replace an attempt.

const std = @import("std");
const protocol = @import("capture_protocol.zig");

pub const call_counts = [_]usize{ 0, 1, 8, 64, 512, 4096 };
pub const shapes = [_]protocol.Shape{
    .core_only,
    .balanced_core_and_poseidon2,
    .poseidon2_dominant,
};
pub const excluded_warmups_per_arm: usize = 10;
pub const measured_rounds: usize = 3;
pub const measured_pairs_per_round: usize = 10;
pub const cooldown_ns: u64 = std.time.ns_per_s;

pub const attempts_per_cell: usize =
    2 * excluded_warmups_per_arm +
    2 * measured_rounds * measured_pairs_per_round;
pub const cell_count: usize = shapes.len * call_counts.len;
pub const attempt_count: usize = cell_count * attempts_per_cell;
pub const calibration_attempt_count: usize = attempts_per_cell;
pub const global_attempt_count: usize =
    calibration_attempt_count + attempt_count;

comptime {
    if (attempts_per_cell != 80 or cell_count != 18 or attempt_count != 1440)
        @compileError("C-013 frozen schedule geometry drifted");
}

pub const Attempt = struct {
    ordinal: usize,
    cell_index: usize,
    shape: protocol.Shape,
    calls: usize,
    phase: protocol.Phase,
    arm: protocol.Arm,
    round: ?usize,
    pair_index: usize,
    position: usize,
};

pub const Iterator = struct {
    ordinal: usize = 0,

    pub fn next(self: *Iterator) ?Attempt {
        if (self.ordinal == attempt_count) return null;
        const ordinal = self.ordinal;
        self.ordinal += 1;
        return attemptAt(ordinal) catch unreachable;
    }
};

pub fn attemptAt(ordinal: usize) !Attempt {
    if (ordinal >= attempt_count) return error.AttemptOutOfRange;
    const cell_index = ordinal / attempts_per_cell;
    const local = ordinal % attempts_per_cell;
    const shape_index = cell_index / call_counts.len;
    const call_index = cell_index % call_counts.len;
    const warmup_attempts = 2 * excluded_warmups_per_arm;

    if (local < warmup_attempts) {
        const pair_index = local / 2;
        const position = local % 2;
        return .{
            .ordinal = ordinal,
            .cell_index = cell_index,
            .shape = shapes[shape_index],
            .calls = call_counts[call_index],
            .phase = .warmup,
            .arm = armAt(pair_index & 1, position),
            .round = null,
            .pair_index = pair_index,
            .position = position,
        };
    }

    const measured = local - warmup_attempts;
    const attempts_per_round = 2 * measured_pairs_per_round;
    const round = measured / attempts_per_round;
    const within_round = measured % attempts_per_round;
    const pair_index = within_round / 2;
    const position = within_round % 2;
    return .{
        .ordinal = ordinal,
        .cell_index = cell_index,
        .shape = shapes[shape_index],
        .calls = call_counts[call_index],
        .phase = .measured,
        .arm = armAt(round & 1, position),
        .round = round,
        .pair_index = pair_index,
        .position = position,
    };
}

pub fn validateAttempt(
    ordinal: usize,
    shape: protocol.Shape,
    calls: usize,
    phase: protocol.Phase,
    arm: protocol.Arm,
) !void {
    const expected = try attemptAt(ordinal);
    if (expected.shape != shape or expected.calls != calls or
        expected.phase != phase or expected.arm != arm)
    {
        return error.CaptureScheduleAttemptMismatch;
    }
}

fn armAt(precompile_first: usize, position: usize) protocol.Arm {
    return if ((precompile_first ^ position) == 0) .software else .precompile;
}

pub const CalibrationArm = enum { a, a_control };

pub const CalibrationAttempt = struct {
    ordinal: usize,
    phase: protocol.Phase,
    arm: CalibrationArm,
    round: ?usize,
    pair_index: usize,
    position: usize,
};

pub const GlobalAttempt = union(enum) {
    calibration: CalibrationAttempt,
    m6: Attempt,
};

/// A/A is an admission gate and therefore occupies the first eighty global
/// launch ordinals. Candidate workload execution begins only after all of it.
pub fn globalAttemptAt(ordinal: usize) !GlobalAttempt {
    if (ordinal < calibration_attempt_count) {
        return .{ .calibration = try calibrationAttemptAt(ordinal) };
    }
    if (ordinal < global_attempt_count) {
        return .{ .m6 = try attemptAt(ordinal - calibration_attempt_count) };
    }
    return error.AttemptOutOfRange;
}

/// A/A uses the same executable and source identity under two labels. Its
/// ordering is isomorphic to one workload cell and therefore receives the
/// complete warmup/paired-round/cooldown procedure.
pub fn calibrationAttemptAt(ordinal: usize) !CalibrationAttempt {
    if (ordinal >= calibration_attempt_count)
        return error.AttemptOutOfRange;
    const warmup_attempts = 2 * excluded_warmups_per_arm;
    if (ordinal < warmup_attempts) {
        const pair_index = ordinal / 2;
        const position = ordinal % 2;
        return .{
            .ordinal = ordinal,
            .phase = .calibration,
            .arm = calibrationArmAt(pair_index & 1, position),
            .round = null,
            .pair_index = pair_index,
            .position = position,
        };
    }
    const measured = ordinal - warmup_attempts;
    const attempts_per_round = 2 * measured_pairs_per_round;
    const round = measured / attempts_per_round;
    const within_round = measured % attempts_per_round;
    const pair_index = within_round / 2;
    const position = within_round % 2;
    return .{
        .ordinal = ordinal,
        .phase = .calibration,
        .arm = calibrationArmAt(round & 1, position),
        .round = round,
        .pair_index = pair_index,
        .position = position,
    };
}

fn calibrationArmAt(control_first: usize, position: usize) CalibrationArm {
    return if ((control_first ^ position) == 0) .a else .a_control;
}

/// Domain-separated identity over every derived launch fact. Fixed-width
/// little-endian integers avoid JSON or allocator-dependent identity drift.
pub fn digest() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("STWC013S\x00v1");
    for (0..calibration_attempt_count) |ordinal| {
        const attempt = calibrationAttemptAt(ordinal) catch unreachable;
        hashInt(&hash, ordinal);
        hash.update(&.{
            @intFromEnum(attempt.phase),
            @intFromEnum(attempt.arm),
            @intCast(attempt.position),
        });
        hashOptionalInt(&hash, attempt.round);
        hashInt(&hash, attempt.pair_index);
    }
    var iterator = Iterator{};
    while (iterator.next()) |attempt| hashAttempt(&hash, attempt);
    hashInt(&hash, cooldown_ns);
    return hash.finalResult();
}

fn hashAttempt(hash: anytype, attempt: Attempt) void {
    hashInt(hash, attempt.ordinal);
    hashInt(hash, attempt.cell_index);
    hash.update(&.{
        @intFromEnum(attempt.shape),
        @intFromEnum(attempt.phase),
        @intFromEnum(attempt.arm),
        @intCast(attempt.position),
    });
    hashInt(hash, attempt.calls);
    hashOptionalInt(hash, attempt.round);
    hashInt(hash, attempt.pair_index);
}

fn hashOptionalInt(hash: anytype, value: ?usize) void {
    hash.update(&.{if (value == null) 0 else 1});
    hashInt(hash, value orelse 0);
}

fn hashInt(hash: anytype, value: anytype) void {
    var encoded: [8]u8 = undefined;
    std.mem.writeInt(u64, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}
