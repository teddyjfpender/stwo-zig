//! Boundary-aware direct constraints for the candidate bulk-memcpy traces.
//!
//! The original word-row evaluator is correct on a finite row slice but its
//! `next` mask is cyclic once committed as a circle-domain polynomial.  This
//! adapter preserves its row semantics while binding the main `active` column
//! to the deterministic prefix selector, terminating an active final domain
//! row, and disabling only the padding wrap edge.  It remains candidate-only;
//! no production profile imports this module.

const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const caller = @import("bulk_memcpy_caller_candidate_v1.zig");
const words = @import("bulk_memcpy_word_candidate_v1.zig");

pub const production_active = false;
pub const caller_legacy_constraint_count: usize = 176;
pub const caller_constraint_count: usize = caller_legacy_constraint_count + 1;
pub const word_legacy_constraint_count: usize = 89;
pub const word_constraint_count: usize = word_legacy_constraint_count + 2;
pub const caller_maximum_constraint_degree: u8 = 3;
pub const word_maximum_constraint_degree: u8 = 4;

pub const CallerOrder = struct {
    pub const legacy_start: usize = 0;
    pub const active_binding: usize = caller_legacy_constraint_count;
    pub const end: usize = active_binding + 1;
};

pub const WordOrder = struct {
    pub const legacy_start: usize = 0;
    pub const active_binding: usize = word_legacy_constraint_count;
    pub const terminal_domain_row: usize = active_binding + 1;
    pub const end: usize = terminal_domain_row + 1;
};

pub fn evaluateCaller(
    comptime S: type,
    main: *const [caller.main_column_count]S,
    active_prefix: S,
    sink: anytype,
) !void {
    try caller.evaluateDirect(S, main, sink);
    sink.add(main[caller.Layout.active].sub(active_prefix), 1);
}

pub fn evaluateWord(
    comptime S: type,
    current: *const [words.main_column_count]S,
    next: *const [words.main_column_count]S,
    domain_last: S,
    active_prefix: S,
    sink: anytype,
) !void {
    const zero = S.zero();
    const one = S.one();
    const active = current[words.Layout.active];
    const first = current[words.Layout.is_first];
    const last = current[words.Layout.is_last];
    const next_active = next[words.Layout.active];
    const next_first = next[words.Layout.is_first];
    const next_last = next[words.Layout.is_last];
    boolean(sink, active);
    boolean(sink, first);
    boolean(sink, last);
    boolean(sink, next_active);
    boolean(sink, next_first);
    boolean(sink, next_last);
    sink.add(first.mul(one.sub(active)), 2);
    sink.add(last.mul(one.sub(active)), 2);

    const padding = one.sub(active);
    for (current[1..]) |value| sink.add(padding.mul(value), 2);
    sink.add(padding.mul(next_active).mul(one.sub(domain_last)), 3);

    for (0..4) |index| {
        boolean(sink, current[words.Layout.mask(index)]);
        boolean(sink, current[words.Layout.startSelector(index)]);
        boolean(sink, current[words.Layout.endSelector(index)]);
    }
    sink.add(sum4(S, current, words.Layout.start_selectors).sub(active), 1);
    sink.add(sum4(S, current, words.Layout.end_selectors).sub(active), 1);

    const start = weighted4(S, current, words.Layout.start_selectors, 0);
    const end = weighted4(S, current, words.Layout.end_selectors, 1);
    sink.add(active.mul(one.sub(first)).mul(start), 3);
    sink.add(active.mul(one.sub(last)).mul(end.sub(scalar(S, 4))), 3);
    for (1..4) |start_index| for (0..start_index) |end_index| {
        sink.add(current[words.Layout.startSelector(start_index)].mul(
            current[words.Layout.endSelector(end_index)],
        ), 2);
    };
    for (0..4) |byte| {
        var starts_before = zero;
        for (0..byte + 1) |index|
            starts_before = starts_before.add(current[words.Layout.startSelector(index)]);
        var ends_after = zero;
        for (byte..4) |index|
            ends_after = ends_after.add(current[words.Layout.endSelector(index)]);
        const mask = current[words.Layout.mask(byte)];
        sink.add(mask.sub(starts_before.mul(ends_after)), 2);
        const source = current[words.Layout.sourceByte(byte)];
        const before = current[words.Layout.destinationBefore(byte)];
        const after = current[words.Layout.destinationAfter(byte)];
        sink.add(after.sub(mask.mul(source).add(one.sub(mask).mul(before))), 2);
    }

    sink.add(first.mul(current[words.Layout.word_index]), 2);
    sink.add(last.mul(
        current[words.Layout.word_index]
            .add(one)
            .sub(current[words.Layout.expected_word_count]),
    ), 2);

    const continues = active.mul(one.sub(last));
    sink.add(continues.mul(next_active.sub(one)), 3);
    sink.add(continues.mul(next_first), 3);
    sink.add(continues.mul(
        next[words.Layout.execution_clock].sub(current[words.Layout.execution_clock]),
    ), 3);
    sink.add(continues.mul(
        next[words.Layout.call_index].sub(current[words.Layout.call_index]),
    ), 3);
    sink.add(continues.mul(next[words.Layout.pc].sub(current[words.Layout.pc])), 3);
    sink.add(continues.mul(
        next[words.Layout.word_index].sub(current[words.Layout.word_index]).sub(one),
    ), 3);
    sink.add(continues.mul(
        next[words.Layout.expected_word_count]
            .sub(current[words.Layout.expected_word_count]),
    ), 3);
    sink.add(continues.mul(
        next[words.Layout.length].sub(current[words.Layout.length]),
    ), 3);
    sink.add(continues.mul(
        next[words.Layout.source_word_index]
            .sub(current[words.Layout.source_word_index])
            .sub(one),
    ), 3);
    sink.add(continues.mul(
        next[words.Layout.destination_word_index]
            .sub(current[words.Layout.destination_word_index])
            .sub(one),
    ), 3);

    // On the cyclic final domain row, `next_active` is row zero's activity.
    // Subtracting the deterministic final-row selector disables exactly that
    // edge without adding a fifth factor to the boundary constraints.
    const boundary = active.mul(last).mul(next_active.sub(domain_last));
    sink.add(boundary.mul(next_first.sub(one)), 4);
    sink.add(boundary.mul(
        next[words.Layout.call_index]
            .sub(current[words.Layout.call_index])
            .sub(one),
    ), 4);

    sink.add(active.sub(active_prefix), 1);
    sink.add(domain_last.mul(active).mul(one.sub(last)), 3);
}

fn boolean(sink: anytype, value: anytype) void {
    sink.add(value.mul(value.sub(@TypeOf(value).one())), 2);
}

fn sum4(comptime S: type, values: []const S, start: usize) S {
    var result = S.zero();
    for (0..4) |index| result = result.add(values[start + index]);
    return result;
}

fn weighted4(
    comptime S: type,
    values: []const S,
    start: usize,
    comptime offset: u32,
) S {
    var result = S.zero();
    for (0..4) |index| result = result.add(
        values[start + index].mul(scalar(S, @as(u32, @intCast(index)) + offset)),
    );
    return result;
}

fn scalar(comptime S: type, value: u32) S {
    if (comptime S == M31) return M31.fromCanonical(value);
    if (comptime S == QM31) return QM31.fromBase(M31.fromCanonical(value));
    return S.fromBase(M31.fromCanonical(value));
}

comptime {
    if (caller.production_active or words.production_active or
        caller.main_column_count != 99 or words.main_column_count != 37 or
        CallerOrder.end != caller_constraint_count or
        WordOrder.end != word_constraint_count)
    {
        @compileError("bulk memcpy boundary-aware geometry drifted");
    }
}
