//! Exact and mutation-complete evidence for the pure C-009 direct AIR.

const std = @import("std");
const fields = @import("stwo_core").fields;
const m31 = fields.m31;
const M31 = m31.M31;
const QM31 = fields.qm31.QM31;
const poseidon2_air = @import("../memory_commitment/poseidon2_air.zig");
const components = @import("component_registry.zig");
const main_trace = @import("main_trace.zig");
const support = @import("main_trace_test_support.zig");
const statement_mod = @import("statement.zig");
const subject = @import("direct_constraints.zig");

fn q(value: anytype) QM31 {
    return QM31.fromBase(M31.fromU64(@as(u64, value)));
}

fn generatedMain(count: u32) !main_trace.Result {
    var core = support.coreFixture(count);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, count);
    var logs = try support.logsFixture(std.testing.allocator, count);
    defer logs.deinit();
    return main_trace.generate(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
}

fn callerRow(
    trace: *const main_trace.Result,
    logical_row: usize,
) [subject.caller_main_column_count]QM31 {
    const row = main_trace.committedRow(logical_row, trace.log_size);
    var result: [subject.caller_main_column_count]QM31 = undefined;
    for (&result, 0..) |*value, column| {
        value.* = QM31.fromBase(trace.callerMain(column)[row]);
    }
    return result;
}

fn providerRow(
    trace: *const main_trace.Result,
    logical_row: usize,
) [subject.provider_main_column_count]QM31 {
    const row = main_trace.committedRow(logical_row, trace.log_size);
    var result: [subject.provider_main_column_count]QM31 = undefined;
    for (&result, 0..) |*value, column| {
        value.* = QM31.fromBase(trace.providerMain(column)[row]);
    }
    return result;
}

fn callerActivity(trace: *const main_trace.Result, logical_row: usize) QM31 {
    const row = main_trace.committedRow(logical_row, trace.log_size);
    return QM31.fromBase(trace.callerPreprocessed(1)[row]);
}

fn providerActivity(trace: *const main_trace.Result, logical_row: usize) QM31 {
    const row = main_trace.committedRow(logical_row, trace.log_size);
    return QM31.fromBase(trace.providerPreprocessed(1)[row]);
}

fn expectAllZero(values: anytype) !void {
    for (values) |value| try std.testing.expect(value.isZero());
}

fn expectAnyNonzero(values: anytype) !void {
    for (values) |value| if (!value.isZero()) return;
    return error.TestExpectedNonZero;
}

fn addOne(value: QM31) QM31 {
    return value.add(QM31.one());
}

fn wordByteStart(output: bool, lane: u8) usize {
    return if (output)
        components.caller_layout.outputByte(lane, 0)
    else
        components.caller_layout.inputByte(lane, 0);
}

fn setWord(
    row: *[subject.caller_main_column_count]QM31,
    output: bool,
    lane: u8,
    word: u32,
) void {
    const start = wordByteStart(output, lane);
    inline for (0..4) |byte| {
        row[start + byte] = q((word >> @intCast(byte * 8)) & 0xff);
    }
    const b0 = M31.fromCanonical(word & 0xff);
    const b1 = M31.fromCanonical((word >> 8) & 0xff);
    const b2 = M31.fromCanonical((word >> 16) & 0xff);
    const b3 = M31.fromCanonical((word >> 24) & 0xff);
    const d0 = b0.sub(M31.fromCanonical(255));
    const d1 = b1.sub(M31.fromCanonical(255));
    const d2 = b2.sub(M31.fromCanonical(255));
    const d3 = b3.sub(M31.fromCanonical(127));
    const s0 = d0.square().add(d1.square());
    const s1 = d2.square().add(d3.square());
    const nz = s0.square().add(s1.square());
    const values = [4]M31{
        s0,
        s1,
        nz,
        if (nz.isZero()) M31.zero() else nz.invUncheckedNonZero(),
    };
    for (values, 0..) |value, part| {
        row[
            components.caller_layout.canonicalMaterialization(
                output,
                lane,
                @intCast(part),
            )
        ] = QM31.fromBase(value);
    }
}

fn expectWordGadgetZero(
    constraints: [subject.caller_constraint_count]QM31,
    output: bool,
    lane: u8,
) !void {
    inline for (std.meta.tags(subject.CanonicalPart)) |part| {
        try std.testing.expect(constraints[
            subject.CallerOrder.canonical(output, lane, part)
        ].isZero());
    }
}

fn setPointerGeometry(
    row: *[subject.caller_main_column_count]QM31,
    pointer: u32,
) void {
    const layout = components.caller_layout;
    inline for (0..4) |byte| {
        row[layout.pointer_bytes + byte] = q(
            (pointer >> @intCast(byte * 8)) & 0xff,
        );
    }
    const word_index = pointer / 4;
    row[layout.pointer_word_index] = q(word_index);
    const span = word_index + 15;
    inline for (0..4) |byte| {
        row[layout.span_end_limbs + byte] = q(
            (span >> @intCast(byte * 8)) & 0xff,
        );
    }
}

fn pointerRangePremise(pointer: u32) bool {
    const word_index = pointer / 4;
    const span = word_index + 15;
    return pointer & 3 == 0 and
        ((pointer >> 24) & 0xff) < 64 and
        ((span >> 24) & 0xff) < 16;
}

test "guest direct AIR accepts every honest C-007 active and padding row" {
    var trace = try generatedMain(2);
    defer trace.deinit();
    for (0..trace.domainSize()) |logical_row| {
        try expectAllZero(subject.evaluateCaller(
            callerRow(&trace, logical_row),
            callerActivity(&trace, logical_row),
        ));
        try expectAllZero(subject.evaluateProvider(
            providerRow(&trace, logical_row),
            providerActivity(&trace, logical_row),
        ));
    }
}

test "guest direct AIR zero-call components are canonical all-zero padding" {
    var trace = try generatedMain(0);
    defer trace.deinit();
    try std.testing.expectEqual(@as(usize, 16), trace.domainSize());
    for (0..trace.domainSize()) |logical_row| {
        try expectAllZero(subject.evaluateCaller(
            callerRow(&trace, logical_row),
            callerActivity(&trace, logical_row),
        ));
        try expectAllZero(subject.evaluateProvider(
            providerRow(&trace, logical_row),
            providerActivity(&trace, logical_row),
        ));
    }
}

test "guest direct AIR: caller pins selector and every non-enabler padding cell" {
    var trace = try generatedMain(1);
    defer trace.deinit();
    const active = callerRow(&trace, 0);

    var non_boolean = active;
    non_boolean[components.caller_layout.enabler] = q(2);
    const boolean_constraints = subject.evaluateCaller(non_boolean, QM31.one());
    try std.testing.expect(!boolean_constraints[
        subject.CallerOrder.enabler_boolean
    ].isZero());

    var detached = active;
    detached[components.caller_layout.enabler] = QM31.zero();
    const detached_constraints = subject.evaluateCaller(detached, QM31.one());
    try std.testing.expect(!detached_constraints[
        subject.CallerOrder.enabler_activity
    ].isZero());

    const padding = callerRow(&trace, 1);
    for (1..subject.caller_main_column_count) |column| {
        var mutated = padding;
        mutated[column] = QM31.one();
        const constraints = subject.evaluateCaller(mutated, QM31.zero());
        try std.testing.expect(!constraints[
            subject.CallerOrder.padding(column)
        ].isZero());
    }
}

test "guest direct AIR: caller pointer equations reject alignment and span mutations" {
    var trace = try generatedMain(1);
    defer trace.deinit();
    const active = callerRow(&trace, 0);
    const layout = components.caller_layout;

    var misaligned = active;
    misaligned[layout.pointer_bytes] = addOne(misaligned[layout.pointer_bytes]);
    var constraints = subject.evaluateCaller(misaligned, QM31.one());
    try std.testing.expect(!constraints[
        subject.CallerOrder.pointer_composition
    ].isZero());

    var wrong_word_index = active;
    wrong_word_index[layout.pointer_word_index] =
        addOne(wrong_word_index[layout.pointer_word_index]);
    constraints = subject.evaluateCaller(wrong_word_index, QM31.one());
    try std.testing.expect(!constraints[
        subject.CallerOrder.pointer_composition
    ].isZero());
    try std.testing.expect(!constraints[subject.CallerOrder.pointer_span].isZero());

    var wrong_span = active;
    wrong_span[layout.span_end_limbs + 2] =
        addOne(wrong_span[layout.span_end_limbs + 2]);
    constraints = subject.evaluateCaller(wrong_span, QM31.one());
    try std.testing.expect(!constraints[subject.CallerOrder.pointer_span].isZero());

    // The degree-one equalities and the authenticated 8/8/8/4 request are a
    // joint proof.  A self-consistent wrapped u32 satisfies the equalities but
    // violates both high-limb table premises; silently claiming otherwise
    // would exceed degree three.
    const wrapped: u32 = std.math.maxInt(u32) - 3;
    var wrapped_row = active;
    setPointerGeometry(&wrapped_row, wrapped);
    constraints = subject.evaluateCaller(wrapped_row, QM31.one());
    try std.testing.expect(constraints[
        subject.CallerOrder.pointer_composition
    ].isZero());
    try std.testing.expect(constraints[subject.CallerOrder.pointer_span].isZero());
    try std.testing.expect(!pointerRangePremise(wrapped));
    try std.testing.expect(pointerRangePremise(0x2000));

    wrapped_row[layout.span_end_limbs + 3] = QM31.zero();
    constraints = subject.evaluateCaller(wrapped_row, QM31.one());
    try std.testing.expect(!constraints[subject.CallerOrder.pointer_span].isZero());
}

test "guest direct AIR: all 32 caller word gadgets bind every byte and materialization" {
    var trace = try generatedMain(1);
    defer trace.deinit();
    const active = callerRow(&trace, 0);
    for (0..subject.canonical_word_count) |word| {
        const output = word >= 16;
        const lane: u8 = @intCast(word % 16);
        for (0..4) |byte| {
            var mutated = active;
            const column = wordByteStart(output, lane) + byte;
            mutated[column] = addOne(mutated[column]);
            const constraints = subject.evaluateCaller(mutated, QM31.one());
            const part: subject.CanonicalPart = if (byte < 2) .s0 else .s1;
            try std.testing.expect(!constraints[
                subject.CallerOrder.canonical(output, lane, part)
            ].isZero());
        }
        for (std.meta.tags(subject.CanonicalPart), 0..) |part, value| {
            var mutated = active;
            const column = components.caller_layout.canonicalMaterialization(
                output,
                lane,
                @intCast(value),
            );
            mutated[column] = addOne(mutated[column]);
            const constraints = subject.evaluateCaller(mutated, QM31.one());
            try std.testing.expect(!constraints[
                subject.CallerOrder.canonical(output, lane, part)
            ].isZero());
        }
    }
}

test "guest direct AIR: canonical boundary closes p and exposes high-bit premises" {
    var trace = try generatedMain(1);
    defer trace.deinit();
    const honest = callerRow(&trace, 0);

    for ([_]u32{ 0, 1, m31.Modulus - 1 }) |word| {
        var row = honest;
        setWord(&row, false, 0, word);
        try expectWordGadgetZero(
            subject.evaluateCaller(row, QM31.one()),
            false,
            0,
        );
    }

    var modulus_row = honest;
    setWord(&modulus_row, false, 0, m31.Modulus);
    const modulus_constraints = subject.evaluateCaller(modulus_row, QM31.one());
    try std.testing.expect(!modulus_constraints[
        subject.CallerOrder.canonical(false, 0, .inverse)
    ].isZero());
    try std.testing.expectEqual(@as(u32, 127), m31.Modulus >> 24);

    // These values are rejected by range_check_m31(0,b3): their direct nz
    // witnesses are intentionally satisfiable because b3<128 is the gadget's
    // authenticated premise, not a hidden high-degree direct constraint.
    for ([_]u32{
        m31.Modulus + 1,
        2 * m31.Modulus,
        std.math.maxInt(u32),
    }) |word| {
        var row = honest;
        setWord(&row, true, 15, word);
        const constraints = subject.evaluateCaller(row, QM31.one());
        try expectWordGadgetZero(constraints, true, 15);
        try std.testing.expect(((word >> 24) & 0xff) >= 128);
    }

    try std.testing.expectEqual(@as(u32, 3), m31.Modulus % 4);
    const minus_one = M31.one().neg();
    try std.testing.expect(minus_one.pow((m31.Modulus - 1) / 2).eql(minus_one));
}

test "guest direct AIR: provider binds modes and every nonmode padding cell" {
    var trace = try generatedMain(1);
    defer trace.deinit();
    const active = providerRow(&trace, 0);

    var detached = active;
    detached[0] = QM31.zero();
    var constraints = subject.evaluateProvider(detached, QM31.one());
    try std.testing.expect(!constraints[
        subject.ProviderOrder.enabler_activity
    ].isZero());

    var wrong_io = active;
    wrong_io[subject.provider_main_column_count - 1] = QM31.zero();
    constraints = subject.evaluateProvider(wrong_io, QM31.one());
    try std.testing.expect(!constraints[subject.ProviderOrder.io_activity].isZero());

    var wide = active;
    wide[subject.provider_main_column_count - 2] = QM31.one();
    constraints = subject.evaluateProvider(wide, QM31.one());
    try std.testing.expect(!constraints[subject.ProviderOrder.wide_zero].isZero());

    // Guest active rows are atomic IO rows.  The legacy Merkle narrow shell
    // rejects this honest mode, while the dedicated provider evaluator does not.
    try std.testing.expect(!poseidon2_air.narrowModeConstraints(active)[1].isZero());
    try expectAllZero(subject.evaluateProvider(active, QM31.one()));

    const padding = providerRow(&trace, 1);
    for (1..subject.provider_main_column_count - 2) |column| {
        var mutated = padding;
        mutated[column] = QM31.one();
        constraints = subject.evaluateProvider(mutated, QM31.zero());
        try std.testing.expect(!constraints[
            subject.ProviderOrder.padding(column)
        ].isZero());
    }
    var padding_enabler = padding;
    padding_enabler[0] = QM31.one();
    try std.testing.expect(!subject.evaluateProvider(
        padding_enabler,
        QM31.zero(),
    )[subject.ProviderOrder.enabler_activity].isZero());
    var padding_wide = padding;
    padding_wide[subject.provider_main_column_count - 2] = QM31.one();
    try std.testing.expect(!subject.evaluateProvider(
        padding_wide,
        QM31.zero(),
    )[subject.ProviderOrder.wide_zero].isZero());
    var padding_io = padding;
    padding_io[subject.provider_main_column_count - 1] = QM31.one();
    try std.testing.expect(!subject.evaluateProvider(
        padding_io,
        QM31.zero(),
    )[subject.ProviderOrder.io_activity].isZero());
}

test "guest direct AIR: provider Poseidon rejects every input and temporary mutation" {
    var trace = try generatedMain(1);
    defer trace.deinit();
    const active = providerRow(&trace, 0);
    for (1..subject.provider_main_column_count - 2) |column| {
        var mutated = active;
        mutated[column] = addOne(mutated[column]);
        const constraints = subject.evaluateProvider(mutated, QM31.one());
        try expectAnyNonzero(
            constraints[0..subject.provider_poseidon_constraint_count],
        );
    }
    // Pin both ends of the carried output segment, temporaries 410..425.
    inline for (.{ 427, 442 }) |column| {
        var mutated = active;
        mutated[column] = addOne(mutated[column]);
        const constraints = subject.evaluateProvider(mutated, QM31.one());
        try expectAnyNonzero(
            constraints[0..subject.provider_poseidon_constraint_count],
        );
    }
}

test "guest direct AIR: evaluators preserve full secure-field point values" {
    const extension_value = QM31.fromU32Unchecked(3, 5, 7, 11);
    var caller = [_]QM31{QM31.zero()} ** subject.caller_main_column_count;
    caller[components.caller_layout.execution_clock] = extension_value;
    const caller_constraints = subject.evaluateCaller(caller, QM31.zero());
    try std.testing.expect(caller_constraints[
        subject.CallerOrder.padding(components.caller_layout.execution_clock)
    ].eql(extension_value));

    var provider = [_]QM31{QM31.zero()} ** subject.provider_main_column_count;
    provider[1] = extension_value;
    const provider_constraints = subject.evaluateProvider(provider, QM31.zero());
    try std.testing.expect(provider_constraints[
        subject.ProviderOrder.padding(1)
    ].eql(extension_value));
}

test "guest direct AIR: constraint counts order and algebraic degree are pinned" {
    try std.testing.expectEqual(@as(usize, 417), subject.caller_constraint_count);
    try std.testing.expectEqual(@as(usize, 875), subject.provider_constraint_count);
    try std.testing.expectEqual(@as(usize, 287), subject.CallerOrder.pointer_composition);
    try std.testing.expectEqual(@as(usize, 288), subject.CallerOrder.pointer_span);
    try std.testing.expectEqual(@as(usize, 289), subject.CallerOrder.canonical_start);
    try std.testing.expectEqual(@as(usize, 416), subject.CallerOrder.canonical(
        true,
        15,
        .inverse,
    ));
    try std.testing.expectEqual(@as(usize, 430), subject.ProviderOrder.enabler_activity);
    try std.testing.expectEqual(@as(usize, 433), subject.ProviderOrder.padding_start);
    try std.testing.expectEqual(@as(usize, 874), subject.ProviderOrder.padding(442));

    var caller_maximum: u8 = 0;
    for (0..subject.caller_constraint_count) |index| {
        caller_maximum = @max(
            caller_maximum,
            subject.callerConstraintDegreeBound(index),
        );
    }
    var provider_maximum: u8 = 0;
    for (0..subject.provider_constraint_count) |index| {
        provider_maximum = @max(
            provider_maximum,
            subject.providerConstraintDegreeBound(index),
        );
    }
    try std.testing.expectEqual(subject.maximum_constraint_degree, caller_maximum);
    try std.testing.expectEqual(subject.maximum_constraint_degree, provider_maximum);
    try std.testing.expectEqual(
        components.CallerConstraintIdentity.canonical().maximum_constraint_degree,
        caller_maximum,
    );
    try std.testing.expectEqual(
        components.ProviderCompatibilityIdentity.canonical().maximum_constraint_degree,
        provider_maximum,
    );
}
