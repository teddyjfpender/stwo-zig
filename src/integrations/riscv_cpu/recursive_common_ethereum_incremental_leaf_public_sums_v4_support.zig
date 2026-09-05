//! Internal fixed-program builder for the role-0 V4 public-sum lane.
//! Use `recursive_common_ethereum_incremental_leaf_public_sums_v4.zig`.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const role_io =
    @import("recursive_common_ethereum_incremental_leaf_role_aware_io_v4.zig");

pub const M31 = stwo_core.fields.m31.M31;
pub const QM31 = stwo_core.fields.qm31.QM31;
pub const arithmetic = frontend.recursion.arithmetic_circuit;
pub const graph_mod = frontend.recursion.air.composition_circuit;
pub const span = frontend.recursion.span_statement;
pub const segment_v2 = frontend.recursion.segment_statement_v2;

pub const DOMAIN_COUNT: usize = 4;
pub const PUBLISHED_VALUE_COUNT: usize = 5;
pub const SECURE_WORD_COUNT: usize = 4;
pub const PUBLISHED_WORD_COUNT: usize =
    PUBLISHED_VALUE_COUNT * SECURE_WORD_COUNT;
pub const CHALLENGE_WORD_COUNT: usize =
    DOMAIN_COUNT * 2 * SECURE_WORD_COUNT;
pub const STATEMENT_WORD_COUNT: usize = span.SPAN_STATEMENT_CANONICAL_WORDS;
pub const REGISTER_COUNT: usize = 32;
pub const CLOCK_LIMB_COUNT: usize = REGISTER_COUNT * 2 * 2;
pub const REGISTER_BYTE_COUNT: usize = REGISTER_COUNT * 2 * 4;
pub const SELECTOR_COUNT: usize = 5;

pub const Boundary = enum(u8) { entry = 0, exit = 1 };
pub const Selector = enum(u8) {
    padding = 0,
    input_memory = 1,
    output_memory = 2,
    halt_memory = 3,
    program_completion = 4,
};
pub const Domain = enum(u8) {
    registers_state = 0,
    memory_access = 1,
    program_access = 2,
    merkle = 3,
};

pub const RegisterClockCoordinateV4 = struct {
    boundary: Boundary,
    register: u5,
    limb: u1,
};

pub const RegisterByteCoordinateV4 = struct {
    boundary: Boundary,
    register: u5,
    byte: u2,
};

pub const TupleSelectorCoordinateV4 = struct {
    slot: u32,
    selector: Selector,
};

pub const PublishedValueCoordinateV4 = struct {
    value: u3,
    limb: u2,
};

pub const RelationChallengeCoordinateV4 = struct {
    domain: Domain,
    alpha: bool,
    limb: u2,
};

pub const InputSourceV4 = union(enum) {
    segment_selector,
    statement_word: u16,
    register_clock_limb: RegisterClockCoordinateV4,
    register_byte: RegisterByteCoordinateV4,
    role_io_word: u32,
    tuple_selector: TupleSelectorCoordinateV4,
    published_value_word: PublishedValueCoordinateV4,
    relation_challenge_word: RelationChallengeCoordinateV4,
};

pub const BuiltProgramV4 = struct {
    circuit: arithmetic.Circuit,
    bindings: []InputSourceV4,

    pub fn deinit(self: *BuiltProgramV4, allocator: std.mem.Allocator) void {
        allocator.free(self.bindings);
        self.circuit.deinit();
        self.* = undefined;
    }
};

const BoundRelation = struct {
    z: arithmetic.Value,
    alpha_powers: [7]arithmetic.Value,
    arity: u8,

    fn init(
        builder: *arithmetic.Builder,
        words: []const arithmetic.Value,
        arity: u8,
    ) !BoundRelation {
        if (words.len != 8 or arity == 0 or arity > 7)
            return error.InvalidPublicSumProgramV4;
        const z = try composeSecure(builder, words[0..4]);
        const alpha = try composeSecure(builder, words[4..8]);
        var powers: [7]arithmetic.Value = undefined;
        var power = arithmetic.Value.one();
        for (powers[0..arity]) |*destination| {
            destination.* = power;
            power = try builder.mul(power, alpha);
        }
        for (powers[arity..]) |*destination|
            destination.* = arithmetic.Value.zero();
        return .{ .z = z, .alpha_powers = powers, .arity = arity };
    }

    fn combine(
        self: BoundRelation,
        builder: *arithmetic.Builder,
        values: []const arithmetic.Value,
    ) !arithmetic.Value {
        if (values.len != self.arity)
            return error.InvalidPublicSumProgramV4;
        var result = arithmetic.Value.zero();
        for (values, self.alpha_powers[0..self.arity]) |value, power|
            result = try builder.add(result, try builder.mul(value, power));
        return builder.sub(result, self.z);
    }
};

const Accumulator = struct {
    builder: *arithmetic.Builder,
    relations: *const [DOMAIN_COUNT]BoundRelation,
    sums: [DOMAIN_COUNT]arithmetic.Value =
        .{arithmetic.Value.zero()} ** DOMAIN_COUNT,

    fn add(
        self: *Accumulator,
        domain: Domain,
        tuple: []const arithmetic.Value,
        sign: enum { positive, negative },
    ) !void {
        const index = @intFromEnum(domain);
        const denominator = try self.relations[index].combine(
            self.builder,
            tuple,
        );
        const inverse = try self.builder.inverse(denominator);
        self.sums[index] = switch (sign) {
            .positive => try self.builder.add(self.sums[index], inverse),
            .negative => try self.builder.sub(self.sums[index], inverse),
        };
    }

    fn addSelected(
        self: *Accumulator,
        domain: Domain,
        tuple: []const arithmetic.Value,
        signed_selector: arithmetic.Value,
        active_selector: arithmetic.Value,
    ) !void {
        const denominator = try self.relations[@intFromEnum(domain)].combine(
            self.builder,
            tuple,
        );
        const selected = try self.builder.add(
            try self.builder.mul(active_selector, denominator),
            try self.builder.sub(arithmetic.Value.one(), active_selector),
        );
        const contribution = try self.builder.mul(
            signed_selector,
            try self.builder.inverse(selected),
        );
        self.sums[@intFromEnum(domain)] = try self.builder.add(
            self.sums[@intFromEnum(domain)],
            contribution,
        );
    }
};

pub fn inputCount(tuple_capacity: u32) !usize {
    const role_words = try roleIoWordCount(tuple_capacity);
    const selectors = std.math.mul(
        usize,
        tuple_capacity,
        SELECTOR_COUNT,
    ) catch return error.ArithmeticOverflow;
    var result = 1 + STATEMENT_WORD_COUNT + CLOCK_LIMB_COUNT +
        REGISTER_BYTE_COUNT;
    result = std.math.add(usize, result, role_words) catch
        return error.ArithmeticOverflow;
    result = std.math.add(usize, result, selectors) catch
        return error.ArithmeticOverflow;
    result = std.math.add(
        usize,
        result,
        PUBLISHED_WORD_COUNT + CHALLENGE_WORD_COUNT,
    ) catch return error.ArithmeticOverflow;
    return result;
}

pub fn roleIoWordCount(tuple_capacity: u32) !usize {
    return std.math.add(
        usize,
        role_io.HEADER_WORD_COUNT,
        std.math.mul(
            usize,
            tuple_capacity,
            role_io.TUPLE_WORD_COUNT,
        ) catch return error.ArithmeticOverflow,
    ) catch return error.ArithmeticOverflow;
}

/// Builds one value-independent graph for the campaign capacity. Every leaf
/// supplies only input values; selectors, tuple metadata, active-prefix
/// ordering, public sums, and all relation denominators are constrained by the
/// same fixed operation DAG.
pub fn build(
    allocator: std.mem.Allocator,
    tuple_capacity: u32,
) !BuiltProgramV4 {
    if (tuple_capacity == 0 or !std.math.isPowerOfTwo(tuple_capacity))
        return error.InvalidPublicSumProgramV4;
    const count = try inputCount(tuple_capacity);
    var builder = arithmetic.Builder.initDefault(allocator);
    errdefer builder.deinit();
    const node_reservation = std.math.mul(usize, count, 12) catch
        return error.ArithmeticOverflow;
    const output_reservation = std.math.mul(usize, count, 3) catch
        return error.ArithmeticOverflow;
    try builder.reserve(count, node_reservation, output_reservation);
    const values = try allocator.alloc(arithmetic.Value, count);
    defer allocator.free(values);
    const bindings = try allocator.alloc(InputSourceV4, count);
    errdefer allocator.free(bindings);
    var at: usize = 0;
    const selector_start = at;
    values[at] = try builder.input(@intCast(at));
    bindings[at] = .segment_selector;
    at += 1;
    const statement_start = at;
    for (0..STATEMENT_WORD_COUNT) |index| {
        values[at] = try builder.input(@intCast(at));
        bindings[at] = .{ .statement_word = @intCast(index) };
        at += 1;
    }
    const clock_start = at;
    for (std.enums.values(Boundary)) |boundary| for (0..REGISTER_COUNT) |reg| {
        for (0..2) |limb| {
            values[at] = try builder.input(@intCast(at));
            bindings[at] = .{ .register_clock_limb = .{
                .boundary = boundary,
                .register = @intCast(reg),
                .limb = @intCast(limb),
            } };
            at += 1;
        }
    };
    const bytes_start = at;
    for (std.enums.values(Boundary)) |boundary| for (0..REGISTER_COUNT) |reg| {
        for (0..4) |byte| {
            values[at] = try builder.input(@intCast(at));
            bindings[at] = .{ .register_byte = .{
                .boundary = boundary,
                .register = @intCast(reg),
                .byte = @intCast(byte),
            } };
            at += 1;
        }
    };
    const role_start = at;
    const role_word_count = try roleIoWordCount(tuple_capacity);
    for (0..role_word_count) |index| {
        values[at] = try builder.input(@intCast(at));
        bindings[at] = .{ .role_io_word = @intCast(index) };
        at += 1;
    }
    const selectors_start = at;
    for (0..tuple_capacity) |slot| for (std.enums.values(Selector)) |selector| {
        values[at] = try builder.input(@intCast(at));
        bindings[at] = .{ .tuple_selector = .{
            .slot = @intCast(slot),
            .selector = selector,
        } };
        at += 1;
    };
    const published_start = at;
    for (0..PUBLISHED_VALUE_COUNT) |value| for (0..SECURE_WORD_COUNT) |limb| {
        values[at] = try builder.input(@intCast(at));
        bindings[at] = .{ .published_value_word = .{
            .value = @intCast(value),
            .limb = @intCast(limb),
        } };
        at += 1;
    };
    const challenges_start = at;
    for (std.enums.values(Domain)) |domain| for ([_]bool{ false, true }) |alpha| {
        for (0..SECURE_WORD_COUNT) |limb| {
            values[at] = try builder.input(@intCast(at));
            bindings[at] = .{ .relation_challenge_word = .{
                .domain = domain,
                .alpha = alpha,
                .limb = @intCast(limb),
            } };
            at += 1;
        }
    };
    std.debug.assert(at == count);

    var relations: [DOMAIN_COUNT]BoundRelation = undefined;
    const arities = [_]u8{ 2, 7, 5, 4 };
    for (&relations, arities, 0..) |*relation, arity, index|
        relation.* = try BoundRelation.init(
            &builder,
            values[challenges_start + index * 8 ..][0..8],
            arity,
        );
    var accumulator = Accumulator{ .builder = &builder, .relations = &relations };

    _ = try builder.markOutput(try builder.sub(
        values[selector_start],
        arithmetic.Value.one(),
    ));
    try constrainRoleHeader(&builder, values[role_start..], tuple_capacity);
    try addBaseTerms(
        &builder,
        &accumulator,
        values[statement_start..][0..STATEMENT_WORD_COUNT],
        values[clock_start..][0..CLOCK_LIMB_COUNT],
        values[bytes_start..][0..REGISTER_BYTE_COUNT],
    );
    try addRoleTerms(
        &builder,
        &accumulator,
        values[role_start..][0..role_word_count],
        values[selectors_start..][0 .. tuple_capacity * SELECTOR_COUNT],
        tuple_capacity,
    );

    var published: [PUBLISHED_VALUE_COUNT]arithmetic.Value = undefined;
    for (&published, 0..) |*value, index| value.* = try composeSecure(
        &builder,
        values[published_start + index * SECURE_WORD_COUNT ..][0..SECURE_WORD_COUNT],
    );
    for (accumulator.sums, published[0..DOMAIN_COUNT]) |actual, expected|
        _ = try builder.markOutput(try builder.sub(actual, expected));
    var total = arithmetic.Value.zero();
    for (accumulator.sums) |sum| total = try builder.add(total, sum);
    _ = try builder.markOutput(try builder.sub(
        total,
        published[PUBLISHED_VALUE_COUNT - 1],
    ));

    return .{ .circuit = try builder.finish(), .bindings = bindings };
}

fn constrainRoleHeader(
    builder: *arithmetic.Builder,
    role_words: []const arithmetic.Value,
    tuple_capacity: u32,
) !void {
    const constants = [_]?u32{
        role_io.STREAM_DOMAIN_WORD,
        role_io.FORMAT_VERSION,
        role_io.SCHEMA_VERSION,
        null,
        tuple_capacity,
        role_io.TUPLE_WORD_COUNT,
    };
    for (constants, 0..) |maybe, index| {
        if (maybe) |expected| {
            _ = try builder.markOutput(try builder.sub(
                role_words[index],
                base(expected),
            ));
        }
    }
}

fn addBaseTerms(
    builder: *arithmetic.Builder,
    accumulator: *Accumulator,
    statement: []const arithmetic.Value,
    clock_limbs: []const arithmetic.Value,
    register_bytes: []const arithmetic.Value,
) !void {
    const layout = span.canonical_layout;
    const entry_pc = try u32At(
        builder,
        statement,
        layout.entry_state_start + layout.machine_state_pc_start_offset,
    );
    const exit_pc = try u32At(
        builder,
        statement,
        layout.exit_state_start + layout.machine_state_pc_start_offset,
    );
    const cycle_start = try u64At(builder, statement, layout.first_cycle_start);
    const cycle_count = try u64At(
        builder,
        statement,
        layout.executed_cycle_count_start,
    );
    const cycle_end = try builder.add(cycle_start, cycle_count);
    try accumulator.add(.registers_state, &.{
        entry_pc,
        try builder.add(cycle_start, arithmetic.Value.one()),
    }, .positive);
    try accumulator.add(.registers_state, &.{
        exit_pc,
        try builder.add(cycle_end, arithmetic.Value.one()),
    }, .negative);

    for (std.enums.values(Boundary), 0..) |boundary, boundary_index| {
        const state_start = if (boundary == .entry)
            layout.entry_state_start
        else
            layout.exit_state_start;
        for (0..REGISTER_COUNT) |reg| {
            const register_at = state_start +
                layout.machine_state_registers_start_offset + reg * 2;
            const clock_at = (boundary_index * REGISTER_COUNT + reg) * 2;
            const byte_at = (boundary_index * REGISTER_COUNT + reg) * 4;
            const register_value = try u32At(builder, statement, register_at);
            const reconstructed = try bytesToU32(
                builder,
                register_bytes[byte_at..][0..4],
            );
            _ = try builder.markOutput(try builder.sub(
                register_value,
                reconstructed,
            ));
            const clock = try u32At(
                builder,
                clock_limbs,
                clock_at,
            );
            const tuple = [7]arithmetic.Value{
                base(0),
                base(reg),
                clock,
                register_bytes[byte_at],
                register_bytes[byte_at + 1],
                register_bytes[byte_at + 2],
                register_bytes[byte_at + 3],
            };
            try accumulator.add(
                .memory_access,
                &tuple,
                if (boundary == .entry) .positive else .negative,
            );
        }
    }

    const program_root = statement[layout.program_start];
    const entry_root = statement[
        layout.entry_state_start + layout.machine_state_rw_digest_start_offset
    ];
    const exit_root = statement[
        layout.exit_state_start + layout.machine_state_rw_digest_start_offset
    ];
    for ([_]arithmetic.Value{ program_root, entry_root, exit_root }) |root|
        try accumulator.add(.merkle, &.{ base(0), base(0), root, root }, .positive);
}

fn addRoleTerms(
    builder: *arithmetic.Builder,
    accumulator: *Accumulator,
    role_words: []const arithmetic.Value,
    selectors: []const arithmetic.Value,
    tuple_capacity: u32,
) !void {
    var active_count = arithmetic.Value.zero();
    var previous_padding = arithmetic.Value.zero();
    for (0..tuple_capacity) |slot| {
        const tuple_at = role_io.HEADER_WORD_COUNT +
            slot * role_io.TUPLE_WORD_COUNT;
        const words = role_words[tuple_at..][0..role_io.TUPLE_WORD_COUNT];
        const selected = selectors[slot * SELECTOR_COUNT ..][0..SELECTOR_COUNT];
        var sum = arithmetic.Value.zero();
        for (selected) |selector| {
            _ = try builder.markOutput(try builder.mul(
                selector,
                try builder.sub(selector, arithmetic.Value.one()),
            ));
            sum = try builder.add(sum, selector);
        }
        _ = try builder.markOutput(try builder.sub(sum, arithmetic.Value.one()));
        const active = try builder.sub(arithmetic.Value.one(), selected[0]);
        _ = try builder.markOutput(try builder.mul(previous_padding, active));
        previous_padding = selected[0];
        active_count = try builder.add(active_count, active);

        try constrainTupleMetadata(builder, words, selected);
        const memory = try builder.add(
            try builder.add(selected[1], selected[2]),
            selected[3],
        );
        const program = selected[4];
        var values: [role_io.MAX_RELATION_ARITY]arithmetic.Value = undefined;
        for (&values, 0..) |*value, index| value.* = try u32At(
            builder,
            words,
            4 + index * role_io.LIMBS_PER_FIELD,
        );
        _ = try builder.markOutput(try builder.mul(
            memory,
            try builder.sub(values[0], arithmetic.Value.one()),
        ));
        for (0..role_io.MAX_RELATION_ARITY) |index| {
            const used = if (index < 5)
                active
            else
                memory;
            const high = words[4 + index * 2 + 1];
            _ = try builder.markOutput(try builder.mul(
                try builder.sub(arithmetic.Value.one(), used),
                values[index],
            ));
            if (index >= 3 and index < 7)
                _ = try builder.markOutput(try builder.mul(memory, high));
        }
        const signed_memory = try builder.sub(
            selected[1],
            try builder.add(selected[2], selected[3]),
        );
        try accumulator.addSelected(
            .memory_access,
            &values,
            signed_memory,
            memory,
        );
        try accumulator.addSelected(
            .program_access,
            values[0..5],
            try builder.neg(program),
            program,
        );
    }
    _ = try builder.markOutput(try builder.sub(
        active_count,
        role_words[3],
    ));
}

fn constrainTupleMetadata(
    builder: *arithmetic.Builder,
    words: []const arithmetic.Value,
    selected: []const arithmetic.Value,
) !void {
    const kind_values = [_]u32{ 0, 1, 2, 3, 4 };
    const relation_values = [_]u32{ 0, 1, 1, 1, 2 };
    const direction_values = [_]u32{ 0, 1, 2, 2, 2 };
    const arity_values = [_]u32{ 0, 7, 7, 7, 5 };
    inline for (.{
        .{ words[0], kind_values },
        .{ words[1], relation_values },
        .{ words[2], direction_values },
        .{ words[3], arity_values },
    }) |entry| {
        var expected = arithmetic.Value.zero();
        for (selected, entry[1]) |selector, value|
            expected = try builder.add(
                expected,
                try builder.mul(selector, base(value)),
            );
        _ = try builder.markOutput(try builder.sub(entry[0], expected));
    }
}

fn bytesToU32(
    builder: *arithmetic.Builder,
    bytes: []const arithmetic.Value,
) !arithmetic.Value {
    if (bytes.len != 4) return error.InvalidPublicSumProgramV4;
    var result = arithmetic.Value.zero();
    var radix: u64 = 1;
    for (bytes) |byte| {
        result = try builder.add(result, try builder.mul(base(radix), byte));
        radix *= 256;
    }
    return result;
}

fn u32At(
    builder: *arithmetic.Builder,
    words: []const arithmetic.Value,
    index: usize,
) !arithmetic.Value {
    if (index + 2 > words.len) return error.InvalidPublicSumProgramV4;
    return builder.add(words[index], try builder.mul(base(1 << 16), words[index + 1]));
}

fn u64At(
    builder: *arithmetic.Builder,
    words: []const arithmetic.Value,
    index: usize,
) !arithmetic.Value {
    if (index + 4 > words.len) return error.InvalidPublicSumProgramV4;
    var result = arithmetic.Value.zero();
    var radix: u64 = 1;
    for (words[index..][0..4]) |word| {
        result = try builder.add(result, try builder.mul(base(radix), word));
        radix *= 1 << 16;
    }
    return result;
}

fn composeSecure(
    builder: *arithmetic.Builder,
    words: []const arithmetic.Value,
) !arithmetic.Value {
    if (words.len != 4) return error.InvalidPublicSumProgramV4;
    var result = words[0];
    inline for (1..4) |index| {
        var limbs = [_]u32{0} ** 4;
        limbs[index] = 1;
        result = try builder.add(result, try builder.mul(
            words[index],
            arithmetic.Value.fromSecure(QM31.fromU32Unchecked(
                limbs[0],
                limbs[1],
                limbs[2],
                limbs[3],
            )),
        ));
    }
    return result;
}

fn base(value: anytype) arithmetic.Value {
    return arithmetic.Value.fromBase(M31.fromU64(@as(u64, value)));
}

pub fn graphNode(source: arithmetic.Node) graph_mod.Node {
    return .{ .op = switch (source.op) {
        .input => .input,
        .constant => |words| .{ .constant = words },
        .add => |operands| .{ .add = .{
            .lhs = operands.lhs,
            .rhs = operands.rhs,
        } },
        .sub => |operands| .{ .sub = .{
            .lhs = operands.lhs,
            .rhs = operands.rhs,
        } },
        .mul => |operands| .{ .mul = .{
            .lhs = operands.lhs,
            .rhs = operands.rhs,
        } },
        .neg => |operand| .{ .neg = operand },
        .inverse => |operand| .{ .inverse = operand },
    } };
}
