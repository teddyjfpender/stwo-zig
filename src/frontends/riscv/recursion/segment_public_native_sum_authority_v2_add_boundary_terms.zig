//! Internal segment public native sum authority v2 authority shard; use segment_public_native_sum_authority_v2.zig publicly.

const dependency_0 = @import("segment_public_native_sum_authority_v2_contract.zig");

const AuthoredGraph = dependency_0.AuthoredGraph;
const CHALLENGE_WORD_COUNT = dependency_0.CHALLENGE_WORD_COUNT;
const DOMAIN_COUNT = dependency_0.DOMAIN_COUNT;
const Error = dependency_0.Error;
const INPUT_SUFFIX_WORD_COUNT = dependency_0.INPUT_SUFFIX_WORD_COUNT;
const InputSourceV2 = dependency_0.InputSourceV2;
const OUTPUT_COUNT = dependency_0.OUTPUT_COUNT;
const QM31 = dependency_0.QM31;
const RelationAccumulator = dependency_0.RelationAccumulator;
const TermCountsV2 = dependency_0.TermCountsV2;
const addContinuationCompensation = dependency_0.addContinuationCompensation;
const addSparseMemoryTerms = dependency_0.addSparseMemoryTerms;
const arithmetic = dependency_0.arithmetic;
const baseU32 = dependency_0.baseU32;
const baseU64 = dependency_0.baseU64;
const baseValue = dependency_0.baseValue;
const bindGraphInputs = dependency_0.bindGraphInputs;
const checkedAdd = dependency_0.checkedAdd;
const fixedU32 = dependency_0.fixedU32;
const graph_mod = dependency_0.graph_mod;
const nextMemoryAddress = dependency_0.nextMemoryAddress;
const program_decode = dependency_0.program_decode;
const public_source = dependency_0.public_source;
const span_statement = dependency_0.span_statement;
const std = dependency_0.std;
const wire_statement = dependency_0.wire_statement;

pub fn buildGraph(
    allocator: std.mem.Allocator,
    view: *const wire_statement.CanonicalWireViewV2,
) Error!AuthoredGraph {
    const input_count = try checkedAdd(view.words.len, INPUT_SUFFIX_WORD_COUNT);
    var builder = arithmetic.Builder.initDefault(allocator);
    errdefer builder.deinit();
    // Inputs are declared before the first operation, making input node IDs
    // exactly equal to their source coordinates.
    try builder.reserve(input_count, input_count, OUTPUT_COUNT);
    const values = try allocator.alloc(arithmetic.Value, input_count);
    defer allocator.free(values);
    for (values, 0..) |*value, index|
        value.* = try builder.input(@intCast(index));

    const graph_inputs = try bindGraphInputs(&builder, values, view.words.len);
    var accumulator = RelationAccumulator{
        .builder = &builder,
        .relations = &graph_inputs.relations,
    };
    try addBoundaryTerms(&accumulator, view, graph_inputs.wire);

    for (0..DOMAIN_COUNT) |index| {
        _ = try builder.markOutput(try builder.sub(
            accumulator.sums[index],
            graph_inputs.published_sums[index],
        ));
    }
    var total = arithmetic.Value.zero();
    for (accumulator.sums) |sum| total = try builder.add(total, sum);
    _ = try builder.markOutput(try builder.sub(
        total,
        graph_inputs.published_total,
    ));
    return .{
        .circuit = try builder.finish(),
        .term_counts = accumulator.counts,
    };
}

pub fn addBoundaryTerms(
    accumulator: *RelationAccumulator,
    view: *const wire_statement.CanonicalWireViewV2,
    wire: []const arithmetic.Value,
) Error!void {
    const base = try view.statement.base();
    const executed = switch (base.body) {
        .empty => return error.InvalidAuthenticatedTopology,
        .executed => |value| value,
    };
    if (executed.segment_count != 1 or base.slots.height != 0)
        return error.InvalidAuthenticatedTopology;

    const entry_pc = try baseU32(
        accumulator.builder,
        wire,
        span_statement.canonical_layout.entry_state_start +
            span_statement.canonical_layout.machine_state_pc_start_offset,
    );
    const exit_pc = try baseU32(
        accumulator.builder,
        wire,
        span_statement.canonical_layout.exit_state_start +
            span_statement.canonical_layout.machine_state_pc_start_offset,
    );
    const cycle_start = try baseU64(
        accumulator.builder,
        wire,
        span_statement.canonical_layout.first_cycle_start,
    );
    const cycle_count = try baseU64(
        accumulator.builder,
        wire,
        span_statement.canonical_layout.executed_cycle_count_start,
    );
    const cycle_end = try accumulator.builder.add(cycle_start, cycle_count);
    try accumulator.add(.registers_state, &.{
        entry_pc,
        try accumulator.builder.add(cycle_start, arithmetic.Value.one()),
    }, .positive);
    try accumulator.add(.registers_state, &.{
        exit_pc,
        try accumulator.builder.add(cycle_end, arithmetic.Value.one()),
    }, .negative);

    for (0..32) |register| {
        const entry_value = executed.entry.registers[register];
        const exit_value = executed.exit.registers[register];
        const entry_clock = try fixedU32(
            accumulator.builder,
            wire,
            wire_statement.fixed_layout.entry_register_clocks + register * 2,
        );
        const exit_clock = try fixedU32(
            accumulator.builder,
            wire,
            wire_statement.fixed_layout.exit_register_clocks + register * 2,
        );
        try accumulator.add(.memory_access, &.{
            baseValue(0),
            baseValue(@as(u32, @intCast(register))),
            entry_clock,
            baseValue(@as(u8, @truncate(entry_value))),
            baseValue(@as(u8, @truncate(entry_value >> 8))),
            baseValue(@as(u8, @truncate(entry_value >> 16))),
            baseValue(@as(u8, @truncate(entry_value >> 24))),
        }, .positive);
        try accumulator.add(.memory_access, &.{
            baseValue(0),
            baseValue(@as(u32, @intCast(register))),
            exit_clock,
            baseValue(@as(u8, @truncate(exit_value))),
            baseValue(@as(u8, @truncate(exit_value >> 8))),
            baseValue(@as(u8, @truncate(exit_value >> 16))),
            baseValue(@as(u8, @truncate(exit_value >> 24))),
        }, .negative);
    }

    try addSparseMemoryTerms(accumulator, view, wire);

    const program_root_index = wire_statement.fixed_layout.base_statement +
        span_statement.canonical_layout.program_start;
    const entry_root = try fixedU32(
        accumulator.builder,
        wire,
        wire_statement.fixed_layout.entry_continuation_root,
    );
    const exit_root = try fixedU32(
        accumulator.builder,
        wire,
        wire_statement.fixed_layout.exit_continuation_root,
    );
    try accumulator.add(.merkle, &.{
        baseValue(0),             baseValue(0), wire[program_root_index],
        wire[program_root_index],
    }, .positive);
    try accumulator.add(.merkle, &.{
        baseValue(0), baseValue(0), entry_root, entry_root,
    }, .positive);
    try accumulator.add(.merkle, &.{
        baseValue(0), baseValue(0), exit_root, exit_root,
    }, .positive);
    try addContinuationCompensation(
        accumulator,
        view,
        wire,
        view.entry_snapshot,
        entry_root,
    );
    try addContinuationCompensation(
        accumulator,
        view,
        wire,
        view.exit_snapshot,
        exit_root,
    );

    if (view.statement.completion) |completion| {
        if (completion.kind == .unretired_self_loop) {
            const decoded = program_decode.decodeProgramWord(completion.value) catch
                unreachable;
            const address = try fixedU32(
                accumulator.builder,
                wire,
                wire_statement.fixed_layout.completion + 2,
            );
            try accumulator.add(.program_access, &.{
                address,
                baseValue(decoded[0]),
                baseValue(decoded[1]),
                baseValue(decoded[2]),
                baseValue(decoded[3]),
            }, .negative);
        }
    }
}

pub fn countTerms(
    view: *const wire_statement.CanonicalWireViewV2,
) Error!TermCountsV2 {
    var memory_addresses: u32 = 0;
    var positions = [_]usize{0} ** 4;
    while (nextMemoryAddress(view, positions)) |address| {
        if (positions[0] < view.entry_snapshot.count and
            view.sparseEntry(view.entry_snapshot, positions[0]).address == address)
            positions[0] += 1;
        if (positions[1] < view.exit_snapshot.count and
            view.sparseEntry(view.exit_snapshot, positions[1]).address == address)
            positions[1] += 1;
        if (positions[2] < view.entry_memory_clocks.count and
            view.clockEntry(view.entry_memory_clocks, positions[2]).address == address)
            positions[2] += 1;
        if (positions[3] < view.exit_memory_clocks.count and
            view.clockEntry(view.exit_memory_clocks, positions[3]).address == address)
            positions[3] += 1;
        memory_addresses = std.math.add(u32, memory_addresses, 1) catch
            return error.ArithmeticOverflow;
    }
    var merkle: u32 = 3;
    inline for (.{ view.entry_snapshot, view.exit_snapshot }) |section| {
        if (section.count == 0) {
            merkle = try checkedAddU32(merkle, 1);
        } else {
            for (0..section.count) |index| {
                const value = view.sparseEntry(section, index).value;
                for (0..4) |limb| {
                    const shift: u5 = @intCast(limb * 8);
                    merkle = try checkedAddU32(
                        merkle,
                        @intFromBool(@as(u8, @truncate(value >> shift)) != 0),
                    );
                }
            }
        }
    }
    return .{
        .registers_state = 2,
        .memory_access = try checkedAddU32(
            64,
            try checkedMulU32(memory_addresses, 2),
        ),
        .program_access = @intFromBool(
            view.statement.completion != null and
                view.statement.completion.?.kind == .unretired_self_loop,
        ),
        .merkle = merkle,
    };
}

pub fn authenticatedView(
    prepared: *const public_source.PreparedV2,
    inputs: public_source.InputsV2,
) Error!wire_statement.CanonicalWireViewV2 {
    try inputs.owned_public_data.validate();
    const view = try wire_statement.authenticateCanonicalWire(
        inputs.owned_public_data.data.words(),
    );
    if (!std.meta.eql(view.wire_id, prepared.wire_id) or
        !std.meta.eql(view.wire_id, inputs.owned_public_data.data.wireId()))
    {
        return error.ArithmeticAuthorityMismatch;
    }
    return view;
}

pub fn inputSource(
    wire_count: u32,
    input_index: usize,
) Error!InputSourceV2 {
    if (input_index < wire_count)
        return .{ .wire_word = @intCast(input_index) };
    var suffix = input_index - wire_count;
    if (suffix < DOMAIN_COUNT * 4) {
        return .{ .published_sum_word = .{
            .domain = @enumFromInt(suffix / 4),
            .limb = @intCast(suffix % 4),
            .publication_index = @intCast(
                public_source.PUBLICATION_SUM_START + suffix,
            ),
        } };
    }
    suffix -= DOMAIN_COUNT * 4;
    if (suffix < 4) return .{ .published_total_word = .{
        .limb = @intCast(suffix),
        .publication_index = @intCast(
            public_source.PUBLICATION_SEAL_START + suffix,
        ),
    } };
    suffix -= 4;
    if (suffix < CHALLENGE_WORD_COUNT) {
        return .{ .native_challenge_word = .{
            .relation = @enumFromInt(suffix / 8),
            .limb = @intCast(suffix % 8),
        } };
    }
    return error.InputBindingMismatch;
}

pub fn fillInputValues(
    prepared: *const public_source.PreparedV2,
    inputs: public_source.InputsV2,
    destination: []QM31,
) void {
    var at: usize = 0;
    for (inputs.owned_public_data.data.words()) |word| {
        destination[at] = QM31.fromBase(word);
        at += 1;
    }
    inline for (.{
        prepared.public_sums.registers_state,
        prepared.public_sums.memory_access,
        prepared.public_sums.program_access,
        prepared.public_sums.merkle,
        prepared.public_total,
    }) |value| {
        for (value.toM31Array()) |word| {
            destination[at] = QM31.fromBase(word);
            at += 1;
        }
    }
    inline for (.{
        .{ inputs.relations.registers_state.z, inputs.relations.registers_state.alpha },
        .{ inputs.relations.memory_access.z, inputs.relations.memory_access.alpha },
        .{ inputs.relations.program_access.z, inputs.relations.program_access.alpha },
        .{ inputs.relations.merkle.z, inputs.relations.merkle.alpha },
    }) |pair| {
        inline for (pair) |value| for (value.toM31Array()) |word| {
            destination[at] = QM31.fromBase(word);
            at += 1;
        };
    }
    std.debug.assert(at == destination.len);
}

pub fn overlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}

pub fn nodeEql(graph: graph_mod.Node, circuit: arithmetic.Node) bool {
    return switch (graph.op) {
        .input => circuit.op == .input,
        .constant => |left| switch (circuit.op) {
            .constant => |right| std.meta.eql(left, right),
            else => false,
        },
        .add => |left| switch (circuit.op) {
            .add => |right| left.lhs == right.lhs and left.rhs == right.rhs,
            else => false,
        },
        .sub => |left| switch (circuit.op) {
            .sub => |right| left.lhs == right.lhs and left.rhs == right.rhs,
            else => false,
        },
        .mul => |left| switch (circuit.op) {
            .mul => |right| left.lhs == right.lhs and left.rhs == right.rhs,
            else => false,
        },
        .neg => |left| switch (circuit.op) {
            .neg => |right| left == right,
            else => false,
        },
        .inverse => |left| switch (circuit.op) {
            .inverse => |right| left == right,
            else => false,
        },
    };
}

pub fn hashDigest(
    hash: *std.crypto.hash.sha2.Sha256,
    value: public_source.Digest,
) void {
    for (value) |word| hashInt(hash, u32, word);
}

pub fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

pub fn checkedAddU32(left: u32, right: anytype) Error!u32 {
    return std.math.add(u32, left, @intCast(right)) catch
        error.ArithmeticOverflow;
}

pub fn checkedMulU32(left: u32, right: u32) Error!u32 {
    return std.math.mul(u32, left, right) catch error.ArithmeticOverflow;
}
