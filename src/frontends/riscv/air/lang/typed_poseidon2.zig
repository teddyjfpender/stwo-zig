//! Pure typed-AIR definition of the pinned width-16 Poseidon2-M31 permutation.
//!
//! This module describes only field semantics. It allocates no witness columns,
//! emits no constraints or effects, and makes no materialization decisions.
//! Later compiler passes may therefore choose a reviewed physical layout while
//! this expression graph remains the single semantic definition.
//!
//! Round constants and the internal diagonal are imported from the production
//! Stark-V compatibility authority. Keeping that file as the only numeric
//! authority prevents a typed implementation and the shipped permutation from
//! drifting together behind duplicated constants.

const m31 = @import("stwo_core").fields.m31;
const constants = @import("../memory_commitment/poseidon2_constants.zig");
const collections = @import("static_collections.zig");
const functions = @import("functions.zig");
const ir = @import("ir.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const WIDTH: usize = 16;
pub const N_EXTERNAL_ROUNDS_FIRST: usize = 4;
pub const N_INTERNAL_ROUNDS: usize = constants.INTERNAL_ROUND.len;
pub const N_EXTERNAL_ROUNDS_LAST: usize = 4;
pub const N_EXTERNAL_ROUNDS: usize = constants.EXTERNAL_ROUND.len;
pub const N_NONLINEAR_ROUNDS: usize =
    N_EXTERNAL_ROUNDS + N_INTERNAL_ROUNDS;

/// Formal degree of an output in the unmaterialized expression graph.
///
/// This is intentionally much larger than the protocol budget. H-003 inserts
/// deterministic degree-reduction boundaries without changing this meaning.
pub const UNMATERIALIZED_OUTPUT_DEGREE: u64 = blk: {
    var result: u64 = 1;
    for (0..N_NONLINEAR_ROUNDS) |_| result *= 5;
    break :blk result;
};

pub const function_name = "riscv.poseidon2_m31.permute.v1";

pub const input_names: [WIDTH][]const u8 = .{
    "riscv.poseidon2_m31.input.00",
    "riscv.poseidon2_m31.input.01",
    "riscv.poseidon2_m31.input.02",
    "riscv.poseidon2_m31.input.03",
    "riscv.poseidon2_m31.input.04",
    "riscv.poseidon2_m31.input.05",
    "riscv.poseidon2_m31.input.06",
    "riscv.poseidon2_m31.input.07",
    "riscv.poseidon2_m31.input.08",
    "riscv.poseidon2_m31.input.09",
    "riscv.poseidon2_m31.input.10",
    "riscv.poseidon2_m31.input.11",
    "riscv.poseidon2_m31.input.12",
    "riscv.poseidon2_m31.input.13",
    "riscv.poseidon2_m31.input.14",
    "riscv.poseidon2_m31.input.15",
};

pub const State = collections.StaticArray(.felt, WIDTH);

pub const ExternalRoundSpans = struct {
    constants: source.SourceSpan,
    sbox: source.SourceSpan,
    linear: source.SourceSpan,

    pub fn uniform(span: source.SourceSpan) ExternalRoundSpans {
        return .{ .constants = span, .sbox = span, .linear = span };
    }

    fn validate(self: ExternalRoundSpans, arena: *const ir.Arena) !void {
        try arena.validateSpan(self.constants);
        try arena.validateSpan(self.sbox);
        try arena.validateSpan(self.linear);
    }
};

pub const InternalRoundSpans = struct {
    constant: source.SourceSpan,
    sbox: source.SourceSpan,
    linear: source.SourceSpan,

    pub fn uniform(span: source.SourceSpan) InternalRoundSpans {
        return .{ .constant = span, .sbox = span, .linear = span };
    }

    fn validate(self: InternalRoundSpans, arena: *const ir.Arena) !void {
        try arena.validateSpan(self.constant);
        try arena.validateSpan(self.sbox);
        try arena.validateSpan(self.linear);
    }
};

/// Source sites for every semantic stage of the statically unrolled body.
/// The table is validated in full before the first expression node is emitted.
pub const BodySpans = struct {
    initial_linear: source.SourceSpan,
    external_rounds: [N_EXTERNAL_ROUNDS]ExternalRoundSpans,
    internal_rounds: [N_INTERNAL_ROUNDS]InternalRoundSpans,

    pub fn uniform(span: source.SourceSpan) BodySpans {
        return .{
            .initial_linear = span,
            .external_rounds = .{ExternalRoundSpans.uniform(span)} ** N_EXTERNAL_ROUNDS,
            .internal_rounds = .{InternalRoundSpans.uniform(span)} ** N_INTERNAL_ROUNDS,
        };
    }

    pub fn validate(self: BodySpans, arena: *const ir.Arena) !void {
        try arena.validateSpan(self.initial_linear);
        for (self.external_rounds) |round| try round.validate(arena);
        for (self.internal_rounds) |round| try round.validate(arena);
    }
};

/// Source sites needed to declare the canonical typed function.
pub const DefinitionSpans = struct {
    declaration: source.SourceSpan,
    inputs: [WIDTH]source.SourceSpan,
    body: BodySpans,

    pub fn uniform(span: source.SourceSpan) DefinitionSpans {
        return .{
            .declaration = span,
            .inputs = .{span} ** WIDTH,
            .body = BodySpans.uniform(span),
        };
    }

    pub fn validate(self: DefinitionSpans, arena: *const ir.Arena) !void {
        try arena.validateSpan(self.declaration);
        for (self.inputs) |span| try arena.validateSpan(span);
        try self.body.validate(arena);
    }
};

pub const Definition = struct {
    function: types.FunctionId,
    inputs: State,
    outputs: State,
};

pub const Error = collections.Error || functions.FunctionError;

/// Declares the canonical static function and retains its expanded body.
///
/// Any failed construction removes every expression node created by this
/// invocation. Stable names may remain interned, but the arena stays valid and
/// owns them until deinitialization.
pub fn define(
    arena: *ir.Arena,
    spans: DefinitionSpans,
) Error!Definition {
    try spans.validate(arena);
    const checkpoint = arena.nodeCheckpoint();
    errdefer arena.rollbackToNodeCheckpoint(checkpoint);

    var sourced_inputs: [WIDTH]collections.SourcedValue = undefined;
    for (&sourced_inputs, input_names, spans.inputs) |*item, name, span| {
        item.* = .{
            .value = try arena.input(name, .felt, span),
            .source_span = span,
        };
    }
    const inputs = try State.fromSourced(arena, &sourced_inputs);
    const outputs = try permute(arena, inputs, spans.body);
    const input_values = values(inputs);
    const output_values = values(outputs);
    const function = try functions.add(
        arena,
        function_name,
        &input_values,
        &output_values,
        spans.declaration,
    );
    return .{ .function = function, .inputs = inputs, .outputs = outputs };
}

/// Expands the exact pinned permutation over an existing typed state.
///
/// Expansion order is initial external matrix, four external rounds,
/// fourteen internal rounds, then four external rounds. The outer checkpoint
/// makes the whole permutation transactional even when a later round fails.
pub fn permute(
    arena: *ir.Arena,
    input: State,
    spans: BodySpans,
) collections.Error!State {
    try input.validate(arena);
    try spans.validate(arena);
    const checkpoint = arena.nodeCheckpoint();
    errdefer arena.rollbackToNodeCheckpoint(checkpoint);

    var state = try externalMatrix(arena, input, spans.initial_linear);
    inline for (0..N_EXTERNAL_ROUNDS_FIRST) |round_index| {
        state = try externalRound(
            arena,
            state,
            &constants.EXTERNAL_ROUND[round_index],
            spans.external_rounds[round_index],
        );
    }
    inline for (0..N_INTERNAL_ROUNDS) |round_index| {
        state = try internalRound(
            arena,
            state,
            constants.INTERNAL_ROUND[round_index],
            spans.internal_rounds[round_index],
        );
    }
    inline for (N_EXTERNAL_ROUNDS_FIRST..N_EXTERNAL_ROUNDS) |round_index| {
        state = try externalRound(
            arena,
            state,
            &constants.EXTERNAL_ROUND[round_index],
            spans.external_rounds[round_index],
        );
    }
    return state;
}

/// Copies the statically shaped state into the ID representation consumed by
/// function declarations and later compiler passes.
pub fn values(state: State) [WIDTH]types.ValueId {
    var result: [WIDTH]types.ValueId = undefined;
    for (&result, state.items) |*output, item| output.* = item.value;
    return result;
}

fn externalRound(
    arena: *ir.Arena,
    state: State,
    round_constants: *const [WIDTH]u32,
    spans: ExternalRoundSpans,
) collections.Error!State {
    const shifted = try state.map(
        arena,
        .felt,
        spans.constants,
        round_constants,
        AddConstants.apply,
    );
    const sboxed = try shifted.map(
        arena,
        .felt,
        spans.sbox,
        {},
        Sbox.apply,
    );
    return externalMatrix(arena, sboxed, spans.linear);
}

fn internalRound(
    arena: *ir.Arena,
    state: State,
    round_constant: u32,
    spans: InternalRoundSpans,
) collections.Error!State {
    const add_builder = collections.ScalarBuilder{
        .arena = arena,
        .expansion_span = spans.constant,
    };
    const shifted = try add_builder.add(
        state.items[0].value,
        try add_builder.constantField(round_constant),
    );
    const sbox_builder = collections.ScalarBuilder{
        .arena = arena,
        .expansion_span = spans.sbox,
    };
    const nonlinear = try Sbox.one(sbox_builder, shifted);
    const replaced = try state.replaced(arena, 0, .{
        .value = nonlinear,
        .source_span = spans.sbox,
    });
    return internalMatrix(arena, replaced, spans.linear);
}

/// Exact Stark-V external matrix schedule: four independent M4 blocks followed
/// by a lane-wise sum added back to every block.
fn externalMatrix(
    arena: *ir.Arena,
    input: State,
    span: source.SourceSpan,
) collections.Error!State {
    var state = input;
    const builder = collections.ScalarBuilder{
        .arena = arena,
        .expansion_span = span,
    };
    for (0..4) |block| {
        const base = 4 * block;
        const mixed = try m4(builder, .{
            state.items[base].value,
            state.items[base + 1].value,
            state.items[base + 2].value,
            state.items[base + 3].value,
        });
        for (mixed, 0..) |value, lane| {
            state.items[base + lane] = .{ .value = value, .source_span = span };
        }
    }

    for (0..4) |lane| {
        var sum = state.items[lane].value;
        for (1..4) |block| {
            sum = try builder.add(sum, state.items[4 * block + lane].value);
        }
        var mixed_lane: [4]types.ValueId = undefined;
        for (&mixed_lane, 0..) |*output, block| {
            output.* = try builder.add(state.items[4 * block + lane].value, sum);
        }
        for (mixed_lane, 0..) |value, block| {
            state.items[4 * block + lane] = .{ .value = value, .source_span = span };
        }
    }
    return state;
}

/// Exact addition schedule of the production M4 implementation.
fn m4(
    builder: collections.ScalarBuilder,
    input: [4]types.ValueId,
) collections.Error![4]types.ValueId {
    const t0 = try builder.add(input[0], input[1]);
    const t1 = try builder.add(input[2], input[3]);
    const t2 = try builder.add(try builder.add(input[1], input[1]), t1);
    const t3 = try builder.add(try builder.add(input[3], input[3]), t0);
    const t1_twice = try builder.add(t1, t1);
    const t0_twice = try builder.add(t0, t0);
    const t4 = try builder.add(try builder.add(t1_twice, t1_twice), t3);
    const t5 = try builder.add(try builder.add(t0_twice, t0_twice), t2);
    return .{
        try builder.add(t3, t5),
        t5,
        try builder.add(t2, t4),
        t4,
    };
}

fn internalMatrix(
    arena: *ir.Arena,
    state: State,
    span: source.SourceSpan,
) collections.Error!State {
    const builder = collections.ScalarBuilder{
        .arena = arena,
        .expansion_span = span,
    };
    const zero = try builder.constantField(0);
    const sum = try state.fold(
        arena,
        .felt,
        .{ .value = zero, .source_span = span },
        span,
        {},
        Add.fold,
    );
    return state.map(
        arena,
        .felt,
        span,
        sum.value,
        InternalMix.apply,
    );
}

const AddConstants = struct {
    fn apply(
        builder: collections.ScalarBuilder,
        round_constants: *const [WIDTH]u32,
        index: usize,
        value: types.ValueId,
    ) collections.Error!types.ValueId {
        return builder.add(
            value,
            try builder.constantField(round_constants[index]),
        );
    }
};

const Sbox = struct {
    fn apply(
        builder: collections.ScalarBuilder,
        _: void,
        _: usize,
        value: types.ValueId,
    ) collections.Error!types.ValueId {
        return one(builder, value);
    }

    fn one(
        builder: collections.ScalarBuilder,
        value: types.ValueId,
    ) collections.Error!types.ValueId {
        const square = try builder.mul(value, value);
        const fourth = try builder.mul(square, square);
        return builder.mul(value, fourth);
    }
};

const Add = struct {
    fn fold(
        builder: collections.ScalarBuilder,
        _: void,
        _: usize,
        accumulator: types.ValueId,
        item: types.ValueId,
    ) collections.Error!types.ValueId {
        return builder.add(accumulator, item);
    }
};

const InternalMix = struct {
    fn apply(
        builder: collections.ScalarBuilder,
        sum: types.ValueId,
        index: usize,
        value: types.ValueId,
    ) collections.Error!types.ValueId {
        const diagonal = try builder.constantField(constants.INTERNAL_MATRIX[index]);
        return builder.add(try builder.mul(value, diagonal), sum);
    }
};

comptime {
    if (constants.EXTERNAL_ROUND.len !=
        N_EXTERNAL_ROUNDS_FIRST + N_EXTERNAL_ROUNDS_LAST)
    {
        @compileError("Poseidon2 external round partition drifted");
    }
    if (constants.INTERNAL_MATRIX.len != WIDTH)
        @compileError("Poseidon2 internal diagonal width drifted");
    for (constants.EXTERNAL_ROUND) |round| {
        if (round.len != WIDTH) @compileError("Poseidon2 round width drifted");
        for (round) |value| {
            if (value >= m31.Modulus)
                @compileError("Poseidon2 external constant is not canonical M31");
        }
    }
    for (constants.INTERNAL_ROUND) |value| {
        if (value >= m31.Modulus)
            @compileError("Poseidon2 internal constant is not canonical M31");
    }
    for (constants.INTERNAL_MATRIX) |value| {
        if (value >= m31.Modulus)
            @compileError("Poseidon2 internal diagonal is not canonical M31");
    }
}
