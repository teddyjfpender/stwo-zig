//! Internal fixed-program builder for the role-0 V4 public-sum lane.
//! Use `recursive_common_ethereum_incremental_leaf_public_sums_v4.zig`.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const role_io =
    @import("recursive_common_ethereum_incremental_leaf_role_aware_io_v4.zig");
pub const role_binding = @import("recursive_common_ethereum_incremental_leaf_role_binding_v4.zig");
pub const CircuitProfileV1 = @import("stwo_riscv_frontend").prover_mod.ethereum_circuit_profile_v1.CircuitProfileV1;
pub const program_admission = @import("recursive_common_ethereum_incremental_leaf_program_admission_v1.zig");
pub const global_binding = @import("recursive_common_ethereum_incremental_leaf_global_binding_v1.zig");
pub const NONFINAL_COMPLETION_INPUT_COUNT: usize = 12;

pub const M31 = stwo_core.fields.m31.M31;
pub const QM31 = stwo_core.fields.qm31.QM31;
pub const arithmetic = frontend.recursion.arithmetic_circuit;
pub const graph_mod = frontend.recursion.air.composition_circuit;
pub const span = frontend.recursion.span_statement;
pub const segment_v2 = frontend.recursion.segment_statement_v2;

pub const DOMAIN_COUNT: usize = 4;
pub const SECURE_WORD_COUNT: usize = 4;
pub const BASE_CANONICAL_CLAIM_COUNT: usize = frontend.air.transcript.COMPONENT_COUNT;
pub const CANONICAL_CLAIM_COUNT: usize = BASE_CANONICAL_CLAIM_COUNT +
    frontend.air.guest_precompile.ethereum_statement.component_count + 1;
pub const CANONICAL_CLAIM_WORD_COUNT: usize = CANONICAL_CLAIM_COUNT * SECURE_WORD_COUNT;
/// One canonical consumer in VM composition and one in global cancellation.
pub const CANONICAL_CLAIM_TRANSCRIPT_USE_COUNT: u32 =
    frontend.recursion.incremental_ethereum_composition_profile_v4.ClaimRoutingPlan.CANONICAL_TRANSCRIPT_USE_COUNT;
pub const CHALLENGE_WORD_COUNT: usize =
    DOMAIN_COUNT * 2 * SECURE_WORD_COUNT;
pub const STATEMENT_WORD_COUNT: usize = span.SPAN_STATEMENT_CANONICAL_WORDS;
pub const REGISTER_COUNT: usize = 32;
pub const CLOCK_LIMB_COUNT: usize = REGISTER_COUNT * 2 * 2;
pub const REGISTER_BYTE_COUNT: usize = REGISTER_COUNT * 2 * 4;
pub const SELECTOR_COUNT: usize = 5;
pub const CLOCK_BIT_COUNT: usize = 26;
pub const CLOCK_CYCLE_BIT_COUNT: usize = 25;
pub const CLOCK_AUX_INPUT_COUNT: usize = 2 * REGISTER_COUNT * CLOCK_BIT_COUNT + 3 * CLOCK_CYCLE_BIT_COUNT;
pub const CompletionPolicyV1 = enum(u16) { nonfinal_program_v1 = 1, terminal_halt_v1 = 2 };
pub const ClockCycleKindV4 = enum(u2) { first, count, end };
pub const ClockAuxSourceV4 = union(enum) {
    register_bit: struct { boundary: Boundary, register: u5, bit: u5 },
    cycle_bit: struct { kind: ClockCycleKindV4, bit: u5 },
};

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

pub const CanonicalClaimCoordinateV4 = struct {
    item: u6,
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
    canonical_claim_word: CanonicalClaimCoordinateV4,
    relation_challenge_word: RelationChallengeCoordinateV4,
    role_source: role_binding.Source,
    clock_aux: ClockAuxSourceV4,
    global_statement_word: u16,
    global_aux: global_binding.AuxSource,
    completion_opening_word: u16,
    native_continuation_root: u1,
    initial_packet_limb: u6,
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

pub const BoundRelation = struct {
    z: arithmetic.Value,
    alpha_powers: [7]arithmetic.Value,
    arity: u8,

    pub fn init(
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

pub const Accumulator = struct {
    builder: *arithmetic.Builder,
    relations: *const [DOMAIN_COUNT]BoundRelation,
    sums: [DOMAIN_COUNT]arithmetic.Value =
        .{arithmetic.Value.zero()} ** DOMAIN_COUNT,

    pub fn add(
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
    const role_budget = try role_binding.budget(tuple_capacity);
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
        CANONICAL_CLAIM_WORD_COUNT + CHALLENGE_WORD_COUNT,
    ) catch return error.ArithmeticOverflow;
    result = try std.math.add(usize, result, role_budget.input_count);
    return std.math.add(usize, result, CLOCK_AUX_INPUT_COUNT) catch error.ArithmeticOverflow;
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
    return buildInternal(allocator, tuple_capacity, null, false, .legacy_v4, .nonfinal_program_v1, false);
}

pub fn buildWithProgram(allocator: std.mem.Allocator, tuple_capacity: u32, admission: *const program_admission.ProgramAdmissionV1) !BuiltProgramV4 {
    return buildInternal(allocator, tuple_capacity, admission, false, .legacy_v4, .nonfinal_program_v1, false);
}

pub fn buildWithGlobalProgram(allocator: std.mem.Allocator, tuple_capacity: u32, admission: *const program_admission.ProgramAdmissionV1) !BuiltProgramV4 {
    return buildInternal(allocator, tuple_capacity, admission, true, .legacy_v4, .nonfinal_program_v1, false);
}
pub fn inputCountWithGlobalProgram(tuple_capacity: u32) !usize {
    return std.math.add(usize, try inputCountWithProgram(tuple_capacity), global_binding.WORD_COUNT + global_binding.AUX_COUNT);
}

pub fn inputCountWithProgram(tuple_capacity: u32) !usize {
    return std.math.add(usize, try inputCount(tuple_capacity), NONFINAL_COMPLETION_INPUT_COUNT);
}

pub fn buildWithCircuitProfile(allocator: std.mem.Allocator, tuple_capacity: u32, admission: ?*const program_admission.ProgramAdmissionV1, global_admitted: bool, circuit_profile: CircuitProfileV1) !BuiltProgramV4 {
    return buildInternal(allocator, tuple_capacity, admission, global_admitted, circuit_profile, .nonfinal_program_v1, false);
}

pub fn buildWithCompletionPolicy(allocator: std.mem.Allocator, tuple_capacity: u32, admission: ?*const program_admission.ProgramAdmissionV1, global_admitted: bool, circuit_profile: CircuitProfileV1, policy: CompletionPolicyV1) !BuiltProgramV4 {
    return buildInternal(allocator, tuple_capacity, admission, global_admitted, circuit_profile, policy, false);
}

pub fn buildWithNativeRoots(allocator: std.mem.Allocator, tuple_capacity: u32, admission: ?*const program_admission.ProgramAdmissionV1, global_admitted: bool, circuit_profile: CircuitProfileV1, policy: CompletionPolicyV1) !BuiltProgramV4 {
    return buildInternal(allocator, tuple_capacity, admission, global_admitted, circuit_profile, policy, true);
}

fn buildInternal(allocator: std.mem.Allocator, tuple_capacity: u32, admission: ?*const program_admission.ProgramAdmissionV1, global_admitted: bool, circuit_profile: CircuitProfileV1, policy: CompletionPolicyV1, native_roots: bool) !BuiltProgramV4 {
    if (policy == .terminal_halt_v1 and (!global_admitted or admission == null or circuit_profile != .fixed_program_narrow_v1)) return error.EthereumTerminalAdmissionRequired;
    if (tuple_capacity == 0 or !std.math.isPowerOfTwo(tuple_capacity))
        return error.InvalidPublicSumProgramV4;
    const opening_count = if (policy == .nonfinal_program_v1) (if (admission) |program| program.openingInputWordCount() else 0) else 0;
    const base_count = if (global_admitted) try inputCountWithGlobalProgram(tuple_capacity) else if (admission != null) try inputCountWithProgram(tuple_capacity) else try inputCount(tuple_capacity);
    const count = try std.math.add(usize, try std.math.add(usize, base_count, opening_count), if (native_roots) 2 else 0);
    var builder = arithmetic.Builder.initDefault(allocator);
    errdefer builder.deinit();
    errdefer |err| std.debug.print(
        "ETHEREUM_PUBLIC_SUM_BUILD capacity={d} inputs={d} nodes={d} outputs={d} error={s}\n",
        .{ tuple_capacity, count, builder.nodes_storage.items.len, builder.outputs_storage.items.len, @errorName(err) },
    );
    const node_reservation = std.math.mul(usize, count, 12) catch
        return error.ArithmeticOverflow;
    const output_reservation = std.math.mul(usize, count, 3) catch
        return error.ArithmeticOverflow;
    // These are allocation hints, not graph sizes. A conservative estimate
    // must not reject a graph that fits the unchanged builder limits.
    try builder.reserve(
        count,
        @min(node_reservation, builder.limits.max_nodes),
        @min(output_reservation, builder.limits.max_outputs),
    );
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
    const role_sources_start = at;
    const role_source_count = (try role_binding.budget(tuple_capacity)).input_count;
    for (0..role_source_count) |index| {
        values[at] = try builder.input(@intCast(at));
        bindings[at] = .{ .role_source = try role_binding.sourceAt(tuple_capacity, index) };
        at += 1;
    }
    const completion_start = at;
    if (admission != null) {
        for (0..4) |index| {
            values[at] = try builder.input(@intCast(at));
            bindings[at] = .{ .role_source = .{ .completion_word = @intCast(index) } };
            at += 1;
        }
        for (0..4) |index| {
            values[at] = try builder.input(@intCast(at));
            bindings[at] = .{ .role_source = .{ .completion_decoded_word = @intCast(index) } };
            at += 1;
        }
        for (0..3) |index| {
            values[at] = try builder.input(@intCast(at));
            bindings[at] = .{ .role_source = .{ .completion_policy_word = @intCast(index) } };
            at += 1;
        }
        values[at] = try builder.input(@intCast(at));
        bindings[at] = .{ .role_source = if (policy == .terminal_halt_v1) .terminal_reserved else .nonfinal_inverse };
        at += 1;
    }
    const global_start = at;
    if (global_admitted) {
        for (0..global_binding.WORD_COUNT) |index| {
            values[at] = try builder.input(@intCast(at));
            bindings[at] = .{ .global_statement_word = @intCast(index) };
            at += 1;
        }
        for (0..global_binding.AUX_COUNT) |index| {
            values[at] = try builder.input(@intCast(at));
            bindings[at] = .{ .global_aux = try global_binding.sourceAt(index) };
            at += 1;
        }
    }
    const clock_aux_start = at;
    for (0..CLOCK_AUX_INPUT_COUNT) |index| {
        values[at] = try builder.input(@intCast(at));
        bindings[at] = .{ .clock_aux = try clockAuxSourceAt(index) };
        at += 1;
    }
    const opening_start = at;
    for (0..opening_count) |index| {
        values[at] = try builder.input(@intCast(at));
        bindings[at] = .{ .completion_opening_word = @intCast(index) };
        at += 1;
    }
    const native_root_start = at;
    if (native_roots) for (0..2) |side| {
        values[at] = try builder.input(@intCast(at));
        bindings[at] = .{ .native_continuation_root = @intCast(side) };
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
    const claims_start = at;
    for (0..CANONICAL_CLAIM_COUNT) |item| for (0..SECURE_WORD_COUNT) |limb| {
        values[at] = try builder.input(@intCast(at));
        bindings[at] = .{ .canonical_claim_word = .{ .item = @intCast(item), .limb = @intCast(limb) } };
        at += 1;
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
    try constrainRawClocks(
        &builder,
        values[statement_start..][0..STATEMENT_WORD_COUNT],
        values[clock_start..][0..CLOCK_LIMB_COUNT],
        values[clock_aux_start..][0..CLOCK_AUX_INPUT_COUNT],
    );
    if (global_admitted) try global_binding.constrain(
        &builder,
        values[statement_start..][0..STATEMENT_WORD_COUNT],
        values[global_start..][0..global_binding.WORD_COUNT],
        values[global_start + global_binding.WORD_COUNT ..][0..global_binding.AUX_COUNT],
    );
    try addBaseTerms(
        &builder,
        &accumulator,
        values[statement_start..][0..STATEMENT_WORD_COUNT],
        values[clock_start..][0..CLOCK_LIMB_COUNT],
        values[bytes_start..][0..REGISTER_BYTE_COUNT],
        circuit_profile,
        if (native_roots) values[native_root_start..][0..2].* else null,
    );
    try addRoleTerms(
        &builder,
        &accumulator,
        values[role_start..][0..role_word_count],
        values[selectors_start..][0 .. tuple_capacity * SELECTOR_COUNT],
        tuple_capacity,
    );
    try role_binding.constrain(&builder, allocator, tuple_capacity, values[role_sources_start..][0..role_source_count], values[role_start..][0..role_word_count], values[selectors_start..][0 .. tuple_capacity * SELECTOR_COUNT]);
    if (admission) |program| {
        if (policy == .terminal_halt_v1) {
            try @import("recursive_common_ethereum_incremental_leaf_terminal_binding_v1.zig").constrain(&builder, program, tuple_capacity, .{
                .statement = values[global_start..][0..global_binding.WORD_COUNT],
                .global_aux = values[global_start + global_binding.WORD_COUNT ..][0..global_binding.AUX_COUNT],
                .native_end_bits = values[clock_aux_start + 2 * REGISTER_COUNT * CLOCK_BIT_COUNT + 2 * CLOCK_CYCLE_BIT_COUNT ..][0..CLOCK_CYCLE_BIT_COUNT],
                .role_sources = values[role_sources_start..][0..role_source_count],
                .role_words = values[role_start..][0..role_word_count],
                .selectors = values[selectors_start..][0 .. tuple_capacity * SELECTOR_COUNT],
                .completion = values[completion_start..][0..NONFINAL_COMPLETION_INPUT_COUNT],
            });
        } else {
            try constrainNonfinalProgram(&builder, program, tuple_capacity, values[statement_start..][0..STATEMENT_WORD_COUNT], values[role_sources_start..][0..role_source_count], values[role_start..][0..role_word_count], values[selectors_start..][0 .. tuple_capacity * SELECTOR_COUNT], values[completion_start..][0..NONFINAL_COMPLETION_INPUT_COUNT], values[opening_start..][0..opening_count]);
        }
    }

    try constrainGlobalCancellation(&builder, accumulator.sums, values[claims_start..][0..CANONICAL_CLAIM_WORD_COUNT]);

    return .{ .circuit = try builder.finish(), .bindings = bindings };
}

fn constrainNonfinalProgram(builder: *arithmetic.Builder, admission: *const program_admission.ProgramAdmissionV1, capacity: u32, statement: []const arithmetic.Value, role_sources: []const arithmetic.Value, role_words: []const arithmetic.Value, selectors: []const arithmetic.Value, completion: []const arithmetic.Value, opening: []const arithmetic.Value) !void {
    try constrainNonfinalCompletionHeader(builder, statement, completion);
    try role_binding.constrainNonfinalRoleOrder(builder, capacity, role_sources, selectors);
    for (0..capacity) |slot| {
        const selected = selectors[slot * SELECTOR_COUNT ..][0..SELECTOR_COUNT];
        const words = role_words[role_io.HEADER_WORD_COUNT + slot * role_io.TUPLE_WORD_COUNT ..][0..role_io.TUPLE_WORD_COUNT];
        for (0..2) |limb| _ = try builder.markOutput(try builder.mul(selected[4], try builder.sub(words[4 + limb], completion[limb])));
        for (0..4) |i| _ = try builder.markOutput(try builder.mul(selected[4], try builder.sub(try u32At(builder, words, 6 + 2 * i), completion[4 + i])));
        try role_binding.constrainCanonicalDecoded(builder, capacity, role_sources, slot, selected[4]);
    }
    try constrainNonfinalCompletionOpening(builder, admission, statement, completion, opening);
}

/// Shared prefix and opening used by both bounded and streamed role policies.
/// Factoring preserves the operation order of the legacy bounded constructor.
pub fn constrainNonfinalCompletionHeader(builder: *arithmetic.Builder, statement: []const arithmetic.Value, completion: []const arithmetic.Value) !void {
    const layout = span.canonical_layout;
    const exit_pc_at = layout.exit_state_start + layout.machine_state_pc_start_offset;
    try role_binding.requireNonfinal(builder, try u32At(builder, statement, layout.job_segment_count_start), try u32At(builder, statement, layout.first_segment_start), try u32At(builder, statement, layout.executed_segment_count_start), completion[11]);
    try role_binding.constrainNonfinalCompletionPolicy(builder, completion[8..11].*);
    for (0..2) |limb| _ = try builder.markOutput(try builder.sub(completion[limb], statement[exit_pc_at + limb]));
}
pub fn constrainNonfinalCompletionOpening(builder: *arithmetic.Builder, admission: *const program_admission.ProgramAdmissionV1, statement: []const arithmetic.Value, completion: []const arithmetic.Value, opening: []const arithmetic.Value) !void {
    const layout = span.canonical_layout;
    const exit_pc_at = layout.exit_state_start + layout.machine_state_pc_start_offset;
    try admission.constrainCompletionWithOpening(builder, .{ .active = arithmetic.Value.one(), .pc = try u32At(builder, statement, exit_pc_at), .raw_word_limbs = completion[2..4].*, .decoded = completion[4..8].*, .program_root = statement[layout.program_start] }, opening);
}

/// Matches native logup.verifyGlobalCancellation: the public boundary plus
/// all canonical component claims must vanish under the same challenges.
pub fn constrainGlobalCancellation(
    builder: *arithmetic.Builder,
    public_sums: [DOMAIN_COUNT]arithmetic.Value,
    claim_words: []const arithmetic.Value,
) !void {
    if (claim_words.len != CANONICAL_CLAIM_WORD_COUNT) return error.InvalidPublicSumProgramV4;
    var total = arithmetic.Value.zero();
    for (public_sums) |sum| total = try builder.add(total, sum);
    for (0..CANONICAL_CLAIM_COUNT) |item| {
        const claim = try composeSecure(builder, claim_words[item * SECURE_WORD_COUNT ..][0..SECURE_WORD_COUNT]);
        total = try builder.add(total, claim);
    }
    _ = try builder.markOutput(total);
}

test "Ethereum public sum endpoint matches native cancellation and rejects every claim limb mutation" {
    const allocator = std.testing.allocator;
    var builder = arithmetic.Builder.initDefault(allocator);
    var builder_live = true;
    defer if (builder_live) builder.deinit();
    var public_inputs: [DOMAIN_COUNT]arithmetic.Value = undefined;
    for (&public_inputs, 0..) |*value, index| value.* = try builder.input(@intCast(index));
    var claim_inputs: [CANONICAL_CLAIM_WORD_COUNT]arithmetic.Value = undefined;
    for (&claim_inputs, DOMAIN_COUNT..) |*value, index| value.* = try builder.input(@intCast(index));
    try constrainGlobalCancellation(&builder, public_inputs, &claim_inputs);
    try std.testing.expectError(error.InvalidPublicSumProgramV4, constrainGlobalCancellation(&builder, public_inputs, claim_inputs[0 .. claim_inputs.len - 1]));
    var circuit = try builder.finish();
    builder_live = false;
    defer circuit.deinit();
    var inputs = [_]QM31{QM31.zero()} ** (DOMAIN_COUNT + CANONICAL_CLAIM_WORD_COUNT);
    var boundary = QM31.zero();
    for (inputs[0..DOMAIN_COUNT], 0..) |*value, index| {
        const word: u32 = @intCast(index + 1);
        value.* = QM31.fromU32Unchecked(word, word + 1, word + 2, word + 3);
        boundary = boundary.add(value.*);
    }
    var claims = [_]QM31{QM31.zero()} ** CANONICAL_CLAIM_COUNT;
    claims[0] = boundary.neg();
    for (claims, 0..) |claim, item| {
        for (claim.toM31Array(), 0..) |word, limb| inputs[DOMAIN_COUNT + item * 4 + limb] = QM31.fromBase(word);
    }
    try frontend.air.logup.verifyGlobalCancellation(&claims, boundary);
    {
        var evaluated = try circuit.evaluate(allocator, &inputs);
        defer evaluated.deinit();
        try std.testing.expect(try circuit.outputsAreZero(evaluated.values));
    }
    for (DOMAIN_COUNT..inputs.len) |index| {
        const saved = inputs[index];
        inputs[index] = saved.add(QM31.one());
        var changed = try circuit.evaluate(allocator, &inputs);
        defer changed.deinit();
        try std.testing.expect(!try circuit.outputsAreZero(changed.values));
        inputs[index] = saved;
    }
}

test "Ethereum public sum fixed program removes only native program root anchor" {
    const allocator = std.testing.allocator;
    var builder = arithmetic.Builder.initDefault(allocator);
    var builder_live = true;
    defer if (builder_live) builder.deinit();
    var statement = [_]arithmetic.Value{arithmetic.Value.zero()} ** STATEMENT_WORD_COUNT;
    const layout = span.canonical_layout;
    const root_indices = [_]usize{ layout.program_start, layout.entry_state_start + layout.machine_state_rw_digest_start_offset, layout.exit_state_start + layout.machine_state_rw_digest_start_offset };
    for (root_indices, 0..) |at, index| statement[at] = try builder.input(@intCast(index));
    const z = QM31.fromU32Unchecked(3, 5, 7, 11);
    const alpha = QM31.fromU32Unchecked(13, 17, 19, 23);
    var challenge_words: [8]arithmetic.Value = undefined;
    for (z.toM31Array(), alpha.toM31Array(), 0..) |zw, aw, i| {
        challenge_words[i] = arithmetic.Value.fromBase(zw);
        challenge_words[4 + i] = arithmetic.Value.fromBase(aw);
    }
    var relations: [DOMAIN_COUNT]BoundRelation = undefined;
    for ([_]u8{ 2, 7, 5, 4 }, &relations) |arity, *relation| relation.* = try BoundRelation.init(&builder, &challenge_words, arity);
    const clocks = [_]arithmetic.Value{arithmetic.Value.zero()} ** CLOCK_LIMB_COUNT;
    const bytes = [_]arithmetic.Value{arithmetic.Value.zero()} ** REGISTER_BYTE_COUNT;
    var sums: [2][DOMAIN_COUNT]arithmetic.Value = undefined;
    for ([_]CircuitProfileV1{ .legacy_v4, .fixed_program_narrow_v1 }, &sums, 0..) |profile, *result, i| {
        var accumulator = Accumulator{ .builder = &builder, .relations = &relations };
        try addBaseTerms(&builder, &accumulator, &statement, &clocks, &bytes, profile, null);
        result.* = accumulator.sums;
        _ = try builder.markOutput(try builder.sub(result[@intFromEnum(Domain.merkle)], try builder.input(@intCast(3 + i))));
    }
    for (0..@intFromEnum(Domain.merkle)) |i| _ = try builder.markOutput(try builder.sub(sums[0][i], sums[1][i]));
    var circuit = try builder.finish();
    builder_live = false;
    defer circuit.deinit();
    const native_relation = frontend.air.relation_challenges.RelationElements(4).init(z, alpha);
    for ([_][3]u32{ .{ 29, 31, 37 }, .{ 41, 31, 37 }, .{ 29, 43, 47 } }) |roots| {
        var inputs: [5]QM31 = undefined;
        var anchors: [3]QM31 = undefined;
        for (roots, 0..) |root, i| {
            const word = M31.fromCanonical(root);
            inputs[i] = QM31.fromBase(word);
            anchors[i] = try native_relation.combineBase(.{ M31.zero(), M31.zero(), word, word }).inv();
        }
        inputs[3] = anchors[0].add(anchors[1]).add(anchors[2]);
        inputs[4] = anchors[1].add(anchors[2]);
        var evaluated = try circuit.evaluate(allocator, &inputs);
        defer evaluated.deinit();
        try std.testing.expect(try circuit.outputsAreZero(evaluated.values));
        inputs[4] = inputs[4].add(anchors[0]);
        var changed = try circuit.evaluate(allocator, &inputs);
        defer changed.deinit();
        try std.testing.expect(!try circuit.outputsAreZero(changed.values));
    }
}

pub fn constrainRoleHeader(
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

/// Private bit coordinates only. The corresponding graph inputs are bound
/// pointwise to the same public/raw limbs used by addBaseTerms.
pub fn clockAuxSourceAt(index: usize) !ClockAuxSourceV4 {
    const register_bits = 2 * REGISTER_COUNT * CLOCK_BIT_COUNT;
    if (index < register_bits) return .{ .register_bit = .{
        .boundary = @enumFromInt(index / (REGISTER_COUNT * CLOCK_BIT_COUNT)),
        .register = @intCast((index / CLOCK_BIT_COUNT) % REGISTER_COUNT),
        .bit = @intCast(index % CLOCK_BIT_COUNT),
    } };
    if (index >= CLOCK_AUX_INPUT_COUNT) return error.InvalidPublicSumClockSourceV4;
    const offset = index - register_bits;
    return .{ .cycle_bit = .{ .kind = @enumFromInt(offset / CLOCK_CYCLE_BIT_COUNT), .bit = @intCast(offset % CLOCK_CYCLE_BIT_COUNT) } };
}

pub fn clockAuxValue(source: ClockAuxSourceV4, statement_words: *const [STATEMENT_WORD_COUNT]u32, native_words: []const M31) !QM31 {
    const bit_value: u32 = switch (source) {
        .register_bit => |coordinate| blk: {
            if (coordinate.bit >= CLOCK_BIT_COUNT) return error.InvalidPublicSumClockSourceV4;
            const start = (if (coordinate.boundary == .entry) segment_v2.fixed_layout.entry_register_clocks else segment_v2.fixed_layout.exit_register_clocks) + @as(usize, coordinate.register) * 2;
            if (start + 2 > native_words.len) return error.InvalidPublicSumClockSourceV4;
            const low = native_words[start].toU32();
            const high = native_words[start + 1].toU32();
            if (low > 65535 or high > 65535) return error.InvalidPublicSumClockSourceV4;
            break :blk ((low | (high << 16)) >> coordinate.bit) & 1;
        },
        .cycle_bit => |coordinate| blk: {
            if (coordinate.bit >= CLOCK_CYCLE_BIT_COUNT) return error.InvalidPublicSumClockSourceV4;
            const first = try clockCycleU64(statement_words, span.canonical_layout.first_cycle_start);
            const count = try clockCycleU64(statement_words, span.canonical_layout.executed_cycle_count_start);
            const value = switch (coordinate.kind) {
                .first => first,
                .count => count,
                .end => try std.math.add(u64, first, count),
            };
            break :blk @intCast((value >> coordinate.bit) & 1);
        },
    };
    return QM31.fromBase(M31.fromCanonical(bit_value));
}

fn clockCycleU64(words: *const [STATEMENT_WORD_COUNT]u32, start: usize) !u64 {
    var result: u64 = 0;
    for (words[start..][0..4], 0..) |word, limb| {
        if (word > 65535) return error.InvalidPublicSumClockSourceV4;
        result |= @as(u64, word) << @as(u6, @intCast(limb * 16));
    }
    return result;
}

/// Native StatementV2 register-boundary validity inside the admitted sums
/// program. No clock is independently re-emitted: both constraints and tuples
/// consume the existing 128 raw source limbs. This also binds the full u64
/// span coordinates; checking only a field sum or the claim's local count
/// would leave overflow/alias and nonzero-start gaps.
pub fn constrainRawClocks(builder: *arithmetic.Builder, statement: []const arithmetic.Value, clocks: []const arithmetic.Value, auxiliary: []const arithmetic.Value) !void {
    if (statement.len != STATEMENT_WORD_COUNT or clocks.len != CLOCK_LIMB_COUNT or auxiliary.len != CLOCK_AUX_INPUT_COUNT)
        return error.InvalidPublicSumClockSourceV4;
    for (auxiliary) |bit| try clockZero(builder, try builder.mul(bit, try builder.sub(bit, arithmetic.Value.one())));
    const register_bits = 2 * REGISTER_COUNT * CLOCK_BIT_COUNT;
    const first_bits = auxiliary[register_bits..][0..CLOCK_CYCLE_BIT_COUNT];
    const count_bits = auxiliary[register_bits + CLOCK_CYCLE_BIT_COUNT ..][0..CLOCK_CYCLE_BIT_COUNT];
    const end_bits = auxiliary[register_bits + 2 * CLOCK_CYCLE_BIT_COUNT ..][0..CLOCK_CYCLE_BIT_COUNT];
    for ([_]usize{ span.canonical_layout.first_cycle_start, span.canonical_layout.executed_cycle_count_start }, [_][]const arithmetic.Value{ first_bits, count_bits }) |start, bits| {
        try clockJoinLimbs(builder, statement[start..][0..2], bits);
        try clockZero(builder, statement[start + 2]);
        try clockZero(builder, statement[start + 3]);
    }
    // All three values are at most 2^24. A set bit24 therefore requires all
    // lower bits zero; their sum is far below p, so field equality is exact.
    for ([_][]const arithmetic.Value{ first_bits, count_bits, end_bits }) |bits|
        for (bits[0..24]) |low_bit| try clockZero(builder, try builder.mul(bits[24], low_bit));
    var count_is_zero = arithmetic.Value.one();
    for (count_bits) |bit| count_is_zero = try builder.mul(count_is_zero, try builder.sub(arithmetic.Value.one(), bit));
    try clockZero(builder, count_is_zero);
    try clockZero(builder, try builder.sub(
        try builder.add(try clockBitsValue(builder, first_bits), try clockBitsValue(builder, count_bits)),
        try clockBitsValue(builder, end_bits),
    ));
    for (0..2) |boundary| for (0..REGISTER_COUNT) |reg| {
        const at = boundary * REGISTER_COUNT + reg;
        const bits = auxiliary[at * CLOCK_BIT_COUNT ..][0..CLOCK_BIT_COUNT];
        try clockJoinLimbs(builder, clocks[at * 2 ..][0..2], bits);
        try constrainZeroAwareAccessClock(builder, bits, if (boundary == 0) first_bits else end_bits);
    };
    for (0..REGISTER_COUNT) |reg| {
        const entry = auxiliary[reg * CLOCK_BIT_COUNT ..][0..CLOCK_BIT_COUNT];
        const exit = auxiliary[(REGISTER_COUNT + reg) * CLOCK_BIT_COUNT ..][0..CLOCK_BIT_COUNT];
        try clockZero(builder, try clockLessThanBits(builder, exit, entry));
    }
}

fn clockJoinLimbs(builder: *arithmetic.Builder, limbs: []const arithmetic.Value, bits: []const arithmetic.Value) !void {
    try clockZero(builder, try builder.sub(limbs[0], try clockBitsValue(builder, bits[0..16])));
    try clockZero(builder, try builder.sub(limbs[1], try clockBitsValue(builder, bits[16..])));
}

fn clockBitsValue(builder: *arithmetic.Builder, bits: []const arithmetic.Value) !arithmetic.Value {
    var value = arithmetic.Value.zero();
    for (bits, 0..) |bit, index| value = try builder.add(value, try builder.mul(base(@as(u32, 1) << @as(u5, @intCast(index))), bit));
    return value;
}

/// Zero is valid even at boundary cycle0. Otherwise residues1,2,3 are the
/// native access-clock ordinals and their bucket must precede the boundary.
fn constrainZeroAwareAccessClock(builder: *arithmetic.Builder, bits: []const arithmetic.Value, boundary: []const arithmetic.Value) !void {
    const residue_nonzero = try builder.sub(try builder.add(bits[0], bits[1]), try builder.mul(bits[0], bits[1]));
    const residue_zero = try builder.sub(arithmetic.Value.one(), residue_nonzero);
    for (bits[2..]) |bit| try clockZero(builder, try builder.mul(residue_zero, bit));
    var bucket = [_]arithmetic.Value{arithmetic.Value.zero()} ** CLOCK_CYCLE_BIT_COUNT;
    @memcpy(bucket[0 .. CLOCK_BIT_COUNT - 2], bits[2..]);
    const before = try clockLessThanBits(builder, &bucket, boundary);
    try clockZero(builder, try builder.mul(residue_nonzero, try builder.sub(arithmetic.Value.one(), before)));
}

// Same high-to-low boolean comparator used by the existing claim and span
// graph builders; this builder consumes already constrained private bits.
fn clockLessThanBits(builder: *arithmetic.Builder, left: []const arithmetic.Value, right: []const arithmetic.Value) !arithmetic.Value {
    return role_binding.lessThanBits(builder, left, right);
}

fn clockZero(builder: *arithmetic.Builder, value: arithmetic.Value) !void {
    _ = try builder.markOutput(value);
}

comptime {
    if (segment_v2.MAX_GLOBAL_CYCLES != (1 << 24) or frontend.access_clock.STRIDE != 4)
        @compileError("Ethereum raw clock bit geometry must follow the native protocol");
}

pub fn addBaseTerms(
    builder: *arithmetic.Builder,
    accumulator: *Accumulator,
    statement: []const arithmetic.Value,
    clock_limbs: []const arithmetic.Value,
    register_bytes: []const arithmetic.Value,
    circuit_profile: CircuitProfileV1,
    native_roots: ?[2]arithmetic.Value,
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
    const entry_root = if (native_roots) |roots| roots[0] else statement[
        layout.entry_state_start + layout.machine_state_rw_digest_start_offset
    ];
    const exit_root = if (native_roots) |roots| roots[1] else statement[
        layout.exit_state_start + layout.machine_state_rw_digest_start_offset
    ];
    if (circuit_profile.programPolicy() == .sparse_merkle_v1)
        try accumulator.add(.merkle, &.{ base(0), base(0), program_root, program_root }, .positive);
    for ([_]arithmetic.Value{ entry_root, exit_root }) |root|
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
            // Canonical unused fields are two zero limbs. Checking only the
            // recomposed M31 value would also accept an encoding of its modulus.
            try constrainUnusedLimbs(builder, used, words[4 + index * 2 ..][0..2].*);
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

fn constrainUnusedLimbs(builder: *arithmetic.Builder, used: arithmetic.Value, limbs: [2]arithmetic.Value) !void {
    for (limbs) |limb| _ = try builder.markOutput(try builder.mul(try builder.sub(arithmetic.Value.one(), used), limb));
}

test "Ethereum role padding rejects noncanonical zero limbs" {
    const allocator = std.testing.allocator;
    var builder = arithmetic.Builder.initDefault(allocator);
    var live = true;
    defer if (live) builder.deinit();
    const used = try builder.input(0);
    const low = try builder.input(1);
    const high = try builder.input(2);
    try constrainUnusedLimbs(&builder, used, .{ low, high });
    var circuit = try builder.finish();
    live = false;
    defer circuit.deinit();
    var inputs = [_]QM31{ QM31.zero(), QM31.zero(), QM31.zero() };
    var valid = try circuit.evaluate(allocator, &inputs);
    defer valid.deinit();
    try std.testing.expect(try circuit.outputsAreZero(valid.values));
    inputs[1] = QM31.fromBase(M31.fromCanonical(65535));
    inputs[2] = QM31.fromBase(M31.fromCanonical(32767));
    try std.testing.expect(inputs[1].add(inputs[2].mul(QM31.fromBase(M31.fromCanonical(65536)))).isZero());
    var alias = try circuit.evaluate(allocator, &inputs);
    defer alias.deinit();
    try std.testing.expect(!try circuit.outputsAreZero(alias.values));
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

pub fn u32At(
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
    for (words[index..][0..4], 0..) |word, limb_index| {
        result = try builder.add(result, try builder.mul(base(radix), word));
        if (limb_index + 1 != 4) radix *= 1 << 16;
    }
    return result;
}

pub fn composeSecure(
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
