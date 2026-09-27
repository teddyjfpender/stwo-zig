//! Exactness, cancellation, adversarial, and performance gates for row 13.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const compat = @import("../../air/lang/typed_poseidon2_compat.zig");
const degree = @import("../../air/lang/degree.zig");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const materializer = @import("../../air/lang/degree3_materializer.zig");
const poseidon_typed = @import("../../air/lang/typed_poseidon2.zig");
const poseidon_witness = @import("../../air/lang/typed_poseidon2_witness.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const static_profile = @import("../../air/lang/static_profile.zig");
const types = @import("../../air/lang/types.zig");
const poseidon_production = @import("../../air/memory_commitment/poseidon2_air.zig");
const poseidon_channel = @import("../poseidon2_channel.zig");
const component = @import("vm_public_claim_hash.zig");
const interaction_mod = @import("vm_public_claim_hash_relation.zig");
const claim_input = @import("vm_public_claim_input_witness.zig");
const support = @import("test_support.zig");
const universal = @import("universal_challenges.zig");
const witness = @import("vm_public_claim_hash_witness.zig");

const SHAPE = claim_input.Shape{ .max_input_words = 2, .max_output_words = 2 };
const WORD_COUNT = claim_input.FIXED_CLAIM_WORDS +
    2 * claim_input.INPUT_SLOT_WORDS + 2 * claim_input.OUTPUT_SLOT_WORDS;
const HASH_ROW_COUNT = (WORD_COUNT + 1 + component.RATE - 1) / component.RATE;

// Shared fixtures and mutation helpers for this conformance suite.

pub const Fixture = struct {
    claim_preprocessing: claim_input.Preprocessed,
    preprocessing: witness.Preprocessed,
    words: [WORD_COUNT]M31,

    pub fn init(allocator: std.mem.Allocator) !Fixture {
        var claim_preprocessing = try claim_input.Preprocessed.init(allocator, SHAPE);
        errdefer claim_preprocessing.deinit();
        var preprocessing = try witness.Preprocessed.init(allocator, &claim_preprocessing);
        errdefer preprocessing.deinit();
        return .{
            .words = fixtureWords(&claim_preprocessing),
            .claim_preprocessing = claim_preprocessing,
            .preprocessing = preprocessing,
        };
    }

    pub fn deinit(self: *Fixture) void {
        self.preprocessing.deinit();
        self.claim_preprocessing.deinit();
        self.* = undefined;
    }
};

pub fn fixtureWords(preprocessing: *const claim_input.Preprocessed) [WORD_COUNT]M31 {
    var result: [WORD_COUNT]M31 = undefined;
    for (&result, preprocessing.rows, 0..) |*value, row, index| value.* = switch (row.kind) {
        .constant => |constant| M31.fromCanonical(constant),
        .boolean => M31.fromCanonical(@intCast(index & 1)),
        .u16 => M31.fromCanonical(@intCast((index * 17 + 3) & 0xffff)),
        .field => M31.fromCanonical(@intCast(index * 101 + 7)),
    };
    return result;
}

pub fn expectSatisfied(
    definition: *const component.Definition,
    inputs: [component.LOGICAL_INPUT_COUNT]M31,
) !void {
    const evaluated = try support.evaluateArena(
        std.testing.allocator,
        &definition.arena,
        &inputs,
    );
    defer std.testing.allocator.free(evaluated);
    for (definition.constraints) |constraint_id| {
        const constraint = definition.arena.constraint(constraint_id).?;
        try std.testing.expect(evaluated[types.idIndex(constraint.root)].isZero());
    }
}

pub fn expectRejected(
    definition: *const component.Definition,
    inputs: [component.LOGICAL_INPUT_COUNT]M31,
) !void {
    const evaluated = try support.evaluateArena(
        std.testing.allocator,
        &definition.arena,
        &inputs,
    );
    defer std.testing.allocator.free(evaluated);
    var rejected = false;
    for (definition.constraints) |constraint_id| {
        const constraint = definition.arena.constraint(constraint_id).?;
        rejected = rejected or !evaluated[types.idIndex(constraint.root)].isZero();
    }
    try std.testing.expect(rejected);
}

pub fn completeRelationSum(
    definition: *const component.Definition,
    plan: *const interaction_mod.Plan,
    fixture: *const Fixture,
    main: *const witness.MainWitness,
    relations: *const universal.UniversalRelations,
    tamper_previous: bool,
) !QM31 {
    var sum = QM31.zero();
    for (main.rows, fixture.preprocessing.rows, 0..) |main_row_value, metadata, index| {
        var main_row = main_row_value;
        if (tamper_previous and index == 1)
            main_row.previous[0] = main_row.previous[0].add(M31.one());
        const entries = try plan.entries(
            &definition.arena,
            component.SEMANTIC_DIGEST,
            definition.events,
            witness.logicalInputs(main_row, metadata, .segment_leaf),
        );
        for (entries) |entry| {
            if (entry.numerator.isZero()) continue;
            const denominator = try relations.get(entry.domain).combineSecure(
                entry.values[0..entry.arity],
            );
            sum = sum.add(entry.numerator.mul(try denominator.inv()));
        }
    }
    for (fixture.words, 0..) |word, index| sum = sum.add(try sourceTerm(
        relations,
        .recursion_vm_public_claim_word,
        &.{
            M31.fromCanonical(component.VM_CLAIM_HASH_SCOPE),
            M31.fromCanonical(@intCast(index)),
            word,
        },
    ));
    for (main.rows) |row| {
        const input = permutationInput(row);
        sum = sum.add(try sourceTerm(
            relations,
            .poseidon2_io,
            &(input ++ row.output),
        ));
    }
    for (main.output_digest, 0..) |word, limb| sum = sum.add(try sourceTerm(
        relations,
        .recursion_verifier_input_word,
        &.{
            M31.fromCanonical(component.SEGMENT_VERIFIER_ID),
            M31.fromCanonical(component.VM_PUBLIC_CLAIM_DIGEST_INPUT_KIND),
            M31.zero(),
            M31.fromCanonical(@intCast(limb)),
            M31.fromCanonical(word),
        },
    ));
    return sum;
}

pub fn sourceTerm(
    relations: *const universal.UniversalRelations,
    domain: relation.Domain,
    values: []const M31,
) !QM31 {
    return (try relations.get(domain).combineBase(values)).inv();
}

pub fn permutationInput(row: witness.MainRow) [component.STATE_WIDTH]M31 {
    var result = row.previous;
    for (row.chunks, 0..) |word, index| result[index] = result[index].add(word);
    return result;
}

pub fn OwnedColumns(comptime count: usize) type {
    return struct {
        allocator: std.mem.Allocator,
        slab: []M31,
        views: [count][]M31,

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator, len: usize, initial: M31) !Self {
            const slab = try allocator.alloc(M31, count * len);
            errdefer allocator.free(slab);
            @memset(slab, initial);
            var views: [count][]M31 = undefined;
            for (&views, 0..) |*view, index|
                view.* = slab[index * len ..][0..len];
            return .{ .allocator = allocator, .slab = slab, .views = views };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.slab);
            self.* = undefined;
        }
    };
}

pub fn expectPaddingZero(columns: anytype, row_count: usize) !void {
    for (columns.*) |column| for (column[row_count..]) |word|
        try std.testing.expect(word.isZero());
}

pub const PoseidonHarness = struct {
    fixture: PoseidonFixture,
    plan: materializer.Plan,
    binding: compat.OwnedBinding,

    pub fn init(allocator: std.mem.Allocator) !PoseidonHarness {
        var fixture = try PoseidonFixture.init(allocator);
        errdefer fixture.deinit();
        var plan = try fixture.makePlan(allocator);
        errdefer plan.deinit();
        var schedule_value = try compat.generate(allocator);
        defer schedule_value.deinit(allocator);
        const binding = try compat.bindPlan(
            allocator,
            &fixture.arena,
            fixture.definition,
            fixture.spans,
            schedule_value,
            &plan,
        );
        return .{ .fixture = fixture, .plan = plan, .binding = binding };
    }

    pub fn deinit(self: *PoseidonHarness) void {
        self.binding.deinit(self.fixture.arena.allocator);
        self.plan.deinit();
        self.fixture.deinit();
        self.* = undefined;
    }

    pub fn makeExecutor(
        self: *const PoseidonHarness,
        allocator: std.mem.Allocator,
    ) !poseidon_witness.Executor {
        return poseidon_witness.Executor.init(
            allocator,
            &self.fixture.arena,
            self.fixture.definition,
            self.fixture.spans,
            &self.plan,
            &self.binding,
        );
    }
};

pub const PoseidonFixture = struct {
    arena: ir.Arena,
    gate: types.ValueId,
    spans: poseidon_typed.DefinitionSpans,
    definition: poseidon_typed.Definition,

    pub fn init(allocator: std.mem.Allocator) !PoseidonFixture {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();
        const source_id = try arena.addSource("air/components/poseidon2_m31.typed.zig");
        const gate = try arena.input(
            compat.ENABLER_NAME,
            .selector,
            try spanAt(source_id, 1),
        );
        const spans = try distinctSpans(source_id);
        const definition = try poseidon_typed.define(&arena, spans);
        return .{ .arena = arena, .gate = gate, .spans = spans, .definition = definition };
    }

    pub fn deinit(self: *PoseidonFixture) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn makePlan(
        self: *const PoseidonFixture,
        allocator: std.mem.Allocator,
    ) !materializer.Plan {
        const roots = poseidon_typed.values(self.definition.outputs);
        return materializer.plan(allocator, &self.arena, .{
            .roots = &roots,
            .gate = self.gate,
        });
    }
};

pub fn distinctSpans(source_id: types.SourceId) !poseidon_typed.DefinitionSpans {
    var next_line: u32 = 2;
    const declaration = try spanAt(source_id, next_line);
    next_line += 1;
    var inputs: [poseidon_typed.WIDTH]source.SourceSpan = undefined;
    for (&inputs) |*span| {
        span.* = try spanAt(source_id, next_line);
        next_line += 1;
    }
    const initial_linear = try spanAt(source_id, next_line);
    next_line += 1;
    var external: [poseidon_typed.N_EXTERNAL_ROUNDS]poseidon_typed.ExternalRoundSpans = undefined;
    for (&external) |*round| {
        round.* = .{
            .constants = try spanAt(source_id, next_line),
            .sbox = try spanAt(source_id, next_line + 1),
            .linear = try spanAt(source_id, next_line + 2),
        };
        next_line += 3;
    }
    var internal: [poseidon_typed.N_INTERNAL_ROUNDS]poseidon_typed.InternalRoundSpans = undefined;
    for (&internal) |*round| {
        round.* = .{
            .constant = try spanAt(source_id, next_line),
            .sbox = try spanAt(source_id, next_line + 1),
            .linear = try spanAt(source_id, next_line + 2),
        };
        next_line += 3;
    }
    return .{
        .declaration = declaration,
        .inputs = inputs,
        .body = .{
            .initial_linear = initial_linear,
            .external_rounds = external,
            .internal_rounds = internal,
        },
    };
}

pub fn spanAt(source_id: types.SourceId, line: u32) !source.SourceSpan {
    return source.SourceSpan.init(
        source_id,
        .{ .byte_offset = line * 8, .line = line, .column = 1 },
        .{ .byte_offset = line * 8 + 1, .line = line, .column = 2 },
    );
}

pub fn componentFailureCase(allocator: std.mem.Allocator) !void {
    var definition = try component.build(allocator);
    defer definition.deinit();
}

pub fn preprocessingFailureCase(
    allocator: std.mem.Allocator,
    claim_preprocessing: *const claim_input.Preprocessed,
) !void {
    var preprocessing = try witness.Preprocessed.init(allocator, claim_preprocessing);
    defer preprocessing.deinit();
}

pub fn witnessFailureCase(
    allocator: std.mem.Allocator,
    preprocessing: *const witness.Preprocessed,
    words: *const [WORD_COUNT]M31,
) !void {
    var main = try witness.MainWitness.init(
        allocator,
        preprocessing,
        .{ .segment_leaf = words },
    );
    defer main.deinit();
}

pub fn interactionFailureCase(
    allocator: std.mem.Allocator,
    definition: *const component.Definition,
    plan: *const interaction_mod.Plan,
    rows: []const interaction_mod.Row,
    log_size: u32,
    relations: *const universal.UniversalRelations,
) !void {
    var interaction = try plan.generateInteraction(
        allocator,
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        rows,
        log_size,
        relations,
    );
    defer interaction.deinit(allocator);
}
