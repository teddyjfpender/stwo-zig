//! Deterministic protocol diagnostic for heterogeneous lifted composition.
//!
//! This test-only module separates three identities which a mixed-log proof
//! needs simultaneously: canonical domain lifting, PCS-folded trace masks,
//! and recursive split-two composition reconstruction. It mints no proof and
//! leaves the nonproduction bulk-memcpy candidate inactive.

const std = @import("std");
const stwo_core = @import("stwo_core");
const prover_engine = @import("stwo_prover_engine");

const core_air_components = stwo_core.air.components;
const core_constraints = stwo_core.constraints;
const core_proof = stwo_core.proof;
const circle = stwo_core.circle;
const canonic = stwo_core.poly.circle.canonic;
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const MaskPoints = core_air_components.MaskPoints;
const MaskValues = core_air_components.MaskValues;
const CirclePointQM31 = circle.CirclePointQM31;

const prover_accumulation = prover_engine.air.accumulation;
const prover_component = prover_engine.air.component_prover;
const prover_circle = prover_engine.poly.circle;
const SecureColumnByCoords = prover_engine.secure_column.SecureColumnByCoords;

const abi = @import("../../isa/bulk_memcpy_candidate_v1.zig");
const boundary = @import("bulk_memcpy_boundary_candidate_v1.zig");
const caller = @import("bulk_memcpy_caller_candidate_v1.zig");
const contract = @import("bulk_memcpy_component_v1.zig");
const interaction_mod = @import("bulk_memcpy_interaction_v1.zig");
const relations_mod = @import("bulk_memcpy_relations_v1.zig");
const session = @import("../../runner/guest_precompile/bulk_memcpy_session_tape_v1.zig");
const stark_component = @import("bulk_memcpy_stark_component_v1.zig");
const trace_mod = @import("bulk_memcpy_trace_v1.zig");
const words = @import("bulk_memcpy_word_candidate_v1.zig");
const logup = @import("../logup.zig");

pub const production_active = false;
const global_composition_log: u32 = 5;
const aggregate_oods_bound: u32 = global_composition_log -
    stark_component.composition_log_split;
const caller_local_quotient_log: u32 = 1 + stark_component.quotient_expansion_bits;
const caller_fold_count: u32 = aggregate_oods_bound - 1;

pub const Mismatch = enum {
    none,
    canonical_lift_a,
    pcs_folded_row_shift_b,
    pcs_folded_mask_b,
    word_direct_c,
    word_batch_0_c,
    word_batch_1_c,
    word_batch_2_c,
    word_batch_3_c,
    word_component_c,
    caller_active_prefix_preprocessed_c,
    caller_direct_c,
    caller_batch_0_c,
    caller_batch_1_c,
    caller_batch_2_c,
    caller_batch_3_c,
    caller_batch_4_c,
    caller_batch_5_c,
    caller_batch_6_c,
    caller_batch_7_c,
    caller_batch_8_c,
    caller_batch_9_c,
    caller_batch_10_c,
    caller_batch_11_c,
    caller_batch_12_c,
    caller_batch_13_c,
    caller_batch_14_c,
    caller_component_c,
    domain_component_sum_c,
    pcs_component_sum_c,
    mixed_composition_c,
    split_two_not_executed_c,
    split_two_c,
};

pub fn ComponentBreakdown(comptime batch_count: usize) type {
    return struct {
        domain: QM31,
        pcs: QM31,
        direct_domain: QM31,
        direct_pcs: QM31,
        batch_domain: [batch_count]QM31,
        batch_pcs: [batch_count]QM31,
    };
}

pub const CallerDirectClass = enum {
    legacy,
    active_prefix_binding,
};

pub const CallerDirectMismatchV1 = struct {
    index: usize,
    classification: CallerDirectClass,
    domain: QM31,
    pcs: QM31,
};

pub const ResultV1 = struct {
    canonical_lift_at_point: QM31,
    local_quotient_at_folded_point: QM31,
    pcs_caller_constraint_zero_at_point: QM31,
    requested_previous_folded: CirclePointQM31,
    expected_previous_at_folded_point: CirclePointQM31,
    caller_direct_first_mismatch: ?CallerDirectMismatchV1,
    active_prefix_local_at_folded_point: QM31,
    active_prefix_pcs_at_point: QM31,
    caller: ComponentBreakdown(contract.Caller.batch_count),
    word: ComponentBreakdown(contract.Word.batch_count),
    mixed_domain_at_point: QM31,
    mixed_pcs_at_point: QM31,
    mixed_split_two_at_point: QM31,
    split_two_executed: bool,

    pub fn firstMismatch(self: ResultV1) Mismatch {
        if (!self.canonical_lift_at_point.eql(self.local_quotient_at_folded_point))
            return .canonical_lift_a;
        if (!self.requested_previous_folded.eql(self.expected_previous_at_folded_point))
            return .pcs_folded_row_shift_b;
        if (!self.pcs_caller_constraint_zero_at_point.eql(
            self.local_quotient_at_folded_point,
        )) return .pcs_folded_mask_b;
        if (!self.word.direct_domain.eql(self.word.direct_pcs)) return .word_direct_c;
        for (self.word.batch_domain, self.word.batch_pcs, 0..) |domain, pcs, index| {
            if (!domain.eql(pcs)) return switch (index) {
                0 => .word_batch_0_c,
                1 => .word_batch_1_c,
                2 => .word_batch_2_c,
                3 => .word_batch_3_c,
                else => unreachable,
            };
        }
        if (!self.word.domain.eql(self.word.pcs)) return .word_component_c;
        if (self.caller_direct_first_mismatch) |mismatch| {
            if (mismatch.classification == .active_prefix_binding and
                !self.active_prefix_local_at_folded_point.eql(
                    self.active_prefix_pcs_at_point,
                ))
            {
                return .caller_active_prefix_preprocessed_c;
            }
            return .caller_direct_c;
        }
        if (!self.caller.direct_domain.eql(self.caller.direct_pcs)) return .caller_direct_c;
        for (self.caller.batch_domain, self.caller.batch_pcs, 0..) |
            domain,
            pcs,
            index,
        | {
            if (!domain.eql(pcs)) return switch (index) {
                0 => .caller_batch_0_c,
                1 => .caller_batch_1_c,
                2 => .caller_batch_2_c,
                3 => .caller_batch_3_c,
                4 => .caller_batch_4_c,
                5 => .caller_batch_5_c,
                6 => .caller_batch_6_c,
                7 => .caller_batch_7_c,
                8 => .caller_batch_8_c,
                9 => .caller_batch_9_c,
                10 => .caller_batch_10_c,
                11 => .caller_batch_11_c,
                12 => .caller_batch_12_c,
                13 => .caller_batch_13_c,
                14 => .caller_batch_14_c,
                else => unreachable,
            };
        }
        if (!self.caller.domain.eql(self.caller.pcs)) return .caller_component_c;
        if (!self.mixed_domain_at_point.eql(self.caller.domain.add(self.word.domain)))
            return .domain_component_sum_c;
        if (!self.mixed_pcs_at_point.eql(self.caller.pcs.add(self.word.pcs)))
            return .pcs_component_sum_c;
        if (!self.mixed_domain_at_point.eql(self.mixed_pcs_at_point))
            return .mixed_composition_c;
        if (!self.split_two_executed) return .split_two_not_executed_c;
        if (!self.mixed_domain_at_point.eql(self.mixed_split_two_at_point))
            return .split_two_c;
        return .none;
    }

    pub fn validate(self: ResultV1) !void {
        if (self.firstMismatch() != .none) return error.LiftedCompositionDiagnosticMismatch;
    }
};

pub fn run(allocator: std.mem.Allocator) !ResultV1 {
    var tape = try tinyTape(allocator);
    defer tape.deinit();
    var traces = try trace_mod.generate(allocator, &tape);
    defer traces.deinit();
    try traces.validateAgainst(&tape);

    var channel = stwo_core.channel.blake2s.Blake2sChannel{};
    const relations = try relations_mod.Relations.draw(allocator, &channel);
    var pool: prover_engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 2 });
    defer pool.deinit();
    var caller_interaction = try interaction_mod.generate(
        contract.Caller,
        allocator,
        &traces.caller,
        &relations,
        &pool,
    );
    defer caller_interaction.deinit(allocator);
    var word_interaction = try interaction_mod.generate(
        contract.Word,
        allocator,
        &traces.words,
        &relations,
        &pool,
    );
    defer word_interaction.deinit(allocator);

    const caller_claim = try contract.CallerClaim.canonical(
        traces.caller.log_size,
        traces.caller.logical_rows,
        caller_interaction.claims,
    );
    const word_claim = try contract.WordClaim.canonical(
        traces.words.log_size,
        traces.words.logical_rows,
        word_interaction.claims,
    );
    var caller_component = try stark_component.Component(contract.Caller).init(
        caller_claim,
        .{ .preprocessed_offset = 0, .main_offset = 0, .interaction_offset = 0 },
        &relations,
    );
    var word_component = try stark_component.Component(contract.Word).init(
        word_claim,
        .{
            .preprocessed_offset = trace_mod.preprocessed_column_count,
            .main_offset = contract.Caller.main_column_count,
            .interaction_offset = contract.Caller.interaction_column_count,
        },
        &relations,
    );
    const caller_prover = caller_component.asProverComponent();
    const word_prover = word_component.asProverComponent();
    const caller_verifier = caller_component.asVerifierComponent();
    const word_verifier = word_component.asVerifierComponent();

    var committed_trace = try OwnedTrace.init(
        allocator,
        &traces,
        &caller_interaction,
        &word_interaction,
    );
    defer committed_trace.deinit();

    const point = circle.SECURE_FIELD_CIRCLE_GEN.mul(0x12345);
    var local_quotient = try isolatedCallerConstraintZero(
        allocator,
        caller_prover,
        &committed_trace.trace,
    );
    defer local_quotient.deinit();
    var local_poly = try prover_circle.secure_poly.interpolateFromEvaluation(
        allocator,
        canonic.CanonicCoset.new(caller_local_quotient_log).circleDomain(),
        local_quotient.column,
    );
    defer local_poly.deinit(allocator);
    var lifted_evaluation = try canonicalLift(
        allocator,
        local_quotient.column,
        caller_local_quotient_log,
        global_composition_log,
    );
    defer lifted_evaluation.deinit(allocator);
    var lifted_poly = try prover_circle.secure_poly.interpolateFromEvaluation(
        allocator,
        canonic.CanonicCoset.new(global_composition_log).circleDomain(),
        &lifted_evaluation,
    );
    defer lifted_poly.deinit(allocator);
    const folded_point = point.repeatedDouble(caller_fold_count);

    var caller_mask_points = try caller_verifier.maskPoints(
        allocator,
        point,
        aggregate_oods_bound,
    );
    defer caller_mask_points.deinitDeep(allocator);
    var caller_mask_values = try evaluateMasks(
        allocator,
        &committed_trace.trace,
        &caller_mask_points,
        aggregate_oods_bound,
    );
    defer caller_mask_values.deinitDeep(allocator);
    const pcs_constraint_zero = try callerConstraintZeroAtPoint(
        &relations,
        point,
        &caller_mask_values,
    );
    const requested_previous = caller_mask_points.items[1][0][1];
    const requested_previous_folded = requested_previous.repeatedDouble(caller_fold_count);
    const caller_step = logup.liftPoint(
        canonic.CanonicCoset.new(traces.caller.log_size).coset_value.step,
    );
    const expected_previous = folded_point.add(caller_step.mulSigned(-1));

    const random_coeff = QM31.fromU32Unchecked(7, 11, 13, 17);
    const total_constraints = caller_prover.nConstraints() + word_prover.nConstraints();
    const powers = try prover_accumulation.generateSecurePowers(
        allocator,
        random_coeff,
        total_constraints,
    );
    defer allocator.free(powers);
    var accumulator = try prover_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        random_coeff,
        global_composition_log,
        total_constraints,
    );
    defer accumulator.deinit();
    try caller_prover.evaluateConstraintQuotientsOnDomain(
        &committed_trace.trace,
        &accumulator,
    );
    try word_prover.evaluateConstraintQuotientsOnDomain(
        &committed_trace.trace,
        &accumulator,
    );
    var mixed_evaluation = try accumulator.finalize();
    defer mixed_evaluation.deinit(allocator);
    var mixed_poly = try prover_circle.secure_poly.interpolateFromEvaluation(
        allocator,
        canonic.CanonicCoset.new(global_composition_log).circleDomain(),
        &mixed_evaluation,
    );
    defer mixed_poly.deinit(allocator);

    const verifier_components = [_]core_air_components.Component{
        caller_verifier,
        word_verifier,
    };
    const components = core_air_components.Components{
        .components = &verifier_components,
        .n_preprocessed_columns = 2 * trace_mod.preprocessed_column_count,
    };
    var mixed_mask_points = try components.maskPoints(
        allocator,
        point,
        aggregate_oods_bound,
        true,
    );
    defer mixed_mask_points.deinitDeep(allocator);
    var mixed_mask_values = try evaluateMasks(
        allocator,
        &committed_trace.trace,
        &mixed_mask_points,
        aggregate_oods_bound,
    );
    defer mixed_mask_values.deinitDeep(allocator);
    const mixed_pcs = try components.evalCompositionPolynomialAtPoint(
        point,
        &mixed_mask_values,
        random_coeff,
        aggregate_oods_bound,
    );

    const caller_quotients = try pointConstraintQuotients(
        contract.Caller,
        caller_claim,
        .{ .preprocessed_offset = 0, .main_offset = 0, .interaction_offset = 0 },
        &relations,
        point,
        &mixed_mask_values,
        aggregate_oods_bound,
    );
    const word_quotients = try pointConstraintQuotients(
        contract.Word,
        word_claim,
        .{
            .preprocessed_offset = trace_mod.preprocessed_column_count,
            .main_offset = contract.Caller.main_column_count,
            .interaction_offset = contract.Caller.interaction_column_count,
        },
        &relations,
        point,
        &mixed_mask_values,
        aggregate_oods_bound,
    );
    const caller_start = total_constraints;
    const word_start = word_prover.nConstraints();
    const caller_direct_first_mismatch = try firstCallerDirectMismatch(
        allocator,
        caller_prover,
        &committed_trace.trace,
        &caller_quotients,
        point,
    );
    const caller_breakdown = try componentBreakdown(
        contract.Caller,
        allocator,
        caller_prover,
        &committed_trace.trace,
        powers,
        caller_start,
        &caller_quotients,
        point,
    );
    const word_breakdown = try componentBreakdown(
        contract.Word,
        allocator,
        word_prover,
        &committed_trace.trace,
        powers,
        word_start,
        &word_quotients,
        point,
    );

    var result = ResultV1{
        .canonical_lift_at_point = lifted_poly.evalAtPoint(point),
        .local_quotient_at_folded_point = local_poly.evalAtPoint(folded_point),
        .pcs_caller_constraint_zero_at_point = pcs_constraint_zero,
        .requested_previous_folded = requested_previous_folded,
        .expected_previous_at_folded_point = expected_previous,
        .caller_direct_first_mismatch = caller_direct_first_mismatch,
        .active_prefix_local_at_folded_point = committed_trace.trace.polys.items[0][trace_mod.active_prefix_column].coefficients.?.evalAtPoint(folded_point),
        .active_prefix_pcs_at_point = mixed_mask_values.items[0][trace_mod.active_prefix_column][0],
        .caller = caller_breakdown,
        .word = word_breakdown,
        .mixed_domain_at_point = mixed_poly.evalAtPoint(point),
        .mixed_pcs_at_point = mixed_pcs,
        .mixed_split_two_at_point = QM31.zero(),
        .split_two_executed = false,
    };
    if (compositionParityBeforeSplit(result)) {
        var chunks = try mixed_poly.splitIntoChunks(
            allocator,
            stark_component.composition_log_split,
        );
        defer chunks.deinit(allocator);
        var chunk_values: [4]QM31 = undefined;
        for (chunks.chunks, &chunk_values) |chunk, *value|
            value.* = chunk.evalAtPoint(point);
        result.mixed_split_two_at_point =
            core_proof.reconstructCompositionChunkEvals(
                &chunk_values,
                point,
                global_composition_log,
                stark_component.composition_log_split,
            ) orelse return error.InvalidSplitTwoDiagnostic;
        result.split_two_executed = true;
    }
    return result;
}

fn compositionParityBeforeSplit(result: ResultV1) bool {
    if (!result.word.direct_domain.eql(result.word.direct_pcs)) return false;
    for (result.word.batch_domain, result.word.batch_pcs) |domain, pcs|
        if (!domain.eql(pcs)) return false;
    if (!result.word.domain.eql(result.word.pcs)) return false;
    if (result.caller_direct_first_mismatch != null) return false;
    if (!result.caller.direct_domain.eql(result.caller.direct_pcs)) return false;
    for (result.caller.batch_domain, result.caller.batch_pcs) |domain, pcs|
        if (!domain.eql(pcs)) return false;
    if (!result.caller.domain.eql(result.caller.pcs)) return false;
    if (!result.mixed_domain_at_point.eql(result.caller.domain.add(result.word.domain)))
        return false;
    if (!result.mixed_pcs_at_point.eql(result.caller.pcs.add(result.word.pcs)))
        return false;
    return result.mixed_domain_at_point.eql(result.mixed_pcs_at_point);
}

fn firstCallerDirectMismatch(
    allocator: std.mem.Allocator,
    component: prover_component.ComponentProver,
    trace: *const prover_component.Trace,
    point_quotients: *const [
        contract.Caller.direct_constraint_count +
            contract.Caller.batch_count
    ]QM31,
    point: CirclePointQM31,
) !?CallerDirectMismatchV1 {
    if (component.nConstraints() != point_quotients.len or
        boundary.CallerOrder.legacy_start != 0 or
        boundary.CallerOrder.active_binding != contract.Caller.direct_constraint_count - 1 or
        boundary.CallerOrder.end != contract.Caller.direct_constraint_count)
    {
        return error.InvalidCallerOrderGeometry;
    }
    for (boundary.CallerOrder.legacy_start..boundary.CallerOrder.end) |index| {
        const domain = try domainUnitConstraintAtPoint(
            allocator,
            component,
            trace,
            index,
            point,
        );
        const pcs = point_quotients[index];
        if (!domain.eql(pcs)) return .{
            .index = index,
            .classification = if (index < boundary.CallerOrder.active_binding)
                .legacy
            else
                .active_prefix_binding,
            .domain = domain,
            .pcs = pcs,
        };
    }
    return null;
}

fn domainUnitConstraintAtPoint(
    allocator: std.mem.Allocator,
    component: prover_component.ComponentProver,
    trace: *const prover_component.Trace,
    constraint: usize,
    point: CirclePointQM31,
) !QM31 {
    const component_constraints = component.nConstraints();
    if (constraint >= component_constraints)
        return error.InvalidDiagnosticConstraintGeometry;
    const filtered = try allocator.alloc(QM31, component_constraints);
    defer allocator.free(filtered);
    @memset(filtered, QM31.zero());
    filtered[component_constraints - 1 - constraint] = QM31.one();
    return evaluateFilteredComponent(
        allocator,
        component,
        trace,
        filtered,
        component_constraints,
        point,
    );
}

fn componentBreakdown(
    comptime Config: type,
    allocator: std.mem.Allocator,
    component: prover_component.ComponentProver,
    trace: *const prover_component.Trace,
    powers: []const QM31,
    start_power_index: usize,
    point_quotients: *const [Config.direct_constraint_count + Config.batch_count]QM31,
    point: CirclePointQM31,
) !ComponentBreakdown(Config.batch_count) {
    const constraint_count = Config.direct_constraint_count + Config.batch_count;
    if (component.nConstraints() != constraint_count or
        start_power_index < constraint_count or start_power_index > powers.len)
    {
        return error.InvalidDiagnosticConstraintGeometry;
    }
    var result: ComponentBreakdown(Config.batch_count) = undefined;
    result.domain = try domainGroupContribution(
        allocator,
        component,
        trace,
        powers,
        start_power_index,
        0,
        constraint_count,
        point,
    );
    result.pcs = weightedPointGroup(
        point_quotients,
        powers,
        start_power_index,
        0,
        constraint_count,
    );
    result.direct_domain = try domainGroupContribution(
        allocator,
        component,
        trace,
        powers,
        start_power_index,
        0,
        Config.direct_constraint_count,
        point,
    );
    result.direct_pcs = weightedPointGroup(
        point_quotients,
        powers,
        start_power_index,
        0,
        Config.direct_constraint_count,
    );
    for (0..Config.batch_count) |batch| {
        const constraint = Config.direct_constraint_count + batch;
        result.batch_domain[batch] = try domainGroupContribution(
            allocator,
            component,
            trace,
            powers,
            start_power_index,
            constraint,
            1,
            point,
        );
        result.batch_pcs[batch] = weightedPointGroup(
            point_quotients,
            powers,
            start_power_index,
            constraint,
            1,
        );
    }
    return result;
}

fn domainGroupContribution(
    allocator: std.mem.Allocator,
    component: prover_component.ComponentProver,
    trace: *const prover_component.Trace,
    powers: []const QM31,
    start_power_index: usize,
    first_constraint: usize,
    constraint_count: usize,
    point: CirclePointQM31,
) !QM31 {
    const component_constraints = component.nConstraints();
    if (start_power_index < component_constraints or
        start_power_index > powers.len or
        first_constraint > component_constraints or
        constraint_count > component_constraints - first_constraint)
    {
        return error.InvalidDiagnosticConstraintGeometry;
    }
    const filtered = try allocator.dupe(QM31, powers);
    defer allocator.free(filtered);
    @memset(filtered, QM31.zero());
    for (first_constraint..first_constraint + constraint_count) |constraint| {
        const power_index = start_power_index - 1 - constraint;
        filtered[power_index] = powers[power_index];
    }
    return evaluateFilteredComponent(
        allocator,
        component,
        trace,
        filtered,
        start_power_index,
        point,
    );
}

fn evaluateFilteredComponent(
    allocator: std.mem.Allocator,
    component: prover_component.ComponentProver,
    trace: *const prover_component.Trace,
    filtered: []QM31,
    start_power_index: usize,
    point: CirclePointQM31,
) !QM31 {
    const component_constraints = component.nConstraints();
    var accumulator = try prover_accumulation.DomainEvaluationAccumulator.initForComponent(
        filtered,
        allocator,
        global_composition_log,
        start_power_index,
    );
    defer accumulator.deinit();
    try component.evaluateConstraintQuotientsOnDomain(trace, &accumulator);
    if (accumulator.next_power_index != start_power_index - component_constraints)
        return error.InvalidDiagnosticPowerConsumption;
    // This diagnostic deliberately runs one component in isolation. Its
    // coefficients already carry their global positions, so no unconsumed
    // sibling component remains to evaluate before canonical finalization.
    accumulator.next_power_index = 0;
    var evaluation = try accumulator.finalize();
    defer evaluation.deinit(allocator);
    var poly = try prover_circle.secure_poly.interpolateFromEvaluation(
        allocator,
        canonic.CanonicCoset.new(global_composition_log).circleDomain(),
        &evaluation,
    );
    defer poly.deinit(allocator);
    return poly.evalAtPoint(point);
}

fn weightedPointGroup(
    quotients: anytype,
    powers: []const QM31,
    start_power_index: usize,
    first_constraint: usize,
    constraint_count: usize,
) QM31 {
    var result = QM31.zero();
    for (first_constraint..first_constraint + constraint_count) |constraint| {
        result = result.add(quotients[constraint].mul(
            powers[start_power_index - 1 - constraint],
        ));
    }
    return result;
}

fn pointConstraintQuotients(
    comptime Config: type,
    claim: contract.Claim(Config),
    placement: stark_component.Placement,
    relations: *const relations_mod.Relations,
    point: CirclePointQM31,
    mask: *const MaskValues,
    max_log_degree_bound: u32,
) ![Config.direct_constraint_count + Config.batch_count]QM31 {
    const constraint_count = Config.direct_constraint_count + Config.batch_count;
    if (mask.items.len < 3 or max_log_degree_bound < claim.log_size)
        return error.InvalidDiagnosticMask;
    const preprocessed = mask.items[0];
    const main_mask = mask.items[1];
    const secure = mask.items[2];
    if (preprocessed.len < placement.preprocessed_offset + trace_mod.preprocessed_column_count or
        main_mask.len < placement.main_offset + Config.main_column_count or
        secure.len < placement.interaction_offset + Config.interaction_column_count)
    {
        return error.InvalidDiagnosticMask;
    }
    var main: [Config.main_column_count]QM31 = undefined;
    var previous: [Config.main_column_count]QM31 = undefined;
    var next: [Config.main_column_count]QM31 = undefined;
    for (0..Config.main_column_count) |column| {
        const values = main_mask[placement.main_offset + column];
        main[column] = try pointAt(values, 0);
        previous[column] = try pointAt(values, 1);
        next[column] = try pointAt(values, 2);
    }
    const pp = placement.preprocessed_offset;
    const domain_first = try pointAt(
        preprocessed[pp + trace_mod.domain_first_column],
        0,
    );
    const domain_last = try pointAt(
        preprocessed[pp + trace_mod.domain_last_column],
        0,
    );
    const active_prefix = try pointAt(
        preprocessed[pp + trace_mod.active_prefix_column],
        0,
    );
    var sink = ConstraintSink(constraint_count){};
    try Config.evaluate(
        QM31,
        &main,
        &previous,
        &next,
        domain_first,
        domain_last,
        active_prefix,
        relations,
        &sink,
    );
    const pairs = Config.rowPairs(QM31, &main, relations);
    for (pairs, 0..) |pair, batch| sink.add(logup.pairConstraint(
        try sampledSecure(secure, placement.interaction_offset + 4 * batch, 0),
        try sampledSecure(secure, placement.interaction_offset + 4 * batch, 1),
        domain_first,
        claim.batch_sums[batch],
        pair,
    ), 3);
    if (sink.index != constraint_count) return error.InvalidDiagnosticConstraintGeometry;
    const denominator_inverse = try core_constraints.cosetVanishing(
        QM31,
        canonic.CanonicCoset.new(claim.log_size).coset(),
        point.repeatedDouble(max_log_degree_bound - claim.log_size),
    ).inv();
    for (&sink.values) |*value| value.* = value.mul(denominator_inverse);
    return sink.values;
}

fn ConstraintSink(comptime constraint_count: usize) type {
    return struct {
        values: [constraint_count]QM31 = [_]QM31{QM31.zero()} ** constraint_count,
        index: usize = 0,

        pub fn add(self: *@This(), value: QM31, degree: u8) void {
            _ = degree;
            std.debug.assert(self.index < constraint_count);
            self.values[self.index] = value;
            self.index += 1;
        }
    };
}

fn pointAt(values: []const QM31, index: usize) !QM31 {
    if (values.len <= index) return error.MissingMaskPoint;
    return values[index];
}

fn sampledSecure(columns: [][]QM31, offset: usize, point_index: usize) !QM31 {
    if (columns.len < offset + 4) return error.InvalidSecureMaskShape;
    return QM31.fromPartialEvals(.{
        try pointAt(columns[offset], point_index),
        try pointAt(columns[offset + 1], point_index),
        try pointAt(columns[offset + 2], point_index),
        try pointAt(columns[offset + 3], point_index),
    });
}

const IsolatedColumn = struct {
    accumulator: prover_accumulation.DomainEvaluationAccumulator,
    column: *const SecureColumnByCoords,

    fn deinit(self: *@This()) void {
        self.accumulator.deinit();
        self.* = undefined;
    }
};

fn isolatedCallerConstraintZero(
    allocator: std.mem.Allocator,
    component: prover_component.ComponentProver,
    trace: *const prover_component.Trace,
) !IsolatedColumn {
    const powers = try allocator.alloc(QM31, component.nConstraints());
    defer allocator.free(powers);
    @memset(powers, QM31.zero());
    powers[powers.len - 1] = QM31.one();
    var accumulator = try prover_accumulation.DomainEvaluationAccumulator.initForComponent(
        powers,
        allocator,
        global_composition_log,
        powers.len,
    );
    errdefer accumulator.deinit();
    try component.evaluateConstraintQuotientsOnDomain(trace, &accumulator);
    if (accumulator.next_power_index != 0 or
        accumulator.sub_accumulations[caller_local_quotient_log] == null)
    {
        return error.MissingCallerLocalQuotient;
    }
    return .{
        .accumulator = accumulator,
        .column = &accumulator.sub_accumulations[caller_local_quotient_log].?,
    };
}

fn canonicalLift(
    allocator: std.mem.Allocator,
    local: *const SecureColumnByCoords,
    local_log: u32,
    global_log: u32,
) !SecureColumnByCoords {
    const size = @as(usize, 1) << @intCast(global_log);
    var result = try SecureColumnByCoords.uninitialized(allocator, size);
    errdefer result.deinit(allocator);
    inline for (0..4) |coordinate| {
        const source = prover_component.Poly{
            .log_size = local_log,
            .values = local.columns[coordinate],
        };
        for (result.columns[coordinate], 0..) |*value, position|
            value.* = try source.valueAtLiftingPosition(global_log, position);
    }
    return result;
}

fn callerConstraintZeroAtPoint(
    relations: *const relations_mod.Relations,
    point: CirclePointQM31,
    mask: *const MaskValues,
) !QM31 {
    if (mask.items.len != 3) return error.InvalidDiagnosticMask;
    const preprocessed = mask.items[0];
    const main_mask = mask.items[1];
    if (preprocessed.len != trace_mod.preprocessed_column_count or
        main_mask.len != contract.Caller.main_column_count)
    {
        return error.InvalidDiagnosticMask;
    }
    var main: [contract.Caller.main_column_count]QM31 = undefined;
    var previous: [contract.Caller.main_column_count]QM31 = undefined;
    var next: [contract.Caller.main_column_count]QM31 = undefined;
    for (main_mask, 0..) |values, column| {
        if (values.len != 3) return error.InvalidDiagnosticMask;
        main[column] = values[0];
        previous[column] = values[1];
        next[column] = values[2];
    }
    var sink = FirstConstraintSink{};
    try contract.Caller.evaluate(
        QM31,
        &main,
        &previous,
        &next,
        preprocessed[trace_mod.domain_first_column][0],
        preprocessed[trace_mod.domain_last_column][0],
        preprocessed[trace_mod.active_prefix_column][0],
        relations,
        &sink,
    );
    const first = sink.first orelse return error.MissingCallerConstraintZero;
    const denominator_inverse = try core_constraints.cosetVanishing(
        QM31,
        canonic.CanonicCoset.new(1).coset(),
        point.repeatedDouble(caller_fold_count),
    ).inv();
    return first.mul(denominator_inverse);
}

const FirstConstraintSink = struct {
    first: ?QM31 = null,

    pub fn add(self: *@This(), value: QM31, degree: u8) void {
        _ = degree;
        if (self.first == null) self.first = value;
    }
};

fn evaluateMasks(
    allocator: std.mem.Allocator,
    trace: *const prover_component.Trace,
    points: *const MaskPoints,
    lifting_log_size: u32,
) !MaskValues {
    if (trace.polys.items.len != points.items.len) return error.InvalidDiagnosticMask;
    const outer = try allocator.alloc([][]QM31, points.items.len);
    var tree_count: usize = 0;
    errdefer {
        for (outer[0..tree_count]) |columns| {
            for (columns) |values| allocator.free(values);
            allocator.free(columns);
        }
        allocator.free(outer);
    }
    for (trace.polys.items, points.items, outer) |polys, tree_points, *tree_values| {
        if (polys.len < tree_points.len) return error.InvalidDiagnosticMask;
        tree_values.* = try allocator.alloc([]QM31, tree_points.len);
        var column_count: usize = 0;
        errdefer {
            for (tree_values.*[0..column_count]) |values| allocator.free(values);
            allocator.free(tree_values.*);
        }
        for (polys[0..tree_points.len], tree_points, tree_values.*) |
            poly,
            column_points,
            *values,
        | {
            if (poly.log_size > lifting_log_size or poly.coefficients == null)
                return error.InvalidDiagnosticPolynomial;
            values.* = try allocator.alloc(QM31, column_points.len);
            for (column_points, values.*) |requested, *value| {
                value.* = poly.coefficients.?.evalAtPoint(
                    requested.repeatedDouble(lifting_log_size - poly.log_size),
                );
            }
            column_count += 1;
        }
        tree_count += 1;
    }
    return MaskValues.initOwned(outer);
}

const OwnedTree = struct {
    allocator: std.mem.Allocator,
    polys: []prover_component.Poly,
    coefficients: []prover_circle.CircleCoefficients,
    initialized: usize = 0,

    fn init(allocator: std.mem.Allocator, count: usize) !OwnedTree {
        const polys = try allocator.alloc(prover_component.Poly, count);
        errdefer allocator.free(polys);
        return .{
            .allocator = allocator,
            .polys = polys,
            .coefficients = try allocator.alloc(prover_circle.CircleCoefficients, count),
        };
    }

    fn append(self: *OwnedTree, log_size: u32, values: []const M31) !void {
        if (self.initialized >= self.polys.len) return error.InvalidDiagnosticTrace;
        const evaluation = try prover_circle.CircleEvaluation.init(
            canonic.CanonicCoset.new(log_size).circleDomain(),
            values,
        );
        const coefficients = try prover_circle.poly.interpolateFromEvaluation(
            self.allocator,
            evaluation,
        );
        self.coefficients[self.initialized] = coefficients;
        self.polys[self.initialized] = .{
            .log_size = log_size,
            .values = values,
            .coefficients = coefficients,
        };
        self.initialized += 1;
    }

    fn finish(self: OwnedTree) !void {
        if (self.initialized != self.polys.len) return error.InvalidDiagnosticTrace;
    }

    fn deinit(self: *OwnedTree) void {
        for (self.coefficients[0..self.initialized]) |*coefficients|
            coefficients.deinit(self.allocator);
        self.allocator.free(self.coefficients);
        self.allocator.free(self.polys);
        self.* = undefined;
    }
};

const OwnedTrace = struct {
    allocator: std.mem.Allocator,
    trees: [3]OwnedTree,
    trace: prover_component.Trace,

    fn init(
        allocator: std.mem.Allocator,
        traces: *const trace_mod.Bundle,
        caller_interaction: *const interaction_mod.Result(contract.Caller),
        word_interaction: *const interaction_mod.Result(contract.Word),
    ) !OwnedTrace {
        var tree0 = try OwnedTree.init(
            allocator,
            2 * trace_mod.preprocessed_column_count,
        );
        errdefer tree0.deinit();
        for (0..trace_mod.preprocessed_column_count) |column|
            try tree0.append(traces.caller.log_size, traces.caller.preprocessedColumn(column));
        for (0..trace_mod.preprocessed_column_count) |column|
            try tree0.append(traces.words.log_size, traces.words.preprocessedColumn(column));
        try tree0.finish();

        var tree1 = try OwnedTree.init(
            allocator,
            contract.Caller.main_column_count + contract.Word.main_column_count,
        );
        errdefer tree1.deinit();
        for (0..contract.Caller.main_column_count) |column|
            try tree1.append(traces.caller.log_size, traces.caller.mainColumn(column));
        for (0..contract.Word.main_column_count) |column|
            try tree1.append(traces.words.log_size, traces.words.mainColumn(column));
        try tree1.finish();

        var tree2 = try OwnedTree.init(
            allocator,
            contract.Caller.interaction_column_count + contract.Word.interaction_column_count,
        );
        errdefer tree2.deinit();
        for (caller_interaction.columns) |column|
            try tree2.append(traces.caller.log_size, column);
        for (word_interaction.columns) |column|
            try tree2.append(traces.words.log_size, column);
        try tree2.finish();

        const outer = try allocator.alloc([]const prover_component.Poly, 3);
        outer[0] = tree0.polys;
        outer[1] = tree1.polys;
        outer[2] = tree2.polys;
        return .{
            .allocator = allocator,
            .trees = .{ tree0, tree1, tree2 },
            .trace = .{
                .polys = stwo_core.pcs.TreeVec([]const prover_component.Poly).initOwned(outer),
            },
        };
    }

    fn deinit(self: *OwnedTrace) void {
        self.allocator.free(self.trace.polys.items);
        for (&self.trees) |*tree| tree.deinit();
        self.* = undefined;
    }
};

fn tinyTape(allocator: std.mem.Allocator) !session.Frozen {
    const record = caller.Record{
        .execution_clock = 1,
        .pc = 0x1000,
        .destination_previous_clock = 0,
        .source_previous_clock = 0,
        .length_previous_clock = 0,
        .destination = 0x2100,
        .source = 0x2000,
        .length = 32,
        .call_index = 0,
    };
    var rows: [8]words.Row = undefined;
    for (&rows, 0..) |*row, index| row.* = try words.materializeRow(
        record.call(),
        @intCast(index),
        .{
            .source_previous_clock = 0,
            .destination_previous_clock = 0,
            .source_bytes = fixtureBytes(@intCast(index), 0x20),
            .destination_before = fixtureBytes(@intCast(index), 0xa0),
        },
    );
    var builder = try session.Builder.init(allocator, 1, rows.len, 0);
    errdefer builder.deinit();
    try builder.reserveOne(rows.len);
    builder.appendAssumeCapacity(abi.fixed_word, record, &rows);
    try builder.validate();
    var result = builder.freeze();
    errdefer result.deinit();
    try result.validate();
    return result;
}

fn fixtureBytes(index: u8, seed: u8) [4]u8 {
    const base = seed +% index *% 4;
    return .{ base, base +% 1, base +% 2, base +% 3 };
}

comptime {
    if (production_active or stark_component.production_active or
        global_composition_log != 5 or aggregate_oods_bound != 3 or
        caller_local_quotient_log != 3 or caller_fold_count != 2)
    {
        @compileError("bulk memcpy lifted-composition diagnostic geometry drifted");
    }
}
