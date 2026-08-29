//! Prover/verifier AIR adapter for exact opcode-family lookup placement.
//!
//! Direct instruction constraints and the main-column declaration remain owned
//! by the semantic component. This adapter borrows those already-opened columns
//! by global offset and owns only its interaction columns. Declaring the main
//! columns here too would duplicate the main tree because core AIR orchestration
//! only aliases preprocessed columns. Every declaration-order relation batch is
//! reconstructed through `opcode_entries.fromMain`.

const std = @import("std");
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const core_air_derive = @import("stwo_core").air.derive;
const core_constraints = @import("stwo_core").constraints;
const circle = @import("stwo_core").circle;
const M31 = @import("stwo_core").fields.m31.M31;
const qm31 = @import("stwo_core").fields.qm31;
const QM31 = qm31.QM31;
const canonic = @import("stwo_core").poly.circle.canonic;
const prover_air_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prepared_domain = @import("stwo_prover_engine").air.prepared_domain;
const work_pool = @import("stwo_prover_engine").work_pool;
const composition_work_support = @import("../composition_work_support.zig");
const logup = @import("../logup.zig");
const relations_mod = @import("../relation_challenges.zig");
const trace = @import("../../runner/trace.zig");
const entry = @import("entry.zig");
const opcode_entries = @import("opcode_entries.zig");
const opcode_interaction = @import("opcode_interaction.zig");
const runtime_program = @import("../extract/runtime_program.zig");
const selected_batching = @import("../lang/lookup_batch_execution.zig");
const batch_planner = @import("../lang/lookup_batch_planner.zig");
const physical_v2 = @import("../lang/lookup_physical_manifest_v2.zig");
const polynomial_v2 = @import("../lang/lookup_polynomial_program_v2.zig");
const composition_manifest = @import("../lang/opcode_composition_manifest.zig");
const row_window = @import("../lang/row_window.zig");
const mask_points = @import("opcode_component_mask_points.zig");
const prepared_domain_executor = @import("opcode_component_prepared_domain.zig");

const CirclePointQM31 = circle.CirclePointQM31;
pub const PARALLEL_DOMAIN_ROWS = prepared_domain_executor.PARALLEL_DOMAIN_ROWS;

pub const PreparedParallelTelemetrySnapshot = prepared_domain_executor.TelemetrySnapshot;

pub fn preparedParallelTelemetrySnapshot() PreparedParallelTelemetrySnapshot {
    return prepared_domain_executor.telemetrySnapshot();
}

pub const Evaluation = struct {
    values: [entry.MAX_BATCHES]QM31 = .{QM31.zero()} ** entry.MAX_BATCHES,
    len: usize = 0,

    pub fn allZero(self: Evaluation) bool {
        for (self.values[0..self.len]) |value| {
            if (!value.isZero()) return false;
        }
        return true;
    }
};

pub const OpcodeLookupComponent = struct {
    const Batching = enum { compatibility, compiler_selected };

    family: trace.OpcodeFamily,
    log_size: u32,
    is_first_col_idx: usize,
    main_col_offset: usize,
    interaction_col_offset: usize,
    relations: *const relations_mod.Relations,
    claims: [entry.MAX_BATCHES]QM31,
    batching: Batching = .compatibility,
    batch_count: u8,
    selected_batches: [entry.MAX_BATCHES]prover_component.LookupPolynomialBatchV2 = undefined,
    selected_plan_digest: batch_planner.Digest = .{0} ** 32,
    selected_v2_authority: ?prover_component.LookupPolynomialAuthorityV2 = null,
    mask_binding: row_window.ComponentMaskBinding,

    const Adapter = core_air_derive.ComponentAdapter(
        @This(),
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_air_accumulation.DomainEvaluationAccumulator,
    );

    pub fn initVerifier(
        family: trace.OpcodeFamily,
        log_size: u32,
        is_first_col_idx: usize,
        main_col_offset: usize,
        interaction_col_offset: usize,
        relations: *const relations_mod.Relations,
        claims: []const QM31,
    ) !OpcodeLookupComponent {
        return init(
            family,
            log_size,
            is_first_col_idx,
            main_col_offset,
            interaction_col_offset,
            relations,
            claims,
        );
    }

    pub fn initProver(
        family: trace.OpcodeFamily,
        log_size: u32,
        is_first_col_idx: usize,
        main_col_offset: usize,
        interaction_col_offset: usize,
        relations: *const relations_mod.Relations,
        claims: []const QM31,
    ) !OpcodeLookupComponent {
        return init(
            family,
            log_size,
            is_first_col_idx,
            main_col_offset,
            interaction_col_offset,
            relations,
            claims,
        );
    }

    /// Research-only candidate constructor. The selected plan deliberately
    /// disables the compatibility backend capability; production activation
    /// requires a versioned polynomial-program ABI and statement identity.
    pub fn initSelectedVerifier(
        family_plan: *const selected_batching.FamilyPlan,
        log_size: u32,
        is_first_col_idx: usize,
        main_col_offset: usize,
        interaction_col_offset: usize,
        relations: *const relations_mod.Relations,
        claims: []const QM31,
    ) !OpcodeLookupComponent {
        return initSelected(
            family_plan,
            log_size,
            is_first_col_idx,
            main_col_offset,
            interaction_col_offset,
            relations,
            claims,
        );
    }

    pub fn initSelectedProver(
        family_plan: *const selected_batching.FamilyPlan,
        log_size: u32,
        is_first_col_idx: usize,
        main_col_offset: usize,
        interaction_col_offset: usize,
        relations: *const relations_mod.Relations,
        claims: []const QM31,
    ) !OpcodeLookupComponent {
        return initSelected(
            family_plan,
            log_size,
            is_first_col_idx,
            main_col_offset,
            interaction_col_offset,
            relations,
            claims,
        );
    }

    /// Dormant V2 backend seam. Only a pinned native selected plan may publish
    /// the capability, and the exported program is revalidated against this
    /// exact pointer-free authority before a backend can prepare it.
    pub fn initSelectedProverV2(
        family_plan: *const selected_batching.FamilyPlan,
        authority: prover_component.LookupPolynomialAuthorityV2,
        log_size: u32,
        is_first_col_idx: usize,
        main_col_offset: usize,
        interaction_col_offset: usize,
        relations: *const relations_mod.Relations,
        claims: []const QM31,
    ) !OpcodeLookupComponent {
        try authority.validate();
        try family_plan.validate();
        if (family_plan.expected_plan_digest_hex == null or
            !std.mem.eql(
                u8,
                &authority.component_identity,
                &family_plan.selection.program_digest,
            ) or !std.mem.eql(
            u8,
            &authority.partition_identity,
            &family_plan.selection.plan_digest,
        ) or authority.entry_count != family_plan.selection.event_count or
            authority.batch_count != family_plan.selection.score.batch_count or
            authority.interaction_column_count !=
                family_plan.selection.score.interaction_columns or
            authority.maximum_interaction_degree !=
                family_plan.selection.score.maximum_interaction_degree)
        {
            return error.InvalidSelectedV2Authority;
        }
        var result = try initSelected(
            family_plan,
            log_size,
            is_first_col_idx,
            main_col_offset,
            interaction_col_offset,
            relations,
            claims,
        );
        result.selected_v2_authority = authority;
        return result;
    }

    /// Allocation-free construction from the versioned physical statement.
    /// The complete entry is compared with the pinned native record before any
    /// geometry is copied; no typed arena or batch planner runs on this path.
    pub fn initAuthenticatedPhysicalV2(
        physical: *const physical_v2.FamilyEntry,
        log_size: u32,
        is_first_col_idx: usize,
        main_col_offset: usize,
        interaction_col_offset: usize,
        relations: *const relations_mod.Relations,
        claims: []const QM31,
    ) !OpcodeLookupComponent {
        try physical_v2.validatePinnedEntry(physical);
        const n_batches: usize = @intCast(physical.detailed_claim_count);
        if (n_batches == 0 or n_batches > entry.MAX_BATCHES or
            claims.len != n_batches or
            physical.main_column_count !=
                composition_manifest.mainColumnCount(physical.family) or
            physical.interaction_column_count != 4 * n_batches)
        {
            return error.InvalidTraceShape;
        }
        var stored_claims = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
        @memcpy(stored_claims[0..n_batches], claims);
        var stored_batches: [entry.MAX_BATCHES]prover_component.LookupPolynomialBatchV2 = undefined;
        @memcpy(stored_batches[0..n_batches], physical.activeBatches());
        const mask_binding =
            try row_window.ComponentMaskBinding.initCompilerSelected(
                physical.family,
                physical.lookup_authority.partition_identity,
                physical.interaction_column_count,
            );
        return .{
            .family = physical.family,
            .log_size = log_size,
            .is_first_col_idx = is_first_col_idx,
            .main_col_offset = main_col_offset,
            .interaction_col_offset = interaction_col_offset,
            .relations = relations,
            .claims = stored_claims,
            .batching = .compiler_selected,
            .batch_count = @intCast(n_batches),
            .selected_batches = stored_batches,
            .selected_plan_digest = physical.lookup_authority.partition_identity,
            .selected_v2_authority = physical.lookup_authority,
            .mask_binding = mask_binding,
        };
    }

    fn init(
        family: trace.OpcodeFamily,
        log_size: u32,
        is_first_col_idx: usize,
        main_col_offset: usize,
        interaction_col_offset: usize,
        relations: *const relations_mod.Relations,
        claims: []const QM31,
    ) !OpcodeLookupComponent {
        const n_batches = opcode_entries.batchCount(family);
        if (claims.len != n_batches) return error.InvalidTraceShape;
        var stored_claims = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
        @memcpy(stored_claims[0..n_batches], claims);
        const mask_binding = try row_window.ComponentMaskBinding.initCompatibility(
            family,
        );
        return .{
            .family = family,
            .log_size = log_size,
            .is_first_col_idx = is_first_col_idx,
            .main_col_offset = main_col_offset,
            .interaction_col_offset = interaction_col_offset,
            .relations = relations,
            .claims = stored_claims,
            .batch_count = @intCast(n_batches),
            .mask_binding = mask_binding,
        };
    }

    fn initSelected(
        family_plan: *const selected_batching.FamilyPlan,
        log_size: u32,
        is_first_col_idx: usize,
        main_col_offset: usize,
        interaction_col_offset: usize,
        relations: *const relations_mod.Relations,
        claims: []const QM31,
    ) !OpcodeLookupComponent {
        try family_plan.validate();
        const n_batches = family_plan.batchCount();
        if (n_batches == 0 or n_batches > entry.MAX_BATCHES or
            claims.len != n_batches)
        {
            return error.InvalidTraceShape;
        }
        var stored_claims = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
        @memcpy(stored_claims[0..n_batches], claims);
        var stored_batches: [entry.MAX_BATCHES]prover_component.LookupPolynomialBatchV2 = undefined;
        for (
            family_plan.selection.batches,
            stored_batches[0..n_batches],
        ) |source_batch, *stored_batch| {
            stored_batch.* = .{
                .first_entry = source_batch.first_event,
                .entry_count = source_batch.event_count,
                .interaction_degree = source_batch.terms.final,
            };
        }
        const mask_binding =
            try row_window.ComponentMaskBinding.initCompilerSelected(
                family_plan.family,
                family_plan.selection.plan_digest,
                4 * n_batches,
            );
        return .{
            .family = family_plan.family,
            .log_size = log_size,
            .is_first_col_idx = is_first_col_idx,
            .main_col_offset = main_col_offset,
            .interaction_col_offset = interaction_col_offset,
            .relations = relations,
            .claims = stored_claims,
            .batching = .compiler_selected,
            .batch_count = @intCast(n_batches),
            .selected_batches = stored_batches,
            .selected_plan_digest = family_plan.selection.plan_digest,
            .mask_binding = mask_binding,
        };
    }

    pub fn asProverComponent(self: *const @This()) prover_component.ComponentProver {
        var component = Adapter.asProverComponent(self);
        component.composition_work_profile = compositionWorkProfileErased;
        component.oods_work_profile = oodsWorkProfileErased;
        if (self.batching == .compatibility) {
            component.backend_composition_capability = .{
                .lookup_polynomial_v1 = .{
                    .program_id = (@as(u64, 2) << 32) | @intFromEnum(self.family),
                    .trace_log_size = self.log_size,
                    .selector_tree_index = 0,
                    .selector_column = self.is_first_col_idx,
                    .main_tree_index = 1,
                    .first_main_column = self.main_col_offset,
                    .main_column_count = self.mask_binding.borrowed_main_current_columns,
                    .interaction_tree_index = 2,
                    .first_interaction_column = self.interaction_col_offset,
                    .interaction_column_count = self.interactionColumnCount(),
                    .export_program = exportRuntimeProgram,
                    .export_parameters = exportRuntimeParameters,
                },
            };
        } else if (self.selected_v2_authority) |*authority| {
            component.backend_composition_capability = .{
                .lookup_polynomial_v2 = .{
                    .authority = authority,
                    .trace_log_size = self.log_size,
                    .selector_tree_index = 0,
                    .selector_column = self.is_first_col_idx,
                    .main_tree_index = 1,
                    .first_main_column = self.main_col_offset,
                    .main_column_count = self.mask_binding.borrowed_main_current_columns,
                    .interaction_tree_index = 2,
                    .first_interaction_column = self.interaction_col_offset,
                    .interaction_column_count = self.interactionColumnCount(),
                    .export_program = exportRuntimeProgramV2,
                    .export_parameters = exportRuntimeParameters,
                },
            };
        }
        component.prepare_domain_evaluator = prepareDomainEvaluatorErased;
        return component;
    }

    fn oodsWorkProfileErased(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
        max_log_degree_bound: u32,
        source: *const composition_work_support.ComponentProfile,
    ) anyerror!composition_work_support.OodsComponentProfile {
        _ = allocator;
        const self: *const OpcodeLookupComponent = @ptrCast(@alignCast(ctx));
        return composition_work_support.oodsProfile(
            source,
            self.log_size,
            max_log_degree_bound,
            2 * self.nConstraints(),
            true,
        );
    }

    fn compositionWorkProfileErased(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror!@import("stwo_prover_engine").air.composition_work.ComponentProfile {
        const self: *const OpcodeLookupComponent = @ptrCast(@alignCast(ctx));
        return switch (self.batching) {
            .compatibility => blk: {
                var program = try runtime_program.buildLookups(
                    allocator,
                    self.family,
                );
                defer program.deinit();
                break :blk try composition_work_support.lookupProgramProfile(
                    allocator,
                    "riscv-opcode-lookup-runtime-program-v1",
                    self.maxConstraintLogDegreeBound(),
                    program,
                );
            },
            .compiler_selected => blk: {
                var program = try exportRuntimeProgramV2(ctx, allocator);
                defer program.deinit();
                break :blk try composition_work_support.lookupProgramV2Profile(
                    allocator,
                    "riscv-opcode-lookup-runtime-program-v2",
                    self.maxConstraintLogDegreeBound(),
                    program,
                );
            },
        };
    }

    fn prepareDomainEvaluatorErased(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
        trace_data: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) anyerror!prepared_domain.PreparedDomainEvaluation {
        const self: *const @This() = @ptrCast(@alignCast(ctx));
        return self.prepareDomainEvaluator(allocator, trace_data, accumulator);
    }

    fn exportRuntimeProgram(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) !prover_component.OwnedLookupPolynomialProgram {
        const self: *const OpcodeLookupComponent = @ptrCast(@alignCast(ctx));
        return runtime_program.buildLookups(allocator, self.family);
    }

    fn exportRuntimeProgramV2(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) !prover_component.OwnedLookupPolynomialProgramV2 {
        const self: *const OpcodeLookupComponent = @ptrCast(@alignCast(ctx));
        const authority = self.selected_v2_authority orelse
            return error.MissingSelectedV2Authority;
        if (self.batching != .compiler_selected or
            !std.mem.eql(
                u8,
                &authority.partition_identity,
                &self.selected_plan_digest,
            ))
        {
            return error.InvalidSelectedV2Authority;
        }
        var plan = try selected_batching.FamilyPlan.initNativeV1(
            allocator,
            self.family,
        );
        defer plan.deinit();
        if (!std.mem.eql(
            u8,
            &plan.selection.plan_digest,
            &self.selected_plan_digest,
        )) return error.InvalidSelectedV2Authority;
        if (plan.selection.batches.len != self.batch_count)
            return error.InvalidSelectedV2Authority;
        for (
            plan.selection.batches,
            self.selected_batches[0..self.batch_count],
        ) |actual, expected| {
            if (actual.first_event != expected.first_entry or
                actual.event_count != expected.entry_count or
                actual.terms.final != expected.interaction_degree)
            {
                return error.InvalidSelectedV2Authority;
            }
        }
        var program = try polynomial_v2.lowerSelected(allocator, &plan);
        errdefer program.deinit();
        try program.validateAgainst(&authority);
        return program;
    }

    fn exportRuntimeParameters(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) ![]QM31 {
        const self: *const OpcodeLookupComponent = @ptrCast(@alignCast(ctx));
        var sampled = [_]QM31{QM31.zero()} ** trace.MAX_FAMILY_COLUMNS;
        const lookups = try opcode_entries.fromMain(
            self.family,
            sampled[0..@as(
                usize,
                self.mask_binding.borrowed_main_current_columns,
            )],
        );
        var parameters = std.ArrayList(QM31).empty;
        errdefer parameters.deinit(allocator);
        for (lookups.entries[0..lookups.len]) |lookup|
            try entry.appendRelationParameters(
                &parameters,
                allocator,
                self.relations,
                lookup.domain,
            );
        try parameters.appendSlice(allocator, self.claims[0..self.nConstraints()]);
        return parameters.toOwnedSlice(allocator);
    }

    pub fn asVerifierComponent(self: *const @This()) core_air_components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn nConstraints(self: *const @This()) usize {
        return self.batch_count;
    }

    pub fn interactionColumnCount(self: *const @This()) usize {
        return @as(
            usize,
            self.mask_binding.owned_interaction_current_previous_columns,
        );
    }

    /// Exact PCS view for this adapter. Compatibility mode is fixed by the
    /// typed composition manifest; compiler-selected research mode may vary
    /// only the authenticated interaction width.
    fn maskGeometry(self: *const @This()) !composition_manifest.AdapterMasks {
        try self.mask_binding.validate();
        const authority = composition_manifest.lookupMasks(self.family).*;
        if (self.mask_binding.family != self.family or
            @as(usize, self.mask_binding.preprocessed_current_columns) !=
                authority.preprocessed.columns or
            @as(usize, self.mask_binding.borrowed_main_current_columns) !=
                authority.main.columns)
        {
            return error.InvalidWindowDigest;
        }

        var result = authority;
        switch (self.mask_binding.mode) {
            .compatibility => {
                if (self.batching != .compatibility or
                    self.interactionColumnCount() != authority.interaction.columns)
                {
                    return error.InvalidWindowDigest;
                }
            },
            .compiler_selected => {
                if (self.batching != .compiler_selected)
                    return error.InvalidWindowDigest;
                result.interaction.columns = self.interactionColumnCount();
                result.interaction.declared_columns = self.interactionColumnCount();
            },
        }
        return result;
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log_size + 1;
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const masks = try self.maskGeometry();
        const preprocessed = try allocator.alloc(
            u32,
            masks.preprocessed.declared_columns,
        );
        errdefer allocator.free(preprocessed);
        @memset(preprocessed, self.log_size);
        // The semantic component owns these shared main columns. Main-tree
        // bounds are concatenated by core orchestration, so aliases must not be
        // declared a second time.
        const main = try allocator.alloc(u32, masks.main.declared_columns);
        errdefer allocator.free(main);
        const secure = try allocator.alloc(
            u32,
            masks.interaction.declared_columns,
        );
        errdefer allocator.free(secure);
        @memset(secure, self.log_size);
        return core_air_components.TraceLogDegreeBounds.initOwned(
            try allocator.dupe([]u32, &.{ preprocessed, main, secure }),
        );
    }

    pub fn maskPoints(
        self: *const @This(),
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        max_log_degree_bound: u32,
    ) !core_air_components.MaskPoints {
        const masks = try self.maskGeometry();
        if (max_log_degree_bound < self.log_size) return error.InvalidProofShape;
        const preprocessed = try mask_points.currentPointColumns(
            allocator,
            masks.preprocessed.declared_columns,
            point,
        );
        errdefer mask_points.freePointColumns(allocator, preprocessed);
        // The semantic owner already requests the shared main columns at the
        // current point. Returning them here would append duplicate masks.
        const main = try mask_points.currentPointColumns(
            allocator,
            masks.main.declared_columns,
            point,
        );
        errdefer mask_points.freePointColumns(allocator, main);
        const previous_point = logup.prevRowPoint(max_log_degree_bound, point);
        const secure = try mask_points.currentAndPreviousPointColumns(
            allocator,
            masks.interaction.declared_columns,
            point,
            previous_point,
        );
        errdefer mask_points.freePointColumns(allocator, secure);
        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe([][]CirclePointQM31, &.{ preprocessed, main, secure }),
        );
    }

    pub fn preprocessedColumnIndices(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) ![]usize {
        const count = (try self.maskGeometry()).preprocessed.declared_columns;
        if (count != 1) return error.InvalidProofShape;
        const result = try allocator.alloc(usize, count);
        result[0] = self.is_first_col_idx;
        return result;
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const @This(),
        point: CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        if (max_log_degree_bound < self.log_size or mask.items.len < 3)
            return error.InvalidProofShape;
        const preprocessed = mask.items[0];
        const main = mask.items[1];
        const secure = mask.items[2];
        try self.mask_binding.validate();
        const n_main: usize = self.mask_binding.borrowed_main_current_columns;
        const n_interaction = self.interactionColumnCount();
        if (preprocessed.len <= self.is_first_col_idx or
            preprocessed[self.is_first_col_idx].len < 1 or
            main.len < self.main_col_offset + n_main or
            secure.len < self.interaction_col_offset + n_interaction)
            return error.InvalidProofShape;

        var sampled: [trace.MAX_FAMILY_COLUMNS]QM31 = undefined;
        for (sampled[0..n_main], main[self.main_col_offset..][0..n_main]) |*value, column| {
            if (column.len < 1) return error.InvalidProofShape;
            value.* = column[0];
        }
        var current = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
        var previous = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
        for (0..self.nConstraints()) |batch| {
            current[batch] = try mask_points.sampledSecure(
                secure,
                self.interaction_col_offset + 4 * batch,
                0,
            );
            previous[batch] = try mask_points.sampledSecure(
                secure,
                self.interaction_col_offset + 4 * batch,
                1,
            );
        }
        const evaluation = try self.evaluateRow(
            sampled[0..n_main],
            current[0..self.nConstraints()],
            previous[0..self.nConstraints()],
            preprocessed[self.is_first_col_idx][0],
        );
        const fold = max_log_degree_bound - self.log_size;
        const denominator_inv = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.log_size).coset(),
            point.repeatedDouble(fold),
        ).inv();
        for (evaluation.values[0..evaluation.len]) |constraint| {
            accumulator.accumulate(constraint.mul(denominator_inv));
        }
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const @This(),
        trace_data: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !void {
        var prepared = try self.prepareDomainEvaluator(
            accumulator.allocator,
            trace_data,
            accumulator,
        );
        defer prepared.deinit();

        try prepared_domain_executor.runSerial(&prepared);
    }

    pub fn evaluateConstraintQuotientsOnDomainParallel(
        self: *const @This(),
        trace_data: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
        pool: *work_pool.WorkPool,
    ) !void {
        _ = pool;
        return self.evaluateConstraintQuotientsOnDomain(trace_data, accumulator);
    }

    fn prepareDomainEvaluator(
        self: *const @This(),
        allocator: std.mem.Allocator,
        trace_data: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !prepared_domain.PreparedDomainEvaluation {
        return prepared_domain_executor.prepare(
            @This(),
            self,
            allocator,
            trace_data,
            accumulator,
        );
    }

    pub fn evaluateRow(
        self: *const @This(),
        main: []const QM31,
        current: []const QM31,
        previous: []const QM31,
        is_first: QM31,
    ) !Evaluation {
        const n_batches = self.nConstraints();
        if (self.family != self.mask_binding.family or
            main.len != @as(
                usize,
                self.mask_binding.borrowed_main_current_columns,
            ) or
            current.len != n_batches or previous.len != n_batches)
            return error.InvalidTraceShape;
        var entries: opcode_entries.List = undefined;
        try opcode_entries.fromMainInto(self.family, main, &entries);
        if (self.batching == .compatibility and
            entries.batchCount() != n_batches)
        {
            return error.InvalidBatchCount;
        }
        if (self.batching == .compiler_selected and
            entries.len != opcode_entries.entryCount(self.family))
        {
            return error.InvalidBatchCount;
        }
        var result = Evaluation{ .len = n_batches };
        for (0..n_batches) |batch| {
            const pair = switch (self.batching) {
                .compatibility => try entries.pair(batch, self.relations),
                .compiler_selected => try selected_batching.rowPairFromRange(
                    &entries,
                    self.selected_batches[batch].first_entry,
                    self.selected_batches[batch].entry_count,
                    self.relations,
                ),
            };
            result.values[batch] = logup.pairConstraint(
                current[batch],
                previous[batch],
                is_first,
                self.claims[batch],
                pair,
            );
        }
        return result;
    }
};
