//! Canonical component construction for the v1 SM83 environment proof.
//!
//! The cartridge proof's exact 22-component prefix is preserved. Joypad
//! semantics and clock binding follow it, then lookup owners follow the
//! environment interaction-column and transcript order.

const std = @import("std");
const core = @import("stwo_core");
const core_air_accumulation = core.air.accumulation;
const core_air_components = core.air.components;
const core_air_derive = core.air.derive;
const QM31 = core.fields.qm31.QM31;
const canonic = core.poly.circle.canonic;
const prover_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const action_lookup = @import("air/joypad_action_lookup.zig");
const ActionLookupComponent = action_lookup.Component;
const IfMemoryComponent =
    @import("air/joypad_if_memory_lookup_component.zig").Component;
const if_memory_lookup = @import("air/joypad_if_memory_lookup.zig");
const joypad_binding = @import("air/joypad_binding.zig");
const joypad_binding_component =
    @import("air/joypad_binding_component.zig");
const JoypadBindingComponent = joypad_binding_component.Component;
const joypad_component = @import("air/joypad_component.zig");
const JoypadComponent = joypad_component.Component;
const mmio_lookup = @import("air/joypad_mmio_lookup.zig");
const MmioLookupComponent =
    @import("air/joypad_mmio_lookup_component.zig").Component;
const timer_binding = @import("air/timer_binding.zig");
const TimerBindingComponent =
    @import("air/timer_binding_component.zig").Component;
const timer_component = @import("air/timer_component.zig");
const TimerComponent = timer_component.Component;
const timer_if_lookup = @import("air/timer_if_memory_lookup.zig");
const TimerIfMemoryComponent =
    @import("air/timer_if_memory_lookup_component.zig").Component;
const timer_mmio_lookup = @import("air/timer_mmio_lookup.zig");
const TimerMmioLookupComponent =
    @import("air/timer_mmio_lookup_component.zig").Component;
const intermediate_observation =
    @import("air/intermediate_ram_observation_lookup.zig");
const IntermediateObservationComponent =
    @import("air/intermediate_ram_observation_lookup_component.zig").Component;
const cartridge_memory_lookup =
    @import("air/cartridge_memory_lookup.zig");
const cartridge_rom_lookup = @import("air/cartridge_rom_lookup.zig");
const component_domain = @import("air/component_domain.zig");
const cartridge_components = @import("cartridge_proof_components.zig");
const cartridge_statement = @import("cartridge_proof_statement.zig");
const environment_statement = @import("environment_statement.zig");

pub const VerifierComponent = core_air_components.Component;
pub const ProverComponent = prover_component.ComponentProver;
pub const N_CARTRIDGE_COMPONENTS: usize =
    cartridge_components.N_COMPONENTS;
pub const N_ENVIRONMENT_COMPONENTS: usize = 12;
pub const N_COMPONENTS: usize =
    N_CARTRIDGE_COMPONENTS + N_ENVIRONMENT_COMPONENTS;

/// Initialized contexts must remain at a stable address while any collected
/// component is used; relation and tail adapters borrow fields from it.
pub const Context = struct {
    statement_value: environment_statement.ExecutionStatement,
    cartridge: cartridge_components.Context,
    action_relation: action_lookup.Relation,
    mmio_relations: mmio_lookup.Relations,
    timer_mmio_relations: timer_mmio_lookup.Relations,
    joypad_component: JoypadComponent,
    binding_component: JoypadBindingComponent,
    action_component: ActionLookupComponent,
    mmio_execution_component: MmioLookupComponent,
    mmio_joypad_component: MmioLookupComponent,
    if_memory_component: IfMemoryComponent,
    timer_component: TimerComponent,
    timer_binding_component: TimerBindingComponent,
    timer_mmio_execution_component: TimerMmioLookupComponent,
    timer_mmio_timer_component: TimerMmioLookupComponent,
    timer_if_memory_component: TimerIfMemoryComponent,
    intermediate_observation_component: IntermediateObservationComponent,
    tail_owners: [N_ENVIRONMENT_COMPONENTS]TailOwner,
};

pub fn init(
    out: *Context,
    statement: environment_statement.ExecutionStatement,
    rom_relation: cartridge_rom_lookup.Relation,
    memory_relation: cartridge_memory_lookup.Relation,
    action_relation: action_lookup.Relation,
    mmio_relations: mmio_lookup.Relations,
    timer_mmio_relations: timer_mmio_lookup.Relations,
) void {
    out.statement_value = statement;
    cartridge_components.init(
        &out.cartridge,
        statement.base,
        rom_relation,
        memory_relation,
        statement.base.rom_lookup_claims,
        statement.base.memory_lookup_claims,
    );
    out.cartridge.packed_access_component.allow_joypad_mmio = true;
    out.cartridge.packed_access_component.allow_timer_mmio = true;
    out.action_relation = action_relation;
    out.mmio_relations = mmio_relations;
    out.timer_mmio_relations = timer_mmio_relations;
    out.joypad_component = .{
        .log_size = statement.joypad_log_size,
        .is_first_column = environment_statement.JOYPAD_FIRST_PREPROCESSED,
        .is_last_column = environment_statement.JOYPAD_LAST_PREPROCESSED,
        .main_offset = environment_statement.JOYPAD_BINDING_MAIN_OFFSET,
        .initial = statement.initial_joypad,
        .final = statement.final_joypad,
    };
    out.binding_component = .{
        .log_size = statement.joypad_log_size,
        .is_first_column = environment_statement.JOYPAD_FIRST_PREPROCESSED,
        .is_last_column = environment_statement.JOYPAD_LAST_PREPROCESSED,
        .main_offset = environment_statement.JOYPAD_BINDING_MAIN_OFFSET,
        .initial_mcycle = statement.base.initial.mcycle,
        .final_mcycle = statement.base.final.mcycle,
    };
    out.action_component = .{
        .log_size = statement.joypad_log_size,
        .is_first_column = environment_statement.JOYPAD_FIRST_PREPROCESSED,
        .public_active_column = environment_statement.ACTION_ACTIVE_PREPROCESSED,
        .public_mcycle_column = environment_statement.ACTION_MCYCLE_PREPROCESSED,
        .public_pressed_column = environment_statement.ACTION_PRESSED_PREPROCESSED,
        .binding_main_offset = environment_statement.JOYPAD_BINDING_MAIN_OFFSET,
        .interaction_offset = environment_statement.ACTION_INTERACTION_OFFSET,
        .relation = &out.action_relation,
        .claims = statement.action_lookup_claims,
    };
    out.mmio_execution_component = .{
        .kind = .execution,
        .log_size = statement.base.log_size,
        .is_first_column = cartridge_statement.EXECUTION_FIRST_PREPROCESSED,
        .execution_offset = cartridge_statement.EXECUTION_MAIN_OFFSET,
        .access_offset = cartridge_statement.PACKED_ACCESS_MAIN_OFFSET,
        .interaction_offset = environment_statement.MMIO_EXECUTION_INTERACTION_OFFSET,
        .relations = &out.mmio_relations,
        .claims = statement.joypad_mmio_lookup_claims,
    };
    out.mmio_joypad_component = .{
        .kind = .joypad,
        .log_size = statement.joypad_log_size,
        .is_first_column = environment_statement.JOYPAD_FIRST_PREPROCESSED,
        .binding_offset = environment_statement.JOYPAD_BINDING_MAIN_OFFSET,
        .interaction_offset = environment_statement.MMIO_JOYPAD_INTERACTION_OFFSET,
        .relations = &out.mmio_relations,
        .claims = statement.joypad_mmio_lookup_claims,
    };
    out.if_memory_component = .{
        .log_size = statement.joypad_log_size,
        .is_first_column = environment_statement.JOYPAD_FIRST_PREPROCESSED,
        .binding_offset = environment_statement.JOYPAD_BINDING_MAIN_OFFSET,
        .predecessor_offset = environment_statement.JOYPAD_IF_MAIN_OFFSET,
        .interaction_offset = environment_statement.JOYPAD_IF_INTERACTION_OFFSET,
        .relation = &out.cartridge.memory_relation,
        .claim = statement.joypad_if_memory_claim,
    };
    out.timer_component = .{
        .log_size = statement.timer_log_size,
        .is_first_column = environment_statement.TIMER_FIRST_PREPROCESSED,
        .is_last_column = environment_statement.TIMER_LAST_PREPROCESSED,
        .main_offset = environment_statement.TIMER_BINDING_MAIN_OFFSET,
        .initial = statement.initial_timer,
        .final = statement.final_timer,
    };
    out.timer_binding_component = .{
        .log_size = statement.timer_log_size,
        .is_first_column = environment_statement.TIMER_FIRST_PREPROCESSED,
        .is_last_column = environment_statement.TIMER_LAST_PREPROCESSED,
        .main_offset = environment_statement.TIMER_BINDING_MAIN_OFFSET,
        .initial_mcycle = statement.base.initial.mcycle,
        .final_mcycle = statement.base.final.mcycle,
    };
    out.timer_mmio_execution_component = .{
        .kind = .execution,
        .log_size = statement.base.log_size,
        .is_first_column = cartridge_statement.EXECUTION_FIRST_PREPROCESSED,
        .execution_offset = cartridge_statement.EXECUTION_MAIN_OFFSET,
        .access_offset = cartridge_statement.PACKED_ACCESS_MAIN_OFFSET,
        .interaction_offset = environment_statement.TIMER_MMIO_EXECUTION_INTERACTION_OFFSET,
        .relations = &out.timer_mmio_relations,
        .claims = statement.timer_mmio_lookup_claims,
    };
    out.timer_mmio_timer_component = .{
        .kind = .timer,
        .log_size = statement.timer_log_size,
        .is_first_column = environment_statement.TIMER_FIRST_PREPROCESSED,
        .binding_offset = environment_statement.TIMER_BINDING_MAIN_OFFSET,
        .interaction_offset = environment_statement.TIMER_MMIO_TIMER_INTERACTION_OFFSET,
        .relations = &out.timer_mmio_relations,
        .claims = statement.timer_mmio_lookup_claims,
    };
    out.timer_if_memory_component = .{
        .log_size = statement.timer_log_size,
        .is_first_column = environment_statement.TIMER_FIRST_PREPROCESSED,
        .binding_offset = environment_statement.TIMER_BINDING_MAIN_OFFSET,
        .predecessor_offset = environment_statement.TIMER_IF_MAIN_OFFSET,
        .interaction_offset = environment_statement.TIMER_IF_INTERACTION_OFFSET,
        .relation = &out.cartridge.memory_relation,
        .claim = statement.timer_if_memory_claim,
    };
    out.intermediate_observation_component = .{
        .log_size = statement.intermediate_observation_log_size,
        .is_first_column = environment_statement.INTERMEDIATE_OBSERVATION_FIRST_PREPROCESSED,
        .public_active_column = environment_statement.OBSERVATION_ACTIVE_PREPROCESSED,
        .public_mcycle_column = environment_statement.OBSERVATION_MCYCLE_PREPROCESSED,
        .public_key_column = environment_statement.OBSERVATION_KEY_PREPROCESSED,
        .public_value_column = environment_statement.OBSERVATION_VALUE_PREPROCESSED,
        .predecessor_offset = environment_statement.INTERMEDIATE_OBSERVATION_MAIN_OFFSET,
        .interaction_offset = environment_statement.INTERMEDIATE_OBSERVATION_INTERACTION_OFFSET,
        .relation = &out.cartridge.memory_relation,
        .schedule_claim = &out.statement_value.intermediate_observation_schedule_claim,
        .claim = statement.intermediate_observation_memory_claim,
    };
    inline for (&out.tail_owners, std.enums.values(TailKind)) |
        *owner,
        kind,
    | owner.* = .{ .kind = kind, .context = out };
}

pub fn verifier(
    context: *const Context,
    out: []VerifierComponent,
) ![]const VerifierComponent {
    return collect(.verifier, context, out);
}

pub fn prover(
    context: *const Context,
    out: []ProverComponent,
) ![]const ProverComponent {
    return collect(.prover, context, out);
}

const Kind = enum { verifier, prover };

fn Component(comptime kind: Kind) type {
    return switch (kind) {
        .verifier => VerifierComponent,
        .prover => ProverComponent,
    };
}

fn collect(
    comptime kind: Kind,
    context: *const Context,
    out: []Component(kind),
) ![]const Component(kind) {
    if (out.len < N_COMPONENTS) return error.InvalidProofShape;
    var cartridge_storage: [cartridge_components.N_COMPONENTS]Component(kind) = undefined;
    const cartridge = switch (kind) {
        .verifier => try cartridge_components.verifier(
            &context.cartridge,
            &cartridge_storage,
        ),
        .prover => try cartridge_components.prover(
            &context.cartridge,
            &cartridge_storage,
        ),
    };
    @memcpy(out[0..N_CARTRIDGE_COMPONENTS], cartridge);

    inline for (0..N_ENVIRONMENT_COMPONENTS) |tail_index| {
        const owner = &context.tail_owners[tail_index];
        out[N_CARTRIDGE_COMPONENTS + tail_index] = switch (kind) {
            .verifier => owner.asVerifierComponent(),
            .prover => owner.asProverComponent(),
        };
    }
    return out[0..N_COMPONENTS];
}

const TailKind = enum {
    joypad_semantic,
    joypad_binding,
    action_lookup,
    mmio_execution,
    mmio_joypad,
    if_memory,
    timer_semantic,
    timer_binding,
    timer_mmio_execution,
    timer_mmio_timer,
    timer_if_memory,
    intermediate_observation,
};

/// Declares only columns newly owned by each environment component while
/// delegating evaluation against the complete shared environment trace.
const TailOwner = struct {
    kind: TailKind,
    context: *const Context,

    const Self = @This();
    const Adapter = core_air_derive.ComponentAdapter(
        Self,
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_accumulation.DomainEvaluationAccumulator,
    );

    pub fn asVerifierComponent(
        self: *const Self,
    ) core_air_components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn asProverComponent(
        self: *const Self,
    ) prover_component.ComponentProver {
        return Adapter.asProverComponent(self);
    }

    pub fn nConstraints(self: *const Self) usize {
        return switch (self.kind) {
            .joypad_semantic => self.context.joypad_component.nConstraints(),
            .joypad_binding => self.context.binding_component.nConstraints(),
            .action_lookup => self.context.action_component.nConstraints(),
            .mmio_execution => self.context.mmio_execution_component.nConstraints(),
            .mmio_joypad => self.context.mmio_joypad_component.nConstraints(),
            .if_memory => self.context.if_memory_component.nConstraints(),
            .timer_semantic => self.context.timer_component.nConstraints(),
            .timer_binding => self.context.timer_binding_component.nConstraints(),
            .timer_mmio_execution => self.context.timer_mmio_execution_component.nConstraints(),
            .timer_mmio_timer => self.context.timer_mmio_timer_component.nConstraints(),
            .timer_if_memory => self.context.timer_if_memory_component.nConstraints(),
            .intermediate_observation => self.context
                .intermediate_observation_component.nConstraints(),
        };
    }

    pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
        return self.logSize() + 1;
    }

    pub fn traceLogDegreeBounds(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try ownedLogs(
            allocator,
            self.ownedPreprocessed(),
            self.logSize(),
        );
        errdefer allocator.free(preprocessed);
        const main = try ownedLogs(
            allocator,
            self.ownedMain(),
            self.logSize(),
        );
        errdefer allocator.free(main);
        const interaction = try ownedLogs(
            allocator,
            self.ownedInteraction(),
            self.logSize(),
        );
        errdefer allocator.free(interaction);
        return core_air_components.TraceLogDegreeBounds.initOwned(
            try allocator.dupe([]u32, &.{
                preprocessed,
                main,
                interaction,
            }),
        );
    }

    pub fn preprocessedColumnIndices(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) ![]usize {
        // Owned indices precede borrowed indices because columnLogSizes maps
        // only the prefix represented by this owner's local bounds.
        return switch (self.kind) {
            .joypad_semantic => allocator.dupe(usize, &.{
                environment_statement.JOYPAD_FIRST_PREPROCESSED,
                environment_statement.JOYPAD_LAST_PREPROCESSED,
            }),
            .joypad_binding => allocator.dupe(usize, &.{
                environment_statement.JOYPAD_FIRST_PREPROCESSED,
                environment_statement.JOYPAD_LAST_PREPROCESSED,
            }),
            .action_lookup => allocator.dupe(usize, &.{
                environment_statement.ACTION_ACTIVE_PREPROCESSED,
                environment_statement.ACTION_MCYCLE_PREPROCESSED,
                environment_statement.ACTION_PRESSED_PREPROCESSED,
                environment_statement.JOYPAD_FIRST_PREPROCESSED,
            }),
            .mmio_execution => allocator.dupe(usize, &.{
                cartridge_statement.EXECUTION_FIRST_PREPROCESSED,
            }),
            .mmio_joypad, .if_memory => allocator.dupe(usize, &.{
                environment_statement.JOYPAD_FIRST_PREPROCESSED,
            }),
            .timer_semantic, .timer_binding => allocator.dupe(usize, &.{
                environment_statement.TIMER_FIRST_PREPROCESSED,
                environment_statement.TIMER_LAST_PREPROCESSED,
            }),
            .timer_mmio_execution => allocator.dupe(usize, &.{
                cartridge_statement.EXECUTION_FIRST_PREPROCESSED,
            }),
            .timer_mmio_timer, .timer_if_memory => allocator.dupe(usize, &.{
                environment_statement.TIMER_FIRST_PREPROCESSED,
            }),
            .intermediate_observation => allocator.dupe(usize, &.{
                environment_statement.INTERMEDIATE_OBSERVATION_FIRST_PREPROCESSED,
                environment_statement.OBSERVATION_ACTIVE_PREPROCESSED,
                environment_statement.OBSERVATION_MCYCLE_PREPROCESSED,
                environment_statement.OBSERVATION_KEY_PREPROCESSED,
                environment_statement.OBSERVATION_VALUE_PREPROCESSED,
            }),
        };
    }

    pub fn maskPoints(
        self: *const Self,
        allocator: std.mem.Allocator,
        point: core.circle.CirclePointQM31,
        max_log_degree_bound: u32,
    ) !core_air_components.MaskPoints {
        if (max_log_degree_bound < self.logSize())
            return error.InvalidProofShape;
        const preprocessed = try component_domain.currentPointColumns(
            allocator,
            self.ownedPreprocessed(),
            point,
        );
        errdefer component_domain.freePointColumns(
            allocator,
            preprocessed,
        );
        const main = if (self.needsNextMain())
            try component_domain.currentAndNextPointColumns(
                allocator,
                self.ownedMain(),
                point,
                nextRowPoint(max_log_degree_bound, point),
            )
        else
            try component_domain.currentPointColumns(
                allocator,
                self.ownedMain(),
                point,
            );
        errdefer component_domain.freePointColumns(allocator, main);
        const interaction =
            try component_domain.currentAndPreviousPointColumns(
                allocator,
                self.ownedInteraction(),
                point,
                previousRowPoint(max_log_degree_bound, point),
            );
        errdefer component_domain.freePointColumns(
            allocator,
            interaction,
        );
        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe([][]core.circle.CirclePointQM31, &.{
                preprocessed,
                main,
                interaction,
            }),
        );
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const Self,
        point: core.circle.CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        return switch (self.kind) {
            .joypad_semantic => self.context.joypad_component
                .evaluateConstraintQuotientsAtPoint(
                point,
                mask,
                accumulator,
                max_log_degree_bound,
            ),
            .joypad_binding => self.context.binding_component
                .evaluateConstraintQuotientsAtPoint(
                point,
                mask,
                accumulator,
                max_log_degree_bound,
            ),
            .action_lookup => self.context.action_component
                .evaluateConstraintQuotientsAtPoint(
                point,
                mask,
                accumulator,
                max_log_degree_bound,
            ),
            .mmio_execution => self.context.mmio_execution_component
                .evaluateConstraintQuotientsAtPoint(
                point,
                mask,
                accumulator,
                max_log_degree_bound,
            ),
            .mmio_joypad => self.context.mmio_joypad_component
                .evaluateConstraintQuotientsAtPoint(
                point,
                mask,
                accumulator,
                max_log_degree_bound,
            ),
            .if_memory => self.context.if_memory_component
                .evaluateConstraintQuotientsAtPoint(
                point,
                mask,
                accumulator,
                max_log_degree_bound,
            ),
            .timer_semantic => self.context.timer_component
                .evaluateConstraintQuotientsAtPoint(
                point,
                mask,
                accumulator,
                max_log_degree_bound,
            ),
            .timer_binding => self.context.timer_binding_component
                .evaluateConstraintQuotientsAtPoint(
                point,
                mask,
                accumulator,
                max_log_degree_bound,
            ),
            .timer_mmio_execution => self.context.timer_mmio_execution_component
                .evaluateConstraintQuotientsAtPoint(
                point,
                mask,
                accumulator,
                max_log_degree_bound,
            ),
            .timer_mmio_timer => self.context.timer_mmio_timer_component
                .evaluateConstraintQuotientsAtPoint(
                point,
                mask,
                accumulator,
                max_log_degree_bound,
            ),
            .timer_if_memory => self.context.timer_if_memory_component
                .evaluateConstraintQuotientsAtPoint(
                point,
                mask,
                accumulator,
                max_log_degree_bound,
            ),
            .intermediate_observation => self.context
                .intermediate_observation_component
                .evaluateConstraintQuotientsAtPoint(
                point,
                mask,
                accumulator,
                max_log_degree_bound,
            ),
        };
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const Self,
        trace: *const prover_component.Trace,
        accumulator: *prover_accumulation.DomainEvaluationAccumulator,
    ) !void {
        return switch (self.kind) {
            .joypad_semantic => self.context.joypad_component
                .evaluateConstraintQuotientsOnDomain(
                trace,
                accumulator,
            ),
            .joypad_binding => self.context.binding_component
                .evaluateConstraintQuotientsOnDomain(
                trace,
                accumulator,
            ),
            .action_lookup => self.context.action_component
                .evaluateConstraintQuotientsOnDomain(
                trace,
                accumulator,
            ),
            .mmio_execution => self.context.mmio_execution_component
                .evaluateConstraintQuotientsOnDomain(
                trace,
                accumulator,
            ),
            .mmio_joypad => self.context.mmio_joypad_component
                .evaluateConstraintQuotientsOnDomain(
                trace,
                accumulator,
            ),
            .if_memory => self.context.if_memory_component
                .evaluateConstraintQuotientsOnDomain(
                trace,
                accumulator,
            ),
            .timer_semantic => self.context.timer_component
                .evaluateConstraintQuotientsOnDomain(
                trace,
                accumulator,
            ),
            .timer_binding => self.context.timer_binding_component
                .evaluateConstraintQuotientsOnDomain(
                trace,
                accumulator,
            ),
            .timer_mmio_execution => self.context.timer_mmio_execution_component
                .evaluateConstraintQuotientsOnDomain(
                trace,
                accumulator,
            ),
            .timer_mmio_timer => self.context.timer_mmio_timer_component
                .evaluateConstraintQuotientsOnDomain(
                trace,
                accumulator,
            ),
            .timer_if_memory => self.context.timer_if_memory_component
                .evaluateConstraintQuotientsOnDomain(
                trace,
                accumulator,
            ),
            .intermediate_observation => self.context
                .intermediate_observation_component
                .evaluateConstraintQuotientsOnDomain(
                trace,
                accumulator,
            ),
        };
    }

    fn logSize(self: *const Self) u32 {
        return switch (self.kind) {
            .mmio_execution, .timer_mmio_execution => self.context
                .statement_value.base.log_size,
            .timer_semantic,
            .timer_binding,
            .timer_mmio_timer,
            .timer_if_memory,
            => self.context.statement_value.timer_log_size,
            .intermediate_observation => self.context.statement_value
                .intermediate_observation_log_size,
            else => self.context.statement_value.joypad_log_size,
        };
    }

    fn ownedPreprocessed(self: *const Self) usize {
        return switch (self.kind) {
            .joypad_semantic => 2,
            .action_lookup => action_lookup.N_PUBLIC_COLUMNS,
            .timer_semantic => 2,
            .intermediate_observation => intermediate_observation.N_PUBLIC_COLUMNS + 1,
            else => 0,
        };
    }

    fn ownedMain(self: *const Self) usize {
        return switch (self.kind) {
            .joypad_semantic => joypad_component.N_MAIN_COLUMNS,
            .joypad_binding => joypad_binding.N_MAIN_COLUMNS -
                joypad_component.N_MAIN_COLUMNS,
            .if_memory => if_memory_lookup.N_MAIN_COLUMNS,
            .timer_semantic => timer_component.N_MAIN_COLUMNS,
            .timer_binding => timer_binding.N_MAIN_COLUMNS -
                timer_component.N_MAIN_COLUMNS,
            .timer_if_memory => timer_if_lookup.N_MAIN_COLUMNS,
            .intermediate_observation => intermediate_observation.N_MAIN_COLUMNS,
            else => 0,
        };
    }

    fn ownedInteraction(self: *const Self) usize {
        return switch (self.kind) {
            .action_lookup => action_lookup.N_INTERACTION_COLUMNS,
            .mmio_execution => mmio_lookup.N_EXECUTION_INTERACTION_COLUMNS,
            .mmio_joypad => mmio_lookup.N_JOYPAD_INTERACTION_COLUMNS,
            .if_memory => if_memory_lookup.N_INTERACTION_COLUMNS,
            .timer_mmio_execution => timer_mmio_lookup.N_EXECUTION_INTERACTION_COLUMNS,
            .timer_mmio_timer => timer_mmio_lookup.N_TIMER_INTERACTION_COLUMNS,
            .timer_if_memory => timer_if_lookup.N_INTERACTION_COLUMNS,
            .intermediate_observation => intermediate_observation.N_INTERACTION_COLUMNS,
            else => 0,
        };
    }

    fn needsNextMain(self: *const Self) bool {
        return self.kind == .joypad_semantic or
            self.kind == .joypad_binding or
            self.kind == .timer_semantic or
            self.kind == .timer_binding;
    }
};

fn ownedLogs(
    allocator: std.mem.Allocator,
    count: usize,
    log_size: u32,
) ![]u32 {
    const result = try allocator.alloc(u32, count);
    @memset(result, log_size);
    return result;
}

fn nextRowPoint(
    log_size: u32,
    point: core.circle.CirclePointQM31,
) core.circle.CirclePointQM31 {
    const step = canonic.CanonicCoset.new(log_size).coset_value.step;
    return point.add(.{
        .x = QM31.fromBase(step.x),
        .y = QM31.fromBase(step.y),
    });
}

fn previousRowPoint(
    log_size: u32,
    point: core.circle.CirclePointQM31,
) core.circle.CirclePointQM31 {
    const step = canonic.CanonicCoset.new(log_size).coset_value.step;
    return point.sub(.{
        .x = QM31.fromBase(step.x),
        .y = QM31.fromBase(step.y),
    });
}
