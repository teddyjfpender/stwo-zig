//! Component composition for the complete cartridge-machine environment.
//!
//! The v3 environment components remain an exact prefix. Tail owners declare
//! only newly committed columns while every leaf evaluates the shared trace.

const std = @import("std");
const core = @import("stwo_core");
const core_air_accumulation = core.air.accumulation;
const core_air_components = core.air.components;
const core_air_derive = core.air.derive;
const QM31 = core.fields.qm31.QM31;
const canonic = core.poly.circle.canonic;
const prover_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const cartridge_statement = @import("cartridge_proof_statement.zig");
const environment_components = @import("environment_proof_components.zig");
const geometry = @import("machine_environment_geometry.zig");
const statement = @import("machine_environment_statement.zig");
const apu_binding = @import("air/apu_binding.zig");
const ApuBindingComponent =
    @import("air/apu_binding_component.zig").Component;
const apu_execution = @import("air/apu_execution_lookup.zig");
const ApuExecutionComponent =
    @import("air/apu_execution_lookup_component.zig").Component;
const component_domain = @import("air/component_domain.zig");
const dma_component = @import("air/dma_component.zig");
const DmaComponent = dma_component.Component;
const dma_binding = @import("air/dma_binding.zig");
const DmaBindingComponent =
    @import("air/dma_binding_component.zig").Component;
const dma_execution = @import("air/dma_execution_lookup.zig");
const DmaExecutionComponent =
    @import("air/dma_execution_lookup_component.zig").Component;
const dma_memory = @import("air/dma_memory_lookup.zig");
const DmaMemoryComponent =
    @import("air/dma_memory_lookup_component.zig").Component;
const execution = @import("air/execution.zig");
const execution_component = @import("air/execution_component.zig");
const ExecutionComponent = execution_component.Component;
const machine = @import("runner/machine.zig");
const ppu_component = @import("air/ppu_timing_component.zig");
const PpuComponent = ppu_component.Component;
const ppu_binding = @import("air/ppu_binding.zig");
const PpuBindingComponent =
    @import("air/ppu_binding_component.zig").Component;
const ppu_mmio = @import("air/ppu_mmio_lookup.zig");
const PpuMmioComponent =
    @import("air/ppu_mmio_lookup_component.zig").Component;
const ppu_if = @import("air/ppu_if_memory_lookup.zig");
const PpuIfComponent =
    @import("air/ppu_if_memory_lookup_component.zig").Component;
const ppu_execution_policy = @import("ppu_execution_policy.zig");
const PpuPolicyComponent = ppu_execution_policy.Component;
const scheduler = @import("air/scheduler_component.zig");
const SchedulerComponent = scheduler.Component;
const scheduler_binding = @import("air/scheduler_binding.zig");
const SchedulerBindingComponent =
    @import("air/scheduler_binding_component.zig").Component;
const scheduler_memory = @import("air/scheduler_memory_lookup.zig");
const SchedulerMemoryComponent =
    @import("air/scheduler_memory_lookup_component.zig").Component;
const service_memory =
    @import("air/interrupt_service_memory_lookup.zig");
const ServiceMemoryComponent =
    @import("air/interrupt_service_memory_lookup_component.zig").Component;

pub const VerifierComponent = core_air_components.Component;
pub const ProverComponent = prover_component.ComponentProver;
pub const N_ENVIRONMENT_COMPONENTS: usize =
    environment_components.N_COMPONENTS;
pub const N_MACHINE_COMPONENTS: usize = 19;
pub const N_COMPONENTS: usize =
    N_ENVIRONMENT_COMPONENTS + N_MACHINE_COMPONENTS;
const N_OWNERS: usize = N_MACHINE_COMPONENTS + 1;

/// Initialized contexts must remain at a stable address while collected
/// components borrow their relations and tail adapters.
pub const Context = struct {
    statement_value: statement.ExecutionStatement,
    environment: environment_components.Context,
    ppu_mmio_relations: ppu_mmio.Relations,
    dma_execution_relations: dma_execution.Relations,
    apu_execution_relation: apu_execution.Relation,
    scheduler_component: SchedulerComponent,
    scheduler_binding_component: SchedulerBindingComponent,
    scheduler_memory_component: SchedulerMemoryComponent,
    service_memory_component: ServiceMemoryComponent,
    ppu_component: PpuComponent,
    ppu_binding_component: PpuBindingComponent,
    ppu_mmio_execution_component: PpuMmioComponent,
    ppu_mmio_ppu_component: PpuMmioComponent,
    ppu_if_component: PpuIfComponent,
    ppu_policy_dma_component: PpuPolicyComponent,
    ppu_policy_ppu_component: PpuPolicyComponent,
    dma_component: DmaComponent,
    dma_binding_component: DmaBindingComponent,
    dma_execution_execution_component: DmaExecutionComponent,
    dma_execution_dma_component: DmaExecutionComponent,
    dma_memory_component: DmaMemoryComponent,
    apu_binding_component: ApuBindingComponent,
    apu_execution_execution_component: ApuExecutionComponent,
    apu_execution_apu_component: ApuExecutionComponent,
    owners: [N_OWNERS]TailOwner,
};

pub fn init(
    out: *Context,
    execution_statement: statement.ExecutionStatement,
    rom_relation: anytype,
    memory_relation: anytype,
    action_relation: anytype,
    joypad_mmio_relations: anytype,
    timer_mmio_relations: anytype,
    ppu_mmio_relations: ppu_mmio.Relations,
    dma_execution_relations: dma_execution.Relations,
    apu_execution_relation: apu_execution.Relation,
) void {
    out.statement_value = execution_statement;
    environment_components.init(
        &out.environment,
        execution_statement.base,
        rom_relation,
        memory_relation,
        action_relation,
        joypad_mmio_relations,
        timer_mmio_relations,
    );
    out.environment.cartridge.packed_access_component.allow_ppu_mmio = true;
    out.environment.cartridge.packed_access_component.allow_apu_mmio = true;
    out.environment.cartridge.cpu.execution_component
        .family_activity_columns = .{
        .instruction = provenanceEventColumn(.instruction),
        .interrupt_service = provenanceEventColumn(.interrupt_service),
    };
    out.ppu_mmio_relations = ppu_mmio_relations;
    out.dma_execution_relations = dma_execution_relations;
    out.apu_execution_relation = apu_execution_relation;

    const base = execution_statement.base.base;
    out.scheduler_component = .{
        .log_size = base.log_size,
        .is_first_column = cartridge_statement.EXECUTION_FIRST_PREPROCESSED,
        .is_last_column = cartridge_statement.EXECUTION_LAST_PREPROCESSED,
        .main_offset = geometry.SCHEDULER_MAIN_OFFSET,
        .initial = schedulerBoundary(
            base.initial,
            execution_statement.initial_halt_bug,
        ),
        .final = schedulerBoundary(
            base.final,
            execution_statement.final_halt_bug,
        ),
    };
    out.scheduler_binding_component = .{
        .log_size = base.log_size,
        .scheduler_offset = geometry.SCHEDULER_MAIN_OFFSET,
        .execution_offset = cartridge_statement.EXECUTION_MAIN_OFFSET,
        .provenance_offset = geometry.SCHEDULER_PROVENANCE_MAIN_OFFSET,
    };
    out.scheduler_memory_component = .{
        .log_size = base.log_size,
        .is_first_column = cartridge_statement.EXECUTION_FIRST_PREPROCESSED,
        .is_last_column = cartridge_statement.EXECUTION_LAST_PREPROCESSED,
        .scheduler_offset = geometry.SCHEDULER_MAIN_OFFSET,
        .memory_offset = geometry.SCHEDULER_MEMORY_MAIN_OFFSET,
        .interaction_offset = geometry.SCHEDULER_MEMORY_INTERACTION_OFFSET,
        .relation = &out.environment.cartridge.memory_relation,
        .claims = execution_statement.scheduler_memory_lookup_claims,
        .boundary = .{
            .initial_mcycle = base.initial.mcycle,
            .final_mcycle = base.final.mcycle,
        },
    };
    out.service_memory_component = .{
        .log_size = base.log_size,
        .is_first_column = cartridge_statement.EXECUTION_FIRST_PREPROCESSED,
        .is_last_column = cartridge_statement.EXECUTION_LAST_PREPROCESSED,
        .service_active_column = provenanceEventColumn(.interrupt_service),
        .execution_offset = cartridge_statement.EXECUTION_MAIN_OFFSET,
        .service_offset = cartridge_statement.FAMILY_MAIN_OFFSET +
            @import("air/family_trace.zig").INTERRUPT_SERVICE_OFFSET,
        .memory_offset = cartridge_statement.MUTABLE_WITNESS_MAIN_OFFSET,
        .lookup_offset = geometry.SERVICE_MEMORY_MAIN_OFFSET,
        .interaction_offset = geometry.SERVICE_MEMORY_INTERACTION_OFFSET,
        .relation = &out.environment.cartridge.memory_relation,
        .claims = execution_statement
            .interrupt_service_memory_lookup_claims,
    };

    out.ppu_component = .{
        .log_size = execution_statement.ppu_log_size,
        .is_last_column = geometry.PPU_LAST_PREPROCESSED,
        .is_active_main_column = geometry.PPU_BINDING_MAIN_OFFSET,
        .main_offset = geometry.PPU_BINDING_MAIN_OFFSET + 1,
    };
    out.ppu_binding_component = .{
        .log_size = execution_statement.ppu_log_size,
        .is_first_column = geometry.PPU_FIRST_PREPROCESSED,
        .is_last_column = geometry.PPU_LAST_PREPROCESSED,
        .main_offset = geometry.PPU_BINDING_MAIN_OFFSET,
        .initial_mcycle = base.initial.mcycle,
        .final_mcycle = base.final.mcycle,
        .initial = execution_statement.initial_ppu,
        .final = execution_statement.final_ppu,
    };
    out.ppu_mmio_execution_component = .{
        .kind = .execution,
        .log_size = base.log_size,
        .is_first_column = cartridge_statement.EXECUTION_FIRST_PREPROCESSED,
        .execution_offset = cartridge_statement.EXECUTION_MAIN_OFFSET,
        .access_offset = cartridge_statement.PACKED_ACCESS_MAIN_OFFSET,
        .interaction_offset = geometry.PPU_MMIO_EXECUTION_INTERACTION_OFFSET,
        .relations = &out.ppu_mmio_relations,
        .claims = execution_statement.ppu_mmio_lookup_claims,
    };
    out.ppu_mmio_ppu_component = .{
        .kind = .ppu,
        .log_size = execution_statement.ppu_log_size,
        .is_first_column = geometry.PPU_FIRST_PREPROCESSED,
        .binding_offset = geometry.PPU_BINDING_MAIN_OFFSET,
        .auxiliary_offset = geometry.PPU_AUXILIARY_MAIN_OFFSET,
        .interaction_offset = geometry.PPU_MMIO_PPU_INTERACTION_OFFSET,
        .relations = &out.ppu_mmio_relations,
        .claims = execution_statement.ppu_mmio_lookup_claims,
    };
    out.ppu_if_component = .{
        .log_size = execution_statement.ppu_log_size,
        .is_first_column = geometry.PPU_FIRST_PREPROCESSED,
        .binding_offset = geometry.PPU_BINDING_MAIN_OFFSET,
        .predecessor_offset = geometry.PPU_IF_MAIN_OFFSET,
        .interaction_offset = geometry.PPU_IF_INTERACTION_OFFSET,
        .relation = &out.environment.cartridge.memory_relation,
        .claim = execution_statement.ppu_if_memory_claim,
    };
    out.ppu_policy_dma_component = .{
        .kind = .dma,
        .log_size = execution_statement.dma_log_size,
        .is_first_column = geometry.DMA_FIRST_PREPROCESSED,
        .binding_offset = geometry.DMA_BINDING_MAIN_OFFSET,
        .interaction_offset = geometry.PPU_POLICY_DMA_INTERACTION_OFFSET,
        .relations = &out.dma_execution_relations,
        .claims = execution_statement.ppu_execution_policy_claims,
    };
    out.ppu_policy_ppu_component = .{
        .kind = .ppu,
        .log_size = execution_statement.ppu_log_size,
        .is_first_column = geometry.PPU_FIRST_PREPROCESSED,
        .binding_offset = geometry.PPU_BINDING_MAIN_OFFSET,
        .selector_offset = geometry.PPU_EXECUTION_POLICY_MAIN_OFFSET,
        .interaction_offset = geometry.PPU_POLICY_PPU_INTERACTION_OFFSET,
        .relations = &out.dma_execution_relations,
        .claims = execution_statement.ppu_execution_policy_claims,
    };

    out.dma_component = .{
        .log_size = execution_statement.dma_log_size,
        .is_last_column = geometry.DMA_LAST_PREPROCESSED,
        .is_active_main_column = geometry.DMA_BINDING_MAIN_OFFSET,
        .main_offset = geometry.DMA_BINDING_MAIN_OFFSET + 1,
    };
    out.dma_binding_component = .{
        .log_size = execution_statement.dma_log_size,
        .is_first_column = geometry.DMA_FIRST_PREPROCESSED,
        .is_last_column = geometry.DMA_LAST_PREPROCESSED,
        .main_offset = geometry.DMA_BINDING_MAIN_OFFSET,
        .initial_state = execution_statement.initial_dma,
        .final_state = execution_statement.final_dma,
    };
    out.dma_execution_execution_component = .{
        .kind = .execution,
        .log_size = base.log_size,
        .is_first_column = cartridge_statement.EXECUTION_FIRST_PREPROCESSED,
        .execution_offset = cartridge_statement.EXECUTION_MAIN_OFFSET,
        .interaction_offset = geometry.DMA_EXECUTION_INTERACTION_OFFSET,
        .relations = &out.dma_execution_relations,
        .claims = execution_statement.dma_execution_lookup_claims,
    };
    out.dma_execution_dma_component = .{
        .kind = .dma,
        .log_size = execution_statement.dma_log_size,
        .is_first_column = geometry.DMA_FIRST_PREPROCESSED,
        .binding_offset = geometry.DMA_BINDING_MAIN_OFFSET,
        .interaction_offset = geometry.DMA_DMA_INTERACTION_OFFSET,
        .relations = &out.dma_execution_relations,
        .claims = execution_statement.dma_execution_lookup_claims,
    };
    out.dma_memory_component = .{
        .log_size = execution_statement.dma_log_size,
        .is_first_column = geometry.DMA_FIRST_PREPROCESSED,
        .binding_offset = geometry.DMA_BINDING_MAIN_OFFSET,
        .predecessor_offset = geometry.DMA_MEMORY_MAIN_OFFSET,
        .interaction_offset = geometry.DMA_MEMORY_INTERACTION_OFFSET,
        .relation = &out.environment.cartridge.memory_relation,
        .claims = execution_statement.dma_memory_claims,
    };
    out.apu_binding_component = .{
        .log_size = execution_statement.apu_log_size,
        .is_first_column = geometry.APU_FIRST_PREPROCESSED,
        .is_last_column = geometry.APU_LAST_PREPROCESSED,
        .main_offset = geometry.APU_BINDING_MAIN_OFFSET,
        .initial_state = execution_statement.initial_apu,
        .final_state = execution_statement.final_apu,
        .event_count = execution_statement.apu_execution_lookup_claims.apu_count,
    };
    out.apu_execution_execution_component = .{
        .kind = .execution,
        .log_size = base.log_size,
        .is_first_column = cartridge_statement.EXECUTION_FIRST_PREPROCESSED,
        .is_last_column = cartridge_statement.EXECUTION_LAST_PREPROCESSED,
        .execution_offset = cartridge_statement.EXECUTION_MAIN_OFFSET,
        .access_offset = cartridge_statement.PACKED_ACCESS_MAIN_OFFSET,
        .auxiliary_offset = geometry.APU_EXECUTION_ORDER_MAIN_OFFSET,
        .interaction_offset = geometry.APU_EXECUTION_INTERACTION_OFFSET,
        .relation = &out.apu_execution_relation,
        .claims = execution_statement.apu_execution_lookup_claims,
    };
    out.apu_execution_apu_component = .{
        .kind = .apu,
        .log_size = execution_statement.apu_log_size,
        .is_first_column = geometry.APU_FIRST_PREPROCESSED,
        .is_last_column = geometry.APU_LAST_PREPROCESSED,
        .binding_offset = geometry.APU_BINDING_MAIN_OFFSET,
        .auxiliary_offset = geometry.APU_MCYCLE_MAIN_OFFSET,
        .interaction_offset = geometry.APU_APU_INTERACTION_OFFSET,
        .relation = &out.apu_execution_relation,
        .claims = execution_statement.apu_execution_lookup_claims,
    };
    inline for (&out.owners, std.enums.values(TailKind)) |
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
    var prefix_storage: [environment_components.N_COMPONENTS]Component(kind) = undefined;
    const prefix = switch (kind) {
        .verifier => try environment_components.verifier(
            &context.environment,
            &prefix_storage,
        ),
        .prover => try environment_components.prover(
            &context.environment,
            &prefix_storage,
        ),
    };
    @memcpy(out[0..N_ENVIRONMENT_COMPONENTS], prefix);
    out[0] = switch (kind) {
        .verifier => context.owners[0].asVerifierComponent(),
        .prover => context.owners[0].asProverComponent(),
    };
    inline for (0..N_MACHINE_COMPONENTS) |index| {
        const owner = &context.owners[index + 1];
        out[N_ENVIRONMENT_COMPONENTS + index] = switch (kind) {
            .verifier => owner.asVerifierComponent(),
            .prover => owner.asProverComponent(),
        };
    }
    return out[0..N_COMPONENTS];
}

const TailKind = enum {
    execution_spine,
    scheduler_semantic,
    scheduler_binding,
    scheduler_memory,
    service_memory,
    ppu_semantic,
    ppu_binding,
    ppu_mmio_execution,
    ppu_mmio_ppu,
    ppu_if_memory,
    ppu_policy_dma,
    ppu_policy_ppu,
    dma_semantic,
    dma_binding,
    dma_execution_execution,
    dma_execution_dma,
    dma_memory,
    apu_binding,
    apu_execution_execution,
    apu_execution_apu,
};

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
    ) VerifierComponent {
        return Adapter.asVerifierComponent(self);
    }

    pub fn asProverComponent(
        self: *const Self,
    ) ProverComponent {
        return Adapter.asProverComponent(self);
    }

    pub fn nConstraints(self: *const Self) usize {
        return switch (self.kind) {
            .execution_spine => self.context.environment.cartridge.cpu
                .execution_component.nConstraints(),
            .scheduler_semantic => self.context.scheduler_component.nConstraints(),
            .scheduler_binding => self.context.scheduler_binding_component.nConstraints(),
            .scheduler_memory => self.context.scheduler_memory_component.nConstraints(),
            .service_memory => self.context.service_memory_component.nConstraints(),
            .ppu_semantic => self.context.ppu_component.nConstraints(),
            .ppu_binding => self.context.ppu_binding_component.nConstraints(),
            .ppu_mmio_execution => self.context.ppu_mmio_execution_component.nConstraints(),
            .ppu_mmio_ppu => self.context.ppu_mmio_ppu_component.nConstraints(),
            .ppu_if_memory => self.context.ppu_if_component.nConstraints(),
            .ppu_policy_dma => self.context.ppu_policy_dma_component.nConstraints(),
            .ppu_policy_ppu => self.context.ppu_policy_ppu_component.nConstraints(),
            .dma_semantic => self.context.dma_component.nConstraints(),
            .dma_binding => self.context.dma_binding_component.nConstraints(),
            .dma_execution_execution => self.context
                .dma_execution_execution_component.nConstraints(),
            .dma_execution_dma => self.context
                .dma_execution_dma_component.nConstraints(),
            .dma_memory => self.context.dma_memory_component.nConstraints(),
            .apu_binding => self.context.apu_binding_component.nConstraints(),
            .apu_execution_execution => self.context
                .apu_execution_execution_component.nConstraints(),
            .apu_execution_apu => self.context
                .apu_execution_apu_component.nConstraints(),
        };
    }

    pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
        return switch (self.kind) {
            inline else => |kind| self.leaf(kind)
                .maxConstraintLogDegreeBound(),
        };
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
        return switch (self.kind) {
            .execution_spine,
            .scheduler_semantic,
            .scheduler_memory,
            .service_memory,
            => allocator.dupe(usize, &.{
                cartridge_statement.EXECUTION_FIRST_PREPROCESSED,
                cartridge_statement.EXECUTION_LAST_PREPROCESSED,
            }),
            .scheduler_binding => allocator.alloc(usize, 0),
            .ppu_semantic, .ppu_binding => allocator.dupe(usize, &.{
                geometry.PPU_FIRST_PREPROCESSED,
                geometry.PPU_LAST_PREPROCESSED,
            }),
            .ppu_mmio_execution, .dma_execution_execution => allocator.dupe(usize, &.{
                cartridge_statement.EXECUTION_FIRST_PREPROCESSED,
            }),
            .ppu_mmio_ppu, .ppu_if_memory, .ppu_policy_ppu => allocator.dupe(usize, &.{
                geometry.PPU_FIRST_PREPROCESSED,
            }),
            .dma_semantic, .dma_binding => allocator.dupe(usize, &.{
                geometry.DMA_FIRST_PREPROCESSED,
                geometry.DMA_LAST_PREPROCESSED,
            }),
            .ppu_policy_dma, .dma_execution_dma, .dma_memory => allocator.dupe(usize, &.{
                geometry.DMA_FIRST_PREPROCESSED,
            }),
            .apu_binding, .apu_execution_apu => allocator.dupe(usize, &.{
                geometry.APU_FIRST_PREPROCESSED,
                geometry.APU_LAST_PREPROCESSED,
            }),
            .apu_execution_execution => allocator.dupe(usize, &.{
                cartridge_statement.EXECUTION_FIRST_PREPROCESSED,
                cartridge_statement.EXECUTION_LAST_PREPROCESSED,
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
        switch (self.kind) {
            inline else => |kind| return self.leaf(kind)
                .evaluateConstraintQuotientsAtPoint(
                point,
                mask,
                accumulator,
                max_log_degree_bound,
            ),
        }
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const Self,
        trace: *const prover_component.Trace,
        accumulator: *prover_accumulation.DomainEvaluationAccumulator,
    ) !void {
        switch (self.kind) {
            inline else => |kind| return self.leaf(kind)
                .evaluateConstraintQuotientsOnDomain(
                trace,
                accumulator,
            ),
        }
    }

    fn leaf(self: *const Self, comptime kind: TailKind) *const switch (kind) {
        .execution_spine => ExecutionComponent,
        .scheduler_semantic => SchedulerComponent,
        .scheduler_binding => SchedulerBindingComponent,
        .scheduler_memory => SchedulerMemoryComponent,
        .service_memory => ServiceMemoryComponent,
        .ppu_semantic => PpuComponent,
        .ppu_binding => PpuBindingComponent,
        .ppu_mmio_execution, .ppu_mmio_ppu => PpuMmioComponent,
        .ppu_if_memory => PpuIfComponent,
        .ppu_policy_dma, .ppu_policy_ppu => PpuPolicyComponent,
        .dma_semantic => DmaComponent,
        .dma_binding => DmaBindingComponent,
        .dma_execution_execution,
        .dma_execution_dma,
        => DmaExecutionComponent,
        .dma_memory => DmaMemoryComponent,
        .apu_binding => ApuBindingComponent,
        .apu_execution_execution,
        .apu_execution_apu,
        => ApuExecutionComponent,
    } {
        return switch (kind) {
            .execution_spine => &self.context.environment.cartridge.cpu
                .execution_component,
            .scheduler_semantic => &self.context.scheduler_component,
            .scheduler_binding => &self.context.scheduler_binding_component,
            .scheduler_memory => &self.context.scheduler_memory_component,
            .service_memory => &self.context.service_memory_component,
            .ppu_semantic => &self.context.ppu_component,
            .ppu_binding => &self.context.ppu_binding_component,
            .ppu_mmio_execution => &self.context.ppu_mmio_execution_component,
            .ppu_mmio_ppu => &self.context.ppu_mmio_ppu_component,
            .ppu_if_memory => &self.context.ppu_if_component,
            .ppu_policy_dma => &self.context.ppu_policy_dma_component,
            .ppu_policy_ppu => &self.context.ppu_policy_ppu_component,
            .dma_semantic => &self.context.dma_component,
            .dma_binding => &self.context.dma_binding_component,
            .dma_execution_execution => &self.context.dma_execution_execution_component,
            .dma_execution_dma => &self.context.dma_execution_dma_component,
            .dma_memory => &self.context.dma_memory_component,
            .apu_binding => &self.context.apu_binding_component,
            .apu_execution_execution => &self.context.apu_execution_execution_component,
            .apu_execution_apu => &self.context.apu_execution_apu_component,
        };
    }

    fn logSize(self: *const Self) u32 {
        return switch (self.kind) {
            .ppu_semantic,
            .ppu_binding,
            .ppu_mmio_ppu,
            .ppu_if_memory,
            .ppu_policy_ppu,
            => self.context.statement_value.ppu_log_size,
            .dma_semantic,
            .dma_binding,
            .ppu_policy_dma,
            .dma_execution_dma,
            .dma_memory,
            => self.context.statement_value.dma_log_size,
            .apu_binding,
            .apu_execution_apu,
            => self.context.statement_value.apu_log_size,
            else => self.context.statement_value.base.base.log_size,
        };
    }

    fn ownedPreprocessed(self: *const Self) usize {
        return switch (self.kind) {
            .execution_spine, .ppu_semantic, .dma_semantic, .apu_binding => 2,
            else => 0,
        };
    }

    fn ownedMain(self: *const Self) usize {
        return switch (self.kind) {
            .execution_spine => execution.N_MAIN_COLUMNS +
                execution.N_FAMILY_SELECTORS,
            .scheduler_semantic => scheduler.N_MAIN_COLUMNS,
            .scheduler_binding => scheduler_binding.N_PROVENANCE_COLUMNS,
            .scheduler_memory => scheduler_memory.N_MAIN_COLUMNS,
            .service_memory => service_memory.N_MAIN_COLUMNS,
            .ppu_semantic => ppu_component.N_MAIN_COLUMNS,
            .ppu_binding => ppu_binding.N_MAIN_COLUMNS -
                ppu_component.N_MAIN_COLUMNS,
            .ppu_mmio_ppu => 1,
            .ppu_if_memory => ppu_if.N_MAIN_COLUMNS,
            .ppu_policy_ppu => ppu_execution_policy.N_MAIN_COLUMNS,
            .dma_semantic => dma_component.N_MAIN_COLUMNS,
            .dma_binding => dma_binding.N_MAIN_COLUMNS -
                dma_component.N_MAIN_COLUMNS,
            .dma_memory => dma_memory.N_MAIN_COLUMNS,
            .apu_binding => apu_binding.layout.N_MAIN_COLUMNS,
            .apu_execution_execution => apu_execution.N_EXECUTION_AUXILIARY_COLUMNS,
            .apu_execution_apu => apu_execution.N_APU_AUXILIARY_COLUMNS,
            else => 0,
        };
    }

    fn ownedInteraction(self: *const Self) usize {
        return switch (self.kind) {
            .scheduler_memory => scheduler_memory.N_INTERACTION_COLUMNS,
            .service_memory => service_memory.N_INTERACTION_COLUMNS,
            .ppu_mmio_execution => ppu_mmio.N_EXECUTION_INTERACTION_COLUMNS,
            .ppu_mmio_ppu => ppu_mmio.N_PPU_INTERACTION_COLUMNS,
            .ppu_if_memory => ppu_if.N_INTERACTION_COLUMNS,
            .ppu_policy_dma => ppu_execution_policy.N_DMA_INTERACTION_COLUMNS,
            .ppu_policy_ppu => ppu_execution_policy.N_PPU_INTERACTION_COLUMNS,
            .dma_execution_execution => dma_execution.N_EXECUTION_INTERACTION_COLUMNS,
            .dma_execution_dma => dma_execution.N_DMA_INTERACTION_COLUMNS,
            .dma_memory => dma_memory.N_INTERACTION_COLUMNS,
            .apu_execution_execution => apu_execution.N_EXECUTION_INTERACTION_COLUMNS,
            .apu_execution_apu => apu_execution.N_APU_INTERACTION_COLUMNS,
            else => 0,
        };
    }

    fn needsNextMain(self: *const Self) bool {
        return switch (self.kind) {
            .execution_spine,
            .scheduler_semantic,
            .ppu_semantic,
            .ppu_binding,
            .dma_semantic,
            .dma_binding,
            .apu_binding,
            .apu_execution_execution,
            .apu_execution_apu,
            => true,
            else => false,
        };
    }
};

fn provenanceEventColumn(event: machine.SchedulerEvent) usize {
    return geometry.SCHEDULER_PROVENANCE_MAIN_OFFSET +
        scheduler_binding.EVENT_OFFSET + @intFromEnum(event);
}

fn schedulerBoundary(
    boundary: @import("air/execution.zig").Boundary,
    halt_bug: bool,
) scheduler.Boundary {
    return .{
        .mcycle = boundary.mcycle,
        .ime = boundary.cpu.ime,
        .ime_enable_pending = boundary.cpu.ime_enable_pending,
        .halted = boundary.cpu.halted,
        .halt_bug = halt_bug,
    };
}

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
