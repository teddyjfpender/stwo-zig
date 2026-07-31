//! Canonical construction and order of the SM83 proof components.

const core_air_components = @import("stwo_core").air.components;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const Alu16Component = @import("air/alu16_component.zig").Component;
const Alu8Component = @import("air/alu8_component.zig").Component;
const BranchComponent = @import("air/branch_component.zig").Component;
const CbBitComponent = @import("air/cb_bit_component.zig").Component;
const CbResSetComponent = @import("air/cb_res_set_component.zig").Component;
const CbRotateShiftComponent =
    @import("air/cb_rotate_shift_component.zig").Component;
const DaaComponent = @import("air/daa_component.zig").Component;
const Incdec16Component = @import("air/incdec16_component.zig").Component;
const Incdec8Component = @import("air/incdec8_component.zig").Component;
const InterruptComponent = @import("air/interrupt_component.zig").Component;
const InterruptServiceComponent =
    @import("air/interrupt_service_component.zig").Component;
const Load16Component = @import("air/load16_component.zig").Component;
const Load8Component = @import("air/load8_component.zig").Component;
const MiscComponent = @import("air/misc_component.zig").Component;
const RotateAccumulatorComponent =
    @import("air/rotate_accumulator_component.zig").Component;
const StackComponent = @import("air/stack_component.zig").Component;
const ExecutionComponent = @import("air/execution_component.zig").Component;
const MemoryLookupComponent = @import("air/memory_lookup_component.zig").Component;
const ProgramLookupComponent = @import("air/program_lookup_component.zig").Component;
const family_trace = @import("air/family_trace.zig");
const memory_lookup = @import("air/memory_lookup.zig");
const program_lookup = @import("air/program_lookup.zig");
const protocol = @import("proof_statement.zig");
const rom = @import("rom.zig");

pub const VerifierComponent = core_air_components.Component;
pub const ProverComponent = prover_component.ComponentProver;
pub const N_COMPONENTS: usize = 21;

pub const Context = struct {
    statement_value: protocol.ExecutionStatement,
    program_relation: program_lookup.Relation,
    memory_relation: memory_lookup.Relation,
    execution_component: ExecutionComponent,
    alu8_component: Alu8Component,
    daa_component: DaaComponent,
    incdec8_component: Incdec8Component,
    incdec16_component: Incdec16Component,
    rotate_accumulator_component: RotateAccumulatorComponent,
    load8_component: Load8Component,
    alu16_component: Alu16Component,
    cb_rotate_shift_component: CbRotateShiftComponent,
    cb_bit_component: CbBitComponent,
    cb_res_set_component: CbResSetComponent,
    load16_component: Load16Component,
    misc_component: MiscComponent,
    branch_component: BranchComponent,
    stack_component: StackComponent,
    interrupt_component: InterruptComponent,
    interrupt_service_component: InterruptServiceComponent,
    execution_lookup_component: ProgramLookupComponent,
    memory_execution_component: MemoryLookupComponent,
    rom_lookup_component: ProgramLookupComponent,
    memory_boundary_component: MemoryLookupComponent,
};

pub fn init(
    out: *Context,
    statement: protocol.ExecutionStatement,
    program_relation: program_lookup.Relation,
    memory_relation: memory_lookup.Relation,
    program_claims: program_lookup.Claims,
    memory_claims: memory_lookup.Claims,
) void {
    out.statement_value = statement;
    out.statement_value.program_lookup_claims = program_claims;
    out.statement_value.memory_lookup_claims = memory_claims;
    out.program_relation = program_relation;
    out.memory_relation = memory_relation;
    out.execution_component = .{
        .log_size = statement.log_size,
        .is_first_column = 0,
        .is_last_column = 1,
        .main_offset = 0,
        .initial = statement.initial,
        .final = statement.final,
    };
    out.alu8_component = .{
        .log_size = statement.log_size,
        .is_active_main_column = protocol.FAMILY_MAIN_OFFSET + family_trace.ALU8_SELECTOR,
        .execution_offset = 0,
        .main_offset = protocol.FAMILY_MAIN_OFFSET + family_trace.ALU8_OFFSET,
    };
    out.daa_component = .{
        .log_size = statement.log_size,
        .is_active_main_column = protocol.FAMILY_MAIN_OFFSET + family_trace.DAA_SELECTOR,
        .execution_offset = 0,
        .main_offset = protocol.FAMILY_MAIN_OFFSET + family_trace.DAA_OFFSET,
    };
    out.incdec8_component = .{
        .log_size = statement.log_size,
        .is_active_main_column = protocol.FAMILY_MAIN_OFFSET + family_trace.INCDEC8_SELECTOR,
        .execution_offset = 0,
        .main_offset = protocol.FAMILY_MAIN_OFFSET + family_trace.INCDEC8_OFFSET,
    };
    out.incdec16_component = .{
        .log_size = statement.log_size,
        .is_active_main_column = protocol.FAMILY_MAIN_OFFSET + family_trace.INCDEC16_SELECTOR,
        .execution_offset = 0,
        .main_offset = protocol.FAMILY_MAIN_OFFSET + family_trace.INCDEC16_OFFSET,
    };
    out.rotate_accumulator_component = .{
        .log_size = statement.log_size,
        .is_active_main_column = protocol.FAMILY_MAIN_OFFSET + family_trace.ROTATE_ACCUMULATOR_SELECTOR,
        .execution_offset = 0,
        .main_offset = protocol.FAMILY_MAIN_OFFSET + family_trace.ROTATE_ACCUMULATOR_OFFSET,
    };
    out.load8_component = .{
        .log_size = statement.log_size,
        .is_active_main_column = protocol.FAMILY_MAIN_OFFSET + family_trace.LOAD8_SELECTOR,
        .execution_offset = 0,
        .main_offset = protocol.FAMILY_MAIN_OFFSET + family_trace.LOAD8_OFFSET,
    };
    out.alu16_component = .{
        .log_size = statement.log_size,
        .is_active_main_column = protocol.FAMILY_MAIN_OFFSET + family_trace.ALU16_SELECTOR,
        .execution_offset = 0,
        .main_offset = protocol.FAMILY_MAIN_OFFSET + family_trace.ALU16_OFFSET,
    };
    out.cb_rotate_shift_component = .{
        .log_size = statement.log_size,
        .is_active_main_column = protocol.FAMILY_MAIN_OFFSET + family_trace.CB_ROTATE_SHIFT_SELECTOR,
        .execution_offset = 0,
        .main_offset = protocol.FAMILY_MAIN_OFFSET + family_trace.CB_ROTATE_SHIFT_OFFSET,
    };
    out.cb_bit_component = .{
        .log_size = statement.log_size,
        .is_active_main_column = protocol.FAMILY_MAIN_OFFSET + family_trace.CB_BIT_SELECTOR,
        .execution_offset = 0,
        .main_offset = protocol.FAMILY_MAIN_OFFSET + family_trace.CB_BIT_OFFSET,
    };
    out.cb_res_set_component = .{
        .log_size = statement.log_size,
        .is_active_main_column = protocol.FAMILY_MAIN_OFFSET + family_trace.CB_RES_SET_SELECTOR,
        .execution_offset = 0,
        .main_offset = protocol.FAMILY_MAIN_OFFSET + family_trace.CB_RES_SET_OFFSET,
    };
    out.load16_component = .{
        .log_size = statement.log_size,
        .is_active_main_column = protocol.FAMILY_MAIN_OFFSET + family_trace.LOAD16_SELECTOR,
        .execution_offset = 0,
        .main_offset = protocol.FAMILY_MAIN_OFFSET + family_trace.LOAD16_OFFSET,
    };
    out.misc_component = .{
        .log_size = statement.log_size,
        .is_active_main_column = protocol.FAMILY_MAIN_OFFSET + family_trace.MISC_SELECTOR,
        .execution_offset = 0,
        .main_offset = protocol.FAMILY_MAIN_OFFSET + family_trace.MISC_OFFSET,
    };
    out.branch_component = .{
        .log_size = statement.log_size,
        .is_active_main_column = protocol.FAMILY_MAIN_OFFSET + family_trace.BRANCH_SELECTOR,
        .execution_offset = 0,
        .main_offset = protocol.FAMILY_MAIN_OFFSET + family_trace.BRANCH_OFFSET,
    };
    out.stack_component = .{
        .log_size = statement.log_size,
        .is_active_main_column = protocol.FAMILY_MAIN_OFFSET + family_trace.STACK_SELECTOR,
        .execution_offset = 0,
        .main_offset = protocol.FAMILY_MAIN_OFFSET + family_trace.STACK_OFFSET,
    };
    out.interrupt_component = .{
        .log_size = statement.log_size,
        .is_active_main_column = protocol.FAMILY_MAIN_OFFSET + family_trace.INTERRUPT_SELECTOR,
        .execution_offset = 0,
        .main_offset = protocol.FAMILY_MAIN_OFFSET + family_trace.INTERRUPT_OFFSET,
    };
    out.interrupt_service_component = .{
        .log_size = statement.log_size,
        .is_active_main_column = protocol.FAMILY_MAIN_OFFSET +
            family_trace.INTERRUPT_SERVICE_SELECTOR,
        .execution_offset = 0,
        .main_offset = protocol.FAMILY_MAIN_OFFSET +
            family_trace.INTERRUPT_SERVICE_OFFSET,
    };
    out.execution_lookup_component = .{
        .kind = .execution,
        .log_size = statement.log_size,
        .is_first_column = 0,
        .main_offset = 0,
        .interaction_offset = 0,
        .relation = &out.program_relation,
        .claims = program_claims.execution,
    };
    out.memory_execution_component = .{
        .kind = .execution,
        .log_size = statement.log_size,
        .is_first_column = 0,
        .execution_offset = 0,
        .main_offset = protocol.MEMORY_ACCESS_OFFSET,
        .interaction_offset = protocol.MEMORY_EXECUTION_INTERACTION_OFFSET,
        .relation = &out.memory_relation,
        .claims = memory_claims.execution,
    };
    out.rom_lookup_component = .{
        .kind = .rom,
        .log_size = rom.LOG_SIZE,
        .is_first_column = 2,
        .address_column = 3,
        .value_column = 4,
        .main_offset = protocol.ROM_MULTIPLICITY_OFFSET,
        .interaction_offset = protocol.PROGRAM_ROM_INTERACTION_OFFSET,
        .relation = &out.program_relation,
        .claims = .{ program_claims.rom, QM31.zero() },
    };
    out.memory_boundary_component = .{
        .kind = .boundary,
        .log_size = 16,
        .is_first_column = 5,
        .address_column = 6,
        .initial_value_column = 7,
        .final_value_column = 8,
        .main_offset = protocol.MEMORY_BOUNDARY_OFFSET,
        .interaction_offset = protocol.MEMORY_BOUNDARY_INTERACTION_OFFSET,
        .relation = &out.memory_relation,
        .claims = .{memory_claims.boundary} ++
            .{QM31.zero()} ** (memory_lookup.N_EXECUTION_SUMS - 1),
    };
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
    const ordered = .{
        &context.execution_component,
        &context.alu8_component,
        &context.daa_component,
        &context.incdec8_component,
        &context.incdec16_component,
        &context.rotate_accumulator_component,
        &context.load8_component,
        &context.alu16_component,
        &context.cb_rotate_shift_component,
        &context.cb_bit_component,
        &context.cb_res_set_component,
        &context.load16_component,
        &context.misc_component,
        &context.branch_component,
        &context.stack_component,
        &context.interrupt_component,
        &context.interrupt_service_component,
        &context.execution_lookup_component,
        &context.memory_execution_component,
        &context.rom_lookup_component,
        &context.memory_boundary_component,
    };
    comptime {
        if (ordered.len != N_COMPONENTS) @compileError("invalid component count");
    }
    inline for (ordered, 0..) |component, index| {
        out[index] = switch (kind) {
            .verifier => component.asVerifierComponent(),
            .prover => component.asProverComponent(),
        };
    }
    return out[0..N_COMPONENTS];
}
