//! Canonical component construction for detached-device cartridge proofs.
//!
//! The CPU spine and all sixteen family components are reused verbatim from
//! the flat proof context. Cartridge access, ROM, and mutable-memory
//! components then replace the flat lookup tail. Component registration
//! follows commitment ownership order, which is also transcript order.

const std = @import("std");
const core_air_components = @import("stwo_core").air.components;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const CartridgeAccessComponent =
    @import("air/cartridge_access_component.zig").Component;
const CartridgeMemoryLookupComponent =
    @import("air/cartridge_memory_lookup_component.zig").Component;
const CartridgeRomLookupComponent =
    @import("air/cartridge_rom_lookup_component.zig").Component;
const cartridge_memory_lookup =
    @import("air/cartridge_memory_lookup.zig");
const cartridge_rom_lookup = @import("air/cartridge_rom_lookup.zig");
const flat_memory_lookup = @import("air/memory_lookup.zig");
const flat_program_lookup = @import("air/program_lookup.zig");
const cartridge_protocol = @import("cartridge_proof_statement.zig");
const flat_components = @import("proof_components.zig");
const flat_protocol = @import("proof_statement.zig");

pub const VerifierComponent = core_air_components.Component;
pub const ProverComponent = prover_component.ComponentProver;
pub const N_CPU_COMPONENTS: usize = 17;
pub const N_CARTRIDGE_COMPONENTS: usize = 5;
pub const N_COMPONENTS: usize =
    N_CPU_COMPONENTS + N_CARTRIDGE_COMPONENTS;

comptime {
    std.debug.assert(flat_components.N_COMPONENTS >= N_CPU_COMPONENTS);
    std.debug.assert(
        cartridge_protocol.FAMILY_MAIN_OFFSET ==
            flat_protocol.FAMILY_MAIN_OFFSET,
    );
}

pub const Context = struct {
    statement_value: cartridge_protocol.ExecutionStatement,
    cpu: flat_components.Context,
    rom_relation: cartridge_rom_lookup.Relation,
    memory_relation: cartridge_memory_lookup.Relation,
    packed_access_component: CartridgeAccessComponent,
    rom_execution_component: CartridgeRomLookupComponent,
    memory_execution_component: CartridgeMemoryLookupComponent,
    rom_table_component: CartridgeRomLookupComponent,
    memory_boundary_component: CartridgeMemoryLookupComponent,
};

pub fn init(
    out: *Context,
    statement: cartridge_protocol.ExecutionStatement,
    rom_relation: cartridge_rom_lookup.Relation,
    memory_relation: cartridge_memory_lookup.Relation,
    rom_claims: cartridge_rom_lookup.Claims,
    memory_claims: cartridge_memory_lookup.Claims,
) void {
    out.statement_value = statement;
    out.statement_value.rom_lookup_claims = rom_claims;
    out.statement_value.memory_lookup_claims = memory_claims;
    initCanonicalCpu(&out.cpu, statement);
    out.rom_relation = rom_relation;
    out.memory_relation = memory_relation;
    out.packed_access_component = .{
        .log_size = statement.log_size,
        .is_first_column = cartridge_protocol.EXECUTION_FIRST_PREPROCESSED,
        .is_last_column = cartridge_protocol.EXECUTION_LAST_PREPROCESSED,
        .execution_offset = cartridge_protocol.EXECUTION_MAIN_OFFSET,
        .main_offset = cartridge_protocol.PACKED_ACCESS_MAIN_OFFSET,
        .initial = statement.initial_mapper,
        .final = statement.final_mapper,
        .allow_joypad_mmio = false,
        .allow_timer_mmio = false,
        .allow_ppu_mmio = false,
        .allow_open_bus = false,
    };
    out.rom_execution_component = .{
        .kind = .execution,
        .log_size = statement.log_size,
        .is_first_column = cartridge_protocol.EXECUTION_FIRST_PREPROCESSED,
        .main_offset = cartridge_protocol.PACKED_ACCESS_MAIN_OFFSET,
        .interaction_offset = cartridge_protocol.ROM_EXECUTION_INTERACTION_OFFSET,
        .owns_execution_source = false,
        .relation = &out.rom_relation,
        .claims = rom_claims.execution,
    };
    out.memory_execution_component = .{
        .kind = .execution,
        .log_size = statement.log_size,
        .is_first_column = cartridge_protocol.EXECUTION_FIRST_PREPROCESSED,
        .execution_offset = cartridge_protocol.EXECUTION_MAIN_OFFSET,
        .access_offset = cartridge_protocol.PACKED_ACCESS_MAIN_OFFSET,
        .main_offset = cartridge_protocol.MUTABLE_WITNESS_MAIN_OFFSET,
        .interaction_offset = cartridge_protocol.MUTABLE_EXECUTION_INTERACTION_OFFSET,
        .relation = &out.memory_relation,
        .claims = memory_claims.execution,
    };
    out.rom_table_component = .{
        .kind = .rom,
        .log_size = cartridge_rom_lookup.ROM_LOG_SIZE,
        .is_first_column = cartridge_protocol.ROM_FIRST_PREPROCESSED,
        .address_column = cartridge_protocol.ROM_ADDRESS_PREPROCESSED,
        .value_column = cartridge_protocol.ROM_VALUE_PREPROCESSED,
        .main_offset = cartridge_protocol.ROM_MULTIPLICITY_MAIN_OFFSET,
        .interaction_offset = cartridge_protocol.ROM_TABLE_INTERACTION_OFFSET,
        .relation = &out.rom_relation,
        .claims = .{rom_claims.rom} ++
            .{QM31.zero()} **
                (cartridge_rom_lookup.N_EXECUTION_SUMS - 1),
    };
    out.memory_boundary_component = .{
        .kind = .boundary,
        .log_size = cartridge_memory_lookup.BOUNDARY_LOG_SIZE,
        .is_first_column = cartridge_protocol.MEMORY_FIRST_PREPROCESSED,
        .enabled_column = cartridge_protocol.MEMORY_ENABLED_PREPROCESSED,
        .address_column = cartridge_protocol.MEMORY_ADDRESS_PREPROCESSED,
        .initial_value_column = cartridge_protocol.MEMORY_INITIAL_PREPROCESSED,
        .final_value_column = cartridge_protocol.MEMORY_FINAL_PREPROCESSED,
        .main_offset = cartridge_protocol.FINAL_CLOCK_MAIN_OFFSET,
        .interaction_offset = cartridge_protocol.MUTABLE_BOUNDARY_INTERACTION_OFFSET,
        .relation = &out.memory_relation,
        .claims = .{memory_claims.boundary} ++
            .{QM31.zero()} **
                (cartridge_memory_lookup.N_EXECUTION_SUMS - 1),
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
    var canonical_storage: [flat_components.N_COMPONENTS]Component(kind) =
        undefined;
    const canonical = switch (kind) {
        .verifier => try flat_components.verifier(
            &context.cpu,
            &canonical_storage,
        ),
        .prover => try flat_components.prover(
            &context.cpu,
            &canonical_storage,
        ),
    };
    @memcpy(out[0..N_CPU_COMPONENTS], canonical[0..N_CPU_COMPONENTS]);

    // Interactions are committed in execution-domain order before the ROM
    // and memory-boundary tables. Keep registration in that exact order.
    const cartridge_ordered = .{
        &context.packed_access_component,
        &context.rom_execution_component,
        &context.memory_execution_component,
        &context.rom_table_component,
        &context.memory_boundary_component,
    };
    comptime {
        if (cartridge_ordered.len != N_CARTRIDGE_COMPONENTS)
            @compileError("invalid cartridge component count");
    }
    inline for (cartridge_ordered, N_CPU_COMPONENTS..) |
        component,
        index,
    | {
        out[index] = switch (kind) {
            .verifier => component.asVerifierComponent(),
            .prover => component.asProverComponent(),
        };
    }
    return out[0..N_COMPONENTS];
}

fn initCanonicalCpu(
    out: *flat_components.Context,
    statement: cartridge_protocol.ExecutionStatement,
) void {
    const program_claims = flat_program_lookup.Claims{
        .execution = .{ QM31.zero(), QM31.zero() },
        .rom = QM31.zero(),
    };
    const memory_claims = flat_memory_lookup.Claims{
        .execution = .{QM31.zero()} ** flat_memory_lookup.N_EXECUTION_SUMS,
        .boundary = QM31.zero(),
    };
    const synthetic = flat_protocol.ExecutionStatement{
        .log_size = statement.log_size,
        .initial = statement.initial,
        .final = statement.final,
        .rom_digest = [_]u8{0} ** 32,
        .initial_memory_digest = [_]u8{0} ** 32,
        .final_memory_digest = [_]u8{0} ** 32,
        .program_lookup_claims = program_claims,
        .memory_lookup_claims = memory_claims,
    };
    flat_components.init(
        out,
        synthetic,
        flat_program_lookup.Relation.dummy(),
        flat_memory_lookup.Relation.dummy(),
        program_claims,
        memory_claims,
    );
}

test "cartridge collection reuses canonical CPU order and pins tail order" {
    const statement = testStatement();
    const rom_relation = cartridge_rom_lookup.Relation.dummy();
    const memory_relation = cartridge_memory_lookup.Relation.dummy();
    const rom_claims = testRomClaims();
    const memory_claims = testMemoryClaims();
    var context: Context = undefined;
    init(
        &context,
        statement,
        rom_relation,
        memory_relation,
        rom_claims,
        memory_claims,
    );

    var verifier_storage: [N_COMPONENTS]VerifierComponent = undefined;
    const verifier_components = try verifier(
        &context,
        &verifier_storage,
    );
    var canonical_storage: [flat_components.N_COMPONENTS]VerifierComponent =
        undefined;
    const canonical = try flat_components.verifier(
        &context.cpu,
        &canonical_storage,
    );
    try std.testing.expectEqual(N_COMPONENTS, verifier_components.len);
    for (
        verifier_components[0..N_CPU_COMPONENTS],
        canonical[0..N_CPU_COMPONENTS],
    ) |actual, expected| {
        try std.testing.expectEqual(
            @intFromPtr(expected.ctx),
            @intFromPtr(actual.ctx),
        );
        try std.testing.expectEqual(expected.vtable, actual.vtable);
    }
    const verifier_tail = [_]*const anyopaque{
        &context.packed_access_component,
        &context.rom_execution_component,
        &context.memory_execution_component,
        &context.rom_table_component,
        &context.memory_boundary_component,
    };
    for (
        verifier_components[N_CPU_COMPONENTS..],
        verifier_tail,
    ) |actual, expected|
        try std.testing.expectEqual(
            @intFromPtr(expected),
            @intFromPtr(actual.ctx),
        );

    var prover_storage: [N_COMPONENTS]ProverComponent = undefined;
    const prover_components = try prover(&context, &prover_storage);
    try std.testing.expectEqual(N_COMPONENTS, prover_components.len);
    for (
        prover_components[N_CPU_COMPONENTS..],
        verifier_tail,
    ) |actual, expected|
        try std.testing.expectEqual(
            @intFromPtr(expected),
            @intFromPtr(actual.ctx),
        );
    try std.testing.expectError(
        error.InvalidProofShape,
        verifier(&context, verifier_storage[0 .. N_COMPONENTS - 1]),
    );
    try std.testing.expectError(
        error.InvalidProofShape,
        prover(&context, prover_storage[0 .. N_COMPONENTS - 1]),
    );
}

test "cartridge collection exactly owns statement commitment geometry" {
    var context: Context = undefined;
    init(
        &context,
        testStatement(),
        cartridge_rom_lookup.Relation.dummy(),
        cartridge_memory_lookup.Relation.dummy(),
        testRomClaims(),
        testMemoryClaims(),
    );
    var storage: [N_COMPONENTS]VerifierComponent = undefined;
    const collected = try verifier(&context, &storage);
    const components = core_air_components.Components{
        .components = collected,
        .n_preprocessed_columns = cartridge_protocol.N_PREPROCESSED_COLUMNS,
    };
    var logs = try components.columnLogSizes(std.testing.allocator);
    defer logs.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), logs.items.len);
    try std.testing.expectEqualSlices(
        u32,
        &cartridge_protocol.preprocessedLogSizes(
            context.statement_value.log_size,
        ),
        logs.items[0],
    );
    try std.testing.expectEqualSlices(
        u32,
        &cartridge_protocol.mainLogSizes(
            context.statement_value.log_size,
        ),
        logs.items[1],
    );
    try std.testing.expectEqualSlices(
        u32,
        &cartridge_protocol.interactionLogSizes(
            context.statement_value.log_size,
        ),
        logs.items[2],
    );
    try std.testing.expectEqual(
        testRomClaims().execution[0],
        context.statement_value.rom_lookup_claims.execution[0],
    );
    try std.testing.expectEqual(
        testMemoryClaims().boundary,
        context.statement_value.memory_lookup_claims.boundary,
    );
    try std.testing.expect(
        !context.rom_execution_component.owns_execution_source,
    );
}

fn testStatement() cartridge_protocol.ExecutionStatement {
    return .{
        .log_size = 4,
        .initial = .{ .cpu = .{}, .mcycle = 0 },
        .final = .{ .cpu = .{}, .mcycle = 16 },
        .initial_mapper = .{},
        .final_mapper = .{},
        .rom_digest = [_]u8{0} ** 32,
        .initial_system_digest = [_]u8{0} ** 32,
        .final_system_digest = [_]u8{0} ** 32,
        .initial_sram_digest = [_]u8{0} ** 32,
        .final_sram_digest = [_]u8{0} ** 32,
        .rom_lookup_claims = testRomClaims(),
        .memory_lookup_claims = testMemoryClaims(),
    };
}

fn testRomClaims() cartridge_rom_lookup.Claims {
    return .{
        .execution = .{
            QM31.fromU32Unchecked(1, 2, 3, 4),
            QM31.fromU32Unchecked(2, 3, 4, 5),
            QM31.fromU32Unchecked(3, 4, 5, 6),
        },
        .rom = QM31.fromU32Unchecked(4, 5, 6, 7),
    };
}

fn testMemoryClaims() cartridge_memory_lookup.Claims {
    return .{
        .execution = .{
            QM31.fromU32Unchecked(5, 6, 7, 8),
            QM31.zero(),
            QM31.zero(),
            QM31.zero(),
            QM31.zero(),
            QM31.zero(),
        },
        .boundary = QM31.fromU32Unchecked(6, 7, 8, 9),
    };
}
