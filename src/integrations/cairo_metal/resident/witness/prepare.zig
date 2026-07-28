//! Prepared Metal recipe ownership for Cairo base and interaction witnesses.

const std = @import("std");
const arena_plan = @import("../../../../backends/metal/arena_plan.zig");
const metal_runtime = @import("../../../../backends/metal/runtime.zig");
const protocol_recipes = @import("../../../../backends/metal/protocol_recipes.zig");
const cairo_adapter = @import("stwo_cairo_frontend").adapter;
const fixed_table_bundle_mod = @import("stwo_cairo_frontend").witness.fixed_table_bundle;
const witness_bundle_mod = @import("stwo_cairo_frontend").witness.bundle;
const witness_program_mod = @import("stwo_cairo_frontend").witness.program;
const witness_aot = @import("../../witness_aot.zig");
const witness_codegen = @import("../../witness_codegen.zig");
const recipe_requirements = @import("../../recipe_requirements.zig");
const schedule_bindings = @import("../../schedule_bindings.zig");
const preprocessed_bindings = @import("../preprocessed/bindings.zig");
const resident_binding = @import("../binding.zig");
const Error = @import("../errors.zig").Error;

const collect = schedule_bindings.collect;
const collectComponent = schedule_bindings.collectComponent;
const one = schedule_bindings.one;
const oneComponent = schedule_bindings.oneComponent;
const oneComponentOrdinal = schedule_bindings.oneComponentOrdinal;
const collectPreprocessedBindings = preprocessed_bindings.collect;
const wordOffset = resident_binding.wordOffset;

pub const WitnessRecipeRequirements = recipe_requirements.Requirements;

pub const WitnessRecipes = struct {
    compact_verify: ?*protocol_recipes.CompactRecipe = null,
    compact_pedersen: ?*protocol_recipes.CompactRecipe = null,
    compact_poseidon: ?*protocol_recipes.CompactRecipe = null,
    ec_op: ?*protocol_recipes.EcOpRecipe = null,

    pub fn validate(self: WitnessRecipes, required: WitnessRecipeRequirements) Error!void {
        if (required.verify_instruction and self.compact_verify == null or
            required.pedersen and self.compact_pedersen == null or
            required.poseidon and self.compact_poseidon == null or
            required.ec_op and self.ec_op == null)
            return Error.MissingBinding;
        if (!required.verify_instruction and self.compact_verify != null or
            !required.pedersen and self.compact_pedersen != null or
            !required.poseidon and self.compact_poseidon != null or
            !required.ec_op and self.ec_op != null)
            return Error.InvalidSchedule;
    }
};

const aot_narrow_address_limit_bytes = (@as(u64, std.math.maxInt(u32)) + 1) * @sizeOf(u32);

fn aotBindingFitsNarrowAddress(binding: arena_plan.Binding) bool {
    if (binding.offset_bytes % @sizeOf(u32) != 0 or binding.size_bytes % @sizeOf(u32) != 0)
        return false;
    return binding.offset_bytes <= aot_narrow_address_limit_bytes and
        binding.size_bytes <= aot_narrow_address_limit_bytes - binding.offset_bytes;
}

fn recordAotHighBinding(
    high_count: *usize,
    component: []const u8,
    binding_purpose: []const u8,
    binding: arena_plan.Binding,
) void {
    if (aotBindingFitsNarrowAddress(binding)) return;
    high_count.* += 1;
    std.debug.print(
        "aot_high_binding component={s} purpose={s} id={} offset={} end={} words={}\n",
        .{
            component,
            binding_purpose,
            binding.logical_id,
            binding.offset_bytes,
            binding.offset_bytes + binding.size_bytes,
            binding.size_bytes / @sizeOf(u32),
        },
    );
}

pub fn prepareEcOpWitness(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    input: *const cairo_adapter.ProverInput,
    output_mode: protocol_recipes.EcOpOutputMode,
) !protocol_recipes.EcOpRecipe {
    var execution: [37]arena_plan.Binding = undefined;
    execution[0] = try one(schedule, plan, "ExecutionTableRawAddressToId");
    const big = try collect(allocator, schedule, plan, "ExecutionTableBigLimb");
    defer allocator.free(big);
    const small = try collect(allocator, schedule, plan, "ExecutionTableSmallLimb");
    defer allocator.free(small);
    if (big.len != 28 or small.len != 8) return Error.InvalidCardinality;
    @memcpy(execution[1..29], big);
    @memcpy(execution[29..37], small);

    const trace = try collectComponent(allocator, schedule, plan, "BaseTrace", "ec_op_builtin");
    defer allocator.free(trace);
    const partial = try collectComponent(allocator, schedule, plan, "WitnessInput", "partial_ec_mul_generic");
    defer allocator.free(partial);
    if (trace.len != 273 or partial.len != 126) return Error.InvalidCardinality;
    var trace_columns: [273]arena_plan.Binding = undefined;
    var partial_columns: [127]arena_plan.Binding = undefined;
    @memcpy(&trace_columns, trace);
    @memcpy(partial_columns[0..126], partial);
    const partial_iota = try oneComponent(schedule, plan, "EcOpPartialIota", "ec_op_builtin");
    partial_columns[126] = partial_iota;
    const segment_start = try oneComponent(schedule, plan, "EcOpSegmentStart", "ec_op_builtin");
    const ec_segment = input.builtin_segments.ec_op_builtin orelse return Error.MissingBinding;
    if (ec_segment.begin_addr > std.math.maxInt(u32)) return Error.InvalidBindingSize;
    const segment_bytes = try resident_arena.bytes(segment_start);
    const segment_aligned: *align(4) u32 = @ptrCast(@alignCast(segment_bytes.ptr));
    segment_aligned.* = @intCast(ec_segment.begin_addr);
    const row_count = std.math.cast(u32, trace[0].size_bytes / 4) orelse return Error.InvalidBindingSize;
    const multiplicities = [4]arena_plan.Binding{
        try oneComponentOrdinal(schedule, plan, "RuntimeMultiplicity", "memory_address_to_id", 21),
        try oneComponentOrdinal(schedule, plan, "RuntimeMultiplicity", "memory_id_to_big", 22),
        try oneComponentOrdinal(schedule, plan, "RuntimeMultiplicity", "memory_id_to_big", 23),
        try oneComponentOrdinal(schedule, plan, "FixedMultiplicity", "range_check_8", 0),
    };
    return protocol_recipes.EcOpRecipe.init(allocator, metal, resident_arena, .{
        .execution_columns = execution,
        .trace_columns = trace_columns,
        .partial_columns = partial_columns,
        .multiplicities = multiplicities,
        .lookup = try oneComponent(schedule, plan, "LookupInputs", "ec_op_builtin"),
        .segment_start = segment_start,
        .scratch = partial_iota,
        .row_count = row_count,
    }, output_mode);
}

pub fn prepareAotWitnessBatch(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    witness_bundle: witness_bundle_mod.Bundle,
    fixed_bundle: fixed_table_bundle_mod.Bundle,
) !protocol_recipes.AotWitnessBatchRecipe {
    return prepareAotWitnessBatchForMode(
        allocator,
        metal,
        resident_arena,
        schedule,
        plan,
        witness_bundle,
        fixed_bundle,
        .base,
        .source_jit,
    );
}

/// Prepares lookup-only witness replay for the interaction epoch. Generated
/// kernels suppress base columns and multiplicities, but retain subcomponent
/// words so the proof-plan DAG can reconstruct gathered and compacted inputs.
pub fn prepareAotInteractionBatch(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    witness_bundle: witness_bundle_mod.Bundle,
    fixed_bundle: fixed_table_bundle_mod.Bundle,
) !protocol_recipes.AotWitnessBatchRecipe {
    return prepareAotWitnessBatchForMode(
        allocator,
        metal,
        resident_arena,
        schedule,
        plan,
        witness_bundle,
        fixed_bundle,
        .interaction,
        .source_jit,
    );
}

pub const AuthenticatedAotWitnessBatches = struct {
    base: protocol_recipes.AotWitnessBatchRecipe,
    interaction: protocol_recipes.AotWitnessBatchRecipe,

    pub fn deinit(self: *AuthenticatedAotWitnessBatches) void {
        self.interaction.deinit();
        self.base.deinit();
        self.* = undefined;
    }
};

/// Admits one generated witness metallib and resolves the complete base and
/// interaction pipeline set. This explicit API never falls back to source JIT.
pub fn prepareAuthenticatedAotWitnessBatches(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    witness_bundle: witness_bundle_mod.Bundle,
    fixed_bundle: fixed_table_bundle_mod.Bundle,
    program: witness_aot.AuthenticatedMetallib,
) !AuthenticatedAotWitnessBatches {
    try program.authenticate(allocator, witness_bundle);
    var base = try prepareAotWitnessBatchForMode(
        allocator,
        metal,
        resident_arena,
        schedule,
        plan,
        witness_bundle,
        fixed_bundle,
        .base,
        .{ .metallib = program.path },
    );
    errdefer base.deinit();

    // Re-authenticate immediately before the second library acquisition. The
    // caller must still provide an immutable admitted path for the load itself.
    try program.authenticate(allocator, witness_bundle);
    const interaction = try prepareAotWitnessBatchForMode(
        allocator,
        metal,
        resident_arena,
        schedule,
        plan,
        witness_bundle,
        fixed_bundle,
        .interaction,
        .{ .metallib = program.path },
    );
    return .{ .base = base, .interaction = interaction };
}

const FixedDeductionRequirements = struct {
    pedersen: bool = false,
    poseidon: bool = false,
};

const WitnessProgram = union(enum) {
    source_jit,
    metallib: []const u8,
};

fn fixedDeductionRequirements(bundle: witness_bundle_mod.Bundle) FixedDeductionRequirements {
    var result = FixedDeductionRequirements{};
    for (bundle.entries) |entry| {
        for (entry.program.insts) |inst| {
            if (@as(witness_program_mod.Op, @enumFromInt(inst.op)) != .deduce_call) continue;
            switch (inst.imm) {
                2, 3, 12, 13 => result.pedersen = true,
                8, 10, 11 => result.poseidon = true,
                else => {},
            }
        }
    }
    return result;
}

fn prepareAotWitnessBatchForMode(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    witness_bundle: witness_bundle_mod.Bundle,
    fixed_bundle: fixed_table_bundle_mod.Bundle,
    mode: witness_codegen.KernelMode,
    program: WitnessProgram,
) !protocol_recipes.AotWitnessBatchRecipe {
    if (mode == .all) return Error.InvalidCardinality;
    const table_pointers_planned = try one(schedule, plan, "ExecutionTablePointers");
    const table_strides_planned = try one(schedule, plan, "ExecutionTableStrides");
    const table_pointers = table_pointers_planned;
    const table_strides = table_strides_planned;
    var execution_tables = std.ArrayList(arena_plan.Binding).empty;
    defer execution_tables.deinit(allocator);
    try execution_tables.append(allocator, try one(schedule, plan, "ExecutionTableRawAddressToId"));
    const big = try collect(allocator, schedule, plan, "ExecutionTableBigLimb");
    defer allocator.free(big);
    const small = try collect(allocator, schedule, plan, "ExecutionTableSmallLimb");
    defer allocator.free(small);
    if (big.len != 28 or small.len != 8) return Error.InvalidCardinality;
    try execution_tables.appendSlice(allocator, big);
    try execution_tables.appendSlice(allocator, small);
    const stride_bytes = try resident_arena.bytes(table_strides);
    if (stride_bytes.len != 12) return Error.InvalidBindingSize;
    const strides = [3]u32{
        @intCast(execution_tables.items[0].size_bytes / 4),
        @intCast(big[0].size_bytes / 4),
        @intCast(small[0].size_bytes / 4),
    };

    const deduction_requirements = fixedDeductionRequirements(witness_bundle);
    const pedersen_entry = if (deduction_requirements.pedersen)
        fixed_bundle.find("pedersen_points_table_window_bits_18") orelse return Error.MissingBinding
    else
        null;
    const poseidon_entry = if (deduction_requirements.poseidon)
        fixed_bundle.find("poseidon_round_keys") orelse return Error.MissingBinding
    else
        null;
    const pedersen_pointers = if (pedersen_entry) |entry|
        try oneComponent(schedule, plan, "FixedTableSourcePointers", entry.component)
    else
        table_pointers;
    const poseidon_pointers = if (poseidon_entry) |entry|
        try oneComponent(schedule, plan, "FixedTableSourcePointers", entry.component)
    else
        table_pointers;
    const pedersen_sources = if (pedersen_entry) |entry|
        try collectPreprocessedBindings(allocator, schedule, plan, fixed_bundle, entry.preprocessed_sources)
    else
        try allocator.alloc(arena_plan.Binding, 0);
    defer allocator.free(pedersen_sources);
    const poseidon_sources = if (poseidon_entry) |entry|
        try collectPreprocessedBindings(allocator, schedule, plan, fixed_bundle, entry.preprocessed_sources)
    else
        try allocator.alloc(arena_plan.Binding, 0);
    defer allocator.free(poseidon_sources);

    var high_bindings: usize = 0;
    recordAotHighBinding(&high_bindings, "shared", "ExecutionTablePointers", table_pointers);
    recordAotHighBinding(&high_bindings, "shared", "ExecutionTableStrides", table_strides);
    if (pedersen_entry != null)
        recordAotHighBinding(&high_bindings, "shared", "PedersenSourcePointers", pedersen_pointers);
    if (poseidon_entry != null)
        recordAotHighBinding(&high_bindings, "shared", "PoseidonSourcePointers", poseidon_pointers);
    for (execution_tables.items) |binding|
        recordAotHighBinding(&high_bindings, "shared", "ExecutionTable", binding);
    for (pedersen_sources) |binding|
        recordAotHighBinding(&high_bindings, "shared", "PedersenSource", binding);
    for (poseidon_sources) |binding|
        recordAotHighBinding(&high_bindings, "shared", "PoseidonSource", binding);
    for (witness_bundle.entries) |entry| {
        const inputs = try collectComponent(allocator, schedule, plan, "WitnessInput", entry.label);
        defer allocator.free(inputs);
        const outputs = try collectComponent(allocator, schedule, plan, "BaseTrace", entry.label);
        defer allocator.free(outputs);
        for (inputs) |binding| recordAotHighBinding(&high_bindings, entry.label, "WitnessInput", binding);
        for (outputs) |binding| recordAotHighBinding(&high_bindings, entry.label, "BaseTrace", binding);
        recordAotHighBinding(
            &high_bindings,
            entry.label,
            "LookupInputs",
            try oneComponent(schedule, plan, "LookupInputs", entry.label),
        );
        recordAotHighBinding(
            &high_bindings,
            entry.label,
            "SubcomponentInputs",
            try oneComponent(schedule, plan, "SubcomponentInputs", entry.label),
        );
        recordAotHighBinding(
            &high_bindings,
            entry.label,
            "WitnessInputPointers",
            try oneComponent(schedule, plan, "WitnessInputPointers", entry.label),
        );
        recordAotHighBinding(
            &high_bindings,
            entry.label,
            "WitnessOutputPointers",
            try oneComponent(schedule, plan, "WitnessOutputPointers", entry.label),
        );
        recordAotHighBinding(
            &high_bindings,
            entry.label,
            "WitnessMultiplicityPointers",
            try oneComponent(schedule, plan, "WitnessMultiplicityPointers", entry.label),
        );
    }
    if (high_bindings != 0) {
        std.debug.print("aot_high_binding_summary count={} limit_bytes={}\n", .{ high_bindings, aot_narrow_address_limit_bytes });
        return Error.InvalidBindingSize;
    }

    const invocations = try allocator.alloc(protocol_recipes.AotWitnessInvocation, witness_bundle.entries.len);
    defer allocator.free(invocations);
    const names = try allocator.alloc([]u8, witness_bundle.entries.len);
    var names_initialized: usize = 0;
    defer {
        for (names[0..names_initialized]) |name| allocator.free(name);
        allocator.free(names);
    }
    const owned_destinations = try allocator.alloc([]arena_plan.Binding, witness_bundle.entries.len);
    var destinations_initialized: usize = 0;
    defer {
        for (owned_destinations[0..destinations_initialized]) |destinations| allocator.free(destinations);
        allocator.free(owned_destinations);
    }
    const owned_inputs = try allocator.alloc([]arena_plan.Binding, witness_bundle.entries.len);
    var inputs_initialized: usize = 0;
    defer {
        for (owned_inputs[0..inputs_initialized]) |inputs| allocator.free(inputs);
        allocator.free(owned_inputs);
    }
    const owned_trace_outputs = try allocator.alloc([]arena_plan.Binding, witness_bundle.entries.len);
    var trace_outputs_initialized: usize = 0;
    defer {
        for (owned_trace_outputs[0..trace_outputs_initialized]) |outputs| allocator.free(outputs);
        allocator.free(owned_trace_outputs);
    }
    const owned_workspaces = try allocator.alloc([]protocol_recipes.AotWorkspaceWrite, witness_bundle.entries.len);
    var workspaces_initialized: usize = 0;
    defer {
        for (owned_workspaces[0..workspaces_initialized]) |writes| allocator.free(writes);
        allocator.free(owned_workspaces);
    }
    const kernel_modes = try allocator.alloc(witness_codegen.KernelMode, witness_bundle.entries.len);
    defer allocator.free(kernel_modes);

    for (witness_bundle.entries, invocations, names, owned_destinations, owned_inputs, owned_trace_outputs, owned_workspaces, kernel_modes) |entry, *invocation, *name, *owned, *input_storage, *output_storage, *workspace_storage, *kernel_mode| {
        const inputs = try collectComponent(allocator, schedule, plan, "WitnessInput", entry.label);
        input_storage.* = inputs;
        inputs_initialized += 1;
        const outputs = try collectComponent(allocator, schedule, plan, "BaseTrace", entry.label);
        output_storage.* = outputs;
        trace_outputs_initialized += 1;
        if (inputs.len != entry.program.n_inputs or outputs.len != entry.program.n_cols or outputs.len == 0)
            return Error.InvalidCardinality;
        const row_count = std.math.cast(u32, outputs[0].size_bytes / 4) orelse return Error.InvalidBindingSize;
        if (row_count == 0 or !std.math.isPowerOfTwo(row_count)) return Error.InvalidBindingSize;
        for (inputs) |binding| if (binding.size_bytes != @as(u64, row_count) * 4) return Error.InvalidBindingSize;
        for (outputs) |binding| if (binding.size_bytes != @as(u64, row_count) * 4) return Error.InvalidBindingSize;

        const input_pointers_planned = try oneComponent(schedule, plan, "WitnessInputPointers", entry.label);
        const output_pointers_planned = try oneComponent(schedule, plan, "WitnessOutputPointers", entry.label);
        const multiplicity_pointers_planned = try oneComponent(schedule, plan, "WitnessMultiplicityPointers", entry.label);
        if (input_pointers_planned.size_bytes > 2048 or output_pointers_planned.size_bytes > 8192 or
            multiplicity_pointers_planned.size_bytes > 2048)
            return Error.InvalidBindingSize;
        if (entry.program.n_mult_tables != 0) return Error.InvalidCardinality;
        const input_pointers = input_pointers_planned;
        const output_pointers = output_pointers_planned;
        const multiplicity_pointers = multiplicity_pointers_planned;

        const lookup = try oneComponent(schedule, plan, "LookupInputs", entry.label);
        const sub = try oneComponent(schedule, plan, "SubcomponentInputs", entry.label);
        if (lookup.size_bytes != @as(u64, row_count) * entry.program.n_lookup_words * 4 or
            sub.size_bytes != @as(u64, row_count) * entry.program.n_sub_words * 4)
            return Error.InvalidBindingSize;
        kernel_mode.* = switch (mode) {
            .base => witness_aot.kernelMode(entry.label, .base),
            .interaction => witness_aot.kernelMode(entry.label, .interaction),
            .all, .base_lookup, .interaction_subwords => unreachable,
        };
        const destination_count: usize = switch (mode) {
            .base => outputs.len + 1 + @intFromBool(kernel_mode.* == .base_lookup),
            .interaction => if (kernel_mode.* == .interaction_subwords) 1 else 2,
            .all, .base_lookup, .interaction_subwords => unreachable,
        };
        owned.* = try allocator.alloc(arena_plan.Binding, destination_count);
        destinations_initialized += 1;
        switch (mode) {
            .base => {
                @memcpy(owned.*[0..outputs.len], outputs);
                owned.*[outputs.len] = sub;
                if (kernel_mode.* == .base_lookup) owned.*[outputs.len + 1] = lookup;
            },
            .interaction => {
                if (kernel_mode.* == .interaction_subwords) {
                    owned.*[0] = sub;
                } else {
                    owned.*[0] = lookup;
                    owned.*[1] = sub;
                }
            },
            .all, .base_lookup, .interaction_subwords => unreachable,
        }
        const workspace_count: usize = 5 +
            @as(usize, @intFromBool(pedersen_entry != null)) +
            @as(usize, @intFromBool(poseidon_entry != null));
        workspace_storage.* = try allocator.alloc(protocol_recipes.AotWorkspaceWrite, workspace_count);
        workspaces_initialized += 1;
        var workspace_index: usize = 0;
        workspace_storage.*[workspace_index] = .{ .destination = table_pointers, .binding_offsets = execution_tables.items };
        workspace_index += 1;
        workspace_storage.*[workspace_index] = .{ .destination = table_strides, .words = &strides };
        workspace_index += 1;
        if (pedersen_entry != null) {
            workspace_storage.*[workspace_index] = .{ .destination = pedersen_pointers, .binding_offsets = pedersen_sources };
            workspace_index += 1;
        }
        if (poseidon_entry != null) {
            workspace_storage.*[workspace_index] = .{ .destination = poseidon_pointers, .binding_offsets = poseidon_sources };
            workspace_index += 1;
        }
        workspace_storage.*[workspace_index] = .{ .destination = input_pointers, .binding_offsets = inputs };
        workspace_index += 1;
        workspace_storage.*[workspace_index] = .{ .destination = output_pointers, .binding_offsets = outputs };
        workspace_index += 1;
        workspace_storage.*[workspace_index] = .{ .destination = multiplicity_pointers };
        name.* = try witness_codegen.kernelNameForMode(
            allocator,
            entry.program.semanticIdentity(),
            kernel_mode.*,
        );
        names_initialized += 1;
        invocation.* = .{
            .kernel_name = name.*,
            .layout = .{
                .input_offsets = try wordOffset(input_pointers),
                .table_offsets = try wordOffset(table_pointers),
                .table_strides = try wordOffset(table_strides),
                .output_offsets = try wordOffset(output_pointers),
                .multiplicity_offsets = try wordOffset(multiplicity_pointers),
                .lookup_words = try wordOffset(lookup),
                .sub_words = try wordOffset(sub),
                .row_count = row_count,
                .pedersen_offsets = try wordOffset(pedersen_pointers) + 1,
                .pedersen_rows = if (pedersen_entry) |fixed_entry| fixed_entry.row_count else 1,
                .poseidon_keys = try wordOffset(poseidon_pointers) + 1,
            },
            .destinations = owned.*,
            .workspace_writes = workspace_storage.*,
        };
    }
    return switch (program) {
        .source_jit => source_blk: {
            const source = try witness_codegen.generateBatchForModes(allocator, witness_bundle.entries, kernel_modes);
            defer allocator.free(source);
            break :source_blk protocol_recipes.AotWitnessBatchRecipe.initSource(
                allocator,
                metal,
                resident_arena,
                source,
                invocations,
            );
        },
        .metallib => |path| protocol_recipes.AotWitnessBatchRecipe.init(
            allocator,
            metal,
            resident_arena,
            path,
            invocations,
        ),
    };
}

test "Cairo AOT witness narrow addresses validate the complete binding extent" {
    const last_word = arena_plan.Binding{
        .logical_id = 0,
        .slot = 0,
        .offset_bytes = aot_narrow_address_limit_bytes - @sizeOf(u32),
        .size_bytes = @sizeOf(u32),
        .materialization = .resident,
        .occupied = [_]u64{0} ** 16,
    };
    try std.testing.expect(aotBindingFitsNarrowAddress(last_word));

    var invalid = last_word;
    invalid.size_bytes += @sizeOf(u32);
    try std.testing.expect(!aotBindingFitsNarrowAddress(invalid));
    invalid = last_word;
    invalid.offset_bytes = aot_narrow_address_limit_bytes;
    try std.testing.expect(!aotBindingFitsNarrowAddress(invalid));
    invalid = last_word;
    invalid.offset_bytes -= 1;
    try std.testing.expect(!aotBindingFitsNarrowAddress(invalid));
}

test "Cairo AOT fixed-table requirements follow witness bytecode capabilities" {
    var bundle = try witness_bundle_mod.Bundle.readFile(
        std.testing.allocator,
        "vectors/cairo/sn_pie_2_witness_programs.bin",
    );
    defer bundle.deinit();

    const complete = fixedDeductionRequirements(bundle);
    try std.testing.expect(complete.pedersen);
    try std.testing.expect(complete.poseidon);

    const add_ap = bundle.find("add_ap_opcode") orelse return error.MissingBinding;
    const arithmetic_only = witness_bundle_mod.Bundle{
        .allocator = std.testing.allocator,
        .entries = @constCast(add_ap)[0..1],
    };
    const reduced = fixedDeductionRequirements(arithmetic_only);
    try std.testing.expect(!reduced.pedersen);
    try std.testing.expect(!reduced.poseidon);
}
