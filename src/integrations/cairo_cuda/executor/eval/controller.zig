//! Production-shaped resident Cairo constraint controller.
//!
//! Ingress seals every host-derived offset, descriptor, and AOT placement.
//! Constraint execution remains direct and sequential. The only injected
//! operation is the addressed compact-source LDE lift, whose CUDA primitive
//! is not yet present in the backend.

const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const common = @import(
    "../../../../backends/cuda/runtime/stages/common.zig",
);
const arena_module = @import(
    "../../../../backends/cuda/runtime/arena.zig",
);
const eval_stage = @import(
    "../../../../backends/cuda/runtime/stages/cairo_eval.zig",
);
const stages = @import(
    "../../../../backends/cuda/runtime/stages/mod.zig",
);
const transform = stages.transform;
const composition = @import(
    "../../../../frontends/cairo/witness/composition_bundle.zig",
);
const constraint_catalog = @import(
    "../../request_compiler/constraint_admission.zig",
);
const pcs_types = @import("../pcs_hooks_types.zig");
const resident_plan = @import("../resident_plan.zig");
const product_resolution = @import("product_resolution.zig");
const topology_module = @import("topology.zig");

pub const production_ready = true;

const NativeFinalize = struct {
    const Lift = stages.composition_lift.Native;
    const Split = stages.composition_split.Native;
};

pub const Slots = struct {
    args: u32,
    trace_offsets: u32,
    interaction_offsets: u32,
    lde_descriptors: u32,
    extended_descriptors: u32,
    extended_parameters: u32,
    relation_z: u32,
    relation_alpha_powers: u32,
    relation_claimed_sums: u32,
    random_powers: u32,
    denominators: u32,
    lde_tile: u32,
    accumulators: u32,
};

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    topology: topology_module.Topology,
    catalog: constraint_catalog.Catalog,
    products: []eval_stage.Product,
    trace_offsets: []u32,
    interaction_offsets: []u32,
    lde_descriptors: []transform.AddressedLdeDescriptor,
    arguments: []eval_stage.Args,
    denominators: []u32,
    slots: Slots,
    parameters: eval_stage.ParameterLayout,
    lde_tile_offset: usize,
    arena_words: u64,
    plan_identity: proof_ir.Digest,
    identity: proof_ir.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        plan: *const resident_plan.Plan,
        physical: *const arena_module.Plan,
        program: proof_ir.ProofProgram,
        bundle: composition.Bundle,
        preprocessed_logs: []const u32,
    ) !Prepared {
        if (!std.mem.eql(
            u8,
            &plan.program_identity,
            &program.program_digest,
        )) return error.InvalidKernelDescriptor;
        var topology = try topology_module.Topology.derive(
            allocator,
            bundle,
            preprocessed_logs,
        );
        errdefer topology.deinit();
        var catalog = try constraint_catalog.Catalog.init(
            allocator,
            bundle,
        );
        errdefer catalog.deinit();
        try validatePlan(plan, topology, catalog.catalog_identity);
        const slots = try locateSlots(plan);
        const arena_words: u64 = physical.total_words;
        const trace_offsets = try buildTraceOffsets(
            allocator,
            physical,
            topology,
            slots.lde_tile,
        );
        errdefer allocator.free(trace_offsets);
        const interaction_offsets = try buildInteractionOffsets(
            allocator,
            topology,
        );
        errdefer allocator.free(interaction_offsets);
        const lde_descriptors = try buildLdeDescriptors(
            allocator,
            plan,
            physical,
            program,
            topology,
            slots,
        );
        errdefer allocator.free(lde_descriptors);
        const denominators = try buildDenominators(allocator, bundle);
        errdefer allocator.free(denominators);
        const arguments = try allocator.alloc(
            eval_stage.Args,
            topology.placements.len,
        );
        errdefer allocator.free(arguments);
        const products = try allocator.alloc(
            eval_stage.Product,
            topology.placements.len,
        );
        errdefer allocator.free(products);
        const parameters = try parameterLayoutFor(
            plan,
            physical,
            topology,
            slots,
        );
        const lde_tile_offset = try usizeCount(
            try physicalOffset(physical, slots.lde_tile),
        );
        try buildProductsAndArguments(
            allocator,
            physical,
            bundle,
            topology,
            catalog,
            slots,
            arena_words,
            arguments,
            products,
        );
        const identity = preparedIdentity(
            plan.identity,
            topology.identity,
            catalog.catalog_identity,
            slots,
            arguments,
            lde_descriptors,
        );
        return .{
            .allocator = allocator,
            .topology = topology,
            .catalog = catalog,
            .products = products,
            .trace_offsets = trace_offsets,
            .interaction_offsets = interaction_offsets,
            .lde_descriptors = lde_descriptors,
            .arguments = arguments,
            .denominators = denominators,
            .slots = slots,
            .parameters = parameters,
            .lde_tile_offset = lde_tile_offset,
            .arena_words = arena_words,
            .plan_identity = plan.identity,
            .identity = identity,
        };
    }

    pub fn deinit(self: *Prepared) void {
        for (self.products) |product|
            self.allocator.free(product.kernel_name);
        self.allocator.free(self.denominators);
        self.allocator.free(self.arguments);
        self.allocator.free(self.lde_descriptors);
        self.allocator.free(self.interaction_offsets);
        self.allocator.free(self.trace_offsets);
        self.allocator.free(self.products);
        self.catalog.deinit();
        self.topology.deinit();
        self.* = undefined;
    }

    pub fn uploadIngress(
        self: *const Prepared,
        transaction: anytype,
    ) !Bound {
        try transaction.uploadResidentSlice(
            u32,
            self.slots.trace_offsets,
            0,
            self.trace_offsets,
        );
        try transaction.uploadResidentSlice(
            u32,
            self.slots.interaction_offsets,
            0,
            self.interaction_offsets,
        );
        try transaction.uploadResidentSlice(
            transform.AddressedLdeDescriptor,
            self.slots.lde_descriptors,
            0,
            self.lde_descriptors,
        );
        try transaction.uploadResidentSlice(
            eval_stage.ExtSourceDescriptor,
            self.slots.extended_descriptors,
            0,
            self.topology.extended_parameter_descriptors,
        );
        try transaction.uploadResidentSlice(
            u32,
            self.slots.denominators,
            0,
            self.denominators,
        );
        try transaction.uploadResidentSlice(
            eval_stage.Args,
            self.slots.args,
            0,
            self.arguments,
        );
        const launches = try self.allocator.alloc(
            eval_stage.PreparedLaunch,
            self.products.len,
        );
        errdefer self.allocator.free(launches);
        const arena = try transaction.residentArenaWords();
        const device_args = try transaction.slotAs(
            eval_stage.Args,
            self.slots.args,
        );
        for (self.products, launches, 0..) |product, *launch, index| {
            launch.* = try eval_stage.prepare(
                transaction.proofSession(),
                product,
                arena,
                try device_args.sub(index, 1),
            );
        }
        return .{
            .allocator = self.allocator,
            .prepared = self,
            .launches = launches,
            .arena = arena,
            .lde_descriptors = try transaction.slotAs(
                transform.AddressedLdeDescriptor,
                self.slots.lde_descriptors,
            ),
        };
    }
};

pub const Bound = struct {
    allocator: std.mem.Allocator,
    prepared: *const Prepared,
    launches: []eval_stage.PreparedLaunch,
    arena: common.Words,
    lde_descriptors: transform.AddressedLdeDescriptors,

    pub fn deinit(self: *Bound) void {
        self.allocator.free(self.launches);
        self.* = undefined;
    }

    /// Executes every complete evaluation operation around the missing
    /// addressed LDE primitive.
    pub fn execute(
        self: Bound,
        transaction: anytype,
        bindings: pcs_types.Bindings,
        composition_alpha: common.SecureFields,
    ) !void {
        const session = transaction.proofSession();
        try transaction.zeroResidentSlice(
            u32,
            .constraint_evaluation,
            self.prepared.slots.accumulators,
            0,
            try usizeCount(
                self.prepared.topology.summary.accumulator_words,
            ),
        );
        try stages.constraint_power.Native.expand(
            session,
            composition_alpha,
            bindings.composition.random_powers,
        );
        try eval_stage.materializeParameters(
            session,
            self.arena,
            self.prepared.parameters,
        );
        for (self.prepared.topology.components) |component| {
            try transform.Native.extendAddressed(
                session,
                .constraint_evaluation,
                self.arena,
                try self.lde_descriptors.sub(
                    component.first_source,
                    component.source_count,
                ),
                self.prepared.lde_tile_offset,
                component.evaluation_log_size,
                bindings.twiddles_forward,
                false,
            );
            const first = component.first_placement;
            for (self.launches[first..][0..component.placement_count]) |
                *launch,
            | {
                try launch.launch(session);
            }
        }
        try finalize(
            NativeFinalize,
            session,
            self.prepared,
            transaction,
            bindings,
        );
    }
};

fn finalize(
    comptime Ops: type,
    session: anytype,
    prepared: *const Prepared,
    transaction: anytype,
    bindings: pcs_types.Bindings,
) !void {
    const accumulators = prepared.topology.accumulators;
    if (accumulators.len == 0)
        return error.InvalidKernelDescriptor;
    const storage = try slotWords(
        transaction,
        prepared.slots.accumulators,
    );
    const maximum = accumulators[accumulators.len - 1];
    const current = try accumulatorMatrix(storage, maximum);
    for (accumulators[0 .. accumulators.len - 1]) |source| {
        try Ops.Lift.accumulate(
            session,
            try accumulatorMatrix(storage, source),
            source.evaluation_log_size,
            current,
            maximum.evaluation_log_size,
        );
    }
    const tree = try bindings.trees.require(.composition);
    try Ops.Split.interpolateAndSplit(
        session,
        current,
        .{
            .storage = tree.coefficients,
            .column_stride_words = @as(usize, 1) <<
                @intCast(maximum.evaluation_log_size - 1),
        },
        maximum.evaluation_log_size,
        bindings.twiddles_inverse,
    );
}

fn parameterLayoutFor(
    plan: *const resident_plan.Plan,
    physical: *const arena_module.Plan,
    topology: topology_module.Topology,
    slots: Slots,
) !eval_stage.ParameterLayout {
    const alpha_powers = try requireSlotId(
        plan,
        slots.relation_alpha_powers,
    );
    const claimed_sums = try requireSlotId(
        plan,
        slots.relation_claimed_sums,
    );
    if (alpha_powers.words % 4 != 0 or
        claimed_sums.words !=
            @as(usize, topology.summary.component_count) * 4)
    {
        return error.InvalidKernelDescriptor;
    }
    return .{
        .descriptors = try physicalOffset(
            physical,
            slots.extended_descriptors,
        ),
        .descriptor_count = @intCast(
            topology.extended_parameter_descriptors.len,
        ),
        .z = try physicalOffset(physical, slots.relation_z),
        .alpha_powers = try physicalOffset(
            physical,
            slots.relation_alpha_powers,
        ),
        .alpha_power_count = @intCast(alpha_powers.words / 4),
        .claimed_sums = try physicalOffset(
            physical,
            slots.relation_claimed_sums,
        ),
        .claimed_sum_count = topology.summary.component_count,
        .output = try physicalOffset(physical, slots.extended_parameters),
        .output_words = topology.summary.extended_parameter_words,
    };
}

fn buildTraceOffsets(
    allocator: std.mem.Allocator,
    physical: *const arena_module.Plan,
    topology: topology_module.Topology,
    tile_slot: u32,
) ![]u32 {
    const tile = try physicalOffset(physical, tile_slot);
    const output = try allocator.alloc(u32, topology.sources.len);
    for (topology.components) |component| {
        for (
            topology.sources[component.first_source..][0..component.source_count],
            0..,
        ) |source, local| {
            output[component.first_trace_offset + local] =
                std.math.cast(
                    u32,
                    try add64(tile, source.tile_offset),
                ) orelse return error.InvalidKernelDescriptor;
        }
    }
    return output;
}

fn buildInteractionOffsets(
    allocator: std.mem.Allocator,
    topology: topology_module.Topology,
) ![]u32 {
    const output = try allocator.alloc(
        u32,
        topology.summary.interaction_offset_words,
    );
    for (topology.components) |component| {
        const first = component.first_interaction_offset;
        output[first] = 0;
        output[first + 1] = component.preprocessed_count;
        output[first + 2] =
            component.preprocessed_count + component.main_count;
    }
    return output;
}

fn buildLdeDescriptors(
    allocator: std.mem.Allocator,
    plan: *const resident_plan.Plan,
    physical: *const arena_module.Plan,
    program: proof_ir.ProofProgram,
    topology: topology_module.Topology,
    slots: Slots,
) ![]transform.AddressedLdeDescriptor {
    const output = try allocator.alloc(
        transform.AddressedLdeDescriptor,
        topology.sources.len,
    );
    errdefer allocator.free(output);
    const tile_offset = try physicalOffset(physical, slots.lde_tile);
    for (topology.components) |component| {
        for (
            topology.sources[component.first_source..][0..component.source_count],
            component.first_source..,
        ) |source, source_index| {
            const ordinal = try commitmentOrdinal(
                program,
                sourceRole(source.role),
            );
            const tree = program.commitments[ordinal];
            if (source.column >= tree.column_count)
                return error.InvalidKernelDescriptor;
            const column_index = try add64(tree.first_column, source.column);
            if (column_index >= program.trace_columns.len)
                return error.InvalidKernelDescriptor;
            if (program.trace_columns[try usizeCount(column_index)].log_rows !=
                source.log_rows)
            {
                return error.InvalidKernelDescriptor;
            }
            const coefficient_slot = try requireSlot(
                plan,
                .trace_coefficients,
                @intCast(ordinal),
            );
            output[source_index] = transform.AddressedLdeDescriptor.init(
                try add64(
                    try physicalOffset(physical, coefficient_slot.id),
                    try precedingCoefficientWords(
                        program,
                        tree,
                        source.column,
                    ),
                ),
                try add64(tile_offset, source.tile_offset),
                source.log_rows,
            );
        }
        try transform.validateAddressedPlan(
            output[component.first_source..][0..component.source_count],
            try usizeCount(physical.total_words),
            try usizeCount(tile_offset),
            component.evaluation_log_size,
        );
    }
    return output;
}

fn commitmentOrdinal(
    program: proof_ir.ProofProgram,
    role: proof_ir.CommitmentRole,
) !usize {
    var found: ?usize = null;
    for (program.commitments, 0..) |tree, ordinal| {
        if (tree.role != role) continue;
        if (found != null) return error.InvalidKernelDescriptor;
        found = ordinal;
    }
    return found orelse error.InvalidKernelDescriptor;
}

fn sourceRole(role: topology_module.SourceRole) proof_ir.CommitmentRole {
    return switch (role) {
        .preprocessed => .preprocessed,
        .main => .main,
        .interaction => .interaction,
    };
}

fn precedingCoefficientWords(
    program: proof_ir.ProofProgram,
    tree: proof_ir.CommitmentTree,
    column: u32,
) !u64 {
    var words: u64 = 0;
    for (program.trace_columns[tree.first_column..][0..column]) |trace_column| {
        if (trace_column.log_rows >= 63)
            return error.InvalidKernelDescriptor;
        words = try add64(
            words,
            @as(u64, 1) << @intCast(trace_column.log_rows),
        );
    }
    return words;
}

fn buildDenominators(
    allocator: std.mem.Allocator,
    bundle: composition.Bundle,
) ![]u32 {
    var count: usize = 0;
    for (bundle.components) |component|
        count = try addSize(count, component.denominator_inverses.len);
    const output = try allocator.alloc(u32, count);
    var cursor: usize = 0;
    for (bundle.components) |component| {
        @memcpy(
            output[cursor..][0..component.denominator_inverses.len],
            component.denominator_inverses,
        );
        cursor += component.denominator_inverses.len;
    }
    return output;
}

fn buildProductsAndArguments(
    allocator: std.mem.Allocator,
    physical: *const arena_module.Plan,
    bundle: composition.Bundle,
    topology: topology_module.Topology,
    catalog: constraint_catalog.Catalog,
    slots: Slots,
    arena_words: u64,
    arguments: []eval_stage.Args,
    products: []eval_stage.Product,
) !void {
    var initialized: usize = 0;
    errdefer for (products[0..initialized]) |product|
        allocator.free(product.kernel_name);
    const trace_offsets = try physicalOffset(
        physical,
        slots.trace_offsets,
    );
    const interaction_offsets =
        try physicalOffset(physical, slots.interaction_offsets);
    const ext_params = try physicalOffset(
        physical,
        slots.extended_parameters,
    );
    const random_powers = try physicalOffset(
        physical,
        slots.random_powers,
    );
    const denominators = try physicalOffset(
        physical,
        slots.denominators,
    );
    const accumulators = try physicalOffset(
        physical,
        slots.accumulators,
    );
    for (topology.placements, 0..) |placement, index| {
        const component = topology.components[
            placement.component_index
        ];
        const captured = bundle.components[placement.component_index];
        const part = captured.parts[placement.part_index];
        const resolved = try product_resolution.resolve(
            catalog,
            placement.component_index,
            placement.part_index,
            placement.program_identity,
        );
        const rows = @as(u64, 1) <<
            @intCast(component.evaluation_log_size);
        const coordinate = try add64(
            accumulators,
            component.accumulator_offset,
        );
        const args = eval_stage.Args{
            .trace_offsets = try add64(
                trace_offsets,
                component.first_trace_offset,
            ),
            .interaction_offsets = try add64(
                interaction_offsets,
                component.first_interaction_offset,
            ),
            .base_params = 0,
            .ext_params = try add64(
                ext_params,
                component.first_extended_parameter,
            ),
            .random_coeffs = random_powers,
            .denom_inv = try add64(
                denominators,
                component.first_denominator,
            ),
            .coord_0 = coordinate,
            .coord_1 = try add64(coordinate, rows),
            .coord_2 = try add64(coordinate, rows * 2),
            .coord_3 = try add64(coordinate, rows * 3),
            .row_count = @intCast(rows),
            .trace_log_size = component.trace_log_size,
            .domain_log_size = placement.domain_log_size,
            .rc_base = placement.global_rc_base,
        };
        const bounds = eval_stage.Bounds{
            .arena_words = arena_words,
            .trace_offset_count = component.source_count,
            .base_param_count = part.program.header.n_base_params,
            .ext_param_count = component.extended_parameter_count,
            .random_constraint_count = topology.summary.constraint_count,
            .denominator_count = component.denominator_count,
            .rc_count = placement.rc_count,
        };
        if (bounds.base_param_count != 0)
            return error.UnsupportedCairoEvalBaseParameters;
        try args.validate(bounds);
        arguments[index] = args;
        const kernel_name = try allocator.dupeZ(
            u8,
            resolved.kernel_name,
        );
        products[index] = .{
            .cache_key = resolved.cache_key,
            .kernel_name = kernel_name,
            .args = args,
            .bounds = bounds,
        };
        initialized += 1;
    }
}

fn validatePlan(
    plan: *const resident_plan.Plan,
    topology: topology_module.Topology,
    catalog_identity: proof_ir.Digest,
) !void {
    if (topology.summary.placement_count !=
        topology_module.expected_placement_count or
        topology.summary.argument_words !=
            (try requireSlotKind(plan, .eval_arguments)).words or
        topology.summary.trace_offset_words !=
            (try requireSlotKind(plan, .eval_trace_offsets)).words or
        topology.summary.interaction_offset_words !=
            (try requireSlotKind(plan, .eval_interaction_offsets)).words or
        topology.summary.lde_descriptor_words !=
            (try requireSlotKind(plan, .eval_lde_descriptors)).words or
        topology.summary.lde_tile_words !=
            (try requireSlotKind(plan, .eval_lde_tile)).words or
        topology.summary.extended_parameter_descriptor_words !=
            (try requireSlotKind(
                plan,
                .eval_extended_parameter_descriptors,
            )).words or
        topology.summary.accumulator_words !=
            (try requireSlotKind(
                plan,
                .constraint_composition_accumulator,
            )).words or
        std.mem.allEqual(u8, &catalog_identity, 0))
    {
        return error.InvalidKernelDescriptor;
    }
}

fn locateSlots(plan: *const resident_plan.Plan) !Slots {
    return .{
        .args = (try requireSlotKind(plan, .eval_arguments)).id,
        .trace_offsets = (try requireSlotKind(plan, .eval_trace_offsets)).id,
        .interaction_offsets = (try requireSlotKind(plan, .eval_interaction_offsets)).id,
        .lde_descriptors = (try requireSlotKind(plan, .eval_lde_descriptors)).id,
        .extended_descriptors = (try requireSlotKind(
            plan,
            .eval_extended_parameter_descriptors,
        )).id,
        .extended_parameters = (try requireSlotKind(plan, .eval_extended_parameters)).id,
        .relation_z = (try requireSlotKind(plan, .relation_z)).id,
        .relation_alpha_powers = (try requireSlotKind(plan, .relation_alpha_powers)).id,
        .relation_claimed_sums = (try requireSlotKind(plan, .relation_claimed_sums)).id,
        .random_powers = (try requireSlotKind(plan, .constraint_random_powers)).id,
        .denominators = (try requireSlotKind(plan, .constraint_denominators)).id,
        .lde_tile = (try requireSlotKind(plan, .eval_lde_tile)).id,
        .accumulators = (try requireSlotKind(
            plan,
            .constraint_composition_accumulator,
        )).id,
    };
}

fn accumulatorMatrix(
    storage: common.Words,
    descriptor: topology_module.Accumulator,
) !common.WordMatrix {
    const words = try usizeCount(descriptor.words);
    return .{
        .storage = try storage.sub(
            try usizeCount(descriptor.offset_words),
            words,
        ),
        .column_stride_words = @as(usize, 1) <<
            @intCast(descriptor.evaluation_log_size),
    };
}

fn slotWords(transaction: anytype, id: u32) !common.Words {
    return transaction.slot(id);
}

fn requireSlotKind(
    plan: *const resident_plan.Plan,
    kind: resident_plan.SlotKind,
) !resident_plan.Slot {
    return plan.slot(kind, 0) orelse error.InvalidKernelDescriptor;
}

fn requireSlotId(
    plan: *const resident_plan.Plan,
    id: u32,
) !resident_plan.Slot {
    for (plan.slots) |slot| {
        if (slot.id == id) return slot;
    }
    return error.InvalidKernelDescriptor;
}

fn requireSlot(
    plan: *const resident_plan.Plan,
    kind: resident_plan.SlotKind,
    ordinal: u32,
) !resident_plan.Slot {
    return plan.slot(kind, ordinal) orelse error.InvalidKernelDescriptor;
}

fn physicalOffset(physical: *const arena_module.Plan, id: u32) !u64 {
    const placement = try physical.placement(id);
    return placement.offset_words;
}

fn add64(left: anytype, right: anytype) !u64 {
    const lhs = std.math.cast(u64, left) orelse return error.SizeOverflow;
    const rhs = std.math.cast(u64, right) orelse return error.SizeOverflow;
    return std.math.add(u64, lhs, rhs) catch error.SizeOverflow;
}

fn addSize(left: usize, right: usize) !usize {
    return std.math.add(usize, left, right) catch error.SizeOverflow;
}

fn usizeCount(value: anytype) !usize {
    return std.math.cast(usize, value) orelse error.SizeOverflow;
}

fn preparedIdentity(
    plan: proof_ir.Digest,
    topology: proof_ir.Digest,
    catalog: proof_ir.Digest,
    slots: Slots,
    arguments: []const eval_stage.Args,
    lde_descriptors: []const transform.AddressedLdeDescriptor,
) proof_ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/eval-controller/v1\x00");
    hash.update(&plan);
    hash.update(&topology);
    hash.update(&catalog);
    hash.update(std.mem.asBytes(&slots));
    hash.update(std.mem.sliceAsBytes(arguments));
    hash.update(std.mem.sliceAsBytes(lde_descriptors));
    return hash.finalResult();
}
