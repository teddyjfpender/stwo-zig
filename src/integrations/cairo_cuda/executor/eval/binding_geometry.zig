//! Validated resident evaluation slot bindings, physical offsets and identity.
//! Production-shaped resident Cairo constraint controller.
//!
//! Ingress seals every host-derived offset, descriptor, and AOT placement.
//! Constraint execution remains direct and sequential. Exact-domain sources
//! reuse retained commitment evaluations; larger domains use the native
//! addressed compact-source polynomial extension.

const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const common = @import("stwo_cuda_backend").runtime.stages.common;
const arena_module = @import("stwo_cuda_backend").runtime.arena;
const eval_stage = @import("stwo_cuda_backend").runtime.stages.cairo_eval;
const stages = @import("stwo_cuda_backend").runtime.stages;
const transform = stages.transform;
const constraint_catalog = @import(
    "../../request_compiler/constraint_admission.zig",
);
const resident_plan = @import("../resident_plan.zig");
const topology_module = @import("topology.zig");

const Slots = @import("controller.zig").Slots;

pub fn locateSlots(plan: *const resident_plan.Plan) !Slots {
    return .{
        .base_parameters = if (plan.evaluation_codegen_version == 2)
            (try requireSlotKind(plan, .eval_base_parameters)).id
        else
            null,
        .diagnostic = if (plan.slot(.writer_scratch, 1)) |slot| slot.id else null,
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

pub fn accumulatorMatrix(
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

pub fn slotWords(transaction: anytype, id: u32) !common.Words {
    return transaction.slot(id);
}

pub fn requireSlotKind(
    plan: *const resident_plan.Plan,
    kind: resident_plan.SlotKind,
) !resident_plan.Slot {
    return plan.slot(kind, 0) orelse error.InvalidKernelDescriptor;
}

pub fn requireSlotId(
    plan: *const resident_plan.Plan,
    id: u32,
) !resident_plan.Slot {
    for (plan.slots) |slot| {
        if (slot.id == id) return slot;
    }
    return error.InvalidKernelDescriptor;
}

pub fn requireSlot(
    plan: *const resident_plan.Plan,
    kind: resident_plan.SlotKind,
    ordinal: u32,
) !resident_plan.Slot {
    return plan.slot(kind, ordinal) orelse error.InvalidKernelDescriptor;
}

pub fn physicalOffset(physical: *const arena_module.Plan, id: u32) !u64 {
    const placement = try physical.placement(id);
    return placement.offset_words;
}

pub fn add64(left: anytype, right: anytype) !u64 {
    const lhs = std.math.cast(u64, left) orelse return error.SizeOverflow;
    const rhs = std.math.cast(u64, right) orelse return error.SizeOverflow;
    return std.math.add(u64, lhs, rhs) catch error.SizeOverflow;
}

pub fn addSize(left: usize, right: usize) !usize {
    return std.math.add(usize, left, right) catch error.SizeOverflow;
}

pub fn usizeCount(value: anytype) !usize {
    return std.math.cast(usize, value) orelse error.SizeOverflow;
}

pub fn preparedIdentity(
    plan: proof_ir.Digest,
    topology: proof_ir.Digest,
    catalog: proof_ir.Digest,
    slots: Slots,
    arguments: []const eval_stage.Args,
    lde_descriptors: []const transform.AddressedLdeDescriptor,
    trace_offsets: []const u32,
) proof_ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/eval-controller/v2\x00");
    hash.update(&plan);
    hash.update(&topology);
    hash.update(&catalog);
    hash.update(std.mem.asBytes(&slots));
    hash.update(std.mem.sliceAsBytes(arguments));
    hash.update(std.mem.sliceAsBytes(lde_descriptors));
    hash.update(std.mem.sliceAsBytes(trace_offsets));
    return hash.finalResult();
}
