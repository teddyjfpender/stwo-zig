//! Exact typed logical AIR for authority-spine row 19.

const factory = @import("control_slice_component.zig");

pub const Air = factory.Component(.{
    .stable_name = "recursion.vm_air_composition_control.v1",
    .preprocessed_names = .{
        "recursion_vm_air_composition_control_row_mask",
        "recursion_vm_air_composition_control_segment_mask",
        "recursion_vm_air_composition_control_verifier_id",
        "recursion_vm_air_composition_control_sequence",
        "recursion_vm_air_composition_control_tag",
        "recursion_vm_air_composition_control_arg_0",
        "recursion_vm_air_composition_control_arg_1",
        "recursion_vm_air_composition_control_arg_2",
        "recursion_vm_air_composition_control_arg_3",
    },
    .parameter_names = .{
        "recursion.vm_air_composition_control.param.segment_active",
        "recursion.vm_air_composition_control.param.binary_active",
    },
    .constraint_name = "recursion.vm_air_composition_control.enabler_boolean",
    .semantic_digest_hex = "5fc8e4a1a9668d1543e2062a22ff21ead6b7a840aa8cc56ff59e20474822c1a1",
});
