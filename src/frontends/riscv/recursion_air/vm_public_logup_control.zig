//! Exact typed logical AIR for authority-spine row 17.

const factory = @import("control_slice_component.zig");

pub const Air = factory.Component(.{
    .stable_name = "recursion.vm_public_logup_control.v1",
    .preprocessed_names = .{
        "recursion_vm_public_logup_control_row_mask",
        "recursion_vm_public_logup_control_segment_mask",
        "recursion_vm_public_logup_control_verifier_id",
        "recursion_vm_public_logup_control_sequence",
        "recursion_vm_public_logup_control_tag",
        "recursion_vm_public_logup_control_arg_0",
        "recursion_vm_public_logup_control_arg_1",
        "recursion_vm_public_logup_control_arg_2",
        "recursion_vm_public_logup_control_arg_3",
    },
    .parameter_names = .{
        "recursion.vm_public_logup_control.param.segment_active",
        "recursion.vm_public_logup_control.param.binary_active",
    },
    .constraint_name = "recursion.vm_public_logup_control.enabler_boolean",
    .semantic_digest_hex = "98d69ef2a682a92818e4b84caca77ba776e2f64d546eb9dcb4ab46da0ee5ed5b",
});
