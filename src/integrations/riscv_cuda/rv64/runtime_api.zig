//! Per-owner runtime numerical ABI table. Publish only after every symbol resolves.
const std = @import("std");
const A = @import("abi.zig");
pub const Api = struct {
    stwo_rv64_batch_sum_on: ?*const @TypeOf(A.stwo_rv64_batch_sum_on) = null,
    stwo_rv64_batch_fold_on: ?*const @TypeOf(A.stwo_rv64_batch_fold_on) = null,
    stwo_rv64_gkr_eq_on: *const @TypeOf(A.stwo_rv64_gkr_eq_on),
    stwo_rv64_gkr_eq_fused_on: *const @TypeOf(A.stwo_rv64_gkr_eq_fused_on),
    stwo_rv64_gkr_sum_on: *const @TypeOf(A.stwo_rv64_gkr_sum_on),
    stwo_rv64_gkr_sum_split_on: *const @TypeOf(A.stwo_rv64_gkr_sum_split_on),
    stwo_rv64_batch_init_on: *const @TypeOf(A.stwo_rv64_batch_init_on),
    stwo_rv64_batch_mask_on: *const @TypeOf(A.stwo_rv64_batch_mask_on),
    stwo_rv64_batch_round_on: *const @TypeOf(A.stwo_rv64_batch_round_on),
    stwo_rv64_binding_eq_on: *const @TypeOf(A.stwo_rv64_binding_eq_on),
    stwo_rv64_binding_project_on: *const @TypeOf(A.stwo_rv64_binding_project_on),
    stwo_rv64_composition_lift_add_on: *const @TypeOf(A.stwo_rv64_composition_lift_add_on),
    stwo_rv64_composition_finalize_on: *const @TypeOf(A.stwo_rv64_composition_finalize_on),
    stwo_rv64_gkr_begin_on: *const @TypeOf(A.stwo_rv64_gkr_begin_on),
    stwo_rv64_gkr_binding_metadata_on: *const @TypeOf(A.stwo_rv64_gkr_binding_metadata_on),
    stwo_rv64_gkr_close_on: *const @TypeOf(A.stwo_rv64_gkr_close_on),
    stwo_rv64_gkr_fold_on: *const @TypeOf(A.stwo_rv64_gkr_fold_on),
    stwo_rv64_gkr_fold_sum_on: *const @TypeOf(A.stwo_rv64_gkr_fold_sum_on),
    stwo_rv64_gkr_init_on: *const @TypeOf(A.stwo_rv64_gkr_init_on),
    stwo_rv64_gkr_layer_on: *const @TypeOf(A.stwo_rv64_gkr_layer_on),
    stwo_rv64_gkr_pack_mask_on: *const @TypeOf(A.stwo_rv64_gkr_pack_mask_on),
    stwo_rv64_gkr_pack_roots_on: *const @TypeOf(A.stwo_rv64_gkr_pack_roots_on),
    stwo_rv64_gkr_project_on: *const @TypeOf(A.stwo_rv64_gkr_project_on),
    stwo_rv64_global_close_on: *const @TypeOf(A.stwo_rv64_global_close_on),
    stwo_rv64_global_pairs_on: *const @TypeOf(A.stwo_rv64_global_pairs_on),
    stwo_rv64_joined_parameter_gather_on: *const @TypeOf(A.stwo_rv64_joined_parameter_gather_on),
    stwo_rv64_local_close_on: *const @TypeOf(A.stwo_rv64_local_close_on),
    stwo_rv64_ls_dword_witness_on: *const @TypeOf(A.stwo_rv64_ls_dword_witness_on),
    stwo_rv64_parameter_gather_on: *const @TypeOf(A.stwo_rv64_parameter_gather_on),
    stwo_rv64_prefix_scan_on: *const @TypeOf(A.stwo_rv64_prefix_scan_on),
    stwo_rv64_sample_evaluate_on: *const @TypeOf(A.stwo_rv64_sample_evaluate_on),
    stwo_rv64_sample_order_on: *const @TypeOf(A.stwo_rv64_sample_order_on),
    stwo_rv64_sample_points_from_point_on: *const @TypeOf(A.stwo_rv64_sample_points_from_point_on),
    stwo_rv64_sample_points_on: *const @TypeOf(A.stwo_rv64_sample_points_on),
    stwo_rv64_sumcheck_init_on: *const @TypeOf(A.stwo_rv64_sumcheck_init_on),
    stwo_rv64_sumcheck_round_on: *const @TypeOf(A.stwo_rv64_sumcheck_round_on),
    stwo_rv64_sumcheck_tail_on: *const @TypeOf(A.stwo_rv64_sumcheck_tail_on),
    pub fn load(library: *std.DynLib) !Api {
        var out: Api = undefined;
        inline for (std.meta.fields(Api)) |field| {
            switch (@typeInfo(field.type)) {
                .optional => |optional| @field(out, field.name) = library.lookup(optional.child, field.name),
                else => @field(out, field.name) = library.lookup(field.type, field.name) orelse {
                    std.log.err("missing CUDA numerical ABI symbol: {s}", .{field.name});
                    return error.MissingCudaNumericalSymbol;
                },
            }
        }
        return out;
    }
};
