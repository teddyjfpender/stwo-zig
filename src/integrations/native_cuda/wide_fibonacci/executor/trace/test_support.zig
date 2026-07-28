const arena = @import("stwo_cuda_backend").runtime.arena;
const column = @import("stwo_cuda_backend").runtime.column;
const runtime_error =
    @import("stwo_cuda_backend").runtime.runtime_error;
const plan_mod = @import("../../plan.zig");
const request = @import("../../request.zig");

pub const base_address: usize = 0x2000_0000;

pub const Provider = struct {
    prepared: *const plan_mod.PreparedPlan,

    pub fn slot(
        self: *const Provider,
        id: arena.SlotId,
    ) runtime_error.Error!column.DeviceSlice(u32) {
        const placement = try self.prepared.arena_plan.placement(id);
        return .{
            .address = base_address +
                placement.offset_words * @sizeOf(u32),
            .len = placement.requirement.words,
            .owner = 19,
            .generation = 29,
        };
    }
};

pub fn geometry(
    log_n_rows: u32,
    sequence_len: u32,
) !request.Geometry {
    return request.admit(.{
        .statement = .{
            .log_n_rows = log_n_rows,
            .sequence_len = sequence_len,
        },
        .protocol = .{
            .pow_bits = 10,
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = 3,
            .fold_step = 1,
            .lifting_log_size = null,
        },
    });
}
