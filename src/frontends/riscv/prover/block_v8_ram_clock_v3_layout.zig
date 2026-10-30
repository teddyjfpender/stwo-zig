//! Exact disabled V3 construction recipe. This is not a component roster or
//! source verifier. The V2 source remains unchanged and cannot consume it.
//! A complete V3 implementation must author the retained register-gap weights,
//! authenticate new range16 requests, and close RAM without synthetic hops.
const std = @import("std");
const core = @import("stwo_core");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Authority = @import("../air/lang/typed_load_store_authority.zig");
const Halt = @import("block_v8_native_halt_policy_v1.zig");
const Kernel = @import("block_v8_ram_clock_v3_kernel.zig");
const Canonical = @import("../runner/state_chain.zig");
pub const VERSION = 3;
pub const production_active = false;
pub const whole_source_qualified = false;
pub const Group = struct { main_offset: usize, auxiliary_offset: usize, active_fixed_column: usize, n_rows: u32, log_size: u32 };
pub const Weights = enum { store, load };
pub const Replacement = struct { ordinal: u8, retained_register_weight: Weights };
pub const replacements = [2]Replacement{
    .{ .ordinal = @intFromEnum(Authority.LookupRecipe.source_clock_gap), .retained_register_weight = .store },
    .{ .ordinal = @intFromEnum(Authority.LookupRecipe.destination_clock_gap), .retained_register_weight = .load },
};
/// Source gap10 is RAM for loads and register for stores. Destination gap13
/// is RAM for stores and register for loads. Omitting both would drop a real
/// register ordering obligation, so the recipe names each retained weight.
pub fn retainedRegisterWeights(comptime S: type, active: S, main: []const S) ![2]S {
    if (main.len != Halt.NativeColumns.width) return error.InvalidV3RamClockRow;
    const flags = Halt.NativeColumns.store_flags;
    const store = main[flags[0]].add(main[flags[1]]).add(main[flags[2]]);
    return .{ store, active.sub(store) };
}
pub const Recipe = struct {
    allocator: std.mem.Allocator,
    policy: Kernel.Policy,
    candidate_shape: Shape,
    groups: []Group,
    logs: []u32,
    register_hops: u32,
    register_hop_bound: u32,
    digest: [32]u8,
    pub fn init(a: std.mem.Allocator, shape: *const Shape, register_hops: u32) !Recipe {
        try shape.validateBlake3ExecutionWithExternal(0);
        const policy = try Kernel.Policy.fromCycles(shape.public_data.clock);
        const hop_bound: u32 = @intCast(@as(u64, 32) * ((policy.max_clock - 1) / Canonical.MAX_CLOCK_DIFF));
        if (register_hops > hop_bound) return error.UnboundedV3RegisterHops;
        var candidate_shape = shape.*;
        for (shape.infra_descs[0..shape.n_infra]) |desc| if (desc.kind != .clock_update) return error.UnsupportedV3RamClockInfrastructure;
        candidate_shape.n_infra = 0;
        if (register_hops != 0) {
            candidate_shape.n_infra = 1;
            candidate_shape.infra_descs[0] = .{ .kind = .clock_update, .log_size = @max(@as(u32, 1), std.math.log2_int_ceil(u32, register_hops)), .n_rows = register_hops, .n_columns = 10 };
        }
        try candidate_shape.validateBlake3ExecutionWithExternal(0);
        const base_logs = try Halt.mainLogs(a, &candidate_shape);
        defer a.free(base_logs);
        const groups = try a.alloc(Group, Halt.count(shape));
        errdefer a.free(groups);
        const logs = try a.alloc(u32, base_logs.len + Kernel.COLUMN_COUNT * groups.len);
        errdefer a.free(logs);
        @memcpy(logs[0..base_logs.len], base_logs);
        var main_offset: usize = 0;
        var group_index: usize = 0;
        var channel = core.proof_suites.Blake3.Channel{};
        channel.mixU32s(&.{ 0x42385243, VERSION, policy.max_clock, Kernel.COLUMN_COUNT, Kernel.CONSTRAINT_COUNT, Kernel.MAX_DEGREE, register_hops });
        channel.mixRoot(Authority.Authority.pinned().binding.semantic_digest);
        candidate_shape.mixShardManifest(&channel);
        for (shape.component_descs[0..shape.n_components], 0..) |desc, i| {
            defer main_offset += desc.n_columns;
            if (desc.family != .load_store) continue;
            const auxiliary_offset = base_logs.len + Kernel.COLUMN_COUNT * group_index;
            groups[group_index] = .{ .main_offset = main_offset, .auxiliary_offset = auxiliary_offset, .active_fixed_column = 2 * i + 1, .n_rows = desc.n_rows, .log_size = desc.log_size };
            @memset(logs[auxiliary_offset..][0..Kernel.COLUMN_COUNT], desc.log_size);
            channel.mixU32s(&.{ @intCast(main_offset), @intCast(auxiliary_offset), @intCast(2 * i + 1), desc.n_rows, desc.log_size });
            group_index += 1;
        }
        for (replacements) |replacement| channel.mixU32s(&.{ replacement.ordinal, @intFromEnum(replacement.retained_register_weight) });
        return .{ .allocator = a, .policy = policy, .candidate_shape = candidate_shape, .groups = groups, .logs = logs, .register_hops = register_hops, .register_hop_bound = hop_bound, .digest = channel.digestBytes() };
    }
    pub fn deinit(self: *Recipe) void {
        self.allocator.free(self.logs);
        self.allocator.free(self.groups);
        self.* = undefined;
    }
    /// Explicitly reject a V2 collector; a digest or this recipe grants no
    /// authority to remove rows from a committed source.
    pub fn requireCollector(self: Recipe, chain: *const Canonical.StateChainTracker) !void {
        if (chain.clock_updates_mem.items.len != 0 or chain.clock_updates_reg.items.len != self.register_hops) return error.UnadaptedV3RamClockCollector;
        for (chain.accesses.items) |access| if (access.addr_space == 1) {
            if (access.clk % 4 != 3 or (access.clk_prev != 0 and access.clk_prev % 4 != 3)) return error.UnadaptedV3RamClockCollector;
            _ = try Kernel.witness(self.policy, true, access.clk, access.clk_prev);
        };
    }
};
comptime {
    for (replacements) |replacement| {
        const descriptor = Authority.CANONICAL_LOOKUP_RECIPE[replacement.ordinal];
        if (descriptor.domain != .range_check_20 or descriptor.role != .request or descriptor.arity != 1) @compileError("review V3 RAM gap replacement after typed recipe change");
    }
}
