const std = @import("std");
const runtime = @import("../runtime.zig");
const ffi = @import("bindings.zig");
const protocol_mode = @import("protocol_mode.zig");

const MetalError = runtime.MetalError;
const Runtime = runtime.Runtime;
const CommandEpochStats = runtime.CommandEpochStats;
const FriLineCascadeResult = runtime.FriLineCascadeResult;
const Tree = runtime.Tree;

pub fn foldFriCircleLineCascade(
    self: *Runtime,
    allocator: std.mem.Allocator,
    source: *anyopaque,
    source_count: u32,
    circle_source: ?*anyopaque,
    circle_alpha: ?[4]u32,
    inverse_x: ?[]const u32,
    domain_initial_index: u32,
    domain_step_size: u32,
    coordinates: []const *anyopaque,
    final_destination: *anyopaque,
    leaf_seed: [8]u32,
    node_seed: [8]u32,
    domain_prefix_bytes: u32,
    channel_state: *[10]u32,
) (MetalError || std.mem.Allocator.Error)!FriLineCascadeResult {
    return foldFriCircleLineCascadeForSuite(
        false,
        self,
        allocator,
        source,
        source_count,
        circle_source,
        circle_alpha,
        inverse_x,
        domain_initial_index,
        domain_step_size,
        coordinates,
        final_destination,
        leaf_seed,
        node_seed,
        domain_prefix_bytes,
        channel_state,
        false,
    );
}

pub fn foldFriCircleLineCascadeWithReceipt(
    self: *Runtime,
    allocator: std.mem.Allocator,
    source: *anyopaque,
    source_count: u32,
    circle_source: ?*anyopaque,
    circle_alpha: ?[4]u32,
    inverse_x: ?[]const u32,
    domain_initial_index: u32,
    domain_step_size: u32,
    coordinates: []const *anyopaque,
    final_destination: *anyopaque,
    leaf_seed: [8]u32,
    node_seed: [8]u32,
    domain_prefix_bytes: u32,
    channel_state: *[10]u32,
) (MetalError || std.mem.Allocator.Error)!FriLineCascadeResult {
    return foldFriCircleLineCascadeForSuite(
        false,
        self,
        allocator,
        source,
        source_count,
        circle_source,
        circle_alpha,
        inverse_x,
        domain_initial_index,
        domain_step_size,
        coordinates,
        final_destination,
        leaf_seed,
        node_seed,
        domain_prefix_bytes,
        channel_state,
        true,
    );
}

pub fn foldFriCircleLineCascadeForSuite(
    comptime blake3: bool,
    self: *Runtime,
    allocator: std.mem.Allocator,
    source: *anyopaque,
    source_count: u32,
    circle_source: ?*anyopaque,
    circle_alpha: ?[4]u32,
    inverse_x: ?[]const u32,
    domain_initial_index: u32,
    domain_step_size: u32,
    coordinates: []const *anyopaque,
    final_destination: *anyopaque,
    leaf_seed: [8]u32,
    node_seed: [8]u32,
    domain_prefix_bytes: u32,
    channel_state: *[if (blake3) 11 else 10]u32,
    capture_inverse_generation: bool,
) (MetalError || std.mem.Allocator.Error)!FriLineCascadeResult {
    return foldFriCircleLineCascadeForSuiteWithPolicy(blake3, self, allocator, @import("fri_allocation_policy_v1.zig").ordinaryMetal(allocator), source, source_count, circle_source, circle_alpha, inverse_x, domain_initial_index, domain_step_size, coordinates, final_destination, leaf_seed, node_seed, domain_prefix_bytes, channel_state, capture_inverse_generation);
}

pub fn foldFriCircleLineCascadeForSuiteWithPolicy(
    comptime blake3: bool,
    self: *Runtime,
    allocator: std.mem.Allocator,
    policy: @import("fri_allocation_policy_v1.zig").Policy,
    source: *anyopaque,
    source_count: u32,
    circle_source: ?*anyopaque,
    circle_alpha: ?[4]u32,
    inverse_x: ?[]const u32,
    domain_initial_index: u32,
    domain_step_size: u32,
    coordinates: []const *anyopaque,
    final_destination: *anyopaque,
    leaf_seed: [8]u32,
    node_seed: [8]u32,
    domain_prefix_bytes: u32,
    channel_state: *[if (blake3) 11 else 10]u32,
    capture_inverse_generation: bool,
) (MetalError || std.mem.Allocator.Error)!FriLineCascadeResult {
    const binding = @import("fri_allocation_policy_v1.zig").Binding.init(allocator, policy) catch |err| return @import("fri_error_v1.zig").translate(err);
    if ((circle_source == null) != (circle_alpha == null) or
        source_count < 2 or coordinates.len == 0 or coordinates.len >= 31 or
        source_count & (source_count - 1) != 0 or
        !protocol_mode.validDomainPrefixBytes(domain_prefix_bytes))
    {
        return MetalError.InvalidColumns;
    }
    const layer_count = std.math.cast(u32, coordinates.len) orelse return MetalError.InvalidColumns;
    if (source_count >> @intCast(layer_count) == 0) return MetalError.InvalidColumns;
    var expected_inverse_count: u64 = 0;
    var count = source_count;
    for (coordinates) |_| {
        count >>= 1;
        expected_inverse_count += count;
    }
    if (inverse_x) |values| {
        if (values.len != expected_inverse_count or values.len > std.math.maxInt(u32))
            return MetalError.InvalidColumns;
    }
    // Canonical cache buffers are explicit, budget-bound and immutable. A
    // supplied host inverse table uses a distinct diagnostic API, never a
    // silently uncharged or CPU-prepared canonical cache route.
    if (inverse_x != null) return MetalError.InvalidColumns;
    const extent = @import("fri_budget_v1.zig").cascade(source_count, coordinates.len) catch |err| return @import("fri_error_v1.zig").translate(err);
    var reservation = binding.reserve(extent.peak_bytes) catch |err| return @import("fri_error_v1.zig").translate(err);
    defer reservation.deinit();
    var arena = @import("fri_reservation_owner_v1.zig").Owner.createWithPolicy(allocator, &reservation, binding.policy) catch |err| return @import("fri_error_v1.zig").translate(err);
    defer arena.deinit();
    const cache = @import("fri_inverse_cache_v1.zig");
    const key = cache.Key{ .runtime = @intFromPtr(self.handle), .count = source_count, .layers = layer_count, .initial = domain_initial_index, .step = domain_step_size, .kind = .line };
    var circle_key = key;
    circle_key.layers = 1;
    circle_key.kind = .circle;
    var inverses = cache.beginWithPolicy(allocator, self, .{ if (circle_source != null) circle_key else null, key }, binding.policy) catch |err| return @import("fri_error_v1.zig").translate(err);
    defer inverses.abort();
    const trees = try allocator.alloc(Tree, coordinates.len);
    errdefer allocator.free(trees);
    const handles = try allocator.alloc(?*anyopaque, coordinates.len);
    defer allocator.free(handles);
    @memset(handles, null);
    var stats: CommandEpochStats = undefined;
    var inverse_generation_mask: u32 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    var circle_alpha_value = circle_alpha;
    if (!ffi.stwo_zig_metal_fri_line_cascade_budgeted_v1(
        self.handle,
        source,
        source_count,
        circle_source,
        if (circle_alpha_value) |*value| value else null,
        null,
        0,
        0,
        if (inverse_x) |values| values.ptr else null,
        @intCast(expected_inverse_count),
        domain_initial_index,
        domain_step_size,
        coordinates.ptr,
        final_destination,
        layer_count,
        &leaf_seed,
        &node_seed,
        domain_prefix_bytes,
        if (blake3) 3 else 1,
        channel_state,
        handles.ptr,
        &inverse_generation_mask,
        inverses.handle(.circle),
        inverses.handle(.line) orelse unreachable,
        inverses.needsGeneration(.circle),
        inverses.needsGeneration(.line),
        &stats,
        &message,
        message.len,
    )) {
        std.log.err("Metal FRI line cascade failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CommitmentFailed;
    }

    // The FFI has joined and checked command/transcript status. Own every
    // published handle before any further fallible operation.
    var initialized: usize = 0;
    errdefer for (trees[0..initialized]) |*tree| tree.deinit();
    errdefer for (handles[initialized..]) |handle| if (handle) |value| @import("resident_data.zig").stwo_zig_metal_tree_destroy(value);
    const expected_mask: u32 = @as(u32, @intFromBool(inverses.needsGeneration(.circle))) | (@as(u32, @intFromBool(inverses.needsGeneration(.line))) << 1);
    if (inverse_generation_mask != expected_mask) return MetalError.CommitmentFailed;
    arena.owner.?.reservation.resize(extent.retained_bytes) catch |err| return @import("fri_error_v1.zig").translate(err);
    for (trees, handles, 0..) |*tree, handle, stage| {
        tree.* = .{
            .handle = handle orelse unreachable,
            .runtime_handle = self.handle,
            .log_size = std.math.log2_int(u32, source_count >> @intCast(stage)),
            .shared_external_reservation = arena.retain() catch |err| return @import("fri_error_v1.zig").translate(err),
        };
        initialized += 1;
    }
    inverses.complete() catch |err| return @import("fri_error_v1.zig").translate(err);
    return .{
        .stats = stats,
        .trees = trees,
        .inverse_generation_mask = if (capture_inverse_generation) inverse_generation_mask else 0,
    };
}

pub fn foldFriLineCascade(
    self: *Runtime,
    allocator: std.mem.Allocator,
    source: *anyopaque,
    source_count: u32,
    inverse_x: ?[]const u32,
    domain_initial_index: u32,
    domain_step_size: u32,
    coordinates: []const *anyopaque,
    final_destination: *anyopaque,
    leaf_seed: [8]u32,
    node_seed: [8]u32,
    domain_prefix_bytes: u32,
    channel_state: *[10]u32,
) (MetalError || std.mem.Allocator.Error)!FriLineCascadeResult {
    return self.foldFriCircleLineCascade(
        allocator,
        source,
        source_count,
        null,
        null,
        inverse_x,
        domain_initial_index,
        domain_step_size,
        coordinates,
        final_destination,
        leaf_seed,
        node_seed,
        domain_prefix_bytes,
        channel_state,
    );
}

pub fn foldFriLineCascadeWithReceipt(
    self: *Runtime,
    allocator: std.mem.Allocator,
    source: *anyopaque,
    source_count: u32,
    inverse_x: ?[]const u32,
    domain_initial_index: u32,
    domain_step_size: u32,
    coordinates: []const *anyopaque,
    final_destination: *anyopaque,
    leaf_seed: [8]u32,
    node_seed: [8]u32,
    domain_prefix_bytes: u32,
    channel_state: *[10]u32,
) (MetalError || std.mem.Allocator.Error)!FriLineCascadeResult {
    return self.foldFriCircleLineCascadeWithReceipt(
        allocator,
        source,
        source_count,
        null,
        null,
        inverse_x,
        domain_initial_index,
        domain_step_size,
        coordinates,
        final_destination,
        leaf_seed,
        node_seed,
        domain_prefix_bytes,
        channel_state,
    );
}

pub fn foldBlake3FriLineCascadeWithReceipt(
    self: *Runtime,
    allocator: std.mem.Allocator,
    source: *anyopaque,
    source_count: u32,
    inverse_x: ?[]const u32,
    domain_initial_index: u32,
    domain_step_size: u32,
    coordinates: []const *anyopaque,
    final_destination: *anyopaque,
    leaf_seed: [8]u32,
    node_seed: [8]u32,
    domain_prefix_bytes: u32,
    channel_state: *[11]u32,
) (MetalError || std.mem.Allocator.Error)!FriLineCascadeResult {
    return foldFriCircleLineCascadeForSuite(
        true,
        self,
        allocator,
        source,
        source_count,
        null,
        null,
        inverse_x,
        domain_initial_index,
        domain_step_size,
        coordinates,
        final_destination,
        leaf_seed,
        node_seed,
        domain_prefix_bytes,
        channel_state,
        true,
    );
}
