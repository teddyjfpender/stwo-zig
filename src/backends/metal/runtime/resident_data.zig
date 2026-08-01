//! Resident trace materialization, commitment ABI, and resource ownership.

const std = @import("std");

extern fn stwo_zig_metal_buffer_destroy(buffer: ?*anyopaque) void;

pub extern fn stwo_zig_metal_witness_input_gather(
    runtime: *anyopaque,
    arena: *anyopaque,
    producer_offsets: [*]const u32,
    edge_descriptors: [*]const u32,
    edge_count: u32,
    input_width: u32,
    total_real_rows: u32,
    consumer_rows: u32,
    consumer_offsets: [*]const u32,
    include_enabler: u32,
    include_iota: u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_execution_table_split(
    runtime: *anyopaque,
    arena: *anyopaque,
    source_offset: u32,
    value_count: u32,
    column_rows: u32,
    source_words: u32,
    limb_count: u32,
    destination_offsets: [*]const u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_memory_address_base_trace(
    runtime: *anyopaque,
    arena: *anyopaque,
    raw_address_offset: u32,
    address_count: u32,
    multiplicity_offset: u32,
    multiplicity_words: u32,
    row_count: u32,
    output_offsets: [*]const u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_memory_value_base_trace(
    runtime: *anyopaque,
    arena: *anyopaque,
    source_offsets: [*]const u32,
    limb_count: u32,
    source_words: u32,
    source_row_offset: u32,
    multiplicity_offset: u32,
    multiplicity_words: u32,
    row_count: u32,
    output_offsets: [*]const u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_memory_rc99_count(
    runtime: *anyopaque,
    arena: *anyopaque,
    limb_offsets: [*]const u32,
    pair_count: u32,
    row_count: u32,
    lut_offset: u32,
    table_size: u32,
    count_offset: u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_public_memory_seed(
    runtime: *anyopaque,
    arena: *anyopaque,
    address_id_pairs: [*]const u32,
    entry_count: u32,
    address_count_offset: u32,
    address_count_words: u32,
    big_count_offset: u32,
    big_count_words: u32,
    small_count_offset: u32,
    small_count_words: u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_leaf_absorb(
    runtime: *anyopaque,
    arena: *anyopaque,
    column_offsets: [*]const u32,
    column_logs: [*]const u32,
    column_count: u32,
    state_offset: u32,
    lifting_log: u32,
    first_column: u32,
    is_final: u32,
    prefix_bytes: u32,
    leaf_seed: *const [8]u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_leaf_absorb_compact(
    runtime: *anyopaque,
    arena: *anyopaque,
    column_offsets: [*]const u32,
    column_logs: [*]const u32,
    column_count: u32,
    source_state_offset: u32,
    source_state_log: u32,
    destination_state_offset: u32,
    destination_log: u32,
    first_column: u32,
    is_final: u32,
    prefix_bytes: u32,
    leaf_seed: *const [8]u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_parent_seeded(
    runtime: *anyopaque,
    arena: *anyopaque,
    child_offset: u32,
    destination_offset: u32,
    parent_count: u32,
    node_seed: *const [8]u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_parent_plain(
    runtime: *anyopaque,
    arena: *anyopaque,
    child_offset: u32,
    destination_offset: u32,
    parent_count: u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_qm31_to_coordinates(
    runtime: *anyopaque,
    source: [*]const u32,
    value_count: u32,
    destination: [*]u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_felt252_oracle(
    runtime: *anyopaque,
    inputs: [*]const u32,
    count: u32,
    outputs: [*]u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_merkle_commit(
    runtime: *anyopaque,
    columns: [*]const [*]const u32,
    column_lengths: [*]const usize,
    column_log_sizes: [*]const u32,
    backing_words: ?[*]const [*]const u32,
    backing_word_counts: ?[*]const usize,
    backing_count: u32,
    column_count: u32,
    lifting_log_size: u32,
    leaf_seed: *const [8]u32,
    node_seed: *const [8]u32,
    domain_prefix_bytes: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_tree_destroy(tree: ?*anyopaque) void;
pub extern fn stwo_zig_metal_tree_root(
    tree: *anyopaque,
    root: *[32]u8,
    gpu_milliseconds: *f64,
) bool;
pub extern fn stwo_zig_metal_tree_copy_layers(
    runtime: *anyopaque,
    tree: *anyopaque,
    destination: [*]u8,
    destination_len: usize,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_tree_copy_hashes(
    runtime: *anyopaque,
    tree: *anyopaque,
    layer_log_size: u32,
    indices: [*]const u32,
    index_count: u32,
    destination: [*]u8,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_tree_copy_hashes_batch(
    runtime: *anyopaque,
    tree: *anyopaque,
    layer_log_sizes: [*]const u32,
    indices: [*]const [*]const u32,
    index_counts: [*]const u32,
    destinations: [*]const [*]u8,
    request_count: u32,
    error_message: [*]u8,
    error_message_len: usize,
) bool;

pub fn ResidentData(comptime MetalError: type, comptime Runtime: type) type {
    return struct {
        pub const ResidentBuffer = struct {
            handle: *anyopaque,
            contents: *anyopaque,
            byte_length: usize,

            pub fn deinit(self: *ResidentBuffer) void {
                destroyOpaque(self.handle);
                self.* = undefined;
            }

            pub fn destroyOpaque(handle: *anyopaque) void {
                stwo_zig_metal_buffer_destroy(handle);
            }
        };

        pub const Tree = struct {
            handle: *anyopaque,
            runtime_handle: *anyopaque,
            log_size: u32,

            pub fn deinit(self: *Tree) void {
                stwo_zig_metal_tree_destroy(self.handle);
                self.* = undefined;
            }

            pub fn root(self: Tree) MetalError!struct { hash: [32]u8, gpu_ms: f64 } {
                var hash: [32]u8 = undefined;
                var gpu_ms: f64 = 0;
                if (!stwo_zig_metal_tree_root(self.handle, &hash, &gpu_ms)) return MetalError.RootReadFailed;
                return .{ .hash = hash, .gpu_ms = gpu_ms };
            }

            /// Reads only selected hashes from one logical root-to-leaf layer.
            /// `layer_log_size == 0` addresses the root and `log_size` the leaves.
            pub fn copyHashes(
                self: Tree,
                allocator: std.mem.Allocator,
                layer_log_size: u32,
                indices: []const u32,
            ) (MetalError || std.mem.Allocator.Error)![][32]u8 {
                if (layer_log_size > self.log_size) return MetalError.RootReadFailed;
                const layer_len = @as(usize, 1) << @intCast(layer_log_size);
                for (indices) |index| {
                    if (index >= layer_len) return MetalError.RootReadFailed;
                }
                const output = try allocator.alloc([32]u8, indices.len);
                errdefer allocator.free(output);
                if (indices.len == 0) return output;

                var message: [1024]u8 = [_]u8{0} ** 1024;
                if (!stwo_zig_metal_tree_copy_hashes(
                    self.runtime_handle,
                    self.handle,
                    layer_log_size,
                    indices.ptr,
                    @intCast(indices.len),
                    @ptrCast(output.ptr),
                    &message,
                    message.len,
                )) {
                    std.log.err("Metal selective hash readback failed: {s}", .{std.mem.sliceTo(&message, 0)});
                    return MetalError.RootReadFailed;
                }
                return output;
            }

            /// Reads selected hashes from multiple logical layers with one command
            /// buffer and one wait. Request and index order are preserved exactly.
            pub fn copyHashesBatch(
                self: Tree,
                allocator: std.mem.Allocator,
                requests: anytype,
            ) (MetalError || std.mem.Allocator.Error)![][][32]u8 {
                const request_count = std.math.cast(u32, requests.len) orelse return MetalError.RootReadFailed;
                const outputs = try allocator.alloc([][32]u8, requests.len);
                var initialized: usize = 0;
                errdefer {
                    for (outputs[0..initialized]) |output| allocator.free(output);
                    allocator.free(outputs);
                }
                if (requests.len == 0) return outputs;

                const layer_log_sizes = try allocator.alloc(u32, requests.len);
                defer allocator.free(layer_log_sizes);
                const index_pointers = try allocator.alloc([*]const u32, requests.len);
                defer allocator.free(index_pointers);
                const index_counts = try allocator.alloc(u32, requests.len);
                defer allocator.free(index_counts);
                const destinations = try allocator.alloc([*]u8, requests.len);
                defer allocator.free(destinations);

                var total_hashes: usize = 0;
                for (requests, 0..) |request, request_index| {
                    if (request.layer_log_size >= 31 or request.layer_log_size > self.log_size)
                        return MetalError.RootReadFailed;
                    const layer_len = @as(usize, 1) << @intCast(request.layer_log_size);
                    for (request.indices) |index| if (index >= layer_len) return MetalError.RootReadFailed;
                    const index_count = std.math.cast(u32, request.indices.len) orelse return MetalError.RootReadFailed;
                    total_hashes = std.math.add(usize, total_hashes, request.indices.len) catch
                        return MetalError.RootReadFailed;

                    const output = try allocator.alloc([32]u8, request.indices.len);
                    outputs[request_index] = output;
                    initialized += 1;
                    layer_log_sizes[request_index] = request.layer_log_size;
                    index_pointers[request_index] = request.indices.ptr;
                    index_counts[request_index] = index_count;
                    destinations[request_index] = @ptrCast(output.ptr);
                }
                if (total_hashes == 0) return outputs;

                var message: [1024]u8 = [_]u8{0} ** 1024;
                if (!stwo_zig_metal_tree_copy_hashes_batch(
                    self.runtime_handle,
                    self.handle,
                    layer_log_sizes.ptr,
                    index_pointers.ptr,
                    index_counts.ptr,
                    destinations.ptr,
                    request_count,
                    &message,
                    message.len,
                )) {
                    std.log.err("Metal batched hash readback failed: {s}", .{std.mem.sliceTo(&message, 0)});
                    return MetalError.RootReadFailed;
                }
                return outputs;
            }

            /// Copies all layers in root-to-leaf order. This is a compatibility path
            /// for the current CPU decommitter; the resident prover consumes layers on
            /// device and reads back only queried siblings.
            pub fn copyLayers(
                self: Tree,
                runtime: *Runtime,
                allocator: std.mem.Allocator,
                log_size: u32,
            ) (MetalError || std.mem.Allocator.Error)![][32]u8 {
                const hash_count = (@as(usize, 1) << @intCast(log_size + 1)) - 1;
                const output = try allocator.alloc([32]u8, hash_count);
                errdefer allocator.free(output);
                var message: [1024]u8 = [_]u8{0} ** 1024;
                if (!stwo_zig_metal_tree_copy_layers(
                    runtime.handle,
                    self.handle,
                    @ptrCast(output.ptr),
                    output.len * @sizeOf([32]u8),
                    &message,
                    message.len,
                )) {
                    std.log.err("Metal layer readback failed: {s}", .{std.mem.sliceTo(&message, 0)});
                    return MetalError.RootReadFailed;
                }
                return output;
            }
        };
    };
}

const TestRuntime = struct {
    handle: *anyopaque,
};
const TestData = ResidentData(error{RootReadFailed}, TestRuntime);

test "resident resources retain stable host layouts" {
    try std.testing.expectEqual(@as(usize, 3 * @sizeOf(usize)), @sizeOf(TestData.ResidentBuffer));
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(TestData.ResidentBuffer, "handle"));
    try std.testing.expectEqual(@as(usize, @sizeOf(usize)), @offsetOf(TestData.ResidentBuffer, "contents"));

    try std.testing.expectEqual(@as(usize, 0), @offsetOf(TestData.Tree, "handle"));
    try std.testing.expectEqual(@as(usize, @sizeOf(usize)), @offsetOf(TestData.Tree, "runtime_handle"));
    try std.testing.expectEqual(@as(usize, 2 * @sizeOf(usize)), @offsetOf(TestData.Tree, "log_size"));
}

test "resident commitment bindings retain pointer ABI" {
    const commit = @typeInfo(@TypeOf(stwo_zig_metal_merkle_commit)).@"fn";
    try std.testing.expect(commit.params[1].type.? == [*]const [*]const u32);
    try std.testing.expect(commit.params[2].type.? == [*]const usize);
    try std.testing.expect(commit.return_type.? == ?*anyopaque);

    const batch = @typeInfo(@TypeOf(stwo_zig_metal_tree_copy_hashes_batch)).@"fn";
    try std.testing.expect(batch.params[3].type.? == [*]const [*]const u32);
    try std.testing.expect(batch.params[6].type.? == u32);
}
