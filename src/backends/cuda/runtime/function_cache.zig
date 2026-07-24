//! Structural identity for validated AOT function bindings.

const std = @import("std");
const types = @import("../abi/types.zig");
const kernel_module = @import("kernel.zig");

pub const allocator = std.heap.page_allocator;

pub const Key = struct {
    cache_key: u64,
    abi_schema: u32,
    name: []const u8,
    grid: [3]u32,
    block: [3]u32,
    dynamic_shared_bytes: u32,
    argument_count: u32,

    pub fn fromKernel(kernel: kernel_module.Kernel) Key {
        return .{
            .cache_key = kernel.cache_key,
            .abi_schema = @intFromEnum(kernel.abi_schema),
            .name = kernel.name,
            .grid = kernel.grid,
            .block = kernel.block,
            .dynamic_shared_bytes = kernel.dynamic_shared_bytes,
            .argument_count = kernel.argument_count,
        };
    }
};

const KeyContext = struct {
    pub fn hash(_: KeyContext, key: Key) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(std.mem.asBytes(&key.cache_key));
        hasher.update(std.mem.asBytes(&key.abi_schema));
        hasher.update(key.name);
        hasher.update(std.mem.asBytes(&key.grid));
        hasher.update(std.mem.asBytes(&key.block));
        hasher.update(std.mem.asBytes(&key.dynamic_shared_bytes));
        hasher.update(std.mem.asBytes(&key.argument_count));
        return hasher.final();
    }

    pub fn eql(_: KeyContext, left: Key, right: Key) bool {
        return left.cache_key == right.cache_key and
            left.abi_schema == right.abi_schema and
            std.mem.eql(u8, left.name, right.name) and
            std.mem.eql(u32, &left.grid, &right.grid) and
            std.mem.eql(u32, &left.block, &right.block) and
            left.dynamic_shared_bytes == right.dynamic_shared_bytes and
            left.argument_count == right.argument_count;
    }
};

pub const Value = struct {
    handle: *anyopaque,
    receipt: types.NativeAotFunctionReceipt,
};

pub const Map = std.HashMapUnmanaged(
    Key,
    Value,
    KeyContext,
    std.hash_map.default_max_load_percentage,
);
