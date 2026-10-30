//! Public metadata ownership for the new endpoint original proof. Clones no
//! trace, original PCS tree, producer receipt or nominated recursive key.
const std = @import("std");
const Scope = @import("block_v8_endpoint_whole_scope_v1.zig");
const Receiver = @import("block_v7_execution_receiver_v1.zig");
pub const Owned = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    trusted: Receiver.Trusted,
    input: Scope.Input,
    pub fn init(a: std.mem.Allocator, trusted: Receiver.Trusted, input: Scope.Input) !*Owned {
        if (trusted.window == null or input.endpoint_count == 0 or input.memory_geometry.len == 0 or
            input.memory_geometry.len > 4096) return error.InvalidEndpointStatement;
        try input.shape.validateBlake3ExecutionWithExternal(0);
        const io = input.shape.public_data.io_entries;
        if (io.input_len != 0 or io.output_len != 0 or io.input_words.len != 0 or io.output_words.len != 0)
            return error.InvalidEndpointStatementIo;
        const self = try a.create(Owned);
        errdefer a.destroy(self);
        self.allocator = a;
        self.arena = std.heap.ArenaAllocator.init(a);
        errdefer self.arena.deinit();
        const t = self.arena.allocator();
        self.trusted = trusted;
        self.trusted.elf = try t.dupe(u8, trusted.elf);
        self.trusted.window = try trusted.window.?.cloneAlloc(t);
        self.input = input;
        const shape = try t.create(@TypeOf(input.shape.*));
        shape.* = input.shape.*;
        shape.public_data.io_entries.input_words = &.{};
        shape.public_data.io_entries.output_words = &.{};
        self.input.shape = shape;
        self.input.program_plan.leaves = try t.dupe(@TypeOf(input.program_plan.leaves[0]), input.program_plan.leaves);
        self.input.program_plan.multiplicities = try t.dupe(@TypeOf(input.program_plan.multiplicities[0]), input.program_plan.multiplicities);
        self.input.memory_geometry = try t.dupe(@TypeOf(input.memory_geometry[0]), input.memory_geometry);
        return self;
    }
    pub fn deinit(self: *Owned) void {
        const a = self.allocator;
        self.arena.deinit();
        a.destroy(self);
    }
};
