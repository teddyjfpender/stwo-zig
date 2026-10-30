//! Owned public metadata for the local theorem. No complete RAM snapshots,
//! initialized intervals, witness rows, key objects or producer receipts copied.
const std = @import("std");
const Scope = @import("block_v8_endpoint_local_scope_v1.zig");
pub const Owned = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    trusted: Scope.Trusted,
    input: Scope.Input,
    pub fn init(a: std.mem.Allocator, trusted: Scope.Trusted, input: Scope.Input) !*Owned {
        try input.shape.validateBlake3ExecutionWithExternal(0);
        const io = input.shape.public_data.io_entries;
        if (io.input_len != 0 or io.output_len != 0 or io.input_words.len != 0 or io.output_words.len != 0) return error.InvalidEndpointLocalStatementIo;
        const self = try a.create(Owned);
        errdefer a.destroy(self);
        self.allocator = a;
        self.arena = std.heap.ArenaAllocator.init(a);
        errdefer self.arena.deinit();
        const t = self.arena.allocator();
        self.trusted = trusted;
        self.trusted.elf = try t.dupe(u8, trusted.elf);
        self.input = input;
        self.input.sparse_support = try t.dupe(@import("block_v8_sparse_rom_v1.zig").Entry, input.sparse_support);
        const shape = try t.create(@TypeOf(input.shape.*));
        shape.* = input.shape.*;
        shape.public_data.io_entries.input_words = &.{};
        shape.public_data.io_entries.output_words = &.{};
        self.input.shape = shape;
        self.input.program_plan.leaves = try t.dupe(@TypeOf(input.program_plan.leaves[0]), input.program_plan.leaves);
        self.input.program_plan.multiplicities = try t.dupe(u64, input.program_plan.multiplicities);
        return self;
    }
    pub fn deinit(self: *Owned) void {
        const a = self.allocator;
        self.arena.deinit();
        a.destroy(self);
    }
};
