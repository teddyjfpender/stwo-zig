//! Owned public inputs only. This clone is not an admission/key/proof receipt;
//! the mixed receiver independently derives all geometry and fixed keys.
const std = @import("std");
const Scope = @import("block_v8_endpoint_mixed_scope_v1.zig");
pub const Owned = struct {
    a: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    trusted: Scope.Trusted,
    input: Scope.Input,
    pub fn init(a: std.mem.Allocator, trusted: Scope.Trusted, input: Scope.Input) !*Owned {
        try input.shape.validateBlake3ExecutionWithExternal(@import("blake3_ethereum_sha_profile.zig").externalCount(input.caller_statement));
        const io = input.shape.public_data.io_entries;
        if (io.input_len != 0 or io.output_len != 0 or io.input_words.len != 0 or io.output_words.len != 0) return error.InvalidEndpointMixedStatementIo;
        const self = try a.create(Owned);
        errdefer a.destroy(self);
        self.* = .{ .a = a, .arena = std.heap.ArenaAllocator.init(a), .trusted = trusted, .input = input };
        errdefer self.arena.deinit();
        const t = self.arena.allocator();
        self.trusted.elf = try t.dupe(u8, trusted.elf);
        const shape = try t.create(@TypeOf(input.shape.*));
        shape.* = input.shape.*;
        shape.public_data.io_entries.input_words = &.{};
        shape.public_data.io_entries.output_words = &.{};
        self.input.shape = shape;
        const caller = try t.create(@TypeOf(input.caller_statement.*));
        caller.* = input.caller_statement.*;
        self.input.caller_statement = caller;
        self.input.sparse_support = try t.dupe(@import("block_v8_sparse_rom_v1.zig").Entry, input.sparse_support);
        self.input.program_plan.leaves = try t.dupe(@TypeOf(input.program_plan.leaves[0]), input.program_plan.leaves);
        self.input.program_plan.multiplicities = try t.dupe(u64, input.program_plan.multiplicities);
        return self;
    }
    pub fn deinit(self: *Owned) void {
        const a = self.a;
        self.arena.deinit();
        a.destroy(self);
    }
};
