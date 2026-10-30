//! Durable-owned public group metadata. This grants no admission authority.
const std = @import("std");
const Scope = @import("block_v8_endpoint_group_scope_v1.zig");
pub const Owned = struct {
    a: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    trusted: Scope.Trusted,
    input: Scope.Input,
    pub fn init(a: std.mem.Allocator, trusted: Scope.Trusted, input: Scope.Input) !*Owned {
        const self = try a.create(Owned);
        errdefer a.destroy(self);
        self.* = .{ .a = a, .arena = std.heap.ArenaAllocator.init(a), .trusted = trusted, .input = input };
        errdefer self.arena.deinit();
        const t = self.arena.allocator();
        self.trusted.elf = try t.dupe(u8, trusted.elf);
        const members = try t.dupe(Scope.MemberInput, input.members);
        self.input.members = members;
        for (members) |*member| {
            const io = member.shape.public_data.io_entries;
            if (io.input_len != 0 or io.output_len != 0 or io.input_words.len != 0 or io.output_words.len != 0) return error.InvalidGroupStatementIo;
            const shape = try t.create(@TypeOf(member.shape.*));
            shape.* = member.shape.*;
            shape.public_data.io_entries.input_words = &.{};
            shape.public_data.io_entries.output_words = &.{};
            member.shape = shape;
            if (member.caller) |*caller| {
                const statement = try t.create(@TypeOf(caller.statement.*));
                statement.* = caller.statement.*;
                caller.statement = statement;
            }
        }
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
