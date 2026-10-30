//! Owned public statement for a detached union proof. This clones no trace,
//! first-round PCS, successful verifier receipt, or recursive key authority.
const std = @import("std");
const Receiver = @import("block_v7_execution_receiver_v1.zig");
pub fn ForMode(comptime window: bool) type {
    const Multi = @import("block_v7_multi_union_proof_v1.zig").ForMode(window);
    return struct {
        pub const Owned = struct {
            allocator: std.mem.Allocator,
            arena: std.heap.ArenaAllocator,
            trusted: Receiver.Trusted,
            input: Multi.Input,
            pub fn init(a: std.mem.Allocator, trusted: Receiver.Trusted, input: Multi.Input) !*Owned {
                if ((trusted.window != null) != window or input.natives.len == 0 or input.natives.len > 64 or input.callers.len > input.natives.len or input.entries.len > 131) return error.InvalidUnionStatement;
                const self = try a.create(Owned);
                errdefer a.destroy(self);
                self.allocator = a;
                self.arena = std.heap.ArenaAllocator.init(a);
                errdefer self.arena.deinit();
                const t = self.arena.allocator();
                self.trusted = trusted;
                self.trusted.elf = try t.dupe(u8, trusted.elf);
                self.trusted.window = if (trusted.window) |boundary| try boundary.cloneAlloc(t) else null;
                self.input = input;
                self.input.entries = try t.dupe(@TypeOf(input.entries[0]), input.entries);
                const natives = try t.dupe(@TypeOf(input.natives[0]), input.natives);
                self.input.natives = natives;
                for (natives) |*pin| {
                    try pin.validate();
                    const shape = try t.create(@TypeOf(pin.shape.*));
                    shape.* = pin.shape.*;
                    // Pin.validate requires both public I/O slices empty. No
                    // pointer into the producer's zero-length slice survives.
                    shape.public_data.io_entries.input_words = &.{};
                    shape.public_data.io_entries.output_words = &.{};
                    pin.shape = shape;
                }
                const callers = try t.dupe(@TypeOf(input.callers[0]), input.callers);
                self.input.callers = callers;
                for (callers) |*pin| {
                    comptime requirePointerFree(@TypeOf(pin.statement.*));
                    const statement = try t.create(@TypeOf(pin.statement.*));
                    statement.* = pin.statement.*;
                    pin.statement = statement;
                }
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
    };
}
fn requirePointerFree(comptime T: type) void {
    switch (@typeInfo(T)) {
        .pointer => @compileError("union statement clone requires an explicit owner for new pointer fields"),
        .array => |info| requirePointerFree(info.child),
        .optional => |info| requirePointerFree(info.child),
        .@"struct" => |info| for (info.fields) |field| requirePointerFree(field.type),
        .@"union" => |info| for (info.fields) |field| requirePointerFree(field.type),
        else => {},
    }
}
