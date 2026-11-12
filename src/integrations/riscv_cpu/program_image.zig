//! Immutable executable mappings in canonical address order.
//! Allocation, W^X, alignment and historical rejection semantics are preserved.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64;
pub const Program = struct {
    words: []u32,
    addresses: []u64,
    pub fn init(a: std.mem.Allocator, memory: *rv.memory.Memory) !Program {
        var count: usize = 0;
        for (memory.mappings.entries.items) |region| if (region.permissions.execute) {
            if (region.permissions.write or region.first & 3 != 0 or region.last & 3 != 3) return error.InvalidEthereumInstructionMapping;
            count = try std.math.add(usize, count, @intCast((region.last - region.first + 1) / 4));
        };
        if (count == 0 or count > frontend.rv64_air.program.setup.MAX_PROGRAM_WORDS) return error.InvalidEthereumProgramSize;
        const words = try a.alloc(u32, count);
        errdefer a.free(words);
        const addresses = try a.alloc(u64, count);
        errdefer a.free(addresses);
        var at: usize = 0;
        for (memory.mappings.entries.items) |region| if (region.permissions.execute) {
            const n: usize = @intCast((region.last - region.first + 1) / 4);
            for (0..n) |i| {
                const address = region.first + 4 * i;
                words[at] = try memory.fetch(address);
                addresses[at] = address;
                at += 1;
            }
        };
        return .{ .words = words, .addresses = addresses };
    }
    pub fn value(self: Program) frontend.rv64_air.program.setup.Program {
        return .{ .base = self.addresses[0], .words = self.words, .addresses = self.addresses };
    }
    pub fn deinit(self: *Program, a: std.mem.Allocator) void {
        a.free(self.addresses);
        a.free(self.words);
        self.* = undefined;
    }
};
