//! Public conditional bridge metadata. The final DAG must bind sources to
//! local execution roots and global_memory to its independently derived key.
const std = @import("std");
const core = @import("stwo_core");
const Scope = @import("../prover/block_v8_endpoint_global_bridge_scope_v1.zig");
const Epoch = @import("../prover/block_v7_execution_epoch_v1.zig");
pub const Trusted = struct { block_statement: [32]u8, config: core.pcs.PcsConfig };
pub const Input = struct { sources: []const Scope.Source, global_memory: Epoch.Entry, batch_first: u32, batch_count: u32 };
pub const Owned = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    trusted: Trusted,
    input: Input,
    scope: Scope.Owned,
    pub fn init(a: std.mem.Allocator, trusted: Trusted, input: Input) !*Owned {
        const out = try a.create(Owned);
        errdefer a.destroy(out);
        out.allocator = a;
        out.arena = std.heap.ArenaAllocator.init(a);
        errdefer out.arena.deinit();
        out.trusted = trusted;
        out.input = input;
        out.input.sources = try out.arena.allocator().dupe(Scope.Source, input.sources);
        var full = try Scope.Owned.init(a, trusted.block_statement, trusted.config, out.input.sources, input.global_memory);
        defer full.deinit();
        out.scope = try full.batch(a, input.batch_first, input.batch_count);
        return out;
    }
    pub fn deinit(self: *Owned) void {
        const a = self.allocator;
        self.scope.deinit();
        self.arena.deinit();
        a.destroy(self);
    }
};
