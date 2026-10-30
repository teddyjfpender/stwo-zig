//! Admitted compact global metadata; independent snapshot policy owns fixed-key authority.
const std = @import("std");
const core = @import("stwo_core");
const Scope = @import("../prover/block_v8_compact_ram_scope_v1.zig");
const E = @import("../prover/block_v7_execution_epoch_v1.zig");
pub const Trusted = struct { config: core.pcs.PcsConfig, policy: Scope.Policy };
pub const Input = struct { epoch: E.Epoch, entries: []const E.Entry, roots: [4][32]u8 };
pub const Owned = struct {
    allocator: std.mem.Allocator,
    trusted: Trusted,
    input: Input,
    window: *@import("../prover/block_v7_real_window_policy_v2.zig").Owned,
    pub fn init(a: std.mem.Allocator, trusted: Trusted, input: Input) !*Owned {
        try trusted.policy.requireEpoch(input.epoch, input.entries, input.roots);
        if (!std.meta.eql(trusted.config, trusted.policy.config)) return error.UntrustedCompactRecursiveConfig;
        const p = try a.create(Owned);
        errdefer a.destroy(p);
        const w = try trusted.policy.window.cloneAlloc(a);
        errdefer {
            w.deinit();
            a.destroy(w);
        }
        const entries = try a.dupe(E.Entry, input.entries);
        p.* = .{ .allocator = a, .trusted = trusted, .input = input, .window = w };
        p.trusted.policy.window = w;
        p.input.entries = entries;
        return p;
    }
    pub fn deinit(p: *Owned) void {
        const a = p.allocator;
        a.free(p.input.entries);
        p.window.deinit();
        a.destroy(p.window);
        a.destroy(p);
    }
};
