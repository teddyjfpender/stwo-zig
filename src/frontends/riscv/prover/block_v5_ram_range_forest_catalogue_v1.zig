//! Stable independently reconstructed original admissions. This catalogue
//! owns geometry and source pins; it never accepts transported recursive keys.
const std = @import("std");
const Lane = @import("block_v5_ram_lanes_receiver_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Plans = @import("block_v5_ram_lanes_plan_v1.zig");
pub const Ram = @import("block_v5_ram_lanes_recursive_admission_v1.zig");
pub const Range = @import("block_v5_range16_recursive_admission_v1.zig");
pub const Limits = struct { ram: Ram.Limits = .{}, range: Range.Limits = .{}, max_leaves: usize = 4096 };
pub const Owned = struct {
    a: std.mem.Allocator,
    memory: Lane.Pins,
    sealed: Seal.Sealed,
    ram: []Ram.Prepared,
    range: []Range.Prepared,
    pub fn init(a: std.mem.Allocator, memory: Lane.Pins, sealed: Seal.Sealed, limits: Limits) !Owned {
        if (limits.max_leaves == 0 or try std.math.add(usize, memory.pins.len, memory.range_roots.len) > limits.max_leaves) return error.RamForestCatalogueLimit;
        try Lane.admit(a, memory, sealed, memory.limits);
        const entries = try a.dupe(Seal.Entry, memory.first_round);
        errdefer a.free(entries);
        const pins = try a.dupe(@import("block_v5_ram_lanes_proof_v1.zig").Pin, memory.pins);
        errdefer a.free(pins);
        const roots = try a.dupe([2][32]u8, memory.range_roots);
        errdefer a.free(roots);
        var copied = memory;
        copied.first_round = entries;
        copied.pins = pins;
        copied.range_roots = roots;
        var plan = try Plans.rangePlan(a, pins, memory.expected_total_events, memory.limits.plan);
        defer plan.deinit(a);
        const ram = try a.alloc(Ram.Prepared, pins.len);
        errdefer a.free(ram);
        var nr: usize = 0;
        errdefer for (ram[0..nr]) |*p| p.deinit();
        for (ram, pins) |*p, pin| {
            p.* = try Ram.Prepared.init(a, pin, sealed, copied.seal, entries, limits.ram);
            nr += 1;
        }
        const range = try a.alloc(Range.Prepared, roots.len);
        errdefer a.free(range);
        var np: usize = 0;
        errdefer for (range[0..np]) |*p| p.deinit();
        for (range, plan.shards, roots) |*p, shard, pair| {
            p.* = try Range.Prepared.init(a, shard, plan.digest, pair, sealed, copied.seal, entries, limits.range);
            np += 1;
        }
        return .{ .a = a, .memory = copied, .sealed = sealed, .ram = ram, .range = range };
    }
    pub fn deinit(self: *Owned) void {
        for (self.ram) |*p| p.deinit();
        for (self.range) |*p| p.deinit();
        self.a.free(self.ram);
        self.a.free(self.range);
        self.a.free(self.memory.pins);
        self.a.free(self.memory.range_roots);
        self.a.free(self.memory.first_round);
        self.* = undefined;
    }
};
