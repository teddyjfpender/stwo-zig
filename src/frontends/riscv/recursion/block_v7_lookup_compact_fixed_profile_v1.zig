//! Independently selected compact lookup metadata. Physical claims remain public
//! operands and select no graph constants. This profile is not proof admission.
const std = @import("std");
const core = @import("stwo_core");
const Native = @import("../prover/block_v7_lookup_compact_proof_v1.zig");
const Cold = @import("block_v7_lookup_compact_fixed_shape_v1.zig");
const Shape = @import("block_v6_original_fixed_shape_v1.zig");
const Q = core.fields.qm31.QM31;
pub const Input = struct { policy: Native.Policy, claims: [6]Q };
pub const Limits = struct { shape: Shape.Limits = .{}, max_entries: usize = 1 << 16 };
pub const Owned = struct {
    pub const commitment_trees = 4;
    backing: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    input: Input,
    limits: Limits,
    shape: Shape.Owned,
    config: core.pcs.PcsConfig,
    columns: [4][]const u32,
    widths: []u32,
    lifting_log: u32,
    seal: [32]u8,
    pub fn derive(a: std.mem.Allocator, input: Input, limits: Limits) !*Owned {
        if (input.policy.entries.len == 0 or input.policy.entries.len > limits.max_entries) return error.CompactLookupFixedResourceLimit;
        try input.policy.validate();
        const self = try a.create(Owned);
        errdefer a.destroy(self);
        self.arena = std.heap.ArenaAllocator.init(a);
        errdefer self.arena.deinit();
        const temp = self.arena.allocator();
        var owned = input;
        owned.policy.entries = try temp.dupe(@import("../prover/block_v7_execution_epoch_v1.zig").Entry, input.policy.entries);
        const drawn = try owned.policy.epoch.draw(temp);
        _ = try Native.interactionChannel(owned.policy, drawn, input.claims);
        const relations = try @import("air/universal_provider_relations.zig").SharedProviderRelations.init(&drawn.word.universal_prefix);
        var shape = try Cold.compact(temp, owned.policy.layout, input.policy.epoch.config, relations, limits.shape);
        errdefer shape.deinit();
        self.* = .{ .backing = a, .arena = self.arena, .input = owned, .limits = limits, .shape = shape, .config = input.policy.epoch.config, .columns = shape.columns[0..4].*, .widths = shape.widths, .lifting_log = shape.lifting_log, .seal = undefined };
        self.seal = try self.identity();
        return self;
    }
    pub fn identity(self: *const Owned) ![32]u8 {
        var ch = core.proof_suites.Blake3.Channel{};
        ch.mixU32s(&.{ 0x42374c53, 1 });
        ch.mixRoot(try self.input.policy.plan.identity());
        ch.mixRoot(self.input.policy.layout.digest);
        ch.mixRoot(self.input.policy.epoch.digest);
        for (self.input.policy.roots) |root| ch.mixRoot(root);
        ch.mixRoot(self.deepProfile().identityDigest());
        ch.mixRoot(self.friProfile().identityDigest());
        return ch.digestBytes();
    }
    pub fn validate(self: *const Owned) !void {
        try self.validateAgainst(self.input, self.limits);
    }
    pub fn validateAgainst(self: *const Owned, input: Input, limits: Limits) !void {
        const rebuilt = try derive(self.backing, input, limits);
        defer rebuilt.deinit();
        if (!std.meta.eql(self.config, rebuilt.config) or self.lifting_log != rebuilt.lifting_log or
            !std.meta.eql(self.shape.config, rebuilt.shape.config) or self.shape.mask_log != rebuilt.shape.mask_log or
            self.shape.lifting_log != rebuilt.shape.lifting_log or self.shape.composition_log != rebuilt.shape.composition_log or
            self.shape.split != rebuilt.shape.split or self.shape.columns.len != rebuilt.shape.columns.len or
            self.shape.trees.len != rebuilt.shape.trees.len) return error.UntrustedCompactLookupFixedProfile;
        if (!std.meta.eql(self.seal, try self.identity()) or !std.meta.eql(self.seal, rebuilt.seal)) return error.UntrustedCompactLookupFixedProfile;
        for (self.shape.columns, rebuilt.shape.columns) |got, want| if (!std.mem.eql(u32, got, want)) return error.UntrustedCompactLookupFixedProfile;
        for (self.columns, rebuilt.columns) |got, want| if (!std.mem.eql(u32, got, want)) return error.UntrustedCompactLookupFixedProfile;
        if (!std.mem.eql(@import("sample_point_layout.zig").Layout, self.shape.layouts, rebuilt.shape.layouts) or !std.mem.eql(u32, self.shape.mask_logs, rebuilt.shape.mask_logs) or !std.mem.eql(u32, self.widths, rebuilt.widths)) return error.UntrustedCompactLookupFixedProfile;
    }
    pub fn deepProfile(self: *const Owned) @import("air/pcs_deep_circuit.zig").Profile {
        return self.shape.deepProfile();
    }
    pub fn friProfile(self: *const Owned) @import("air/fri_verifier_circuit.zig").Profile {
        return self.shape.friProfile();
    }
    pub fn publicCount(_: *const Owned) !usize {
        return 6;
    }
    pub fn sampleCount(self: *const Owned) !usize {
        var n: usize = 0;
        for (self.shape.layouts) |layout| n = try std.math.add(usize, n, layout.sampleCount());
        return n;
    }
    pub fn deinit(self: *Owned) void {
        self.shape.deinit();
        self.arena.deinit();
        self.backing.destroy(self);
    }
};
