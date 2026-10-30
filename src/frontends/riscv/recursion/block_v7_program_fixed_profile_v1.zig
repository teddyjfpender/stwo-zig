//! Independently selected v7 ROM policy and original PCS geometry. Proposed
//! claims select no circuit constants and are not verification receipts.
const std = @import("std");
const core = @import("stwo_core");
const Native = @import("../prover/block_v7_program_provider_v1.zig");
const Original = @import("../prover/block_v5_program_table_proof_v1.zig");
const Shape = @import("block_v6_original_fixed_shape_v1.zig");
const Q = core.fields.qm31.QM31;
pub const Input = struct { policy: Native.Policy, claim: Q };
pub const Limits = struct { shape: Shape.Limits = .{}, max_entries: usize = 1 << 16, max_rom_words: usize = 1 << 24 };
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
        if (input.policy.entries.len == 0 or input.policy.entries.len > limits.max_entries or input.policy.plan.leaves.len > limits.max_rom_words) return error.ProgramFixedResourceLimit;
        try input.policy.admit();
        const self = try a.create(Owned);
        errdefer a.destroy(self);
        self.arena = std.heap.ArenaAllocator.init(a);
        errdefer self.arena.deinit();
        const temp = self.arena.allocator();
        var owned = input;
        owned.policy.entries = try temp.dupe(@import("../prover/block_v7_execution_epoch_v1.zig").Entry, input.policy.entries);
        owned.policy.plan.leaves = try temp.dupe(@TypeOf(input.policy.plan.leaves[0]), input.policy.plan.leaves);
        owned.policy.plan.multiplicities = try temp.dupe(u64, input.policy.plan.multiplicities);
        const drawn = try owned.policy.epoch.draw(temp);
        _ = try Native.channel(owned.policy, drawn, input.claim);
        var definition = try Original.Air.build(temp);
        defer definition.deinit();
        const relation = try @import("air/universal_relation_binding.zig").Binding(Original.Air).authenticate(&definition);
        const manifest = Original.Roster.Manifest{ .log_sizes = .{input.policy.plan.log_size} };
        const component = try Original.Roster.Component(Original.Air).init(&definition, relation, &manifest, .program, input.policy.plan.log_size, .{}, &drawn.word.universal_prefix, Q.zero());
        const handle = try @import("air/block_v5_program_table_composition_v1.zig").verifier(&component);
        const logs = [3][]const u32{ &([_]u32{input.policy.plan.log_size} ** Original.Air.PREPROCESSED_COLUMN_COUNT), &.{}, &([_]u32{input.policy.plan.log_size} ** Original.Air.INTERACTION_COLUMN_COUNT) };
        var shape = try Shape.Owned.init(temp, &logs, .{ .components = &.{handle}, .n_preprocessed_columns = logs[0].len }, input.policy.epoch.config, limits.shape);
        errdefer shape.deinit();
        self.* = .{ .backing = a, .arena = self.arena, .input = owned, .limits = limits, .shape = shape, .config = input.policy.epoch.config, .columns = shape.columns[0..4].*, .widths = shape.widths, .lifting_log = shape.lifting_log, .seal = undefined };
        self.seal = try self.identity();
        return self;
    }
    pub fn identity(self: *const Owned) ![32]u8 {
        var ch = core.channel.blake3.Channel{};
        ch.mixU32s(&.{ 0x42375053, 1 });
        ch.mixRoot(try self.input.policy.plan.digest());
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
        if (!std.meta.eql(self.seal, try self.identity()) or !std.meta.eql(self.seal, rebuilt.seal) or
            !std.meta.eql(self.config, rebuilt.config) or self.lifting_log != rebuilt.lifting_log or
            self.shape.mask_log != rebuilt.shape.mask_log or self.shape.composition_log != rebuilt.shape.composition_log or self.shape.split != rebuilt.shape.split)
            return error.UntrustedProgramFixedProfile;
        for (self.columns, rebuilt.columns) |got, want| if (!std.mem.eql(u32, got, want)) return error.UntrustedProgramFixedProfile;
        if (!std.mem.eql(@import("sample_point_layout.zig").Layout, self.shape.layouts, rebuilt.shape.layouts) or !std.mem.eql(u32, self.shape.mask_logs, rebuilt.shape.mask_logs) or !std.mem.eql(u32, self.widths, rebuilt.widths)) return error.UntrustedProgramFixedProfile;
    }
    pub fn deepProfile(self: *const Owned) @import("air/pcs_deep_circuit.zig").Profile {
        return self.shape.deepProfile();
    }
    pub fn friProfile(self: *const Owned) @import("air/fri_verifier_circuit.zig").Profile {
        return self.shape.friProfile();
    }
    pub fn publicCount(_: *const Owned) !usize {
        return 1;
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
