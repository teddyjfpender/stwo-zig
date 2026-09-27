//! Shape-only description of the original three-trace recursive parent PCS.
//! No proof values, successful verifier token, received key or claims are inputs.
//! This is geometry, not a complete fixed commitment or verifier admission.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Roster = @import("air/blake3_native_parent_roster.zig").Roster;
const Geometry = @import("air/roster_composition_geometry.zig").ForAirs(Roster.Airs);
const tables = @import("../air/lookups/tables/schema.zig");
const deep = @import("air/pcs_deep_circuit.zig");
const fri = @import("air/fri_verifier_circuit.zig");
const Layout = @import("sample_point_layout.zig").Layout;
pub const Logs = [Roster.Airs.len]u32;
pub const Limits = struct { max_queries: usize = 128, max_columns: usize = 1 << 16 };
pub const Shape = struct {
    allocator: std.mem.Allocator,
    budget: ?*Budget,
    limits: Limits,
    logs: Logs,
    config: core.pcs.PcsConfig,
    columns: [4][]u32,
    trees: [4]deep.TreeProfile,
    layouts: []Layout,
    widths: []u32,
    mask_log: u32,
    lifting_log: u32,
    composition_split: u32,
    seal: [32]u8,

    /// The public caller must independently admit logs/config. This factory
    /// cannot convert proof-carried geometry into an expected key.
    pub fn init(a: std.mem.Allocator, logs: Logs, config: core.pcs.PcsConfig, limits: Limits) !*Shape {
        if (config.fri_config.n_queries == 0 or config.fri_config.n_queries >= core.fields.m31.Modulus or config.fri_config.n_queries > limits.max_queries or
            config.pow_bits > 256 or config.fri_config.fold_step == 0 or config.fri_config.fold_step > fri.MAX_FOLD_STEP)
            return error.InvalidRecursiveParentShape;
        _ = try core.fri.FriConfig.init(config.fri_config.log_last_layer_degree_bound, config.fri_config.log_blowup_factor, config.fri_config.n_queries);
        var maximum: u32 = 0;
        for (logs) |log| {
            if (log == 0 or log > 24) return error.InvalidRecursiveParentShape;
            maximum = @max(maximum, log);
        }
        for ([_]tables.Kind{ .bitwise, .range_check_8_8 }) |kind| maximum = @max(maximum, tables.logSize(kind));
        const split: u32 = Geometry.quotient_log_blowup;
        const quotient_log = try std.math.add(u32, maximum, split);
        const mask_log = core.verifier_types.compositionMaskLogSize(quotient_log, split) orelse return error.InvalidRecursiveParentShape;
        const composition_count = core.verifier_types.compositionColumnCount(split, 4) orelse return error.InvalidRecursiveParentShape;
        var counts: [4]usize = .{ 0, 0, 0, composition_count };
        inline for (Roster.Airs) |Air| {
            counts[0] = try std.math.add(usize, counts[0], Air.PREPROCESSED_COLUMN_COUNT);
            counts[1] = try std.math.add(usize, counts[1], Air.PHYSICAL_MAIN_COLUMN_COUNT);
            counts[2] = try std.math.add(usize, counts[2], Air.INTERACTION_COLUMN_COUNT);
        }
        for ([_]tables.Kind{ .bitwise, .range_check_8_8 }) |kind| {
            counts[0] = try std.math.add(usize, counts[0], 1 + tables.arity(kind));
            counts[1] = try std.math.add(usize, counts[1], 1);
            counts[2] = try std.math.add(usize, counts[2], 4);
        }
        var column_count: usize = 0;
        for (counts) |count| column_count = try std.math.add(usize, column_count, count);
        if (column_count > limits.max_columns) return error.RecursiveParentShapeResourceLimit;
        const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
        errdefer if (lease) |owner| owner.destroy();
        const self = try a.create(Shape);
        errdefer a.destroy(self);
        self.* = .{ .allocator = a, .budget = lease, .limits = limits, .logs = logs, .config = config, .columns = @splat(&.{}), .trees = undefined, .layouts = &.{}, .widths = &.{}, .mask_log = mask_log, .lifting_log = try std.math.add(u32, mask_log, config.fri_config.log_blowup_factor), .composition_split = split, .seal = undefined };
        errdefer self.freeStorage();
        self.layouts = try a.alloc(Layout, column_count);
        @memset(self.layouts, .current);
        for (counts, &self.columns) |count, *columns| columns.* = try a.alloc(u32, count);
        var cursors: [3]usize = @splat(0);
        inline for (Roster.Airs, 0..) |Air, i| {
            inline for (.{ Air.PREPROCESSED_COLUMN_COUNT, Air.PHYSICAL_MAIN_COLUMN_COUNT, Air.INTERACTION_COLUMN_COUNT }, 0..) |count, tree| {
                @memset(self.columns[tree][cursors[tree]..][0..count], try std.math.add(u32, logs[i], config.fri_config.log_blowup_factor));
                cursors[tree] += count;
            }
            if (Air.INTERACTION_COLUMN_COUNT != 0) {
                const first = counts[0] + counts[1] + cursors[2] - 4;
                @memset(self.layouts[first..][0..4], .previous_current);
            }
        }
        for ([_]tables.Kind{ .bitwise, .range_check_8_8 }) |kind| {
            const extended = try std.math.add(u32, tables.logSize(kind), config.fri_config.log_blowup_factor);
            for ([_]usize{ 1 + tables.arity(kind), 1, 4 }, 0..) |count, tree| {
                @memset(self.columns[tree][cursors[tree]..][0..count], extended);
                cursors[tree] += count;
            }
            const first = counts[0] + counts[1] + cursors[2] - 4;
            @memset(self.layouts[first..][0..4], .current_previous);
        }
        @memset(self.columns[3], self.lifting_log);
        for (&self.trees, self.columns) |*tree, columns| tree.* = .{ .column_log_sizes = columns };
        var widths: std.ArrayList(u32) = .empty;
        defer widths.deinit(a);
        var remaining = self.lifting_log;
        const terminal = try std.math.add(u32, config.fri_config.log_blowup_factor, config.fri_config.log_last_layer_degree_bound);
        while (remaining > terminal) {
            const step = @min(config.fri_config.fold_step, remaining - terminal);
            try widths.append(a, @as(u32, 1) << @intCast(step));
            remaining -= step;
        }
        self.widths = try widths.toOwnedSlice(a);
        try self.deepProfile().validate();
        try self.friProfile().validate();
        self.seal = self.identity();
        return self;
    }
    pub fn initForAdmission(a: std.mem.Allocator, admission: anytype, limits: Limits) !*Shape {
        try admission.validate();
        return init(a, admission.key.log_sizes, try admission.config(), limits);
    }
    pub fn deepProfile(self: *const Shape) deep.Profile {
        return .{ .trees = &self.trees, .sample_layouts = self.layouts, .lifting_log_size = self.lifting_log, .log_blowup_factor = self.config.fri_config.log_blowup_factor, .query_count = @intCast(self.config.fri_config.n_queries) };
    }
    pub fn friProfile(self: *const Shape) fri.Profile {
        return .{ .lifting_log_size = self.lifting_log, .log_blowup_factor = self.config.fri_config.log_blowup_factor, .log_last_layer_degree_bound = self.config.fri_config.log_last_layer_degree_bound, .fold_widths = self.widths, .query_count = @intCast(self.config.fri_config.n_queries) };
    }
    pub fn identity(self: *const Shape) [32]u8 {
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x42355348, 1, self.mask_log, self.composition_split });
        channel.mixU32s(&self.logs);
        self.config.mixInto(&channel);
        channel.mixRoot(self.deepProfile().identityDigest());
        channel.mixRoot(self.friProfile().identityDigest());
        return channel.digestBytes();
    }
    pub fn validate(self: *const Shape) !void {
        try self.deepProfile().validate();
        try self.friProfile().validate();
        for (self.trees, self.columns) |tree, columns| if (tree.column_log_sizes.ptr != columns.ptr or tree.column_log_sizes.len != columns.len) return error.MutatedRecursiveParentShape;
        if (!std.meta.eql(self.seal, self.identity())) return error.MutatedRecursiveParentShape;
    }
    pub fn validateAgainst(self: *const Shape, admission: anytype) !void {
        try self.validate();
        try admission.validate();
        if (!std.meta.eql(self.logs, admission.key.log_sizes) or !std.meta.eql(self.config, try admission.config())) return error.UntrustedRecursiveParentShape;
        // A mutated object cannot become admitted merely by recomputing its
        // own seal. Reconstruct from the independent caller's actual geometry.
        const independently_derived = try init(self.allocator, admission.key.log_sizes, try admission.config(), self.limits);
        defer independently_derived.deinit();
        if (!std.meta.eql(self.seal, independently_derived.seal)) return error.UntrustedRecursiveParentShape;
    }
    fn freeStorage(self: *Shape) void {
        for (self.columns) |columns| self.allocator.free(columns);
        self.allocator.free(self.layouts);
        self.allocator.free(self.widths);
    }
    pub fn deinit(self: *Shape) void {
        const a = self.allocator;
        const lease = self.budget;
        self.freeStorage();
        a.destroy(self);
        if (lease) |owner| owner.destroy();
    }
};
