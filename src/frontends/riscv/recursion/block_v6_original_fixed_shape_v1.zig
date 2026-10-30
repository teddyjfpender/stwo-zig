//! Capture-free PCS shape from independently reconstructed original components.
//! Preserves empty trees, heterogeneous logs and exact previous/current masks.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Layout = @import("sample_point_layout.zig");
const Deep = @import("air/pcs_deep_circuit.zig");
const Fri = @import("air/fri_verifier_circuit.zig");
pub const Limits = struct { max_columns: usize = 1 << 16, max_queries: u32 = 128 };
pub const Owned = struct {
    arena: std.heap.ArenaAllocator,
    config: core.pcs.PcsConfig,
    columns: []const []const u32,
    trees: []Deep.TreeProfile,
    layouts: []Layout.Layout,
    mask_logs: []const u32,
    widths: []u32,
    mask_log: u32,
    lifting_log: u32,
    composition_log: u32,
    split: u32,
    pub fn init(a: std.mem.Allocator, logs: []const []const u32, all: core.air.components.Components, config: core.pcs.PcsConfig, limits: Limits) !Owned {
        return switch (logs.len) {
            3 => initForTraceTrees(3, a, logs, all, config, limits),
            4 => initForTraceTrees(4, a, logs, all, config, limits),
            else => error.InvalidOriginalFixedShape,
        };
    }
    /// The tree count is selected by a protocol at compile time, never decoded
    /// from a candidate. Existing init retains its original three/four-tree gate.
    pub fn initForTraceTrees(comptime trace_trees: usize, a: std.mem.Allocator, logs: []const []const u32, all: core.air.components.Components, config: core.pcs.PcsConfig, limits: Limits) !Owned {
        if (trace_trees < 3 or trace_trees > 5) @compileError("unsupported original trace tree inventory");
        if (logs.len != trace_trees) return error.InvalidOriginalFixedShape;
        return initForBoundedTraceTrees(a, logs, all, config, limits, trace_trees);
    }
    /// Explicit runtime shape for an independently admitted union placement.
    /// The old three/four/five-tree entry points retain their original gates.
    /// This constructs PCS arithmetic geometry, not a key or an admission receipt.
    pub fn initForBoundedTraceTrees(a: std.mem.Allocator, logs: []const []const u32, all: core.air.components.Components, config: core.pcs.PcsConfig, limits: Limits, max_trace_trees: usize) !Owned {
        if (max_trace_trees < 3 or max_trace_trees > 256 or logs.len < 3 or logs.len > max_trace_trees or limits.max_columns == 0 or config.fri_config.n_queries == 0 or config.fri_config.n_queries > limits.max_queries or config.fri_config.fold_step == 0 or config.fri_config.fold_step > Fri.MAX_FOLD_STEP) return error.InvalidOriginalFixedShape;
        var arena = std.heap.ArenaAllocator.init(a);
        errdefer arena.deinit();
        const temp = arena.allocator();
        const composition_log = all.compositionLogDegreeBound();
        const split = try all.compositionLogSplit();
        const mask_log = core.verifier_types.compositionMaskLogSize(composition_log, split) orelse return error.InvalidOriginalFixedShape;
        const point = core.circle.SECURE_FIELD_CIRCLE_GEN;
        var masks = try all.maskPoints(temp, point, mask_log, false);
        defer masks.deinitDeep(temp);
        if (masks.items.len != logs.len) return error.InvalidOriginalFixedShape;
        const columns = try temp.alloc([]const u32, logs.len + 1);
        const trees = try temp.alloc(Deep.TreeProfile, logs.len + 1);
        var layouts: std.ArrayList(Layout.Layout) = .empty;
        var mask_logs: std.ArrayList(u32) = .empty;
        var explicit_step = false;
        var lifting: u32 = 0;
        for (logs, masks.items, columns[0..logs.len]) |raw, points, *out| {
            if (raw.len != points.len or try std.math.add(usize, layouts.items.len, raw.len) > limits.max_columns) return error.OriginalFixedShapeResourceLimit;
            const extended = try temp.alloc(u32, raw.len);
            for (raw, points, extended) |log, samples, *value| {
                value.* = try std.math.add(u32, log, config.fri_config.log_blowup_factor);
                if (samples.len != 0) lifting = @max(lifting, value.*);
                const resolved = try @import("component_sample_layout_v1.zig").resolve(samples, point, mask_log, log);
                try layouts.append(temp, resolved.layout);
                try mask_logs.append(temp, resolved.mask_log);
                explicit_step = explicit_step or (resolved.layout == .current_keccak_final or resolved.layout == .current_keccak_final_composition);
            }
            out.* = extended;
        }
        const n = core.verifier_types.compositionColumnCount(split, 4) orelse return error.InvalidOriginalFixedShape;
        if (n == 0 or try std.math.add(usize, layouts.items.len, n) > limits.max_columns) return error.OriginalFixedShapeResourceLimit;
        const composition_columns = try temp.alloc(u32, n);
        @memset(composition_columns, try std.math.add(u32, mask_log, config.fri_config.log_blowup_factor));
        lifting = @max(lifting, composition_columns[0]);
        columns[logs.len] = composition_columns;
        try layouts.appendNTimes(temp, .current, n);
        try mask_logs.appendNTimes(temp, mask_log, n);
        for (trees, columns) |*tree, values| tree.* = .{ .column_log_sizes = values };
        var widths: std.ArrayList(u32) = .empty;
        var remaining = lifting;
        const terminal = try std.math.add(u32, config.fri_config.log_blowup_factor, config.fri_config.log_last_layer_degree_bound);
        while (remaining > terminal) {
            const shift = @min(config.fri_config.fold_step, remaining - terminal);
            try widths.append(temp, @as(u32, 1) << @intCast(shift));
            remaining -= shift;
        }
        const result = Owned{ .arena = arena, .config = config, .columns = columns, .trees = trees, .layouts = layouts.items, .mask_logs = if (explicit_step) mask_logs.items else &.{}, .widths = widths.items, .mask_log = mask_log, .lifting_log = lifting, .composition_log = composition_log, .split = split };
        try result.deepProfile().validate();
        try result.friProfile().validate();
        return result;
    }
    pub fn deepProfile(self: *const Owned) Deep.Profile {
        return .{ .trees = self.trees, .sample_layouts = self.layouts, .mask_log_sizes = self.mask_logs, .lifting_log_size = self.lifting_log, .log_blowup_factor = self.config.fri_config.log_blowup_factor, .query_count = @intCast(self.config.fri_config.n_queries) };
    }
    pub fn friProfile(self: *const Owned) Fri.Profile {
        return .{ .lifting_log_size = self.lifting_log, .log_blowup_factor = self.config.fri_config.log_blowup_factor, .log_last_layer_degree_bound = self.config.fri_config.log_last_layer_degree_bound, .query_count = @intCast(self.config.fri_config.n_queries), .fold_widths = self.widths };
    }
    pub fn deinit(self: *Owned) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
