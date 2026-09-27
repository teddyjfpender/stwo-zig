//! Exact static PCS geometry for the original word-memory quotient adapter.
//! No Spec value, proof/capture, transcript draws or verifier-success token.
//! The caller independently admits row_log/config; this is not a key authority.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Deep = @import("air/pcs_deep_circuit.zig");
const Fri = @import("air/fri_verifier_circuit.zig");
const Layout = @import("sample_point_layout.zig").Layout;
pub const Limits = struct { max_queries: usize = 128, max_columns: usize = 1 << 16, max_row_log: u32 = 24 };
pub fn ForSpec(comptime Spec: type) type {
    return struct {
        pub const Shape = struct {
            const Self = @This();
            allocator: std.mem.Allocator,
            budget: ?*Budget,
            row_log: u32,
            config: core.pcs.PcsConfig,
            limits: Limits,
            columns: [4][]u32,
            trees: [4]Deep.TreeProfile,
            layouts: []Layout,
            widths: []u32,
            mask_log: u32,
            lifting_log: u32,
            seal: [32]u8,
            pub const fixed_setup_only = true;
            pub const complete_family_setup = false;
            pub const counts = [4]usize{ Spec.FIXED_COUNT, Spec.MAIN_COUNT, Spec.INTERACTION_COUNT, 4 * (@as(usize, 1) << Spec.EXPANSION_BITS) };
            pub fn init(a: std.mem.Allocator, row_log: u32, config: core.pcs.PcsConfig, limits: Limits) !*Self {
                try requireGeometry(row_log, config, limits);
                const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
                errdefer if (lease) |owner| owner.destroy();
                const self = try a.create(Self);
                errdefer a.destroy(self);
                self.* = .{ .allocator = a, .budget = lease, .row_log = row_log, .config = config, .limits = limits, .columns = @splat(&.{}), .trees = undefined, .layouts = &.{}, .widths = &.{}, .mask_log = row_log, .lifting_log = try std.math.add(u32, row_log, config.fri_config.log_blowup_factor), .seal = undefined };
                errdefer self.freeStorage();
                var total: usize = 0;
                for (counts) |count| total = try std.math.add(usize, total, count);
                self.layouts = try a.alloc(Layout, total);
                @memset(self.layouts, .current);
                for (counts, &self.columns) |count, *columns| {
                    columns.* = try a.alloc(u32, count);
                    @memset(columns.*, self.lifting_log);
                }
                for (Spec.PREVIOUS_MAIN_MASK, 0..) |needed, column| if (needed) {
                    self.layouts[counts[0] + column] = .current_previous;
                };
                @memset(self.layouts[counts[0] + counts[1] ..][0..counts[2]], .current_previous);
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
            pub fn deepProfile(self: *const Self) Deep.Profile {
                return .{ .trees = &self.trees, .sample_layouts = self.layouts, .lifting_log_size = self.lifting_log, .log_blowup_factor = self.config.fri_config.log_blowup_factor, .query_count = @intCast(self.config.fri_config.n_queries) };
            }
            pub fn friProfile(self: *const Self) Fri.Profile {
                return .{ .lifting_log_size = self.lifting_log, .log_blowup_factor = self.config.fri_config.log_blowup_factor, .log_last_layer_degree_bound = self.config.fri_config.log_last_layer_degree_bound, .fold_widths = self.widths, .query_count = @intCast(self.config.fri_config.n_queries) };
            }
            pub fn identity(self: *const Self) [32]u8 {
                var channel = core.channel.blake3.Channel{};
                channel.mixU32s(&.{ 0x42355753, 1, Spec.FIXED_COUNT, Spec.MAIN_COUNT, Spec.INTERACTION_COUNT, Spec.CONSTRAINT_COUNT, Spec.DEGREE, Spec.EXPANSION_BITS, self.row_log, self.mask_log, self.lifting_log });
                self.config.mixInto(&channel);
                channel.mixRoot(self.deepProfile().identityDigest());
                channel.mixRoot(self.friProfile().identityDigest());
                return channel.digestBytes();
            }
            /// Cold-independent original Spec geometry, not just a self-seal.
            /// All authoritative arrays are checked without scratch allocation.
            pub fn validateAgainst(self: *const Self, row_log: u32, config: core.pcs.PcsConfig) !void {
                try requireGeometry(row_log, config, self.limits);
                if (self.row_log != row_log or self.mask_log != row_log or self.lifting_log != try std.math.add(u32, row_log, config.fri_config.log_blowup_factor) or !std.meta.eql(self.config, config)) return error.UntrustedWordRecursiveShape;
                var cursor: usize = 0;
                for (counts, self.columns, self.trees, 0..) |count, columns, tree, index| {
                    if (columns.len != count or tree.column_log_sizes.ptr != columns.ptr or tree.column_log_sizes.len != count) return error.UntrustedWordRecursiveShape;
                    for (columns, 0..) |log, column| {
                        if (log != self.lifting_log or cursor >= self.layouts.len) return error.UntrustedWordRecursiveShape;
                        const expected: Layout = if (index == 2 or (index == 1 and Spec.PREVIOUS_MAIN_MASK[column])) .current_previous else .current;
                        if (self.layouts[cursor] != expected) return error.UntrustedWordRecursiveShape;
                        cursor += 1;
                    }
                }
                if (cursor != self.layouts.len) return error.UntrustedWordRecursiveShape;
                var remaining = self.lifting_log;
                const terminal = try std.math.add(u32, config.fri_config.log_blowup_factor, config.fri_config.log_last_layer_degree_bound);
                var index: usize = 0;
                while (remaining > terminal) {
                    const step = @min(config.fri_config.fold_step, remaining - terminal);
                    if (index >= self.widths.len or self.widths[index] != @as(u32, 1) << @intCast(step)) return error.UntrustedWordRecursiveShape;
                    remaining -= step;
                    index += 1;
                }
                if (index != self.widths.len or !std.meta.eql(self.seal, self.identity())) return error.UntrustedWordRecursiveShape;
                try self.deepProfile().validate();
                try self.friProfile().validate();
            }
            pub fn sampleCount(self: *const Self) !usize {
                var count: usize = 0;
                for (self.layouts) |layout| count = try std.math.add(usize, count, layout.sampleCount());
                return count;
            }
            pub fn requireCompleteFamilySetup(_: *const Self) error{MissingWordRecursiveTranscriptAndSourcePorts}!void {
                return error.MissingWordRecursiveTranscriptAndSourcePorts;
            }
            fn freeStorage(self: *Self) void {
                for (self.columns) |columns| self.allocator.free(columns);
                self.allocator.free(self.layouts);
                self.allocator.free(self.widths);
            }
            pub fn deinit(self: *Self) void {
                const a = self.allocator;
                const lease = self.budget;
                self.freeStorage();
                a.destroy(self);
                if (lease) |owner| owner.destroy();
            }
        };
        pub fn requireGeometry(row_log: u32, config: core.pcs.PcsConfig, limits: Limits) !void {
            if (row_log == 0 or row_log > @min(limits.max_row_log, 24) or config.fri_config.n_queries == 0 or config.fri_config.n_queries >= core.fields.m31.Modulus or config.fri_config.n_queries > limits.max_queries or config.pow_bits > 256 or config.fri_config.fold_step == 0 or config.fri_config.fold_step > Fri.MAX_FOLD_STEP) return error.InvalidWordRecursiveShape;
            _ = try core.fri.FriConfig.init(config.fri_config.log_last_layer_degree_bound, config.fri_config.log_blowup_factor, config.fri_config.n_queries);
            var total: usize = 0;
            for (Shape.counts) |count| total = try std.math.add(usize, total, count);
            if (total > limits.max_columns or try std.math.add(u32, row_log, config.fri_config.log_blowup_factor) > Deep.MAX_DOMAIN_LOG) return error.WordRecursiveShapeResourceLimit;
        }
    };
}
