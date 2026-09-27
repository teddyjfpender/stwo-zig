//! Actual bottom PAGE static compiler source, both original raw/fold families.
//! The public semantic graph is independently reconstructed by Page.Admission;
//! compiler views retain authenticated setups, never fake Owner/Frame/captures.
//! Exact mask-union and recorder facades remain REQUIRED before full setup.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Page = @import("../prover/block_v5_memory_source_unified_page_proof_v1.zig");
const Admission = @import("../prover/block_v5_memory_source_page_recursive_admission_v1.zig");
const Semantic = @import("../prover/block_v5_memory_source_page_semantic_columns_v1.zig");
const Components = @import("../prover/block_v5_memory_source_unified_page_components_v1.zig");
const Canonical = @import("../prover/block_v5_memory_source_page_canonical_component_v1.zig");
const ArithAirs = @import("air/arithmetic_fusion_fixed_columns_v1.zig").Airs;
const Tables = @import("../air/lookups/tables/schema.zig");
const TableInteraction = @import("../air/lookups/tables/interaction.zig");
const Compiler = @import("air/block_v5_static_component_compiler_v1.zig");
pub const Limits = struct { max_columns: usize = 1 << 16 };
pub fn ForKind(comptime kind: Semantic.Kind) type {
    // The canonical CPU driver instantiates the complete raw/fold static AIR
    // compiler together. This quota affects type expansion only, not rows or
    // any protocol parameter.
    @setEvalBranchQuota(200_000);
    const C = Components.ForKind(kind);
    const Original = Page.ForKind(kind);
    const Admitted = Admission.ForKind(kind).Prepared;
    const CoreCompiler = Compiler.ForAirs(C.CoreAirs);
    const ArithmeticCompiler = Compiler.ForAirs(ArithAirs);
    const CoreParameters = [C.CoreAirs.len][0]core.fields.m31.M31;
    return struct {
        pub const Geometry = C.Geometry;
        pub const CompilerView = struct { cores: *const CoreCompiler, arithmetic: *const ArithmeticCompiler };
        pub const GeometryView = struct { geometry: Geometry, constraint_count: usize, constraint_log: u32, split: u32 };
        pub const Owned = struct {
            const Self = @This();
            allocator: std.mem.Allocator,
            budget: ?*Budget,
            template_id: [32]u8,
            public_claims: Semantic.Claims,
            original: Original.Admission,
            geometry: Geometry,
            logs: [9][]u32,
            cores: *CoreCompiler,
            arithmetic: *ArithmeticCompiler,
            limits: Limits,
            pub const fixed_setup_only = true;
            pub const native_trace_trees = 9;
            pub const complete_family_setup = false;
            /// `public_claims` MUST be independently supplied expected public
            /// policy, not extracted from a received proof to choose a key.
            /// Original.Admission is public graph/fixed construction only;
            /// its construction is not a successful verifier operation.
            pub fn derive(a: std.mem.Allocator, admitted: *const Admitted, expected: [32]u8, public_claims: Semantic.Claims, limits: Limits) !*Self {
                try admitted.validate(expected);
                const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
                errdefer if (lease) |owner| owner.destroy();
                const self = try a.create(Self);
                errdefer a.destroy(self);
                var original = try Original.Admission.init(a, admitted.context, admitted.pin, admitted.fold_rows, public_claims, admitted.limits.page);
                errdefer original.deinit();
                const geometry: Geometry = .{
                    .source_log = if (kind == .raw) admitted.pin.raw.page.row_log else admitted.pin.page.row_log,
                    .capture_log = if (kind == .raw) admitted.pin.geometry.connector_log else admitted.pin.geometry.capture_log,
                    .core_logs = admitted.pin.geometry.logs,
                    .arithmetic_logs = original.fixed.arithmetic.logs,
                    .capture_requests = try std.math.mul(u64, admitted.pin.geometry.compressions, if (kind == .raw) 32 else @import("../prover/block_v5_memory_source_blake_capture_air_v1.zig").requestMass()),
                };
                const logs = try deriveLogs(a, geometry, limits);
                errdefer for (logs) |columns| a.free(columns);
                const cores = try CoreCompiler.init(a, admitted.core_setup, geometry.core_logs, @as(CoreParameters, @splat(.{})));
                errdefer cores.deinit();
                const arithmetic = try ArithmeticCompiler.init(a, admitted.arithmetic_setup, geometry.arithmetic_logs, Components.ARITHMETIC_PARAMETERS);
                errdefer arithmetic.deinit();
                try admitted.validate(expected);
                self.* = .{ .allocator = a, .budget = lease, .template_id = expected, .public_claims = public_claims, .original = original, .geometry = geometry, .logs = logs, .cores = cores, .arithmetic = arithmetic, .limits = limits };
                return self;
            }
            pub fn logViews(self: *const Self) [9][]const u32 {
                var views: [9][]const u32 = undefined;
                for (&views, self.logs) |*view, logs| view.* = logs;
                return views;
            }
            pub fn compilerView(self: *const Self) CompilerView {
                return .{ .cores = self.cores, .arithmetic = self.arithmetic };
            }
            pub fn geometryView(self: *const Self) !GeometryView {
                try requireGeometry(self.geometry, self.limits);
                var maximum = @max(self.geometry.source_log, self.geometry.capture_log);
                for (self.geometry.core_logs ++ self.geometry.arithmetic_logs) |log| maximum = @max(maximum, log);
                for ([_]Tables.Kind{ .bitwise, .range_check_8_8 }) |table_kind| maximum = @max(maximum, Tables.logSize(table_kind));
                var count: usize = 2; // Original two table equations.
                inline for (C.CoreAirs ++ ArithAirs) |Air| count = try std.math.add(usize, count, Air.DIRECT_CONSTRAINT_COUNT + Air.INTERACTION_BATCH_COUNT);
                const capture_count = if (kind == .raw) @import("../prover/block_v5_memory_source_sha_connector_air_v1.zig").CONSTRAINT_COUNT else @import("../prover/block_v5_memory_source_blake_capture_air_v1.zig").CONSTRAINT_COUNT;
                count = try std.math.add(usize, count, capture_count + Canonical.ForKind(kind).CONSTRAINT_COUNT + C.SourceInput.CONSTRAINT_COUNT + C.CaptureInput.CONSTRAINT_COUNT);
                return .{ .geometry = self.geometry, .constraint_count = count, .constraint_log = try std.math.add(u32, maximum, C.SPLIT), .split = C.SPLIT };
            }
            pub fn validateAgainst(self: *const Self, admitted: *const Admitted, expected: [32]u8, public_claims: Semantic.Claims) !void {
                try admitted.validate(expected);
                if (!std.meta.eql(self.template_id, expected) or !std.meta.eql(self.public_claims, public_claims)) return error.UntrustedSourcePageShapePolicy;
                // Reconstruct the actual public graph/arithmetic plan; self-
                // identity cannot turn mutated geometry into independent setup.
                var independent = try Original.Admission.init(self.allocator, admitted.context, admitted.pin, admitted.fold_rows, public_claims, admitted.limits.page);
                defer independent.deinit();
                const expected_geometry: Geometry = .{ .source_log = if (kind == .raw) admitted.pin.raw.page.row_log else admitted.pin.page.row_log, .capture_log = if (kind == .raw) admitted.pin.geometry.connector_log else admitted.pin.geometry.capture_log, .core_logs = admitted.pin.geometry.logs, .arithmetic_logs = independent.fixed.arithmetic.logs, .capture_requests = try std.math.mul(u64, admitted.pin.geometry.compressions, if (kind == .raw) 32 else @import("../prover/block_v5_memory_source_blake_capture_air_v1.zig").requestMass()) };
                if (!std.meta.eql(self.geometry, expected_geometry) or !std.meta.eql(self.original.graph.identity, independent.graph.identity) or !std.meta.eql(self.original.fixed.plan.authority_digest, independent.fixed.plan.authority_digest)) return error.UntrustedSourcePageShapePolicy;
                try validateLogs(self.logViews(), expected_geometry, self.limits);
                try self.cores.validateAgainst(admitted.core_setup, expected_geometry.core_logs, @as(CoreParameters, @splat(.{})));
                try self.arithmetic.validateAgainst(admitted.arithmetic_setup, expected_geometry.arithmetic_logs, Components.ARITHMETIC_PARAMETERS);
                try admitted.validate(expected);
            }
            pub fn requireComplete(_: *const Self) error{MissingPageRecursiveTranscriptPathsSourcesAndContext}!void {
                return error.MissingPageRecursiveTranscriptPathsSourcesAndContext;
            }
            pub fn deinit(self: *Self) void {
                const a = self.allocator;
                const lease = self.budget;
                self.arithmetic.deinit();
                self.cores.deinit();
                for (self.logs) |logs| a.free(logs);
                self.original.deinit();
                a.destroy(self);
                if (lease) |owner| owner.destroy();
            }
        };
        pub const counts = [9]usize{ C.SOURCE_FIXED, C.SOURCE_MAIN, C.CORE_FIXED, C.CORE_MAIN, C.CAPTURE_FIXED, C.CAPTURE_MAIN, C.ARITHMETIC_FIXED_OFFSET + C.ARITHMETIC_FIXED, C.ARITHMETIC_MAIN, C.ARITHMETIC_INTERACTION_OFFSET + C.ARITHMETIC_INTERACTION };
        pub fn requireGeometry(geometry: Geometry, limits: Limits) !void {
            if (geometry.source_log < 1 or geometry.source_log > 12 or geometry.capture_log < 1 or geometry.capture_log > 14 or (kind == .raw and geometry.source_log != geometry.capture_log) or geometry.capture_requests >= core.fields.m31.Modulus) return error.InvalidSourcePageShapeGeometry;
            for (geometry.core_logs ++ geometry.arithmetic_logs) |log| if (log < 1 or log > 24) return error.InvalidSourcePageShapeGeometry;
            var count: usize = 0;
            for (counts) |width| count = try std.math.add(usize, count, width);
            if (count > limits.max_columns) return error.SourcePageShapeResourceLimit;
        }
        /// Original nine-tree column order; no parent geometry is involved.
        /// A separate original-mask port is mandatory before building PCS.
        pub fn deriveLogs(a: std.mem.Allocator, geometry: Geometry, limits: Limits) ![9][]u32 {
            try requireGeometry(geometry, limits);
            var logs: [9][]u32 = @splat(&.{});
            errdefer for (logs) |columns| a.free(columns);
            for (counts, &logs) |count, *columns| columns.* = try a.alloc(u32, count);
            try fillLogs(logs, geometry);
            return logs;
        }
        pub fn validateLogs(logs: [9][]const u32, geometry: Geometry, limits: Limits) !void {
            try requireGeometry(geometry, limits);
            for (counts, logs, 0..) |count, columns, tree| if (columns.len != count) {
                _ = tree;
                return error.UntrustedSourcePageShapeLogs;
            };
            var cursors: [9]usize = @splat(0);
            try walkLogs(logs, geometry, &cursors, false);
            for (counts, cursors) |count, cursor| if (count != cursor) return error.UntrustedSourcePageShapeLogs;
        }
        fn fillLogs(logs: [9][]u32, geometry: Geometry) !void {
            var cursors: [9]usize = @splat(0);
            try walkLogs(logs, geometry, &cursors, true);
            for (counts, cursors) |count, cursor| if (count != cursor) return error.InvalidSourcePageShapeLogs;
        }
        fn walkLogs(logs: anytype, geometry: Geometry, cursors: *[9]usize, comptime write: bool) !void {
            try run(logs, cursors, 0, C.SOURCE_FIXED, geometry.source_log, write);
            try run(logs, cursors, 1, C.SOURCE_MAIN, geometry.source_log, write);
            inline for (C.CoreAirs, 0..) |Air, index| {
                try run(logs, cursors, 2, Air.PREPROCESSED_COLUMN_COUNT, geometry.core_logs[index], write);
                try run(logs, cursors, 3, Air.PHYSICAL_MAIN_COLUMN_COUNT, geometry.core_logs[index], write);
                try run(logs, cursors, 8, Air.INTERACTION_COLUMN_COUNT, geometry.core_logs[index], write);
            }
            for ([_]Tables.Kind{ .bitwise, .range_check_8_8 }) |table_kind| {
                try run(logs, cursors, 2, Tables.arity(table_kind) + 1, Tables.logSize(table_kind), write);
                try run(logs, cursors, 3, 1, Tables.logSize(table_kind), write);
                try run(logs, cursors, 8, TableInteraction.N_COLUMNS, Tables.logSize(table_kind), write);
            }
            try run(logs, cursors, 4, C.CAPTURE_FIXED, geometry.capture_log, write);
            try run(logs, cursors, 5, C.CAPTURE_MAIN, geometry.capture_log, write);
            try run(logs, cursors, 6, Canonical.CANONICAL_FIXED_COUNT + C.SourceInput.FIXED_COUNT, geometry.source_log, write);
            try run(logs, cursors, 6, C.CaptureInput.FIXED_COUNT, geometry.capture_log, write);
            try run(logs, cursors, 8, C.CAPTURE_INTERACTION, geometry.capture_log, write);
            try run(logs, cursors, 8, C.SourceInput.INTERACTION_COUNT, geometry.source_log, write);
            try run(logs, cursors, 8, C.CaptureInput.INTERACTION_COUNT, geometry.capture_log, write);
            inline for (ArithAirs, 0..) |Air, index| {
                try run(logs, cursors, 6, Air.PREPROCESSED_COLUMN_COUNT, geometry.arithmetic_logs[index], write);
                try run(logs, cursors, 7, Air.PHYSICAL_MAIN_COLUMN_COUNT, geometry.arithmetic_logs[index], write);
                try run(logs, cursors, 8, Air.INTERACTION_COLUMN_COUNT, geometry.arithmetic_logs[index], write);
            }
        }
    };
}
fn run(logs: anytype, cursors: *[9]usize, tree: usize, count: usize, log: u32, comptime write: bool) !void {
    const end = try std.math.add(usize, cursors[tree], count);
    if (end > logs[tree].len) return error.UntrustedSourcePageShapeLogs;
    const columns = logs[tree][cursors[tree]..end];
    if (write) {
        @memset(columns, log);
    } else {
        for (columns) |actual| if (actual != log) return error.UntrustedSourcePageShapeLogs;
    }
    cursors[tree] = end;
}
