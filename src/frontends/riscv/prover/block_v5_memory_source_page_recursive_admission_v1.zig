//! Independently selected original PAGE admission. Context, authenticated fold
//! descriptors and immutable setups must outlive every borrowed Prepared.
//! Proposed claim/root values choose no source roster, fixed recipe or epoch.
const std = @import("std");
const core = @import("stwo_core");
const Page = @import("block_v5_memory_source_unified_page_proof_v1.zig");
const Protocol = @import("block_v5_memory_source_unified_page_protocol_v1.zig");
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Components = @import("block_v5_memory_source_unified_page_components_v1.zig");
const Frame = @import("block_v5_memory_source_page_capture_frame_v1.zig");
const Universal = @import("../recursion/air/universal_challenges.zig");
pub const VERSION: u32 = 1;
pub const Limits = struct { page: Page.Limits = .{}, max_capture_bytes: usize = 512 << 20, max_preparation_bytes: usize = 4 << 30, max_public_wires: usize = 1 << 20 };
pub fn ForKind(comptime kind: Semantic.Kind) type {
    const Original = Page.ForKind(kind);
    const C = Components.ForKind(kind);
    return struct {
        pub const Recipe = struct {
            a: std.mem.Allocator,
            admitted: Original.Admission,
            owner: *C.Owner,
            geometry: C.Geometry,
            pub fn deinit(self: *Recipe) void {
                self.owner.deinit();
                self.admitted.deinit();
                self.a.destroy(self);
            }
        };
        pub const Prepared = struct {
            allocator: std.mem.Allocator,
            context: *const Page.Context,
            pin: Original.Pin,
            fold_rows: []const Semantic.FoldRow,
            core_setup: *const C.CoreColumns.Setup,
            arithmetic_setup: *const Components.ArithmeticSetup,
            config: core.pcs.PcsConfig,
            template_id: [32]u8,
            limits: Limits,
            pub fn init(a: std.mem.Allocator, context: *const Page.Context, pin: Original.Pin, fold_rows: []const Semantic.FoldRow, core_setup: *const C.CoreColumns.Setup, arithmetic_setup: *const Components.ArithmeticSetup, limits: Limits) !Prepared {
                if (limits.max_capture_bytes == 0 or limits.max_preparation_bytes == 0 or limits.page.max_receiver_heap_bytes == 0 or limits.max_public_wires == 0) return error.SourcePageRecursiveResourceLimit;
                var self = Prepared{ .allocator = a, .context = context, .pin = pin, .fold_rows = fold_rows, .core_setup = core_setup, .arithmetic_setup = arithmetic_setup, .config = context.fold_plan.config, .template_id = undefined, .limits = limits };
                self.template_id = try self.identity();
                try self.validate(self.template_id);
                return self;
            }
            pub fn identity(self: *const Prepared) ![32]u8 {
                try self.context.require(self.allocator, self.limits.page);
                const original = try Original.identity(self.context, self.pin, self.limits.page);
                var channel = core.proof_suites.Blake3.Channel{};
                channel.mixU32s(&.{ 0x50474b31, VERSION, @intFromEnum(kind), Frame.TRACE_TREES, Frame.COMMITMENTS }); // PGK1
                channel.mixRoot(Original.abiId());
                channel.mixRoot(original);
                channel.mixRoot(self.context.admitted.identity);
                channel.mixRoot(self.context.sealed.digest);
                channel.mixRoot(self.context.epoch.after_draw_digest);
                self.config.mixInto(&channel);
                return channel.digestBytes();
            }
            pub fn validate(self: *const Prepared, expected: [32]u8) !void {
                if (self.limits.max_capture_bytes == 0 or self.limits.max_preparation_bytes == 0 or self.limits.page.max_receiver_heap_bytes == 0 or self.limits.max_public_wires == 0) return error.SourcePageRecursiveResourceLimit;
                if (!std.meta.eql(self.config, self.context.fold_plan.config) or !std.meta.eql(self.template_id, expected) or !std.meta.eql(expected, try self.identity()) or
                    (kind == .raw and self.fold_rows.len != 0) or (kind == .fold and self.fold_rows.len != self.pin.page.count)) return error.UntrustedSourcePageRecursiveAdmission;
                const position = if (kind == .raw) self.pin.raw.page.index else self.pin.page.index;
                const roster = if (kind == .raw) self.context.raw else self.context.fold;
                if (position >= roster.len or !std.meta.eql(roster[position], self.pin)) return error.UntrustedSourcePageRecursiveAdmission;
                if (kind == .raw) try self.pin.require(&self.context.admitted.source, self.context.raw_plan, self.limits.page.raw) else try self.pin.require(&self.context.admitted, self.context.fold_plan, self.limits.page.protocol);
            }
            /// Rebuild the original public graph, exact routing, fixed columns,
            /// all child components and separate local closures. No captured
            /// frame selects geometry or authenticates its own checksum.
            pub fn reconstruct(self: *const Prepared, a: std.mem.Allocator, frame: *const Frame.ForKind(kind), relations: Universal.UniversalRelations) !*Recipe {
                try self.validate(self.template_id);
                const result = try a.create(Recipe);
                errdefer a.destroy(result);
                result.a = a;
                result.admitted = try Original.Admission.init(a, self.context, self.pin, self.fold_rows, frame.semantic.claims, self.limits.page);
                errdefer result.admitted.deinit();
                const source_log = if (kind == .raw) self.pin.raw.page.row_log else self.pin.page.row_log;
                const capture_log = if (kind == .raw) self.pin.geometry.connector_log else self.pin.geometry.capture_log;
                result.geometry = .{ .source_log = source_log, .capture_log = capture_log, .core_logs = self.pin.geometry.logs, .arithmetic_logs = result.admitted.fixed.arithmetic.logs, .capture_requests = @as(u64, self.pin.geometry.compressions) * if (kind == .raw) 32 else @import("block_v5_memory_source_blake_capture_air_v1.zig").requestMass() };
                const graph = result.admitted.graph;
                const independent = Protocol.SemanticPin{ .premix_identity = try Original.identity(self.context, self.pin, self.limits.page), .source_epoch = self.context.epoch.seal_digest, .graph_identity = graph.identity, .circuit_id = graph.circuit_id, .input_requests = graph.input_requests, .claims = frame.semantic.claims, .roots = frame.semantic.roots };
                if (!std.meta.eql(independent, frame.semantic)) return error.UntrustedSourcePageRecursiveAdmission;
                for (independent.roots) |root| if (std.mem.allEqual(u8, &root, 0)) return error.UntrustedSourcePageRecursiveAdmission;
                if (kind == .raw) {
                    try @import("block_v5_memory_source_packed_sha_proof_v1.zig").verifyFixedRoots(a, &self.context.admitted.source, self.context.raw_plan, self.pin, .{ .operands = self.limits.page.raw, .max_interaction_cells = self.limits.page.interaction.max_cells });
                } else {
                    var fixed = try @import("block_v5_memory_source_fold_fixed_columns_v1.zig").Columns.init(a, self.pin, self.fold_rows, self.limits.page.protocol.fold_cores);
                    defer fixed.deinit();
                    const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
                    const groups = [_][]const Column{ fixed.source.columns, fixed.core.items, fixed.capture.columns };
                    try Page.requireFixedRoots(a, self.config, &groups, &.{ self.pin.roots[0], self.pin.roots[2], self.pin.roots[4] });
                }
                try Page.requireFixedRoots(a, self.config, &.{result.admitted.fixed.columns}, &.{frame.semantic.roots[0]});
                result.owner = try C.Owner.init(a, graph, &result.admitted.fixed.plan, &result.admitted.fixed.arithmetic, &result.admitted.fixed.source_inputs, &result.admitted.fixed.capture_inputs, result.geometry, relations, frame.claims, self.core_setup, self.arithmetic_setup, self.limits.page.composition);
                errdefer result.owner.deinit();
                try frame.require(result.geometry, independent, result.owner);
                return result;
            }
        };
    };
}
