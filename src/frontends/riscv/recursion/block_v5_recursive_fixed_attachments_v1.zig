//! Bounded fixed-only child/graph namespace and row attachment ports. These are
//! setup compiler artifacts, not successful child admissions or verifier keys.
//! The caller independently derives every child roster and graph before entry.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const Storage = @import("air/blake3_parent_row_storage.zig");
const Namespace = @import("air/block_v5_recursive_fixed_namespace_v1.zig");
const Projection = @import("air/blake3_row_columns.zig");
const Direct = @import("air/blake3_direct_cohort_columns_v1.zig");
const ScopedBus = @import("block_v5_heterogeneous_scoped_public_bus_v1.zig");
const Session = @import("block_v5_public_supply_session_v2.zig");
const Boundary = @import("air/block_v5_closed_public_supply_v1.zig");
pub const Limits = struct { max_children: usize = 4, max_rows: usize = 1 << 24 };
pub fn ForWire(comptime Wire: type) type {
    return struct {
        const Self = @This();
        allocator: std.mem.Allocator,
        lease: ?*Budget,
        limits: Limits,
        fixed: Storage.FixedTuple(true),
        wires: std.ArrayList(Wire) = .empty,
        next_namespace: u32 = 1,
        child_count: usize = 0,
        main_identifier_rows: usize = 0,
        attachments: std.ArrayList([32]u8) = .empty,
        closure: ?[32]u8 = null,
        finalized: bool = false,
        pub fn init(a: std.mem.Allocator, limits: Limits) !Self {
            if (limits.max_children == 0 or limits.max_children > 4 or limits.max_rows == 0 or limits.max_rows > 1 << 24) return error.InvalidRecursiveFixedAttachmentLimits;
            var self = Self{ .allocator = a, .lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null, .limits = limits, .fixed = undefined };
            inline for (0..Storage.Airs.len) |i| self.fixed[i] = .empty;
            return self;
        }
        pub fn deinit(self: *Self) void {
            const lease = self.lease;
            inline for (0..Storage.Airs.len) |i| self.fixed[i].deinit(self.allocator);
            self.wires.deinit(self.allocator);
            self.attachments.deinit(self.allocator);
            self.* = undefined;
            if (lease) |owner| owner.destroy();
        }
        /// Fixed rows already independently derived by the true child compiler.
        /// Namespace relocation preserves original cohort order, including G
        /// partitions; no descendant supplier schedule is silently discarded.
        pub fn appendChild(self: *Self, fixed: Storage.FixedTuple(false), wires: []const Wire) !void {
            if (self.child_count >= self.limits.max_children) return error.InvalidRecursiveFixedChildCount;
            for (wires) |wire| if (wire.child != self.child_count) return error.InvalidRecursiveFixedChildOrder;
            try self.append(fixed, wires, null, null);
            self.child_count += 1;
        }
        pub fn appendChildWithArithmetic(self: *Self, fixed: Storage.FixedTuple(false), wires: []const Wire, port: Namespace.ArithmeticPort) !void {
            if (self.child_count >= self.limits.max_children) return error.InvalidRecursiveFixedChildCount;
            for (wires) |wire| if (wire.child != self.child_count) return error.InvalidRecursiveFixedChildOrder;
            try self.append(fixed, wires, null, port);
            self.child_count += 1;
        }
        /// Shared original graph ports are appended after genuine children, as
        /// in RAM/PAGE prepare. `graph_identity` must be derived from the exact
        /// original Lower.Reference, not a received graph or claimed flag.
        pub fn appendGraph(self: *Self, fixed: Storage.FixedTuple(false), wires: []const Wire, graph_identity: [32]u8) !void {
            if (self.child_count == 0) return error.InvalidRecursiveFixedChildCount;
            try self.append(fixed, wires, graph_identity, null);
        }
        pub fn appendGraphWithArithmetic(self: *Self, fixed: Storage.FixedTuple(false), wires: []const Wire, graph_identity: [32]u8, port: Namespace.ArithmeticPort) !void {
            if (self.child_count == 0) return error.InvalidRecursiveFixedChildCount;
            try self.append(fixed, wires, graph_identity, port);
        }
        fn append(self: *Self, source: Storage.FixedTuple(false), wires: []const Wire, graph_identity: ?[32]u8, arithmetic: ?Namespace.ArithmeticPort) !void {
            if (self.finalized or self.closure != null) return error.ConsumedRecursiveFixedAttachments;
            var copy: Storage.FixedTuple(false) = undefined;
            inline for (0..Storage.Airs.len) |i| copy[i] = &.{};
            defer inline for (0..Storage.Airs.len) |i| self.allocator.free(copy[i]);
            inline for (Storage.Airs, 0..) |Air, i| {
                const count = try std.math.add(usize, self.fixed[i].items.len, source[i].len);
                if (count > self.limits.max_rows) return error.RecursiveFixedAttachmentResourceLimit;
                _ = try Direct.rowLog(count);
                copy[i] = try self.allocator.dupe(Storage.FixedRow(Air), source[i]);
            }
            var namespace = if (arithmetic) |port| try Namespace.prepareForArithmetic(self.allocator, copy, self.next_namespace, port) else try Namespace.prepare(self.allocator, copy, self.next_namespace);
            defer namespace.deinit();
            if (namespace.original.old.len == 0) return error.InvalidParentJoinNamespace;
            const end = try namespace.end();
            const namespace_id = try namespace.identity();
            const main_rows = try std.math.add(usize, self.main_identifier_rows, namespace.main_identifier_rows);
            const relocated = try self.allocator.dupe(Wire, wires);
            defer self.allocator.free(relocated);
            for (relocated) |*wire| wire.circuit = namespace.original.map(wire.circuit) orelse return error.MissingScopedChildVerifierNamespace;
            try Namespace.apply(&copy, &namespace, namespace_id);
            // Reserve the complete transaction before changing lengths/order.
            inline for (0..Storage.Airs.len) |i| try self.fixed[i].ensureUnusedCapacity(self.allocator, copy[i].len);
            try self.wires.ensureUnusedCapacity(self.allocator, relocated.len);
            try self.attachments.ensureUnusedCapacity(self.allocator, 1);
            var identity = namespace_id;
            if (graph_identity) |graph_id| {
                var channel = core.channel.blake3.Channel{};
                channel.mixRoot(graph_id);
                channel.mixRoot(namespace_id);
                identity = channel.digestBytes();
            }
            inline for (0..Storage.Airs.len) |i| self.fixed[i].appendSliceAssumeCapacity(copy[i]);
            self.wires.appendSliceAssumeCapacity(relocated);
            self.attachments.appendAssumeCapacity(identity);
            self.main_identifier_rows = main_rows;
            self.next_namespace = end;
        }
        /// RAM/PAGE closing recipe: sorted original suppliers -> exact original
        /// boundary.fixed tails + independently guarded streaming-v2 identity.
        /// Does NOT apply to public21's externally supplied PublicBus grammar.
        pub fn closePublicSupply(self: *Self, values: anytype, limits: Session.Limits) ![32]u8 {
            comptime if (Wire != ScopedBus.Wire) @compileError("external public grammar cannot be silently closed");
            if (self.finalized or self.closure != null or self.child_count == 0) return error.ConsumedRecursiveFixedAttachments;
            const sorted = try self.allocator.dupe(Wire, self.wires.items);
            defer self.allocator.free(sorted);
            std.mem.sort(Wire, sorted, {}, less);
            var session = try Session.ForValues(@TypeOf(values)).begin(values, sorted, limits);
            const rows = try self.allocator.alloc(Storage.FixedRow(Storage.Airs[2]), sorted.len);
            defer self.allocator.free(rows);
            for (sorted, rows, 0..) |wire, *row, i| row.* = Storage.compactFixed(Storage.Airs[2], try Boundary.row(wire, try session.at(i)));
            const closure = try session.finish();
            const count = try std.math.add(usize, self.fixed[2].items.len, rows.len);
            if (count > self.limits.max_rows) return error.RecursiveFixedAttachmentResourceLimit;
            _ = try Direct.rowLog(count);
            try self.fixed[2].ensureUnusedCapacity(self.allocator, rows.len);
            self.fixed[2].appendSliceAssumeCapacity(rows);
            self.wires.clearRetainingCapacity();
            self.closure = closure;
            return closure;
        }
        fn less(_: void, left: Wire, right: Wire) bool {
            return if (left.circuit == right.circuit) left.wire < right.wire else left.circuit < right.circuit;
        }
        /// Exact original projectFixed/tablePreprocessed order, once after all
        /// joins. Context/key construction remains owned by the actual family.
        pub fn project(self: *Self) !Projected {
            if (self.finalized or self.child_count == 0) return error.ConsumedRecursiveFixedAttachments;
            var columns: std.ArrayList(Column) = .empty;
            errdefer {
                for (columns.items) |column| self.allocator.free(column.values);
                columns.deinit(self.allocator);
            }
            var logs: [Storage.Airs.len]u32 = undefined;
            inline for (Storage.Airs, 0..) |Air, i| {
                logs[i] = try Direct.rowLog(self.fixed[i].items.len);
                try Projection.projectFixed(Air, self.allocator, self.fixed[i].items, logs[i], &columns);
            }
            for ([_]@import("../air/lookups/tables/schema.zig").Kind{ .bitwise, .range_check_8_8 }) |kind| try Projection.tablePreprocessed(self.allocator, kind, &columns);
            const owned = try columns.toOwnedSlice(self.allocator);
            self.finalized = true;
            return .{ .allocator = self.allocator, .lease = if (self.lease) |owner| owner.retain() else null, .columns = owned, .logs = logs };
        }
        /// Do not turn an incomplete namespace port or externally supplied
        /// grammar into a verified/closed setup by toggling an output flag.
        pub fn requireClosedSetup(self: *const Self) !void {
            if (self.child_count == 0 or self.closure == null) return error.MissingRecursiveFixedPublicClosure;
            if (self.main_identifier_rows != 0) return error.MissingRecursiveFixedMainIdentifierPort;
            return error.MissingRecursiveFixedFamilyAdmission;
        }
    };
}
pub const Projected = struct {
    allocator: std.mem.Allocator,
    lease: ?*Budget,
    columns: []Column,
    logs: [Storage.Airs.len]u32,
    pub fn deinit(self: *Projected) void {
        const lease = self.lease;
        for (self.columns) |column| self.allocator.free(column.values);
        self.allocator.free(self.columns);
        self.* = undefined;
        if (lease) |owner| owner.destroy();
    }
};
pub const Scoped = ForWire(@import("block_v5_heterogeneous_scoped_public_bus_v1.zig").Wire);
