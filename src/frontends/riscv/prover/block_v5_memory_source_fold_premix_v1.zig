//! Bounded actual six-root FOLD PAGE owner. Original fold bits, original
//! packed BLAKE G/XOR mains, exact two table providers and byte captures all
//! precede source challenges. Compact replay regenerates and matches ALL six
//! roots. No sibling files, source receipt, STARK or proof authority here.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const suite = core.proof_suites.Blake3;
const Protocol = @import("block_v5_memory_source_unified_page_protocol_v1.zig");
const Batch = @import("block_v5_memory_source_batch_protocol_v1.zig");
const Fold = @import("block_v5_memory_source_batch_fold_v1.zig");
const Eq = @import("../recursion/air/block_v5_memory_source_batch_equations_v1.zig");
const Blake = @import("block_v5_memory_source_packed_blake_columns_v1.zig");
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Recipe = @import("block_v5_memory_source_blake_semantics_v1.zig").Recipe;
const Store = @import("block_v5_memory_source_fold_operand_store_v1.zig");
const Matrix = Blake.Matrix;
const Register = @import("../recursion/air/blake3_row_columns.zig");
const Tables = @import("../air/lookups/tables/schema.zig");
const Place = @import("../air/block/memory_component_trace.zig");
pub const SOURCE_FIXED_COUNT: usize = 4; // active,kind,height,original ordinal
pub const Limits = struct { protocol: Protocol.Limits = .{}, stored: Store.Limits = .{}, max_page_heap_bytes: usize = 2 << 30 };
pub fn inventoryId(page: Protocol.Page, first_circuit: u32, rows: []const Semantic.FoldRow) ![32]u8 {
    if (rows.len != page.count) return error.InvalidSourceFoldInventory;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-v5/source-FOLD-PAGE-inventory/v1\x00");
    var raw: [24]u8 = undefined;
    std.mem.writeInt(u64, raw[0..8], page.first, .little);
    std.mem.writeInt(u32, raw[8..12], page.index, .little);
    std.mem.writeInt(u32, raw[12..16], page.count, .little);
    std.mem.writeInt(u32, raw[16..20], page.row_log, .little);
    std.mem.writeInt(u32, raw[20..24], first_circuit, .little);
    hash.update(&raw);
    var next: u32 = 0;
    for (rows) |row| {
        try row.descriptor.validate();
        if (row.first_compression != next) return error.InvalidSourceFoldInventory;
        try @import("block_v5_memory_source_blake_semantics_v1.zig").requireRecipes(row.descriptor.kind, row.descriptor.height, row.recipes, row.first_compression, row.compressions);
        std.mem.writeInt(u32, raw[0..4], @intFromEnum(row.descriptor.kind), .little);
        std.mem.writeInt(u32, raw[4..8], row.descriptor.height, .little);
        std.mem.writeInt(u32, raw[8..12], row.first_compression, .little);
        std.mem.writeInt(u32, raw[12..16], row.compressions, .little);
        std.mem.writeInt(u32, raw[16..20], @intCast(row.recipes.len), .little);
        hash.update(raw[0..20]);
        for (row.recipes) |recipe| {
            std.mem.writeInt(u32, raw[0..4], recipe.slot, .little);
            std.mem.writeInt(u32, raw[4..8], recipe.multiplicity, .little);
            std.mem.writeInt(u32, raw[8..12], recipe.default_height orelse std.math.maxInt(u32), .little);
            std.mem.writeInt(u32, raw[12..16], recipe.first_compression, .little);
            std.mem.writeInt(u32, raw[16..20], recipe.compression_count, .little);
            hash.update(raw[0..20]);
        }
        next = try std.math.add(u32, next, row.compressions);
    }
    return hash.finalResult();
}
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Api = @This();
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
        pub const Owner = struct {
            child: std.mem.Allocator,
            budget: engine.host_budget_allocator.HostBudgetAllocator,
            operations: []Fold.Operation = &.{},
            descriptors: []Semantic.FoldRow = &.{},
            recipes: []Recipe = &.{},
            source_fixed: ?Matrix = null,
            source_main: ?Matrix = null,
            cores: ?*Blake.Columns = null,
            table_fixed: std.ArrayList(engine.pcs.ColumnEvaluation) = .empty,
            table_main: [2][]M = .{ &.{}, &.{} },
            fixed: []engine.pcs.ColumnEvaluation = &.{},
            main: []engine.pcs.ColumnEvaluation = &.{},
            scheme: ?Scheme = null,
            pin: ?Protocol.FoldPin = null,
            active_leases: usize = 0,
            snapshot: [32]u8 = @splat(0),
            pub fn allocator(self: *Owner) std.mem.Allocator {
                return self.budget.allocator();
            }
            pub fn deinit(self: *Owner) !void {
                if (self.active_leases != 0) return error.SourceFoldPremixLeaseLive;
                if (self.scheme) |*scheme| for (scheme.trees.items) |tree| if (tree.shared_owner) |shared| {
                    if (shared.references.load(.acquire) != 1) return error.SourceFoldPremixLeaseLive;
                };
                const a = self.allocator();
                if (self.scheme) |*scheme| scheme.deinit(a);
                a.free(self.fixed);
                a.free(self.main);
                for (self.table_main) |values| a.free(values);
                for (self.table_fixed.items) |column| a.free(column.values);
                self.table_fixed.deinit(a);
                if (self.cores) |columns| columns.deinit();
                if (self.source_main) |*matrix| matrix.deinit();
                if (self.source_fixed) |*matrix| matrix.deinit();
                a.free(self.recipes);
                a.free(self.descriptors);
                a.free(self.operations);
                if (self.budget.live_bytes != 0) @panic("source FOLD premix budget owner leak");
                self.child.destroy(self);
            }
            fn columnSnapshot(self: *const Owner) [32]u8 {
                var hash = std.crypto.hash.sha2.Sha256.init(.{});
                const groups = [_][]const engine.pcs.ColumnEvaluation{
                    self.source_fixed.?.columns,          self.source_main.?.columns,          self.fixed, self.main,
                    self.cores.?.capture_fixed.?.columns, self.cores.?.capture_main.?.columns,
                };
                var bytes: [4]u8 = undefined;
                for (groups) |columns| for (columns) |column| {
                    std.mem.writeInt(u32, &bytes, column.log_size, .little);
                    hash.update(&bytes);
                    for (column.values) |value| {
                        std.mem.writeInt(u32, &bytes, value.toU32(), .little);
                        hash.update(&bytes);
                    }
                };
                return hash.finalResult();
            }
            pub fn require(self: *Owner, admitted: *const Batch.Admission, plan: Protocol.FoldPlan, expected: Protocol.FoldPin, limits: Limits) !void {
                try expected.require(admitted, plan, limits.protocol);
                if (self.pin == null or self.scheme == null or self.source_main == null or self.source_fixed == null or self.cores == null or
                    !std.meta.eql(self.pin.?, expected) or !std.meta.eql(self.cores.?.geometry, expected.geometry) or
                    !std.meta.eql(try inventoryId(expected.page, expected.geometry.first_circuit, self.descriptors), expected.inventory_id) or
                    !std.meta.eql(self.snapshot, self.columnSnapshot())) return error.ChangedSourceFoldPremix;
                var roots = try self.scheme.?.roots(self.allocator());
                defer roots.deinit(self.allocator());
                if (roots.items.len != Protocol.PREMIX_TREES or !std.meta.eql(roots.items[0..Protocol.PREMIX_TREES].*, expected.roots)) return error.ChangedSourceFoldPremix;
            }
            pub fn semanticReader(self: *Owner) Semantic.Reader {
                return .{ .context = self, .read = read };
            }
            fn read(context: *anyopaque, group: Semantic.Group, logical: u32, column: u32) !M {
                const self: *Owner = @ptrCast(@alignCast(context));
                const matrix = switch (group) {
                    .source => &self.source_main.?,
                    .capture => &self.cores.?.capture_main.?,
                };
                if (column >= matrix.columns.len or logical >= matrix.columns[column].values.len) return error.InvalidSourcePageCell;
                return matrix.columns[column].values[Place.committedRow(logical, matrix.columns[column].log_size)];
            }
        };
        pub fn collect(a: std.mem.Allocator, admitted: *const Batch.Admission, plan: Protocol.FoldPlan, page_index: u32, operations: []const Fold.Operation, first_circuit: u32, setup: *const Blake.Setup, limits: Limits) !*Owner {
            try plan.require(admitted, limits.protocol);
            const page = try plan.page(page_index);
            if (operations.len != page.count or limits.max_page_heap_bytes == 0 or page.count > limits.protocol.fold_cores.max_operations)
                return error.SourceFoldPremixResourceLimit;
            const owner = try a.create(Owner);
            owner.* = .{ .child = a, .budget = .init(a, limits.max_page_heap_bytes) };
            errdefer owner.deinit() catch @panic("source FOLD rollback lease invariant");
            const bounded = owner.allocator();
            owner.operations = try bounded.dupe(Fold.Operation, operations);
            owner.source_fixed = try Matrix.init(bounded, SOURCE_FIXED_COUNT, page.row_log);
            owner.source_main = try Matrix.init(bounded, Eq.BIT_COUNT, page.row_log);
            for (operations, 0..) |operation, logical| {
                if (operation.ordinal != page.first + logical or operation.ordinal >= core.fields.m31.Modulus) return error.InvalidSourceFoldOperandOrder;
                const fixed = [_]M{ M.one(), M.fromCanonical(@intFromEnum(operation.kind)), M.fromCanonical(operation.coordinate.height), M.fromCanonical(@intCast(operation.ordinal)) };
                try owner.source_fixed.?.put(logical, &fixed);
                var bits: [Eq.BIT_COUNT]Q = undefined;
                var values: [Eq.BIT_COUNT]M = undefined;
                try Eq.writeInputs(operation, &bits);
                for (&values, bits) |*value, bit| value.* = bit.toM31Array()[0];
                try owner.source_main.?.put(logical, &values);
            }
            owner.cores = try Blake.Columns.regenerateWithSetup(bounded, operations, first_circuit, limits.protocol.fold_cores, setup);
            const cores = owner.cores.?;
            owner.recipes = try bounded.alloc(Recipe, cores.geometry.frames);
            owner.descriptors = try bounded.alloc(Semantic.FoldRow, operations.len);
            var frame: usize = 0;
            var compression: u32 = 0;
            for (owner.descriptors, operations, 0..) |*row, operation, logical| {
                const start = frame;
                const first = compression;
                while (frame < cores.frames.len and cores.frames[frame].operation == logical) : (frame += 1) {
                    owner.recipes[frame] = Recipe.fromCapture(cores.frames[frame]);
                    compression = try std.math.add(u32, compression, cores.frames[frame].compression_count);
                }
                row.* = .{ .descriptor = .{ .kind = operation.kind, .height = operation.coordinate.height }, .recipes = owner.recipes[start..frame], .first_compression = first, .compressions = compression - first };
            }
            if (frame != cores.frames.len or compression != cores.geometry.compressions) return error.InvalidSourceFoldInventory;
            for ([_]Tables.Kind{ .bitwise, .range_check_8_8 }, 0..) |kind, i| {
                try Register.tablePreprocessed(bounded, kind, &owner.table_fixed);
                owner.table_main[i] = try bounded.dupe(M, cores.counters[i].values);
            }
            owner.fixed = try bounded.alloc(engine.pcs.ColumnEvaluation, cores.fixed.items.len + owner.table_fixed.items.len);
            @memcpy(owner.fixed[0..cores.fixed.items.len], cores.fixed.items);
            @memcpy(owner.fixed[cores.fixed.items.len..], owner.table_fixed.items);
            owner.main = try bounded.alloc(engine.pcs.ColumnEvaluation, cores.main.len + 2);
            @memcpy(owner.main[0..cores.main.len], cores.main);
            for ([_]Tables.Kind{ .bitwise, .range_check_8_8 }, 0..) |kind, i| owner.main[cores.main.len + i] = .{ .log_size = Tables.logSize(kind), .values = owner.table_main[i] };
            var pin = Protocol.FoldPin{ .page = page, .plan_id = plan.identity, .inventory_id = try inventoryId(page, first_circuit, owner.descriptors), .geometry = cores.geometry, .roots = @splat(@splat(0)) };
            var channel = Protocol.foldFirstChannel(plan, pin);
            var scheme = try Scheme.init(bounded, plan.config);
            errdefer scheme.deinit(bounded);
            scheme.setCoefficientRetentionPolicy(.never);
            const groups = [_][]const engine.pcs.ColumnEvaluation{
                owner.source_fixed.?.columns,  owner.source_main.?.columns,  owner.fixed, owner.main,
                cores.capture_fixed.?.columns, cores.capture_main.?.columns,
            };
            for (groups) |columns| try scheme.commitBorrowedStreaming(bounded, columns, 16, &channel);
            var roots = try scheme.roots(bounded);
            defer roots.deinit(bounded);
            if (roots.items.len != Protocol.PREMIX_TREES) return error.InvalidSourceFoldPremixRoots;
            pin.roots = roots.items[0..Protocol.PREMIX_TREES].*;
            try pin.require(admitted, plan, limits.protocol);
            owner.pin = pin;
            owner.snapshot = owner.columnSnapshot();
            owner.scheme = scheme;
            return owner;
        }
        pub fn persist(dir: std.fs.Dir, name: []const u8, owner: *Owner, admitted: *const Batch.Admission, plan: Protocol.FoldPlan, expected: Protocol.FoldPin, limits: Limits) !Store.Pin {
            try owner.require(admitted, plan, expected, limits);
            return Store.publish(owner.allocator(), dir, name, expected.page, plan.identity, try expected.identity(admitted, plan, limits.protocol), owner.operations, limits.stored);
        }
        pub fn replay(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, admitted: *const Batch.Admission, plan: Protocol.FoldPlan, expected: Protocol.FoldPin, stored: Store.Pin, setup: *const Blake.Setup, limits: Limits) !*Owner {
            try expected.require(admitted, plan, limits.protocol);
            var loaded = try Store.load(a, dir, name, expected.page, plan.identity, try expected.identity(admitted, plan, limits.protocol), stored, limits.stored);
            defer loaded.deinit();
            const owner = try Api.collect(a, admitted, plan, expected.page.index, loaded.operations, expected.geometry.first_circuit, setup, limits);
            errdefer owner.deinit() catch @panic("source FOLD replay rollback lease invariant");
            try owner.require(admitted, plan, expected, limits);
            return owner;
        }
        pub const Lease = struct {
            owner: *Owner,
            scheme: Scheme,
            owns_scheme: bool = true,
            pub fn takeScheme(self: *Lease) !Scheme {
                if (!self.owns_scheme) return error.InvalidSourceFoldPremixLease;
                self.owns_scheme = false;
                return self.scheme;
            }
            pub fn deinit(self: *Lease) void {
                if (self.owns_scheme) self.scheme.deinit(self.owner.allocator());
                std.debug.assert(self.owner.active_leases != 0);
                self.owner.active_leases -= 1;
                self.* = undefined;
            }
        };
        pub fn lease(owner: *Owner, admitted: *const Batch.Admission, plan: Protocol.FoldPlan, expected: Protocol.FoldPin, limits: Limits, channel: *suite.Channel) !Lease {
            try owner.require(admitted, plan, expected, limits);
            if (owner.active_leases == std.math.maxInt(usize)) return error.SourceFoldPremixResourceLimit;
            const a = owner.allocator();
            var scheme = try Scheme.init(a, plan.config);
            errdefer scheme.deinit(a);
            scheme.setCoefficientRetentionPolicy(.never);
            channel.* = Protocol.foldFirstChannel(plan, expected);
            for (owner.scheme.?.trees.items) |*tree| {
                try tree.share(a);
                var retained = tree.retainShared();
                var owns = true;
                defer if (owns) retained.deinit(a);
                try scheme.appendCommittedTree(a, retained, channel);
                owns = false;
            }
            owner.active_leases += 1;
            return .{ .owner = owner, .scheme = scheme };
        }
    };
}
