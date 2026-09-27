//! Page-local original packed BLAKE3 columns and byte captures. Only bounded
//! fold operands are supplied; these matrices are regenerated, never persisted.
//! This owner conveys no source, hash, PCS or verification authority.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Column = engine.pcs.ColumnEvaluation;
const Budget = engine.host_budget_allocator.SharedHostBudget;
const Fold = @import("block_v5_memory_source_batch_fold_v1.zig");
const Hash = @import("block_v5_memory_source_packed_hash_v1.zig");
const Defaults = @import("block_v5_memory_source_batch_defaults_v1.zig");
const G = @import("../recursion/air/blake3_g_call.zig");
const Xor = @import("../recursion/air/blake3_xor_call.zig");
const Topology = @import("../recursion/air/blake3_compression_plan.zig");
const Binding = @import("../recursion/air/universal_relation_binding.zig");
const Direct = @import("../recursion/air/blake3_direct_cohort_columns_v1.zig");
const Project = @import("../recursion/air/blake3_row_columns.zig");
const Storage = @import("../recursion/air/blake3_parent_row_storage.zig");
const Tables = @import("../air/lookups/tables/schema.zig");
const Counter = @import("../air/lookups/tables/counter.zig").Counter;
pub const Matrix = @import("block_v5_memory_source_packed_sha_columns_v1.zig").Matrix;
pub const Airs = .{ G, Xor };
pub const Setup = @import("block_v5_packed_hash_setup_v1.zig").ForAirs(Airs);
const Owners = std.meta.Tuple(&.{ Direct.ForAir(G), Direct.ForAir(Xor) });
const Definitions = std.meta.Tuple(&.{ G.Definition, Xor.Definition });
const Plans = std.meta.Tuple(&.{ Binding.Binding(G).Plan, Binding.Binding(Xor).Plan });
pub const CAPTURE_MAIN_COUNT = 192; // 32 initial +16 output words, each four bytes.
pub const CAPTURE_FIXED_COUNT = 6; // active/circuit/local operation/recipe/block/uses.
pub const Limits = struct {
    max_operations: usize = 4096,
    max_compressions: u32 = 8192,
    max_cells: usize = 1 << 28,
    max_capture_metadata_bytes: usize = 16 << 20,
};
fn rowLog(count: usize) u32 {
    return if (count <= 1) 1 else std.math.log2_int_ceil(usize, count);
}
pub const Geometry = struct {
    operations: u32,
    first_ordinal: u64,
    first_circuit: u32,
    compressions: u32,
    frames: u32,
    logs: [2]u32,
    capture_log: u32,
    cells: usize,
    /// Geometry is a proposal derived from original fold operands. The real
    /// source receiver must prove the fold/recipe/count and fixed-root links.
    pub fn fromOperations(operations: []const Fold.Operation, first_circuit: u32, limits: Limits) !Geometry {
        if (limits.max_operations == 0 or limits.max_cells == 0 or limits.max_capture_metadata_bytes == 0 or
            operations.len > limits.max_operations or operations.len > std.math.maxInt(u32))
            return error.SourcePackedBlakeResourceLimit;
        const first: u64 = if (operations.len == 0) 0 else operations[0].ordinal;
        var compressions: u32 = 0;
        var frames: u32 = 0;
        for (operations, 0..) |operation, index| {
            if (operation.ordinal != try std.math.add(u64, first, index)) return error.InvalidSourcePackedBlakeOrder;
            const recipes = try Hash.recipes(operation);
            compressions = try std.math.add(u32, compressions, recipes.compressionCount());
            frames = try std.math.add(u32, frames, @intCast(recipes.count));
        }
        if (compressions > limits.max_compressions or first_circuit == 0 or
            @as(u64, first_circuit) + compressions > core.fields.m31.Modulus)
            return error.SourcePackedBlakeResourceLimit;
        const counts = [2]usize{ try std.math.mul(usize, compressions, 56), try std.math.mul(usize, compressions, 16) };
        const logs = [2]u32{ rowLog(counts[0]), rowLog(counts[1]) };
        const capture_log = rowLog(compressions);
        var cells = try std.math.mul(usize, @as(usize, 1) << @intCast(capture_log), CAPTURE_MAIN_COUNT + CAPTURE_FIXED_COUNT);
        inline for (Airs, 0..) |Air, i| {
            if (counts[i] > 1 << 24) return error.SourcePackedBlakeResourceLimit;
            cells = try std.math.add(usize, cells, try std.math.mul(usize, @as(usize, 1) << @intCast(logs[i]), Air.PHYSICAL_MAIN_COLUMN_COUNT + Air.PREPROCESSED_COLUMN_COUNT));
            cells = try std.math.add(usize, cells, try std.math.mul(usize, counts[i], Air.PREPROCESSED_COLUMN_COUNT));
        }
        for ([_]Tables.Kind{ .bitwise, .range_check_8_8 }) |kind| cells = try std.math.add(usize, cells, Tables.size(kind));
        if (cells > limits.max_cells or try std.math.mul(usize, frames, @sizeOf(FrameCapture)) > limits.max_capture_metadata_bytes)
            return error.SourcePackedBlakeResourceLimit;
        return .{ .operations = @intCast(operations.len), .first_ordinal = first, .first_circuit = first_circuit, .compressions = compressions, .frames = frames, .logs = logs, .capture_log = capture_log, .cells = cells };
    }
};
pub const FrameCapture = struct {
    operation: u32,
    recipe: u32,
    frame: Hash.Frame,
    multiplicity: u32,
    default_height: ?u32,
    digest: [32]u8,
    first_compression: u32,
    boundaries: [2]Hash.Boundary = undefined,
    compression_count: u32 = 0,
};
pub const Columns = struct {
    a: std.mem.Allocator,
    allocation_owner: ?*Budget,
    geometry: Geometry,
    definitions: Definitions = undefined,
    plans: Plans = undefined,
    setup_lease: ?Setup.Lease = null,
    owners: Owners = undefined,
    definition_count: usize = 0,
    owner_count: usize = 0,
    counter_count: usize = 0,
    counters: [2]Counter = undefined,
    /// Core only. The unified page supplies merged table multiplicities once.
    fixed: std.ArrayList(Column) = .empty,
    main: []Column = &.{},
    frames: []FrameCapture = &.{},
    capture_main: ?Matrix = null,
    capture_fixed: ?Matrix = null,
    compressions_written: u32 = 0,
    frames_written: u32 = 0,
    pub const complete_source_authority = false;
    pub fn deinit(self: *Columns) void {
        if (self.capture_main) |*matrix| matrix.deinit();
        if (self.capture_fixed) |*matrix| matrix.deinit();
        self.a.free(self.frames);
        self.a.free(self.main); // descriptors only; owners release core buffers.
        for (self.fixed.items) |column| self.a.free(column.values);
        self.fixed.deinit(self.a);
        for (self.counters[0..self.counter_count]) |*counter| counter.deinit(self.a);
        inline for (Airs, 0..) |_, i| {
            if (i < self.owner_count) self.owners[i].deinit();
            if (i < self.definition_count) self.definitions[i].deinit();
        }
        if (self.setup_lease) |*lease| lease.deinit();
        const a = self.a;
        const owner = self.allocation_owner;
        a.destroy(self);
        if (owner) |retained| retained.destroy();
    }
    pub fn regenerate(a: std.mem.Allocator, operations: []const Fold.Operation, first_circuit: u32, limits: Limits) !*Columns {
        return regenerateUsing(a, operations, first_circuit, limits, null);
    }
    pub fn regenerateWithSetup(a: std.mem.Allocator, operations: []const Fold.Operation, first_circuit: u32, limits: Limits, setup: *const Setup) !*Columns {
        return regenerateUsing(a, operations, first_circuit, limits, setup);
    }
    fn regenerateUsing(a: std.mem.Allocator, operations: []const Fold.Operation, first_circuit: u32, limits: Limits, setup: ?*const Setup) !*Columns {
        const geometry = try Geometry.fromOperations(operations, first_circuit, limits);
        const allocation_owner = Budget.fromAllocator(a);
        if (allocation_owner) |owner| _ = owner.retain();
        const self = a.create(Columns) catch |failure| {
            if (allocation_owner) |owner| owner.destroy();
            return failure;
        };
        self.* = .{ .a = a, .allocation_owner = allocation_owner, .geometry = geometry };
        errdefer self.deinit();
        if (setup) |shared| {
            self.setup_lease = try shared.lease();
            self.definitions = shared.definitions;
            self.plans = shared.plans;
        }
        inline for (Airs, .{ 56, 16 }, 0..) |Air, rows, i| {
            if (setup == null) {
                self.definitions[i] = try Air.build(a);
                self.definition_count += 1;
                self.plans[i] = try Binding.Binding(Air).authenticate(&self.definitions[i]);
            }
            self.owners[i] = try Direct.ForAir(Air).init(a, try std.math.mul(usize, geometry.compressions, rows));
            self.owner_count += 1;
        }
        for ([_]Tables.Kind{ .bitwise, .range_check_8_8 }, 0..) |kind, i| {
            self.counters[i] = try Counter.init(a, kind);
            self.counter_count += 1;
        }
        self.frames = try a.alloc(FrameCapture, geometry.frames);
        self.capture_main = try Matrix.init(a, CAPTURE_MAIN_COUNT, geometry.capture_log);
        self.capture_fixed = try Matrix.init(a, CAPTURE_FIXED_COUNT, geometry.capture_log);
        var circuit = first_circuit;
        for (operations, 0..) |operation, operation_index| {
            const recipes = try Hash.recipes(operation);
            for (recipes.values[0..recipes.count], 0..) |recipe, recipe_index| {
                const at = self.frames_written;
                const captured = &self.frames[at];
                captured.* = .{ .operation = @intCast(operation_index), .recipe = @intCast(recipe_index), .frame = recipe.frame, .multiplicity = recipe.multiplicity, .default_height = recipe.default_height, .digest = undefined, .first_compression = self.compressions_written };
                if (recipe.default_height) |height| {
                    captured.digest = Defaults.get().defaults[@import("../air/memory_commitment/blake3_state_tree.zig").DEPTH - height].bytes;
                } else {
                    var sink = Sink{ .owner = self, .capture = captured };
                    captured.digest = try Hash.emit(recipe.frame, circuit, &sink);
                    circuit += captured.compression_count;
                }
                const required = if (recipe_index == 0) operation.value.before else operation.value.after;
                if (!std.meta.eql(captured.digest, required) or
                    (recipe.multiplicity == 2 and !operation.value.equal())) return error.UntrustedSourcePackedBlakeDigest;
                self.frames_written += 1;
            }
        }
        if (self.frames_written != geometry.frames or self.compressions_written != geometry.compressions) return error.InvalidSourcePackedBlakeCount;
        inline for (Airs, 0..) |Air, i| {
            try self.owners[i].requireFinished();
            try Project.registerRepeated(Air, &self.plans[i], @splat(M.zero()), self.owners[i].main[0].values.len - self.owners[i].fixed.len, &self.counters);
            try Project.projectFixed(Air, a, self.owners[i].fixed, geometry.logs[i], &self.fixed);
        }
        self.main = try a.alloc(Column, G.PHYSICAL_MAIN_COLUMN_COUNT + Xor.PHYSICAL_MAIN_COLUMN_COUNT);
        @memcpy(self.main[0..G.PHYSICAL_MAIN_COLUMN_COUNT], self.owners[0].main);
        @memcpy(self.main[G.PHYSICAL_MAIN_COLUMN_COUNT..], self.owners[1].main);
        return self;
    }
    const Sink = struct {
        owner: *Columns,
        capture: *FrameCapture,
        pub fn g(self: *@This(), row: *const G.Row) !void {
            const plan = Topology.canonical();
            const ordinal = self.owner.owners[0].next;
            const call = plan.g[ordinal % 56];
            var uses: [4]u32 = undefined;
            for (&uses, call.output) |*value, wire| value.* = plan.uses[wire];
            const fixed = try G.fixedRow(.{ .circuit = self.owner.geometry.first_circuit + @as(u32, @intCast(ordinal / 56)), .input = call.input, .output = call.output, .uses = uses });
            if (!std.meta.eql(Storage.compactFixed(G, row.*), Storage.compactFixed(G, fixed))) return error.UntrustedSourcePackedBlakeFixed;
            try self.owner.owners[0].append(row.*);
            try Project.register(G, &self.owner.plans[0], &.{row.*}, &self.owner.counters);
        }
        pub fn xor(self: *@This(), row: *const Xor.Row) !void {
            const plan = Topology.canonical();
            const ordinal = self.owner.owners[1].next;
            const call = plan.xor[ordinal % 16];
            const fixed = try Xor.fixedRow(.{ .circuit = self.owner.geometry.first_circuit + @as(u32, @intCast(ordinal / 16)), .input = call.input, .output = call.output, .uses = plan.uses[call.output] });
            if (!std.meta.eql(Storage.compactFixed(Xor, row.*), Storage.compactFixed(Xor, fixed))) return error.UntrustedSourcePackedBlakeFixed;
            try self.owner.owners[1].append(row.*);
            try Project.register(Xor, &self.owner.plans[1], &.{row.*}, &self.owner.counters);
        }
        pub fn boundary(self: *@This(), value: Hash.Boundary) !void {
            const plan = Topology.canonical();
            const ordinal = self.owner.compressions_written;
            if (self.capture.compression_count >= 2 or ordinal >= self.owner.geometry.compressions or
                value.circuit != self.owner.geometry.first_circuit + ordinal or
                !std.meta.eql(value.input_uses, plan.uses[0..32].*) or !std.meta.eql(value.output_wire, plan.output)) return error.InvalidSourcePackedBlakeBoundary;
            self.capture.boundaries[self.capture.compression_count] = value;
            var bytes: [CAPTURE_MAIN_COUNT]M = undefined;
            for (value.initial ++ value.output, 0..) |word, i| for (0..4) |part| {
                bytes[4 * i + part] = M.fromCanonical((word >> @as(u5, @intCast(8 * part))) & 255);
            };
            try self.owner.capture_main.?.put(ordinal, &bytes);
            const fixed = [_]M{ M.one(), M.fromCanonical(value.circuit), M.fromCanonical(self.capture.operation), M.fromCanonical(self.capture.recipe), M.fromCanonical(self.capture.compression_count), M.fromCanonical(self.capture.multiplicity) };
            try self.owner.capture_fixed.?.put(ordinal, &fixed);
            self.capture.compression_count += 1;
            self.owner.compressions_written += 1;
        }
    };
};
