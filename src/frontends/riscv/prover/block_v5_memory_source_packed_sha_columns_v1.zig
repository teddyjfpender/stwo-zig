//! Page-local original packed SHA columns regenerated from the exact raw main.
//! Persist raw operands, never these large matrices. Neither the counters nor
//! native digest checks confer authority: all four AIRs and tables must verify.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Budget = engine.host_budget_allocator.SharedHostBudget;
const M = core.fields.m31.M31;
const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
const Schema = @import("block_v5_memory_source_batch_raw_schema_v1.zig");
const Raw = @import("block_v5_memory_source_batch_raw_v1.zig");
const Packed = @import("block_v5_memory_source_packed_sha_v1.zig");
const Connector = @import("block_v5_memory_source_sha_connector_air_v1.zig");
const Input = @import("../air/guest_precompile/sha256_packed_source.zig");
const Rows = @import("../air/guest_precompile/sha256_compression_rows.zig");
const Preprocessed = @import("../air/guest_precompile/sha256_preprocessed.zig");
const Binding = @import("../recursion/air/universal_relation_binding.zig");
const Direct = @import("../recursion/air/blake3_direct_cohort_columns_v1.zig");
const Register = @import("../recursion/air/blake3_row_columns.zig");
const Place = @import("../air/block/memory_component_trace.zig");
const Tables = @import("../air/lookups/tables/schema.zig");
const Counter = @import("../air/lookups/tables/counter.zig").Counter;
pub const Airs = .{ Input, Rows.Schedule, Rows.Round, Rows.FeedForward };
pub const Setup = @import("block_v5_packed_hash_setup_v1.zig").ForAirs(Airs);
const Owners = std.meta.Tuple(&.{ Direct.ForAir(Input), Direct.ForAir(Rows.Schedule), Direct.ForAir(Rows.Round), Direct.ForAir(Rows.FeedForward) });
const Definitions = std.meta.Tuple(&.{ Input.Definition, Rows.Schedule.Definition, Rows.Round.Definition, Rows.FeedForward.Definition });
const Plans = std.meta.Tuple(&.{ Binding.Binding(Input).Plan, Binding.Binding(Rows.Schedule).Plan, Binding.Binding(Rows.Round).Plan, Binding.Binding(Rows.FeedForward).Plan });
pub const Limits = struct { max_compressions: u32 = 8192, max_cells: usize = 1 << 28 };
pub const Geometry = struct {
    compressions: u32,
    logs: [4]u32,
    connector_log: u32,
    cells: usize,
    pub fn fromPage(admitted: *const Source.Admitted, page: Schema.Protocol.Page, limits: Limits) !Geometry {
        if (page.chunks == 0 or page.row_log < 1 or page.row_log > 12 or page.chunks > (@as(u32, 1) << @intCast(page.row_log))) return error.InvalidSourcePackedPage;
        var count: u32 = 0;
        for (0..page.chunks) |i| switch (try Raw.kindAt(admitted, try std.math.add(u64, page.first_chunk, i))) {
            .sha => |sha| count = try std.math.add(u32, count, try Packed.chunkCompressionCount(admitted, sha.stream, sha.block)),
            .record => {},
        };
        if (count > limits.max_compressions) return error.SourcePackedPageResourceLimit;
        const geometry = try Rows.Geometry.init(count);
        var cells = try std.math.mul(usize, @as(usize, 1) << @intCast(page.row_log), Connector.EXPANDED_FIXED_COUNT + Connector.CAPTURE_MAIN_COUNT);
        inline for (Airs, 0..) |Air, i| {
            // Includes compact fixed metadata and final projected fixed columns.
            const capacity = @as(usize, 1) << @intCast(geometry.logs[i]);
            cells = try std.math.add(usize, cells, try std.math.mul(usize, capacity, Air.PHYSICAL_MAIN_COLUMN_COUNT + 2 * Air.PREPROCESSED_COLUMN_COUNT));
        }
        for ([_]Tables.Kind{ .bitwise, .range_check_8_8 }) |kind| cells = try std.math.add(usize, cells, try std.math.mul(usize, Tables.size(kind), Tables.arity(kind) + 4)); // fixed, counters and committed multiplicities
        if (cells > limits.max_cells) return error.SourcePackedPageResourceLimit;
        return .{ .compressions = count, .logs = geometry.logs, .connector_log = page.row_log, .cells = cells };
    }
};
/// Fixed/capture buffers use the original raw page's physical row placement.
pub const Matrix = struct {
    a: std.mem.Allocator,
    values: []M,
    columns: []engine.pcs.ColumnEvaluation,
    pub fn init(a: std.mem.Allocator, count: usize, log: u32) !Matrix {
        if (log < 1 or log > 24) return error.InvalidSourcePackedPage;
        const rows = @as(usize, 1) << @intCast(log);
        const values = try a.alloc(M, try std.math.mul(usize, count, rows));
        errdefer a.free(values);
        @memset(values, M.zero());
        const columns = try a.alloc(engine.pcs.ColumnEvaluation, count);
        for (columns, 0..) |*column, i| column.* = .{ .log_size = log, .values = values[i * rows ..][0..rows] };
        return .{ .a = a, .values = values, .columns = columns };
    }
    pub fn deinit(self: *Matrix) void {
        self.a.free(self.columns);
        self.a.free(self.values);
        self.* = undefined;
    }
    pub fn put(self: *Matrix, logical: usize, row: []const M) !void {
        if (row.len != self.columns.len or self.columns.len == 0 or logical >= self.columns[0].values.len) return error.InvalidSourcePackedPage;
        const rows = self.columns[0].values.len;
        const physical = Place.committedRow(logical, self.columns[0].log_size);
        for (row, 0..) |value, i| self.values[i * rows + physical] = value;
    }
};
pub const Columns = struct {
    a: std.mem.Allocator,
    allocation_owner: ?*Budget = null,
    geometry: Geometry,
    owners: Owners,
    definitions: Definitions,
    plans: Plans,
    setup_lease: ?Setup.Lease = null,
    fixed: std.ArrayList(engine.pcs.ColumnEvaluation),
    main: []engine.pcs.ColumnEvaluation, // core aliases + two owned table columns
    connector_fixed: Matrix,
    captures: Matrix,
    counters: [2]Counter,
    pub fn deinit(self: *Columns) void {
        self.captures.deinit();
        self.connector_fixed.deinit();
        for (&self.counters) |*counter| counter.deinit(self.a);
        for (self.main[self.main.len - 2 ..]) |column| self.a.free(column.values);
        self.a.free(self.main);
        for (self.fixed.items) |column| self.a.free(column.values);
        self.fixed.deinit(self.a);
        inline for (Airs, 0..) |_, i| {
            if (self.setup_lease == null) self.definitions[i].deinit();
            self.owners[i].deinit();
        }
        if (self.setup_lease) |*lease| lease.deinit();
        const allocation_owner = self.allocation_owner;
        self.* = undefined;
        if (allocation_owner) |owner| owner.destroy();
    }
    /// Mutation detection only; genuine verifier authority comes from PCS/AIR.
    pub fn snapshot(self: *const Columns) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("source-packed-sha-columns/guard/v1\x00");
        for ([_][]const engine.pcs.ColumnEvaluation{ self.fixed.items, self.main, self.connector_fixed.columns, self.captures.columns }) |columns| for (columns) |column| {
            for (column.values) |value| {
                var raw: [4]u8 = undefined;
                std.mem.writeInt(u32, &raw, value.toU32(), .little);
                hash.update(&raw);
            }
        };
        for (self.counters) |counter| for (counter.values) |value| {
            var raw: [4]u8 = undefined;
            std.mem.writeInt(u32, &raw, value.toU32(), .little);
            hash.update(&raw);
        };
        return hash.finalResult();
    }
    /// No transient full rows or compression tape. One compression is emitted
    /// immediately into final direct columns and exact signed table counters.
    pub fn regenerate(a: std.mem.Allocator, admitted: *const Source.Admitted, raw: *const Schema.Columns.Columns, limits: Limits) !Columns {
        return regenerateUsing(a, admitted, raw, limits, null);
    }
    pub fn regenerateWithSetup(a: std.mem.Allocator, admitted: *const Source.Admitted, raw: *const Schema.Columns.Columns, limits: Limits, setup: *const Setup) !Columns {
        return regenerateUsing(a, admitted, raw, limits, setup);
    }
    fn regenerateUsing(a: std.mem.Allocator, admitted: *const Source.Admitted, raw: *const Schema.Columns.Columns, limits: Limits, setup: ?*const Setup) !Columns {
        if (raw.written != raw.page.chunks) return error.InvalidSourcePackedPage;
        const geometry = try Geometry.fromPage(admitted, raw.page, limits);
        const allocation_owner = Budget.fromAllocator(a);
        if (allocation_owner) |owner| _ = owner.retain();
        errdefer if (allocation_owner) |owner| owner.destroy();
        var setup_lease: ?Setup.Lease = if (setup) |shared| try shared.lease() else null;
        errdefer if (setup_lease) |*lease| lease.deinit();
        var definitions: Definitions = undefined;
        var definition_count: usize = 0;
        errdefer inline for (Airs, 0..) |_, i| {
            if (i < definition_count) definitions[i].deinit();
        };
        inline for (Airs, 0..) |Air, i| {
            if (setup) |shared| {
                definitions[i] = shared.definitions[i];
            } else {
                definitions[i] = try Air.build(a);
                definition_count += 1;
            }
        }
        var plans: Plans = undefined;
        inline for (Airs, 0..) |Air, i| {
            plans[i] = if (setup) |shared| shared.plans[i] else try Binding.Binding(Air).authenticate(&definitions[i]);
        }
        var owners: Owners = undefined;
        var owner_count: usize = 0;
        errdefer inline for (Airs, 0..) |_, i| {
            if (i < owner_count) owners[i].deinit();
        };
        inline for (Airs, .{ 88, 48, 64, 8 }, 0..) |Air, count, i| {
            owners[i] = try Direct.ForAir(Air).init(a, try std.math.mul(usize, geometry.compressions, count));
            owner_count += 1;
        }
        var fixed: std.ArrayList(engine.pcs.ColumnEvaluation) = .empty;
        errdefer {
            for (fixed.items) |column| a.free(column.values);
            fixed.deinit(a);
        }
        try Preprocessed.append(a, geometry.compressions, false, &fixed);
        for ([_]Tables.Kind{ .bitwise, .range_check_8_8 }) |kind| try Register.tablePreprocessed(a, kind, &fixed);
        var main_count: usize = 0;
        inline for (Airs) |Air| main_count += Air.PHYSICAL_MAIN_COLUMN_COUNT;
        const main = try a.alloc(engine.pcs.ColumnEvaluation, main_count + 2);
        main[main_count..][0..2].* = .{ .{ .log_size = Tables.logSize(.bitwise), .values = &.{} }, .{ .log_size = Tables.logSize(.range_check_8_8), .values = &.{} } };
        errdefer {
            for (main[main_count..]) |column| a.free(column.values);
            a.free(main);
        }
        var offset: usize = 0;
        inline for (Airs, 0..) |_, i| {
            @memcpy(main[offset..][0..owners[i].main.len], owners[i].main);
            offset += owners[i].main.len;
        }
        var connector_fixed = try Matrix.init(a, Connector.EXPANDED_FIXED_COUNT, raw.page.row_log);
        errdefer connector_fixed.deinit();
        var captures = try Matrix.init(a, Connector.CAPTURE_MAIN_COUNT, raw.page.row_log);
        errdefer captures.deinit();
        var counters: [2]Counter = undefined;
        counters[0] = try Counter.init(a, .bitwise);
        errdefer counters[0].deinit(a);
        counters[1] = try Counter.init(a, .range_check_8_8);
        errdefer counters[1].deinit(a);
        // All fallible owners are complete before publishing this aggregate.
        var result = Columns{ .a = a, .allocation_owner = allocation_owner, .geometry = geometry, .owners = owners, .definitions = definitions, .plans = plans, .setup_lease = setup_lease, .fixed = fixed, .main = main, .connector_fixed = connector_fixed, .captures = captures, .counters = counters };
        for (0..raw.page.chunks) |logical| {
            const descriptor = try Raw.kindAt(admitted, raw.page.first_chunk + logical);
            try result.connector_fixed.put(logical, &(try Connector.expandedFixedRow(admitted, descriptor)));
            switch (descriptor) {
                .sha => |sha| {
                    const witness = try raw.witness(@intCast(logical));
                    var sink = Sink{ .owner = &result };
                    _ = try Packed.emitChunk(admitted, sha.stream, sha.block, witness.raw, witness.state, try Raw.firstCall(admitted, sha.stream, sha.block), &sink);
                    var capture: [Connector.CAPTURE_MAIN_COUNT]M = undefined;
                    try Connector.captureInputs(sink.boundaries[0..sink.count], &capture);
                    try result.captures.put(logical, &capture);
                },
                .record => {},
            }
        }
        inline for (Airs, 0..) |Air, i| {
            try result.owners[i].requireFinished();
            const pattern = try Preprocessed.fixedPattern(i);
            for (result.owners[i].fixed, 0..) |tail, logical| if (!std.meta.eql(tail, pattern[logical % pattern.len])) return error.UntrustedSourceShaCoreRecipe;
            // The original arithmetic/source AIRs may retain nonzero table
            // effects on all-zero padding. Count those exact typed rows too.
            const padding_count = result.owners[i].main[0].values.len - result.owners[i].fixed.len;
            try Register.registerRepeated(Air, &result.plans[i], @splat(M.zero()), padding_count, &result.counters);
        }
        for (&result.counters, result.main[main_count..]) |*counter, *column| column.values = try counter.committedColumn(a);
        return result;
    }
    const Sink = struct {
        owner: *Columns,
        boundaries: [2]Packed.Boundary = undefined,
        count: usize = 0,
        fn row(self: *@This(), comptime i: usize, value: Airs[i].Row) !void {
            try self.owner.owners[i].append(value);
            try Register.register(Airs[i], &self.owner.plans[i], &.{value}, &self.owner.counters);
        }
        pub fn source(self: *@This(), value: *const Input.Row) !void {
            try self.row(0, value.*);
        }
        pub fn schedule(self: *@This(), value: *const Rows.Schedule.Row) !void {
            try self.row(1, value.*);
        }
        pub fn round(self: *@This(), value: *const Rows.Round.Row) !void {
            try self.row(2, value.*);
        }
        pub fn feedForward(self: *@This(), value: *const Rows.FeedForward.Row) !void {
            try self.row(3, value.*);
        }
        pub fn boundary(self: *@This(), value: Packed.Boundary) !void {
            if (self.count >= self.boundaries.len) return error.InvalidSourceShaConnectorCapture;
            self.boundaries[self.count] = value;
            self.count += 1;
        }
    };
};
