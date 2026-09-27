//! Mathematical routing/metadata oracles. No proof, accepted capture, admission
//! surrogate or key is constructed. Production typed entrypoints are retained
//! separately and never invoked by these fixtures.
const std = @import("std");
const core = @import("stwo_core");
const Deep = @import("../recursion/air/pcs_deep_circuit.zig");
const Fri = @import("../recursion/air/fri_verifier_circuit.zig");
const Paths = @import("../recursion/air/blake3_stark_paths.zig");
const Ports = @import("../recursion/air/block_v5_recursive_parent_fixed_pcs_ports_v1.zig");
const Queries = @import("../recursion/air/blake3_query_links.zig");
const Fixed = @import("../recursion/block_v5_native_recursive_fixed_pcs_v1.zig");
const Transcript = @import("../recursion/block_v5_word_recursive_fixed_transcript_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
fn pcsConfig() !core.pcs.PcsConfig {
    return .{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 1) };
}
fn WordView(comptime family: @import("../recursion/air/block_v5_word_recursive_shape_composition_v1.zig").Family) type {
    const Shape = @import("../recursion/block_v5_word_recursive_fixed_v1.zig").ForFamily(family).Shape;
    return struct {
        const Self = @This();
        pub const commitment_trees = 4;
        shape: *const Shape,
        columns: [4][]const u32,
        widths: []const u32,
        config: core.pcs.PcsConfig,
        lifting_log: u32,
        seal: [32]u8,
        fn init(shape: *const Shape) Self {
            var columns: [4][]const u32 = undefined;
            for (shape.columns, &columns) |logs, *out| out.* = logs;
            return .{ .shape = shape, .columns = columns, .widths = shape.widths, .config = shape.config, .lifting_log = shape.lifting_log, .seal = shape.seal };
        }
        pub fn validate(self: *const Self) !void {
            try self.shape.validateAgainst(self.shape.row_log, self.config);
            if (!std.meta.eql(self.seal, self.shape.seal) or self.lifting_log != self.shape.lifting_log or self.widths.ptr != self.shape.widths.ptr or self.widths.len != self.shape.widths.len) return error.UntrustedNativeFixedPcsProfile;
            for (self.columns, self.shape.columns) |actual, expected| if (actual.ptr != expected.ptr or actual.len != expected.len) return error.UntrustedNativeFixedPcsProfile;
        }
        pub fn deepProfile(self: *const Self) Deep.Profile {
            return self.shape.deepProfile();
        }
        pub fn friProfile(self: *const Self) Fri.Profile {
            return self.shape.friProfile();
        }
    };
}
fn wordParity(comptime family: @import("../recursion/air/block_v5_word_recursive_shape_composition_v1.zig").Family) !void {
    const a = std.testing.allocator;
    const Shape = @import("../recursion/block_v5_word_recursive_fixed_v1.zig").ForFamily(family).Shape;
    const row_log: u32 = if (family == .ram_lanes) 6 else 16;
    const shape = try Shape.init(a, row_log, try pcsConfig(), .{});
    defer shape.deinit();
    var view = WordView(family).init(shape);
    var dg = try Deep.build(a, shape.deepProfile());
    defer dg.deinit();
    var fg = try Fri.build(a, shape.friProfile());
    defer fg.deinit();
    var transcript = try Transcript.ForFamily(family).recordForShape(a, shape, 1, .{});
    defer transcript.deinit();
    const owned = try Fixed.ForCommitments(4).Owned.compile(a, &view, &dg, &fg, &transcript);
    defer owned.deinit();
    try owned.validateAgainst(&view, &dg, &fg, &transcript);
    const n = shape.config.fri_config.n_queries;
    try std.testing.expectEqual((4 + shape.widths.len) * n, owned.paths.input_routes.len);
    for (owned.paths.input_routes, 0..) |route, index| {
        try std.testing.expectEqual(index / n, route.tree);
        try std.testing.expectEqual(index % n, route.query);
    }
    var links = try Queries.build(a, transcript.fixed.query_outputs, &dg, &fg, n, shape.widths.len);
    defer links.deinit();
    // Same ORIGINAL path kernel's separate two-pass census must reproduce
    // exact hash/nonhash tails, payload coordinates and query read counts.
    var original = try Paths.compileFixedProfile(4, a, &view, &links);
    defer original.deinit();
    try std.testing.expectEqualDeep(original.metadata.g_rows, owned.paths.metadata.g_rows);
    try std.testing.expectEqualDeep(original.metadata.xor_rows, owned.paths.metadata.xor_rows);
    try std.testing.expectEqualDeep(links.queries, owned.queries.queries);
    const retained = owned.paths.input_routes[4 * n].tree;
    owned.paths.input_routes[4 * n].tree = 3;
    try std.testing.expectError(error.UntrustedNativeFixedPcsPorts, owned.validateAgainst(&view, &dg, &fg, &transcript));
    owned.paths.input_routes[4 * n].tree = retained;
    const wrong = try a.dupe(u32, shape.columns[0]);
    defer a.free(wrong);
    view.columns[0] = wrong;
    try std.testing.expectError(error.UntrustedNativeFixedPcsProfile, view.validate());
}
test "native fixed PCS: original RAM query root ordering and all fixed ports cold parity" {
    try wordParity(.ram_lanes);
}
test "native fixed PCS: original range16 table geometry and source mutations" {
    try wordParity(.range16);
}
fn portsAllocation(a: std.mem.Allocator, view: *const WordView(.ram_lanes), dg: *const Deep.Circuit, fg: *const Fri.Circuit, transcript: *const @import("../recursion/air/blake3_transcript_plan.zig").Plan) !void {
    var queries = try Queries.build(a, transcript.fixed.query_outputs, dg, fg, view.config.fri_config.n_queries, view.widths.len);
    defer queries.deinit();
    const ports = try Ports.compileProfile(4, a, view, dg, fg, &queries);
    defer ports.deinit();
    try ports.projection.rows.finish();
    try ports.query_rows.finish();
    try ports.answer_rows.finish();
}
test "native fixed PCS: new query projection terminal port construction exhaustive OOM" {
    const a = std.testing.allocator;
    const Shape = @import("../recursion/block_v5_word_recursive_fixed_v1.zig").ForFamily(.ram_lanes).Shape;
    const shape = try Shape.init(a, 5, try pcsConfig(), .{});
    defer shape.deinit();
    const view = WordView(.ram_lanes).init(shape);
    var dg = try Deep.build(a, shape.deepProfile());
    defer dg.deinit();
    var fg = try Fri.build(a, shape.friProfile());
    defer fg.deinit();
    var transcript = try Transcript.ForFamily(.ram_lanes).recordForShape(a, shape, 1, .{});
    defer transcript.deinit();
    // Shared canonical graphs/transcript are built once. Faults cover new port
    // ownership and original route emission, not repeated original full setup.
    try std.testing.checkAllAllocationFailures(a, portsAllocation, .{ &view, &dg, &fg, &transcript });
}
test "native fixed PCS: allocation owner can release before final query path port frees" {
    const a = std.testing.allocator;
    const Shape = @import("../recursion/block_v5_word_recursive_fixed_v1.zig").ForFamily(.ram_lanes).Shape;
    const shape = try Shape.init(a, 5, try pcsConfig(), .{});
    defer shape.deinit();
    const view = WordView(.ram_lanes).init(shape);
    var dg = try Deep.build(a, shape.deepProfile());
    defer dg.deinit();
    var fg = try Fri.build(a, shape.friProfile());
    defer fg.deinit();
    var transcript = try Transcript.ForFamily(.ram_lanes).recordForShape(a, shape, 1, .{});
    defer transcript.deinit();
    const budget = try Budget.create(a, 128 << 20);
    var active = true;
    defer if (active) budget.destroy();
    const ports = try Fixed.ForCommitments(4).Owned.compile(budget.allocator(), &view, &dg, &fg, &transcript);
    defer ports.deinit();
    budget.destroy();
    active = false;
    try ports.ports.query_rows.finish();
    try ports.openings.rows.finish();
}

// Independent oracle uses the genuine ORIGINAL PAGE component's nominal masks
// and logs. This mathematical fixture is never an admitted PAGE setup owner.
pub const PageView = struct {
    const Self = @This();
    pub const commitment_trees = 10;
    a: std.mem.Allocator,
    original: *const @import("block_v5_memory_source_page_composition_v1.zig").Owner,
    config: core.pcs.PcsConfig,
    columns: [10][]u32,
    trees: [10]Deep.TreeProfile,
    layouts: []@import("../recursion/sample_point_layout.zig").Layout,
    widths: []u32,
    mask_log: u32,
    lifting_log: u32,
    seal: [32]u8,
    pub fn init(a: std.mem.Allocator, original: *@import("block_v5_memory_source_page_composition_v1.zig").Owner) !*Self {
        const cfg = try pcsConfig();
        const mask_log = core.verifier_types.compositionMaskLogSize(original.maxConstraintLogDegreeBound(), original.compositionLogSplit()) orelse return error.InvalidPageShapePcsGeometry;
        const self = try a.create(Self);
        errdefer a.destroy(self);
        self.* = .{ .a = a, .original = original, .config = cfg, .columns = @splat(&.{}), .trees = undefined, .layouts = &.{}, .widths = &.{}, .mask_log = mask_log, .lifting_log = mask_log + cfg.fri_config.log_blowup_factor, .seal = undefined };
        errdefer self.freeStorage();
        const point = core.circle.SECURE_FIELD_CIRCLE_GEN;
        const step = core.poly.circle.canonic.CanonicCoset.new(mask_log).step();
        const previous = point.sub(.{ .x = core.fields.qm31.QM31.fromBase(step.x), .y = core.fields.qm31.QM31.fromBase(step.y) });
        var masks = try original.maskPoints(a, point, mask_log);
        defer masks.deinitDeep(a);
        var layouts: std.ArrayList(@import("../recursion/sample_point_layout.zig").Layout) = .empty;
        defer layouts.deinit(a);
        for (original.logs, masks.items, self.columns[0..9]) |logs, columns, *extended| {
            extended.* = try a.alloc(u32, logs.len);
            for (logs, columns, extended.*) |log, points, *out| {
                out.* = log + cfg.fri_config.log_blowup_factor;
                try layouts.append(a, try @import("../recursion/sample_point_layout.zig").classifyColumn(points, point, previous));
            }
        }
        const composition_count = core.verifier_types.compositionColumnCount(original.compositionLogSplit(), 4).?;
        self.columns[9] = try a.alloc(u32, composition_count);
        @memset(self.columns[9], self.lifting_log);
        try layouts.appendNTimes(a, .current, composition_count);
        self.layouts = try layouts.toOwnedSlice(a);
        for (&self.trees, self.columns) |*tree, logs| tree.* = .{ .column_log_sizes = logs };
        var widths: std.ArrayList(u32) = .empty;
        defer widths.deinit(a);
        var remaining = self.lifting_log;
        const terminal = cfg.fri_config.log_blowup_factor + cfg.fri_config.log_last_layer_degree_bound;
        while (remaining > terminal) {
            const shift = @min(cfg.fri_config.fold_step, remaining - terminal);
            try widths.append(a, @as(u32, 1) << @intCast(shift));
            remaining -= shift;
        }
        self.widths = try widths.toOwnedSlice(a);
        self.seal = self.deepProfile().identityDigest();
        try self.validate();
        return self;
    }
    pub fn deepProfile(self: *const Self) Deep.Profile {
        return .{ .trees = &self.trees, .sample_layouts = self.layouts, .lifting_log_size = self.lifting_log, .log_blowup_factor = self.config.fri_config.log_blowup_factor, .query_count = @intCast(self.config.fri_config.n_queries) };
    }
    pub fn friProfile(self: *const Self) Fri.Profile {
        return .{ .lifting_log_size = self.lifting_log, .log_blowup_factor = self.config.fri_config.log_blowup_factor, .log_last_layer_degree_bound = self.config.fri_config.log_last_layer_degree_bound, .fold_widths = self.widths, .query_count = @intCast(self.config.fri_config.n_queries) };
    }
    pub fn validate(self: *const Self) !void {
        try self.deepProfile().validate();
        try self.friProfile().validate();
        if (!std.meta.eql(self.seal, self.deepProfile().identityDigest())) return error.UntrustedNativeFixedPcsProfile;
        for (self.original.logs, self.columns[0..9]) |original, extended| {
            if (original.len != extended.len) return error.UntrustedNativeFixedPcsProfile;
            for (original, extended) |log, value| if (value != log + self.config.fri_config.log_blowup_factor) return error.UntrustedNativeFixedPcsProfile;
        }
        for (self.columns[9]) |log| if (log != self.lifting_log) return error.UntrustedNativeFixedPcsProfile;
    }
    fn freeStorage(self: *Self) void {
        for (self.columns) |logs| self.a.free(logs);
        self.a.free(self.layouts);
        self.a.free(self.widths);
    }
    pub fn deinit(self: *Self) void {
        const a = self.a;
        self.freeStorage();
        a.destroy(self);
    }
};
fn pageParity(comptime kind: @import("block_v5_memory_source_page_semantic_columns_v1.zig").Kind) !void {
    const a = std.testing.allocator;
    const OriginalFixture = if (kind == .raw) @import("block_v5_memory_source_page_raw_recursive_parity_test_v1.zig").Fixture else @import("block_v5_memory_source_page_recursive_test_v1.zig").Fixture;
    var original = try OriginalFixture.init(a);
    defer original.deinit();
    const view = try PageView.init(a, original.owner.composition.?);
    defer view.deinit();
    var dg = try Deep.build(a, view.deepProfile());
    defer dg.deinit();
    var fg = try Fri.build(a, view.friProfile());
    defer fg.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    const Schema = @import("../recursion/air/blake3_pcs_operation_schema_v1.zig");
    const Sink = @import("../recursion/air/blake3_fixed_operation_recorder_v1.zig");
    var operations: std.ArrayList(Schema.Operation) = .empty;
    try Schema.appendPcsSuffix(temp, &operations, view.config, view.deepProfile(), view.friProfile(), 10);
    var recorder = Sink.Recorder{ .a = temp, .limits = .{} };
    for (operations.items) |operation| try recorder.suffix(operation);
    try recorder.check();
    // Only original suffix routing is exercised: this is not a PAGE prefix
    // admission, channel parity assertion, proof or verifier-success token.
    var routing = try @import("../recursion/air/blake3_transcript_plan.zig").Plan.initCompact(a, .{ .namespace = 1_000_000, .attempt_capacity = 1 }, recorder.operations.items);
    defer routing.deinit();
    const ports = try Fixed.ForCommitments(10).Owned.compile(a, view, &dg, &fg, &routing);
    defer ports.deinit();
    try ports.validateAgainst(view, &dg, &fg, &routing);
    try std.testing.expectEqual((10 + view.widths.len) * view.config.fri_config.n_queries, ports.paths.input_routes.len);
    for (ports.paths.input_routes, 0..) |route, index| try std.testing.expectEqual(index / view.config.fri_config.n_queries, route.tree);
    const saved = ports.paths.input_routes[10].tree;
    ports.paths.input_routes[10].tree = 4; // Original PAGE FRI starts at10, not4.
    try std.testing.expectError(error.UntrustedNativeFixedPcsPorts, ports.validateAgainst(view, &dg, &fg, &routing));
    ports.paths.input_routes[10].tree = saved;
    try std.testing.expectError(error.MissingPageFixedTranscriptAndSourceContext, Fixed.ForPage(kind).requireComplete(ports));
}
test "native fixed PCS: original raw PAGE ten-root masks columns and FRI ordinal" {
    try pageParity(.raw);
}
test "native fixed PCS: original fold PAGE ten-root masks columns and FRI ordinal" {
    try pageParity(.fold);
}
