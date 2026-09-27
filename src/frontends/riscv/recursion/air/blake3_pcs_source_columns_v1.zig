//! Direct FRI/query/opening source constructors for canonical parent preparation.
//! Graphs/evaluations are borrowed only during construction; no child receipt
//! or verifier authority is produced here.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Deep = @import("blake3_native_deep.zig");
const Fri = @import("blake3_native_fri.zig");
const FriAir = @import("fri_verifier_circuit.zig");
const Terminal = @import("blake3_terminal_links.zig");
const QueryLinks = @import("blake3_query_links.zig");
const OpeningInput = @import("blake3_opening_inputs.zig");
const Lower = @import("verifier_arithmetic_lowering.zig");
const Scalar = @import("scalar_wire_source.zig");
const Encoding = @import("blake3_field_bytes.zig");
const Owned = @import("blake3_upstream_source_columns_v1.zig");

fn base(values: []const Q, node: u32, comptime err: anyerror) !M {
    if (node >= values.len) return err;
    const value = values[node].toM31Array()[0];
    if (value.v >= core.fields.m31.Modulus or !values[node].eql(Q.fromBase(value))) return err;
    return value;
}
fn uses(a: std.mem.Allocator, graph: anytype) ![]u32 {
    return Lower.computeUseCountsInto(graph.graph(), try a.alloc(u32, graph.nodes.len));
}

pub const Answers = struct {
    columns: Owned.ForSlots(.{12}),
    answer_words: usize,
    pub fn init(a: std.mem.Allocator, deep: *const Deep.Prepared, graph: *const FriAir.Circuit, evaluation: *const FriAir.Evaluation, deep_circuit: u32, fri_circuit: u32) !Answers {
        try deep.graph.validateEvaluation(&deep.evaluation);
        try evaluation.validateAgainst(graph);
        const dp = deep.graph.profile();
        const fp = graph.profile();
        if (dp.query_count != fp.query_count or dp.lifting_log_size != fp.lifting_log_size or dp.log_blowup_factor != fp.log_blowup_factor) return error.InvalidNativeFriProfile;
        // Terminal mappings have no consumers after these source rows are
        // emitted; terminal encoding reconstructs its own typed coefficient map.
        var links = try Terminal.build(a, &deep.graph, graph, dp.query_count, try fp.lastLayerCoefficientCount());
        defer links.deinit();
        const count = try std.math.mul(usize, links.answers.len, 2);
        var columns = try Owned.ForSlots(.{12}).init(a, .{count});
        errdefer columns.deinit();
        var scratch = std.heap.ArenaAllocator.init(a);
        defer scratch.deinit();
        const temp = scratch.allocator();
        const deep_uses = try uses(temp, &deep.graph);
        const fri_uses = try uses(temp, graph);
        // Separate phases preserve the original sources-then-destinations
        // cohort order, rather than interleaving each answer's two rows.
        for (links.answers, 0..) |link, index| {
            const value = try base(deep.evaluation.values, link.deep, error.InvalidNativeFriAnswer);
            if (!value.eql(try base(evaluation.values, link.fri, error.InvalidNativeFriAnswer))) return error.InvalidNativeFriAnswer;
            const weight = try std.math.add(u32, deep_uses[link.deep], 1);
            try columns.put(12, index, try Scalar.logicalRow(deep_circuit, link.deep, weight, value));
            try columns.put(12, links.answers.len + index, try Scalar.routedRow(fri_circuit, link.fri, fri_uses[link.fri], deep_circuit, link.deep, value));
        }
        try columns.finish();
        return .{ .columns = columns, .answer_words = links.answers.len };
    }
    pub fn deinit(self: *Answers) void {
        self.columns.deinit();
        self.* = undefined;
    }
    pub fn appendInputs(self: *const Answers, b: anytype) !void {
        const view = try self.columns.view(12);
        if (self.answer_words > view.rowCount() or view.rowCount() - self.answer_words != self.answer_words) return error.InvalidNativeFriAnswer;
        try b.appendBorrowed(12, view);
    }
};

pub const Queries = struct {
    columns: Owned.ForSlots(.{ 12, 10 }),
    /// Mutable path multiplicity metadata belongs to this owner and remains
    /// stable while path/projection constructors borrow it. It is not cloned.
    links: QueryLinks.Prepared,
    paths_applied: bool = false,
    pub fn init(a: std.mem.Allocator, transcript: anytype, deep: *const Deep.Prepared, fri: *const Fri.Prepared) !Queries {
        try transcript.plan.validate();
        try deep.graph.validateEvaluation(&deep.evaluation);
        try fri.evaluation.validateAgainst(&fri.graph);
        const dp = deep.graph.profile();
        const fp = fri.graph.profile();
        if (dp.query_count != fp.query_count or dp.lifting_log_size != fp.lifting_log_size) return error.InvalidNativeQueryLink;
        const outputs = transcript.plan.fixed.query_outputs;
        if (@hasField(@TypeOf(transcript.*), "live")) {
            if (outputs.len != transcript.live.query_outputs.len) return error.InvalidNativeQueryLink;
            for (outputs, transcript.live.query_outputs) |fixed, live| if (!std.meta.eql(fixed, live)) return error.InvalidNativeQueryLink;
        }
        var links = try QueryLinks.build(a, outputs, &deep.graph, &fri.graph, dp.query_count, fp.fold_widths.len);
        errdefer links.deinit();
        const count = try std.math.add(usize, try std.math.mul(usize, links.queries.len, 63), links.fri_derived.len);
        var columns = try Owned.ForSlots(.{ 12, 10 }).init(a, .{ count, links.queries.len });
        errdefer columns.deinit();
        var scratch = std.heap.ArenaAllocator.init(a);
        defer scratch.deinit();
        const temp = scratch.allocator();
        const deep_uses = try uses(temp, &deep.graph);
        const fri_uses = try uses(temp, &fri.graph);
        for (links.queries, outputs, 0..) |query, output, index| {
            if (output.operation >= transcript.operations.len or transcript.operations[output.operation] != .queries) return error.InvalidNativeQueryLink;
            const operation = transcript.operations[output.operation].queries;
            if (operation.values.len != links.queries.len or operation.log_domain_size != dp.lifting_log_size) return error.InvalidNativeQueryLink;
            const position = try base(deep.evaluation.values, query.position, error.InvalidNativeQueryLink);
            if (position.v != operation.values[index]) return error.InvalidNativeQueryLink;
            try columns.append(12, try Scalar.logicalRow(1502, query.position, try std.math.add(u32, deep_uses[query.position], 1), position));
            const schedule = Encoding.Schedule{ .source_circuit = 1502, .source_wire = query.position, .destination_circuit = query.source.circuit, .destination_first = query.source.wire, .uses = .{ core.fields.m31.Modulus - 1, 0, 0, 0 } };
            try columns.append(10, try Encoding.logicalRow(schedule, Q.fromBase(position)));
            for (query.bits) |bit| {
                const value = try base(deep.evaluation.values, bit.deep, error.InvalidNativeQueryLink);
                if (value.v > 1 or !value.eql(try base(fri.evaluation.values, bit.fri, error.InvalidNativeQueryLink))) return error.InvalidNativeQueryLink;
                try columns.append(12, try Scalar.logicalRow(1502, bit.deep, try std.math.add(u32, deep_uses[bit.deep], 1), value));
                try columns.append(12, try Scalar.routedRow(1504, bit.fri, fri_uses[bit.fri], 1502, bit.deep, value));
            }
        }
        for (links.fri_derived) |node| try columns.append(12, try Scalar.logicalRow(1504, node, fri_uses[node], try base(fri.evaluation.values, node, error.InvalidNativeQueryLink)));
        try columns.finish();
        return .{ .columns = columns, .links = links };
    }
    pub fn deinit(self: *Queries) void {
        self.links.deinit();
        self.columns.deinit();
        self.* = undefined;
    }
    /// Recompute every updated weight from the graph; publication is atomic
    /// and repeat calls are idempotent. This precedes any inventory borrowing.
    pub fn applyPathReads(self: *Queries, a: std.mem.Allocator, deep: *const Deep.Prepared, projection: []const [31]u32) !void {
        return applyPathReadsInto(a, &self.columns, &self.links, &self.paths_applied, deep, projection);
    }
    /// Existing parent Prepared owns the transferred links and columns once.
    /// This shared implementation borrows them; it never copies an owner arena.
    pub fn applyPathReadsInto(a: std.mem.Allocator, columns: *Owned.ForSlots(.{ 12, 10 }), links: *const QueryLinks.Prepared, paths_applied: *bool, deep: *const Deep.Prepared, projection: []const [31]u32) !void {
        try deep.graph.validateEvaluation(&deep.evaluation);
        if (projection.len != links.queries.len or links.queries.len != deep.graph.profile().query_count) return error.InvalidNativeQueryLink;
        const expected = try std.math.add(usize, try std.math.mul(usize, links.queries.len, 63), links.fri_derived.len);
        if (columns.count(12) != expected or columns.count(10) != links.queries.len) return error.InvalidNativeQueryLink;
        var scratch = std.heap.ArenaAllocator.init(a);
        defer scratch.deinit();
        const temp = scratch.allocator();
        const deep_uses = try uses(temp, &deep.graph);
        const weights = try temp.alloc([31]u32, projection.len);
        const view = try columns.view(12);
        for (links.queries, projection, weights, 0..) |query, projected, *out, q| {
            for (query.bits, query.path_uses, projected, 0..) |bit, paths, extra, b| {
                const row_index = q * 63 + 1 + 2 * b;
                if (bit.deep >= deep_uses.len or row_index >= view.rowCount()) return error.InvalidNativeQueryLink;
                const row = view.rowAt(row_index);
                if (row[1].v != 1502 or row[2].v != bit.deep) return error.InvalidNativeQueryLink;
                const weight = try std.math.add(u32, try std.math.add(u32, try std.math.add(u32, deep_uses[bit.deep], 1), paths), extra);
                if (weight >= core.fields.m31.Modulus) return error.InvalidNativeQueryLink;
                out[b] = weight;
            }
        }
        for (weights, 0..) |tuple, q| for (tuple, 0..) |weight, bit| {
            // logical column3 is compact fixed coordinate2 for scalar cohort12.
            columns.owners[0].fixed[q * 63 + 1 + 2 * bit][2] = M.fromCanonical(weight);
        };
        paths_applied.* = true;
    }
    pub fn appendInputs(self: *const Queries, b: anytype) !void {
        if (!self.paths_applied) return error.UnfinalizedNativeQueryPaths;
        try self.columns.appendTo(12, b);
    }
    pub fn appendEncoded(self: *const Queries, b: anytype) !void {
        if (!self.paths_applied) return error.UnfinalizedNativeQueryPaths;
        try self.columns.appendTo(10, b);
    }
};

pub const Openings = struct {
    columns: Owned.ForSlots(.{12}),
    pub fn init(a: std.mem.Allocator, sources: []const OpeningInput.Source, deep: *const Deep.Prepared, fri: *const Fri.Prepared) !Openings {
        try deep.graph.validateEvaluation(&deep.evaluation);
        try fri.evaluation.validateAgainst(&fri.graph);
        var scratch = std.heap.ArenaAllocator.init(a);
        defer scratch.deinit();
        const temp = scratch.allocator();
        const expected = [2][]bool{ try temp.alloc(bool, deep.graph.nodes.len), try temp.alloc(bool, fri.graph.nodes.len) };
        for (expected) |mask| @memset(mask, false);
        var count: usize = 0;
        for (deep.graph.bindings) |binding| if (binding.source == .queried_value) {
            if (binding.node_id >= expected[0].len or expected[0][binding.node_id]) return error.InvalidNativeOpeningSource;
            expected[0][binding.node_id] = true;
            count = try std.math.add(usize, count, 1);
        };
        for (fri.graph.bindings) |binding| if (binding.source == .authenticated_value_word) {
            if (binding.node_id >= expected[1].len or expected[1][binding.node_id]) return error.InvalidNativeOpeningSource;
            expected[1][binding.node_id] = true;
            count = try std.math.add(usize, count, 1);
        };
        if (sources.len != count) return error.InvalidNativeOpeningSource;
        var columns = try Owned.ForSlots(.{12}).init(a, .{count});
        errdefer columns.deinit();
        const counts = [2][]u32{ try uses(temp, &deep.graph), try uses(temp, &fri.graph) };
        const values = [2][]const Q{ deep.evaluation.values, fri.evaluation.values };
        for (sources) |source| {
            if (source.lane != 1 and source.lane != 2) return error.InvalidNativeOpeningSource;
            const lane = source.lane - 1;
            if (source.node >= expected[lane].len or !expected[lane][source.node] or source.value.v >= core.fields.m31.Modulus or !values[lane][source.node].eql(Q.fromBase(source.value))) return error.InvalidNativeOpeningSource;
            expected[lane][source.node] = false;
            const weight = try std.math.add(u32, counts[lane][source.node], if (lane == 0) @as(u32, 2) else 1);
            try columns.append(12, try Scalar.logicalRow(if (lane == 0) 1502 else 1504, source.node, weight, source.value));
        }
        for (expected) |mask| for (mask) |remaining| if (remaining) return error.InvalidNativeOpeningSource;
        try columns.finish();
        return .{ .columns = columns };
    }
    pub fn deinit(self: *Openings) void {
        self.columns.deinit();
        self.* = undefined;
    }
    pub fn appendInputs(self: *const Openings, b: anytype) !void {
        try self.columns.appendTo(12, b);
    }
};
