//! One arithmetic graph per bounded source PAGE. Inputs are an exact indexed
//! inventory of ORIGINAL source/capture cells; claims/challenges/descriptors
//! are independent public values. A caller must prove the input suppliers and
//! original SHA/BLAKE cores in the same proof before these columns authorize
//! anything. No host hash or graph evaluation is a source receipt.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Record = @import("../recursion/air/composition_graph_recorder.zig");
const Lower = @import("../recursion/air/verifier_arithmetic_lowering.zig");
const Arith = @import("../recursion/air/arithmetic_fusion_rows.zig");
const Old = @import("../recursion/air/block_v5_memory_source_equations_v1.zig");
const Eq = @import("../recursion/air/block_v5_memory_source_batch_equations_v1.zig");
const Raw = @import("block_v5_memory_source_batch_raw_v1.zig");
const Protocol = @import("block_v5_memory_source_batch_protocol_v1.zig");
const Schema = @import("block_v5_memory_source_batch_raw_schema_v1.zig");
const Fold = @import("block_v5_memory_source_batch_fold_v1.zig");
const SHA = @import("block_v5_memory_source_packed_sha_v1.zig");
const Blake = @import("block_v5_memory_source_blake_semantics_v1.zig");
const Crypto = @import("../recursion/air/block_v5_memory_source_crypto_v1.zig");
pub const Kind = enum { raw, fold };
pub const Group = enum { source, capture };
pub const Cell = struct { group: Group, logical_row: u32, column: u32, node: u32, uses: u32 = 0 };
pub const Reader = struct {
    context: *anyopaque,
    read: *const fn (*anyopaque, Group, u32, u32) anyerror!M,
};
pub const Limits = struct {
    max_page_rows: u32 = 4096,
    max_inputs: usize = 1 << 22,
    max_nodes: usize = 1 << 24,
    max_graph_bytes: usize = 2 << 30,
    max_arithmetic_rows: usize = 1 << 24,
    max_wire_requests: u64 = 500_000_000,
};
pub const Claims = struct {
    source: Old.Algebra(Q).Sums,
    indexed: Q,
    fold: Eq.Algebra(Q).Sums,
    pub fn zero() Claims {
        return .{ .source = .zero(), .indexed = Q.zero(), .fold = .{} };
    }
};
pub const FoldRow = struct {
    descriptor: Eq.Descriptor,
    recipes: []const Blake.Recipe,
    first_compression: u32,
    compressions: u32,
};
fn live(comptime kind: Kind, descriptor: if (kind == .raw) Raw.Descriptor else Eq.Descriptor, column: usize) bool {
    if (kind == .raw) return switch (descriptor) {
        .sha => column < 768,
        .record => |record| (column >= 768 and column < 832) or switch (record.stream) {
            .input_words, .rw_words => column >= 864 and column < 896,
            .first_touches => column >= 832 and column < 864,
            .endpoints => column >= 864 and column < 960,
            .public_input => false,
        },
    };
    return switch (descriptor.kind) {
        .leaf => column < 832 or column >= 1856,
        .branch => column < 32 or (column >= 320 and column < 1856),
        .empty, .root => column < 32 or (column >= 320 and column < 832),
    };
}
/// The same independent mask must be used by the source canonical-zero AIR.
/// Cells omitted from graph inputs are not silently treated as zero witness.
pub fn rawLive(descriptor: Raw.Descriptor, column: usize) !bool {
    if (column >= Old.BIT_COUNT) return error.InvalidSourcePageCell;
    return live(.raw, descriptor, column);
}
pub fn foldLive(descriptor: Eq.Descriptor, column: usize) !bool {
    try descriptor.validate();
    if (column >= Eq.BIT_COUNT) return error.InvalidSourcePageCell;
    return live(.fold, descriptor, column);
}
const Sink = struct {
    builder: *Record.Builder,
    pub fn zero(self: *Sink, value: Record.Scalar) !void {
        try self.builder.constrainZero(value);
    }
};
fn lift(value: Q) Record.Scalar {
    return Record.Scalar.fromSecure(value);
}
fn addSums(comptime T: type, target: *T, source: T) void {
    inline for (std.meta.fields(T)) |field| @field(target, field.name) = @field(target.*, field.name).add(@field(source, field.name));
}
fn constrainSums(comptime T: type, builder: *Record.Builder, computed: T, public: anytype) !void {
    inline for (std.meta.fields(T)) |field| try builder.constrainZero(@field(computed, field.name).sub(lift(@field(public, field.name))));
}
pub const Prepared = struct {
    child: std.mem.Allocator,
    budget: engine.host_budget_allocator.HostBudgetAllocator,
    kind: Kind,
    circuit_id: u32,
    cells: []Cell = &.{},
    inputs: []Q = &.{},
    circuit: ?Record.Circuit = null,
    values: []Q = &.{},
    lowering: ?Lower.Plan = null,
    columns: ?Arith.Columns = null,
    input_requests: u64 = 0,
    identity: [32]u8 = @splat(0),
    pub fn deinit(self: *Prepared) void {
        if (self.columns) |*columns| columns.deinit();
        if (self.lowering) |*plan| plan.deinit();
        if (self.circuit) |*circuit| circuit.deinit();
        const a = self.budget.allocator();
        a.free(self.values);
        a.free(self.inputs);
        a.free(self.cells);
        if (self.budget.live_bytes != 0) @panic("source PAGE semantic owner leak");
        self.child.destroy(self);
    }
    pub fn reference(self: *const Prepared, lane: *[2]Lower.Lane) !Lower.Reference {
        if (self.circuit_id == 0 or self.circuit_id >= core.fields.m31.Modulus - 1) return error.InvalidSourcePageCircuit;
        const segment = Lower.Lane{ .circuit_id = self.circuit_id, .active_in = .segment, .circuit_identity = self.identity, .graph = self.circuit.?.graph() };
        var binary = segment;
        binary.circuit_id += 1;
        binary.active_in = .binary;
        lane.* = .{ segment, binary };
        return Lower.Reference.seal(lane);
    }
    /// Graph construction and its fixed input routing never depend on these
    /// values. Read all inputs from the actual precommitted column owners.
    pub fn readAndMaterialize(self: *Prepared, reader: Reader, limits: Limits) !void {
        if (self.columns != null or self.lowering != null or self.values.len != 0) return error.SourcePageSemanticAlreadyMaterialized;
        const a = self.budget.allocator();
        for (self.cells, self.inputs) |cell, *value| value.* = Q.fromBase(try reader.read(reader.context, cell.group, cell.logical_row, cell.column));
        const values = try a.alloc(Q, self.circuit.?.nodes.len);
        errdefer a.free(values);
        try self.circuit.?.evaluateInto(self.inputs, values);
        var lanes: [2]Lower.Lane = undefined;
        const ref = try self.reference(&lanes);
        var lowering = try Lower.Plan.init(a, ref);
        errdefer lowering.deinit();
        const counts = lowering.counts(.segment_leaf);
        const count = try std.math.add(usize, counts.multiply, try std.math.add(usize, counts.inverse, counts.linear));
        if (count > limits.max_arithmetic_rows) return error.SourcePageSemanticResourceLimit;
        const evaluation = Lower.Evaluation{ .circuit_identity = self.identity, .values = values };
        const evaluations = [_]Lower.Evaluation{ evaluation, evaluation };
        const columns = try Arith.materializeColumns(a, &lowering, ref, .{ .lanes = &evaluations }, .segment_leaf);
        // Publish only fully constructed owners. No partially initialized
        // fallible aggregate can be observed by the outer errdefer.
        self.values = values;
        self.lowering = lowering;
        self.columns = columns;
    }
};
fn create(a: std.mem.Allocator, kind: Kind, circuit_id: u32, limits: Limits) !*Prepared {
    if (limits.max_page_rows == 0 or limits.max_page_rows > 4096 or limits.max_inputs == 0 or limits.max_nodes == 0 or
        limits.max_nodes >= core.fields.m31.Modulus or limits.max_graph_bytes == 0 or limits.max_arithmetic_rows == 0 or
        limits.max_wire_requests == 0 or limits.max_wire_requests >= core.fields.m31.Modulus or circuit_id == 0 or circuit_id >= core.fields.m31.Modulus)
        return error.SourcePageSemanticResourceLimit;
    const out = try a.create(Prepared);
    out.* = .{ .child = a, .budget = .init(a, limits.max_graph_bytes), .kind = kind, .circuit_id = circuit_id };
    return out;
}
fn input(builder: *Record.Builder, a: std.mem.Allocator, cells: *std.ArrayList(Cell), group: Group, row: u32, column: usize, limits: Limits) !Record.Scalar {
    if (cells.items.len >= limits.max_inputs or cells.items.len >= core.fields.m31.Modulus) return error.SourcePageSemanticResourceLimit;
    const symbol = try builder.input();
    try cells.append(a, .{ .group = group, .logical_row = row, .column = @intCast(column), .node = symbol.node_id });
    return symbol.value;
}
fn publish(out: *Prepared, builder: *Record.Builder, cells: *std.ArrayList(Cell), public_identity: [32]u8, limits: Limits) !void {
    builder.deactivate();
    if (builder.nodes.items.len > limits.max_nodes) return error.SourcePageSemanticResourceLimit;
    const a = out.budget.allocator();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const scratch = try a.alloc(u32, circuit.nodes.len);
    defer a.free(scratch);
    const uses = try Lower.computeUseCountsInto(circuit.graph(), scratch);
    var total: u64 = 0;
    for (cells.items) |*cell| {
        if (cell.node >= uses.len or std.meta.activeTag(circuit.nodes[cell.node].op) != .input) return error.InvalidSourcePageInputInventory;
        cell.uses = uses[cell.node];
        total = try std.math.add(u64, total, cell.uses);
    }
    if (total > limits.max_wire_requests or cells.items.len != circuit.input_count) return error.SourcePageSemanticResourceLimit;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-v5/source-PAGE-semantic/v1\x00");
    hash.update(&public_identity);
    hash.update(&circuit.identity_digest);
    var namespace: [5]u8 = undefined;
    namespace[0] = @intFromEnum(out.kind);
    std.mem.writeInt(u32, namespace[1..5], out.circuit_id, .little);
    hash.update(&namespace);
    var bytes: [17]u8 = undefined;
    for (cells.items) |cell| {
        bytes[0] = @intFromEnum(cell.group);
        std.mem.writeInt(u32, bytes[1..5], cell.logical_row, .little);
        std.mem.writeInt(u32, bytes[5..9], cell.column, .little);
        std.mem.writeInt(u32, bytes[9..13], cell.node, .little);
        std.mem.writeInt(u32, bytes[13..17], cell.uses, .little);
        hash.update(&bytes);
    }
    const inputs = try a.alloc(Q, cells.items.len);
    errdefer a.free(inputs);
    @memset(inputs, Q.zero());
    const owned_cells = try cells.toOwnedSlice(a);
    out.cells = owned_cells;
    out.inputs = inputs;
    out.circuit = circuit;
    out.input_requests = total;
    out.identity = hash.finalResult();
}
/// Actual RAW PAGE topology: no source sibling paths and no SHA bit circuit.
/// The digest bytes below alias final original packed SHA capture cells.
pub fn prepareRaw(a: std.mem.Allocator, admitted: *const Protocol.Admission, first_plan: Schema.Protocol.Plan, pin: Schema.Protocol.Pin, challenges: Protocol.Challenges, claims: Claims, circuit_id: u32, first_limits: Schema.Protocol.Limits, limits: Limits) !*Prepared {
    try admitted.require();
    try first_plan.require(&admitted.source, first_limits);
    try pin.require(first_plan);
    if (pin.page.chunks > limits.max_page_rows) return error.SourcePageSemanticResourceLimit;
    const out = try create(a, .raw, circuit_id, limits);
    errdefer out.deinit();
    const bounded = out.budget.allocator();
    var builder = Record.Builder.init(bounded);
    defer builder.deinit();
    var cells: std.ArrayList(Cell) = .empty;
    defer cells.deinit(bounded);
    const Row = struct { source: [Old.BIT_COUNT]Record.Scalar, output: [32]Record.Scalar };
    const rows = try bounded.alloc(Row, pin.page.chunks);
    defer bounded.free(rows);
    // All inputs precede activation and all operations.
    for (rows, 0..) |*row, logical| {
        const descriptor = try Raw.kindAt(&admitted.source, pin.page.first_chunk + logical);
        row.source = @splat(Record.Scalar.zero());
        row.output = @splat(Record.Scalar.zero());
        for (&row.source, 0..) |*symbol, column| if (try rawLive(descriptor, column)) {
            symbol.* = try input(&builder, bounded, &cells, .source, @intCast(logical), column, limits);
        };
        switch (descriptor) {
            .sha => |sha| {
                const block = try SHA.chunkCompressionCount(&admitted.source, sha.stream, sha.block);
                for (&row.output, 0..) |*symbol, byte| {
                    const column = 128 * (block - 1) + 96 + 4 * (byte / 4) + (3 - byte % 4);
                    symbol.* = try input(&builder, bounded, &cells, .capture, @intCast(logical), column, limits);
                }
            },
            .record => {},
        }
    }
    try builder.activate();
    var sink = Sink{ .builder = &builder };
    var totals = Old.Algebra(Record.Scalar).Sums.zero();
    var indexed = Record.Scalar.zero();
    for (rows, 0..) |*row, logical| {
        const descriptor = try Raw.kindAt(&admitted.source, pin.page.first_chunk + logical);
        switch (descriptor) {
            .sha => |sha| {
                var raw: [64][8]Record.Scalar = undefined;
                var state: [8][32]Record.Scalar = undefined;
                for (&raw, 0..) |*byte, i| byte.* = row.source[8 * i ..][0..8].*;
                for (&state, 0..) |*word, i| word.* = row.source[512 + 32 * i ..][0..32].*;
                const pairs = [_]Old.Algebra(Record.Scalar).Pair{
                    .{ .z = lift(challenges.source.bytes.z), .alpha = lift(challenges.source.bytes.alpha) },
                    .{ .z = lift(challenges.source.input.z), .alpha = lift(challenges.source.input.alpha) },
                    .{ .z = lift(challenges.source.sha_chain.z), .alpha = lift(challenges.source.sha_chain.alpha) },
                };
                const result = try SHA.Algebra(Record.Scalar).semanticBytes(&admitted.source, sha.stream, sha.block, raw, state, row.output, pairs);
                totals.bytes = totals.bytes.add(result.bytes);
                totals.input = totals.input.add(result.input);
                totals.sha_chain = totals.sha_chain.add(result.sha_chain);
            },
            .record => {
                var inputs: [Old.INPUT_COUNT]Record.Scalar = @splat(Record.Scalar.zero());
                @memcpy(inputs[0..Old.BIT_COUNT], &row.source);
                inline for (.{ challenges.source.bytes, challenges.source.input, challenges.source.insertion, challenges.source.before, challenges.source.after, challenges.source.route, challenges.source.roots, challenges.source.ordering, challenges.source.sha_chain, challenges.source.word.initial, challenges.source.word.endpoint }, 0..) |pair, i| {
                    inputs[Old.BIT_COUNT + 2 * i] = lift(pair.z);
                    inputs[Old.BIT_COUNT + 2 * i + 1] = lift(pair.alpha);
                }
                const result = try Raw.Algebra(Record.Scalar).record(&admitted.source, descriptor, &inputs, .{ .z = lift(challenges.indexed.z), .alpha = lift(challenges.indexed.alpha) }, &sink);
                addSums(@TypeOf(totals), &totals, result.source);
                indexed = indexed.add(result.indexed);
            },
        }
    }
    try constrainSums(@TypeOf(totals), &builder, totals, claims.source);
    try builder.constrainZero(indexed.sub(lift(claims.indexed)));
    inline for (std.meta.fields(@TypeOf(claims.fold))) |field| try builder.constrainZero(lift(@field(claims.fold, field.name)));
    try publish(out, &builder, &cells, try pin.identity(first_plan), limits);
    return out;
}
/// FOLD PAGE topology includes exact full-u64 source joins, simultaneous
/// initial/final roots, route/indexed census and every original packed frame.
/// Recipe labels cannot omit cores without the proved default/shared checks.
pub fn prepareFold(a: std.mem.Allocator, admitted: *const Protocol.Admission, descriptors: []const FoldRow, public_identity: [32]u8, challenges: Protocol.Challenges, claims: Claims, circuit_id: u32, limits: Limits) !*Prepared {
    try admitted.require();
    if (descriptors.len == 0 or descriptors.len > limits.max_page_rows or std.mem.allEqual(u8, &public_identity, 0)) return error.SourcePageSemanticResourceLimit;
    const out = try create(a, .fold, circuit_id, limits);
    errdefer out.deinit();
    const bounded = out.budget.allocator();
    var builder = Record.Builder.init(bounded);
    defer builder.deinit();
    var cells: std.ArrayList(Cell) = .empty;
    defer cells.deinit(bounded);
    const Row = struct { source: [Eq.BIT_COUNT]Record.Scalar, captures: [4][192]Record.Scalar };
    const rows = try bounded.alloc(Row, descriptors.len);
    defer bounded.free(rows);
    var next_compression: u32 = descriptors[0].first_compression;
    for (rows, descriptors, 0..) |*row, descriptor, logical| {
        try descriptor.descriptor.validate();
        if (descriptor.first_compression != next_compression or descriptor.compressions > 4) return error.InvalidSourceBlakeRecipe;
        try Blake.requireRecipes(descriptor.descriptor.kind, descriptor.descriptor.height, descriptor.recipes, descriptor.first_compression, descriptor.compressions);
        next_compression = try std.math.add(u32, next_compression, descriptor.compressions);
        row.source = @splat(Record.Scalar.zero());
        row.captures = @splat(@splat(Record.Scalar.zero()));
        for (&row.source, 0..) |*symbol, column| if (try foldLive(descriptor.descriptor, column)) {
            symbol.* = try input(&builder, bounded, &cells, .source, @intCast(logical), column, limits);
        };
        for (row.captures[0..descriptor.compressions], 0..) |*capture, block| for (capture, 0..) |*symbol, column| {
            symbol.* = try input(&builder, bounded, &cells, .capture, descriptor.first_compression + @as(u32, @intCast(block)), column, limits);
        };
    }
    try builder.activate();
    var sink = Sink{ .builder = &builder };
    const B = Blake.Algebra(Record.Scalar);
    var total = Eq.Algebra(Record.Scalar).Sums{};
    for (rows, descriptors) |*row, descriptor| {
        var result = try Eq.Algebra(Record.Scalar).compute(false, admitted, descriptor.descriptor, &row.source, Eq.Algebra(Record.Scalar).challenges(challenges), &sink);
        var frames: [2]B.Frame = undefined;
        var digests: [2][32]Record.Scalar = undefined;
        for (&digests, 0..) |*digest, side| for (digest, 0..) |*byte, i| {
            byte.* = pack(row.source[320 + side * 256 + 8 * i ..][0..8]);
        };
        switch (descriptor.descriptor.kind) {
            .leaf => for (&frames, 0..) |*frame, side| {
                var bytes: [4]Record.Scalar = undefined;
                for (&bytes, 0..) |*byte, i| byte.* = pack(row.source[64 + side * 32 + 8 * i ..][0..8]);
                frame.* = .{ .leaf = bytes };
            },
            .branch => for (&frames, 0..) |*frame, side| {
                var bytes: [64]Record.Scalar = undefined;
                for (0..32) |i| {
                    bytes[i] = pack(row.source[832 + side * 256 + 8 * i ..][0..8]);
                    bytes[32 + i] = pack(row.source[1344 + side * 256 + 8 * i ..][0..8]);
                }
                frame.* = .{ .node = bytes };
            },
            .empty, .root => frames = @splat(.{ .leaf = @splat(Record.Scalar.zero()) }),
        }
        const supplied = try B.providers(&sink, descriptor.descriptor.kind, descriptor.descriptor.height, frames, digests, descriptor.recipes, row.captures[0..descriptor.compressions], descriptor.first_compression, .{ .z = lift(challenges.hash.z), .alpha = lift(challenges.hash.alpha) });
        try sink.zero(result.hash.add(supplied));
        result.hash = result.hash.add(supplied);
        addSums(@TypeOf(total), &total, result);
    }
    try constrainSums(@TypeOf(total), &builder, total, claims.fold);
    inline for (std.meta.fields(@TypeOf(claims.source))) |field| try builder.constrainZero(lift(@field(claims.source, field.name)));
    try builder.constrainZero(lift(claims.indexed));
    try publish(out, &builder, &cells, public_identity, limits);
    return out;
}
fn pack(bits: []const Record.Scalar) Record.Scalar {
    var result = Record.Scalar.zero();
    var power = Record.Scalar.one();
    for (bits) |bit| {
        result = result.add(power.mul(bit));
        power = power.add(power);
    }
    return result;
}
