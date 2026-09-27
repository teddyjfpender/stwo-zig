//! Actual once-per-job tail-provider equations, using the ORIGINAL complete
//! hash DAG. Public frontier/prefix exports are additional exact hash/word
//! boundary sinks. No scalar CV or receipt replaces the compression constraints.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Public = @import("../block_v5_input_tail_public_v1.zig");
const Tail = @import("../blake3_words_tail_v1.zig");
const Graph = @import("blake3_hash_plan.zig");
const Framed = @import("blake3_frame_witness.zig");
const Boundary = @import("blake3_boundary.zig");
const Word = @import("blake3_private_word.zig");
const Storage = @import("blake3_parent_row_storage.zig");
const Direct = @import("blake3_direct_cohort_columns_v1.zig");
const Parent = @import("../blake3_execution_parent_preparation.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub const HASH_CIRCUIT: u32 = 4_300_240;
pub const INPUT_CIRCUIT: u32 = 4_300_241;
pub const DOMAIN_CIRCUIT: u32 = 4_300_242;
pub const Limits = struct { max_owned_bytes: usize = 8 << 30, public: Public.Limits = .{} };
pub const Prepared = struct {
    recursive: Parent.Prepared,
    budget: *Budget,
    backing_owner: ?*Budget,
    pub fn deinit(self: *Prepared) void {
        self.recursive.deinit();
        self.budget.destroy();
        if (self.backing_owner) |owner| owner.destroy();
        self.* = undefined;
    }
};
pub const Logical = struct {
    arena: std.heap.ArenaAllocator,
    framed: Framed.Prepared,
    boundary_rows: []Boundary.Row,
    word_rows: []Word.Row,
    pub fn deinit(self: *Logical) void {
        self.framed.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
};
/// This logical row path is available for nonproving constraint/fault fixtures.
/// Callers must retain their allocator owner until destruction; prepare() owns
/// the durable shared-budget lease for actual production column storage.
pub fn logical(a: std.mem.Allocator, public: *const Public.Owned, independent: Public.Pin, live: bool) !Logical {
    try public.require(independent);
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temporary = arena.allocator();
    var plan = try Graph.build(a, public.geometry.frame_bytes);
    defer plan.deinit();
    // The original DAG already uses each CV in its exact parent. Add one
    // public frontier sink rather than changing its original internal use.
    for (public.geometry.frontier()) |range| {
        const call = try Public.outputCall(&public.geometry, range);
        if (call >= plan.calls.len) return error.UntrustedInputTailRange;
        for (plan.calls[call].output[0..8]) |wire| plan.uses[wire] = try std.math.add(u32, plan.uses[wire], 1);
    }
    const frame = core.channel.blake3.framing.Frame{ .words = .{ .state = Tail.DOMAIN_STATE, .values = public.job.expected().input_words } };
    const state = [_]Framed.Binding{.{ .role = .state, .caller = .{ .circuit = DOMAIN_CIRCUIT, .first_wire = 0 } }};
    const payload = Framed.PayloadBinding{ .role = .words, .caller = .{ .circuit = INPUT_CIRCUIT, .first_wire = 0 }, .word_count = public.pin.word_count };
    var framed = try Framed.destinationWithPlan(a, HASH_CIRCUIT, frame, &state, payload, independent.root, live, null, null, &plan);
    errdefer framed.deinit();
    if (live and !std.meta.eql(framed.digest.?, independent.root)) return error.UntrustedInputTailDigest;
    var boundaries: std.ArrayList(Boundary.Row) = .empty;
    try boundaries.appendSlice(temporary, framed.rows.boundary_rows);
    for (framed.source_uses[0], 0..) |count, word| {
        if (count == 0) return error.UntrustedInputTailDomain;
        try boundaries.append(temporary, try Boundary.logicalRow(DOMAIN_CIRCUIT, @intCast(word), M.fromCanonical(count), std.mem.readInt(u32, Tail.DOMAIN_STATE[word * 4 ..][0..4], .little)));
    }
    for (public.frontier, public.geometry.frontier()) |cv, range| {
        const call = try Public.outputCall(&public.geometry, range);
        for (plan.calls[call].output[0..8], cv) |wire, expected| try boundaries.append(temporary, try Boundary.logicalRow(HASH_CIRCUIT, wire, M.one().neg(), expected));
    }
    for (public.prefix(), 0..) |expected, word| try boundaries.append(temporary, try Boundary.logicalRow(INPUT_CIRCUIT, @intCast(word), M.one().neg(), expected));
    const rows = try temporary.alloc(Word.Row, public.pin.word_count);
    for (rows, framed.payload_uses, 0..) |*row, count, word| {
        const use_count = try std.math.add(u32, count, @intFromBool(word < public.prefix_count));
        row.* = try Word.logicalRow(INPUT_CIRCUIT, @intCast(word), use_count, if (live) public.job.expected().input_words[word] else 0);
    }
    return .{ .arena = arena, .framed = framed, .boundary_rows = try boundaries.toOwnedSlice(temporary), .word_rows = rows };
}
pub fn prepare(backing: std.mem.Allocator, public: *const Public.Owned, independent: Public.Pin, config: core.pcs.PcsConfig, limits: Limits) !Prepared {
    if (limits.max_owned_bytes == 0 or public.pin.word_count > limits.public.max_words) return error.InputTailResourceLimit;
    const calls = try std.math.add(usize, public.geometry.frame_bytes / 64 + @intFromBool(public.geometry.frame_bytes % 64 != 0), public.geometry.chunks - 1);
    if (calls > limits.public.max_hash_calls) return error.InputTailResourceLimit;
    const backing_owner = if (Budget.fromAllocator(backing)) |owner| owner.retain() else null;
    errdefer if (backing_owner) |owner| owner.destroy();
    const budget = try Budget.create(backing, limits.max_owned_bytes);
    errdefer budget.destroy();
    const a = budget.allocator();
    var live = try logical(a, public, independent, true);
    defer live.deinit();
    var fixed = try logical(a, public, independent, false);
    defer fixed.deinit();
    var rows = Storage.Prepared{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = 0 };
    inline for (0..Storage.Airs.len) |i| rows.fixed[i] = &.{};
    errdefer rows.deinit();
    inline for (Storage.Airs, 0..) |Air, i| {
        const actual = if (comptime i == 0) live.framed.rows.g_rows else if (comptime i == 1) live.framed.rows.xor_rows else if (comptime i == 2) live.boundary_rows else if (comptime i == 7) live.framed.route_rows else if (comptime i == 9) live.word_rows else &[_]Air.Row{};
        const trusted = if (comptime i == 0) fixed.framed.rows.g_rows else if (comptime i == 1) fixed.framed.rows.xor_rows else if (comptime i == 2) fixed.boundary_rows else if (comptime i == 7) fixed.framed.route_rows else if (comptime i == 9) fixed.word_rows else &[_]Air.Row{};
        if (actual.len != trusted.len) return error.UntrustedInputTailRows;
        var emitter = try Direct.ForAir(Air).init(a, actual.len);
        defer emitter.deinit();
        for (actual, trusted) |row, admitted| {
            for (row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], admitted[Air.PHYSICAL_MAIN_COLUMN_COUNT..]) |value, expected| if (!value.eql(expected)) return error.UntrustedInputTailRows;
            try emitter.append(row);
        }
        const taken = try emitter.take();
        rows.main[i] = taken.main;
        rows.fixed[i] = taken.fixed;
    }
    try rows.partitionHashRows();
    var identity = core.channel.blake3.Channel{};
    identity.mixU32s(&.{ 0x42355452, Public.VERSION, HASH_CIRCUIT, INPUT_CIRCUIT, DOMAIN_CIRCUIT, independent.word_count });
    identity.mixRoot(public.statement_id);
    identity.mixRoot(@import("../block_v5_input_tail_protocol_v1.zig").sourceAuthority());
    const graph_id = identity.digestBytes();
    return .{ .budget = budget, .backing_owner = backing_owner, .recursive = .{ .rows = rows, .context = .{ .child_key_id = public.statement_id, .child_config = config, .graph_ids = @splat(graph_id), .transcript_plan_id = graph_id } } };
}
