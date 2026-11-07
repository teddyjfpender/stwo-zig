//! rv64-m9-native-cells (stream m9-native-cells, M9 prep): declaration-level
//! committed-cell census of the native protocol with column-count variants.
//!
//! Same inputs and roster code as `census_main.zig` (production `cpu_components.Plan`,
//! `global_cpu.layout`, `truth_components`, `truth_v3_catalog`); per proof it reports:
//!   * `today`   : the M4 production INTER (local-GKR binding pairs + classic RAM/KIO/Wire + truth classic);
//!   * `logup3`  : today's protocol with three fractions per classic LogUp column instead of two
//!                 (keccak truth local columns are already three per column and stay unchanged);
//!   * `v1`      : native GKR v1 (rv64-native-gkr.md): one 16-column eq+prefix pair per component, no classic.
//!                 "Component" = every slot of the production Plan, as `native_roster.cpu` builds it
//!                 (`inter_offset = 16 * index` for every slot), including the global-only slots without a
//!                 local binding today (core.initial / core.terminal: RAM terms only);
//!   * `v2share` : v1 plus ONE eq+prefix pair per distinct row log of a proof (SharedBindingPlan below):
//!                 all components of one row log read the same eq column (shared row point, rv64-native-gkr.md
//!                 3.2 lemma; one stage-two batch per proof) and one prefix of the rho-combined projections.
//! Columns are counted too (`*_cols`), because a recursion leaf pays per opened column.
//! This is a COST MODEL over declarations, like census_main.zig; it never verifies anything.
const std = @import("std");
const R = @import("../roster.zig");
const Wire = @import("../wire.zig");
const Scope = @import("../gkr_local/service_scope.zig");
const Plan = @import("../gkr_local/cpu_components.zig").Plan;
const Slot = @import("../gkr_local/cpu_components.zig").Slot;
const Global = @import("../gkr_local/global_cpu.zig");
const TruthShapes = @import("../gkr_local/truth_components.zig");
const V3 = @import("../gkr_local/truth_v3_catalog.zig");
const NativeRoster = @import("native_roster.zig");

const Input = struct { cpus: []struct { declaration: Wire.CpuDeclaration }, truths: []struct { declaration: Wire.TruthDeclaration }, memory_words: u32 };

pub const BINDING_COLUMNS: usize = 16;

/// Three fractions per classic column: ceil(q/3) batched columns + one cumulative column, OM31 (8 base each).
pub fn widthThreePerColumn(queries: usize) usize {
    return if (queries == 0) 0 else 8 * ((queries + 2) / 3 + 1);
}

/// The column-count change this stream prototypes: re-plan the binding pairs of a production Plan so that
/// every distinct row log owns one pair. Returns per-slot group indices and the binding INTER column count.
/// v1 semantics: classic global columns are dropped and EVERY plan slot is a native-GKR component with a
/// binding pair (native_roster.cpu), so slots without a local binding today (global-only RAM slots such as
/// core.initial / core.terminal) are grouped too. Review fix: the first cut skipped them (null group), which
/// under-counted v1 by one pair per such slot (24628607 cpu-0: 16.78 M cells) against the M5 exact v1 roster.
pub const SharedBindingPlan = struct {
    group_of_slot: []?usize,
    group_logs: []u32,
    binding_columns: usize,
    pub fn init(a: std.mem.Allocator, plan: *const Plan) !SharedBindingPlan {
        var logs = std.ArrayList(u32).empty;
        const group_of_slot = try a.alloc(?usize, plan.slots.len);
        for (plan.slots, group_of_slot) |slot, *g| {
            const found: ?usize = for (logs.items, 0..) |l, i| {
                if (l == slot.log) break i;
            } else null;
            if (found) |i| g.* = i else {
                try logs.append(a, slot.log);
                g.* = logs.items.len - 1;
            }
        }
        const group_logs = try logs.toOwnedSlice(a);
        return .{ .group_of_slot = group_of_slot, .group_logs = group_logs, .binding_columns = BINDING_COLUMNS * group_logs.len };
    }
    pub fn cells(self: *const SharedBindingPlan) u64 {
        var c: u64 = 0;
        for (self.group_logs) |l| c += BINDING_COLUMNS * (@as(u64, 1) << @intCast(l));
        return c;
    }
};

const Variant = struct { inter_cells: u64 = 0, inter_cols: usize = 0 };
const SlotOut = struct { name: []const u8, log: u32, main_cols: usize, binding: bool, ram_queries: usize, other_queries: usize, today_cols: usize, logup3_cols: usize, share_group: ?usize };
const CpuOut = struct { main_cells: u64, main_cols: usize, today: Variant, logup3: Variant, v1: Variant, v2share: Variant, binding_components: usize, distinct_binding_logs: usize, slots: []SlotOut };
const PartOut = struct { kind: []const u8, log: u32, main_cols: usize, local_cols: usize, global_cols: usize, local_queries: usize, global_queries: usize };
const TruthOut = struct { family: []const u8, calls: u32, main_cells: u64, main_cols: usize, today: Variant, logup3: Variant, v1: Variant, v2share: Variant, parts: []PartOut };

fn add(v: *Variant, rows: u64, cols: usize) void {
    v.inter_cells += rows * cols;
    v.inter_cols += cols;
}

fn originName(a: std.mem.Allocator, origin: anytype) ![]const u8 {
    return switch (origin) {
        .core => |r| std.fmt.allocPrint(a, "core.{s}", .{@tagName(r)}),
        .bridge => |f| std.fmt.allocPrint(a, "bridge.{s}", .{@tagName(f)}),
        .bulk => |k| std.fmt.allocPrint(a, "bulk.{s}", .{@tagName(k)}),
        .sponge => |k| std.fmt.allocPrint(a, "sponge.{s}", .{@tagName(k)}),
        .dword => |k| std.fmt.allocPrint(a, "dword.{d}", .{k}),
    };
}

fn mainCols(setup: *const R.CpuSetup, origin: anytype) usize {
    const T = @import("../types.zig");
    return switch (origin) {
        .core => |r| blk: {
            for (setup.materials.shapes()) |shape| if (shape.role == r) break :blk shape.widths[1];
            break :blk 0;
        },
        .bridge => |f| T.widths(f)[1],
        .bulk => |k| T.bulkWidths(k)[1],
        .sponge => |k| T.spongeWidths(k)[1],
        .dword => T.dwordWidthsFor(setup.materials.geometry)[1],
    };
}

pub fn cpuCensus(a: std.mem.Allocator, declaration: Wire.CpuDeclaration, rom_log: u32) !CpuOut {
    var setup: R.CpuSetup = undefined;
    setup.materials.geometry = declaration.geometry;
    setup.materials.program.log_size = rom_log;
    setup.bridges = declaration.bridges;
    try Scope.declaration(declaration);
    var plan = try Plan.init(a, &setup);
    const shared = try SharedBindingPlan.init(a, &plan);
    var out = CpuOut{ .main_cells = 0, .main_cols = 0, .today = .{}, .logup3 = .{}, .v1 = .{}, .v2share = .{}, .binding_components = 0, .distinct_binding_logs = shared.group_logs.len, .slots = &.{} };
    var slots = std.ArrayList(SlotOut).empty;
    for (plan.slots, shared.group_of_slot) |slot, group| {
        const l = Global.layout(slot.origin);
        const rows = @as(u64, 1) << @intCast(slot.log);
        const bind: usize = if (slot.binding_index != null) BINDING_COLUMNS else 0;
        const mc = mainCols(&setup, slot.origin);
        // cleared_other (wire bridges) keeps its fixed 16-column form under logup3.
        const other3: usize = if (l.other_queries == 0) 0 else if (l.cleared_other) 16 else widthThreePerColumn(l.other_queries);
        const l3 = bind + widthThreePerColumn(l.ram_queries) + other3;
        out.main_cells += rows * mc;
        out.main_cols += mc;
        add(&out.today, rows, bind + l.width());
        add(&out.logup3, rows, l3);
        // v1: one pair per plan slot (native_roster.cpu), with or without a local binding today.
        add(&out.v1, rows, BINDING_COLUMNS);
        out.binding_components += 1;
        try slots.append(a, .{ .name = try originName(a, slot.origin), .log = slot.log, .main_cols = mc, .binding = bind != 0, .ram_queries = l.ram_queries, .other_queries = l.other_queries, .today_cols = bind + l.width(), .logup3_cols = l3, .share_group = group });
    }
    // MAIN of components without an interaction slot (no local terms, no global query).
    for (setup.materials.shapes()) |shape| {
        if (!shape.present()) continue;
        const seen = for (plan.slots) |slot| {
            if (slot.origin == .core and slot.origin.core == shape.role) break true;
        } else false;
        if (!seen) {
            out.main_cells += (@as(u64, 1) << @intCast(shape.log)) * shape.widths[1];
            out.main_cols += shape.widths[1];
            try slots.append(a, .{ .name = try std.fmt.allocPrint(a, "core.{s}", .{@tagName(shape.role)}), .log = shape.log, .main_cols = shape.widths[1], .binding = false, .ram_queries = 0, .other_queries = 0, .today_cols = 0, .logup3_cols = 0, .share_group = null });
        }
    }
    out.v2share = .{ .inter_cells = shared.cells(), .inter_cols = shared.binding_columns };
    // Parity with the production native-GKR receiver roster (review fix): v1 must own exactly one 16-column
    // pair per native_roster.cpu component, at the component's row log.
    var native = try NativeRoster.cpu(a, &setup);
    defer native.deinit();
    if (native.roster.components.len != plan.slots.len) return error.M9V1RosterMismatch;
    var v1_cells: u64 = 0;
    for (native.roster.components) |c| v1_cells += BINDING_COLUMNS * (@as(u64, 1) << @intCast(c.row_log));
    if (v1_cells != out.v1.inter_cells or BINDING_COLUMNS * native.roster.components.len != out.v1.inter_cols) return error.M9V1RosterMismatch;
    out.slots = try slots.toOwnedSlice(a);
    return out;
}

pub fn truthCensus(a: std.mem.Allocator, d: Wire.TruthDeclaration) !TruthOut {
    var parts = std.ArrayList(PartOut).empty;
    var out = TruthOut{ .family = @tagName(d.family), .calls = d.calls, .main_cells = 0, .main_cols = 0, .today = .{}, .logup3 = .{}, .v1 = .{}, .v2share = .{}, .parts = &.{} };
    var logs = std.ArrayList(u32).empty;
    if (d.family == .keccak) {
        for (try TruthShapes.shapesForDeclaration(d)) |shape| {
            const w = shape.widths();
            const local = shape.localWidth();
            try parts.append(a, .{ .kind = @tagName(shape.kind), .log = shape.log_size, .main_cols = w[1], .local_cols = local, .global_cols = w[2] - local, .local_queries = shape.instance().queries, .global_queries = if (shape.kind == .keccak) shape.keccak_policy.ioLookups() else 0 });
        }
    } else {
        const desc = try V3.descriptorForDeclaration(d);
        // v3 batches pack two fractions per inverse column: queries = 2 x batches (census_main.zig convention).
        try parts.append(a, .{ .kind = @tagName(d.family), .log = desc.log_size, .main_cols = desc.shape.main, .local_cols = desc.shape.byte_batches * 8, .global_cols = desc.shape.wire_batches * 8, .local_queries = 2 * desc.shape.byte_batches, .global_queries = 2 * desc.shape.wire_batches });
    }
    for (parts.items) |p| {
        const rows = @as(u64, 1) << @intCast(p.log);
        out.main_cells += rows * p.main_cols;
        out.main_cols += p.main_cols;
        add(&out.today, rows, p.local_cols + p.global_cols);
        // keccak local is already three per column (1152 = 8 x (ceil(427/3) + 1)); v3 byte batches go 2 -> 3.
        const local3 = if (d.family == .keccak) p.local_cols else if (p.local_queries == 0) 0 else 8 * ((p.local_queries + 2) / 3);
        const global3 = if (d.family == .keccak and p.global_queries != 0) widthThreePerColumn(p.global_queries) else p.global_cols;
        add(&out.logup3, rows, local3 + global3);
        add(&out.v1, rows, BINDING_COLUMNS);
        const found = for (logs.items) |l| {
            if (l == p.log) break true;
        } else false;
        if (!found) try logs.append(a, p.log);
    }
    for (logs.items) |l| add(&out.v2share, @as(u64, 1) << @intCast(l), BINDING_COLUMNS);
    // Parity with native_roster.truth (review fix): one v1 pair per receiver component at its row log.
    var native = try NativeRoster.truth(a, d);
    defer native.deinit();
    var v1_cells: u64 = 0;
    for (native.roster.components) |c| v1_cells += BINDING_COLUMNS * (@as(u64, 1) << @intCast(c.row_log));
    if (v1_cells != out.v1.inter_cells) return error.M9V1RosterMismatch;
    out.parts = try parts.toOwnedSlice(a);
    return out;
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const args = try std.process.argsAlloc(a);
    if (args.len != 3) return error.ExpectedBundlePathRomLog;
    const rom_log = try std.fmt.parseInt(u32, args[2], 10);
    const bytes = try std.fs.cwd().readFileAlloc(a, args[1], 64 << 20);
    const input = try std.json.parseFromSliceLeaky(Input, a, bytes, .{ .ignore_unknown_fields = true });
    const cpus = try a.alloc(CpuOut, input.cpus.len);
    for (input.cpus, cpus) |entry, *out| out.* = try cpuCensus(a, entry.declaration, rom_log);
    const truths = try a.alloc(TruthOut, input.truths.len);
    for (input.truths, truths) |entry, *out| out.* = try truthCensus(a, entry.declaration);
    const json = try std.json.Stringify.valueAlloc(a, .{
        .schema = "rv64-m9-native-cells/v1",
        .scope = "declaration-only committed native MAIN/INTER cells per proof and per component (own height, pre-LDE, M31 base cells; OM31 column = 8 base columns) for today / logup3 / v1 / v2share",
        .protocol_today = "RV64-SERVICES-CPU-GKR-TRUTH-CLASSIC-OM31-V3",
        .rom_log = rom_log,
        .cpus = cpus,
        .truths = truths,
    }, .{ .whitespace = .minified });
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
}

test "shared binding plan: one pair per distinct log" {
    // Synthetic slot list: three binding components at log 16, one at 22, one global-only slot (no local
    // binding today) at log 20 that still owns a v1 pair, as native_roster.cpu gives every slot one.
    var slots = [_]Slot{
        .{ .origin = .{ .dword = 0 }, .log = 22, .fixed_offset = 0, .main_offset = 0, .inter_offset = 0, .binding_index = 0, .claim_offset = 0 },
        .{ .origin = .{ .dword = 0 }, .log = 16, .fixed_offset = 0, .main_offset = 0, .inter_offset = 0, .binding_index = 1, .claim_offset = 0 },
        .{ .origin = .{ .dword = 0 }, .log = 16, .fixed_offset = 0, .main_offset = 0, .inter_offset = 0, .binding_index = 2, .claim_offset = 0 },
        .{ .origin = .{ .dword = 0 }, .log = 20, .fixed_offset = 0, .main_offset = 0, .inter_offset = 0, .binding_index = null, .claim_offset = 0 },
        .{ .origin = .{ .dword = 0 }, .log = 16, .fixed_offset = 0, .main_offset = 0, .inter_offset = 0, .binding_index = 3, .claim_offset = 0 },
    };
    const plan = Plan{ .allocator = std.testing.allocator, .slots = &slots, .inter_columns = 0, .claim_count = 0, .binding_count = 4 };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const s = try SharedBindingPlan.init(arena.allocator(), &plan);
    try std.testing.expectEqual(@as(usize, 3), s.group_logs.len);
    try std.testing.expectEqual(@as(usize, 48), s.binding_columns);
    try std.testing.expectEqual(@as(u64, 16 * ((1 << 22) + (1 << 20) + (1 << 16))), s.cells());
    try std.testing.expect(s.group_of_slot[3] != null);
    try std.testing.expect(s.group_of_slot[3].? != s.group_of_slot[1].?);
    try std.testing.expectEqual(s.group_of_slot[1], s.group_of_slot[4]);
    try std.testing.expectEqual(@as(usize, 48), widthThreePerColumn(13)); // ceil(13/3)=5 batched + 1 cumulative
    try std.testing.expectEqual(Global.Layout.ramWidth(.{ .ram_queries = 2 }), widthThreePerColumn(2)); // no gain at q=2
}
