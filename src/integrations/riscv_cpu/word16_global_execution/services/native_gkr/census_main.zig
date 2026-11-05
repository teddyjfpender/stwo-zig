//! rv64-native-gkr-census: declaration-only census of committed native
//! interaction (INTER) cells under the production M4 native protocol
//! `RV64-SERVICES-CPU-GKR-TRUTH-CLASSIC-OM31-V3`, split per physical component
//! into (a) local-GKR binding columns, (b) global RAM/KIO/Wire classic LogUp
//! columns and (c) classic local LogUp columns of truth proofs.
//!
//! Inputs are a produced `bundle.json` (declarations only). This is a COST
//! MODEL: declarations are never verification authority. The physical check is
//! the reconciliation against the GPU_TRACE_OWNERSHIP tree=2 words of the same
//! run (done by scripts/rv64_native_gkr_census.py).
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air;
const R = @import("../roster.zig");
const T = @import("../types.zig");
const Wire = @import("../wire.zig");
const Scope = @import("../gkr_local/service_scope.zig");
const Plan = @import("../gkr_local/cpu_components.zig").Plan;
const Global = @import("../gkr_local/global_cpu.zig");
const Roster = @import("../gkr_local/roster.zig");
const TruthShapes = @import("../gkr_local/truth_components.zig");
const V3 = @import("../gkr_local/truth_v3_catalog.zig");

const Input = struct { cpus: []struct { declaration: Wire.CpuDeclaration }, truths: []struct { declaration: Wire.TruthDeclaration }, memory_words: u32 };

const Slot = struct {
    name: []const u8,
    log: u32,
    local_terms: u32,
    fixed_cols: usize,
    main_cols: usize,
    native_terms: [4]u32 = @splat(0),
    binding_cols: usize,
    ram_cols: usize,
    other_cols: usize,
    other_relation: []const u8,
    ram_queries: usize = 0,
    other_queries: usize = 0,
};
const Cpu = struct { slots: []Slot, main_cells: u64, inter_cells: u64, inter_cols: usize };
const TruthPart = struct { kind: []const u8, log: u32, fixed_cols: usize, native_terms: [4]u32, composition_split: u8, main_cols: usize, local_cols: usize, global_cols: usize, global_relation: []const u8, local_queries: usize = 0, global_queries: usize = 0, queries_exact: bool = false };
const Truth = struct { native_supported: bool, family: []const u8, calls: u32, logs: [2]u32, parts: []TruthPart, main_cells: u64, inter_cells: u64 };

fn originName(a: std.mem.Allocator, origin: anytype) ![]const u8 {
    return switch (origin) {
        .core => |r| std.fmt.allocPrint(a, "core.{s}", .{@tagName(r)}),
        .bridge => |f| std.fmt.allocPrint(a, "bridge.{s}", .{@tagName(f)}),
        .bulk => |k| std.fmt.allocPrint(a, "bulk.{s}", .{@tagName(k)}),
        .sponge => |k| std.fmt.allocPrint(a, "sponge.{s}", .{@tagName(k)}),
        .dword => |k| std.fmt.allocPrint(a, "dword.{d}", .{k}),
    };
}

fn localTerms(setup: *const R.CpuSetup, origin: anytype) u32 {
    return switch (origin) {
        .core => |r| Roster.termsForSetup(setup, r),
        .bridge => |f| Roster.bridgeTerms(f),
        .bulk => |k| @import("../gkr_local/bulk_projection.zig").localTerms(k),
        .sponge => |k| @import("../gkr_local/sponge_projection.zig").localTerms(k),
        .dword => @import("../gkr_local/dword_projection.zig").LOCAL_TERMS,
    };
}

fn mainCols(setup: *const R.CpuSetup, origin: anytype) usize {
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

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const args = try std.process.argsAlloc(a);
    if (args.len != 3) return error.ExpectedBundlePathRomLog;
    const rom_log = try std.fmt.parseInt(u32, args[2], 10);
    const bytes = try std.fs.cwd().readFileAlloc(a, args[1], 64 << 20);
    const input = try std.json.parseFromSliceLeaky(Input, a, bytes, .{ .ignore_unknown_fields = true });

    const cpus = try a.alloc(Cpu, input.cpus.len);
    for (input.cpus, cpus) |entry, *out| {
        var setup: R.CpuSetup = undefined;
        setup.materials.geometry = entry.declaration.geometry;
        setup.materials.program.log_size = rom_log;
        setup.bridges = entry.declaration.bridges;
        try Scope.declaration(entry.declaration);
        const plan = try Plan.init(a, &setup);
        var slots = std.ArrayList(Slot).empty;
        var main_cells: u64 = 0;
        var inter_cells: u64 = 0;
        for (plan.slots) |slot| {
            const l = Global.layout(slot.origin);
            const rows = @as(u64, 1) << @intCast(slot.log);
            const descriptor = @import("cpu_component.zig").Authority.Source.Descriptor{ .origin = slot.origin, .cpu_u8_pairs = setup.materials.geometry.cpu_u8_pairs, .cpu_compact_decode = setup.materials.geometry.cpu_compact_decode };
            const source_shape = try @import("cpu_component.zig").Authority.shape(descriptor);
            const s = Slot{
                .fixed_cols = source_shape.fixed,
                .native_terms = try @import("cpu_component.zig").terms(descriptor),
                .name = try originName(a, slot.origin),
                .log = slot.log,
                .local_terms = localTerms(&setup, slot.origin),
                .main_cols = mainCols(&setup, slot.origin),
                .binding_cols = if (slot.binding_index != null) 16 else 0,
                .ram_cols = l.ramWidth(),
                .other_cols = l.otherWidth(),
                .other_relation = if (l.other_queries == 0) "none" else if (Global.isKio(slot.origin)) "kio" else "wire",
                .ram_queries = l.ram_queries,
                .other_queries = l.other_queries,
            };
            main_cells += rows * s.main_cols;
            inter_cells += rows * (s.binding_cols + s.ram_cols + s.other_cols);
            try slots.append(a, s);
        }
        // Main columns of components without an interaction slot (no local
        // terms and no global query) still count toward MAIN.
        for (setup.materials.shapes()) |shape| {
            if (!shape.present()) continue;
            var seen = false;
            for (plan.slots) |slot| if (slot.origin == .core and slot.origin.core == shape.role) {
                seen = true;
            };
            if (!seen) {
                main_cells += (@as(u64, 1) << @intCast(shape.log)) * shape.widths[1];
                try slots.append(a, .{ .name = try std.fmt.allocPrint(a, "core.{s}", .{@tagName(shape.role)}), .log = shape.log, .local_terms = 0, .fixed_cols = shape.widths[0], .main_cols = shape.widths[1], .binding_cols = 0, .ram_cols = 0, .other_cols = 0, .other_relation = "none" });
            }
        }
        out.* = .{ .slots = try slots.toOwnedSlice(a), .main_cells = main_cells, .inter_cells = inter_cells, .inter_cols = plan.inter_columns };
    }

    const truths = try a.alloc(Truth, input.truths.len);
    for (input.truths, truths) |entry, *out| {
        const d = entry.declaration;
        var parts = std.ArrayList(TruthPart).empty;
        var native_plan: ?@import("native_roster.zig").Plan = @import("native_roster.zig").truth(a, d) catch |err| switch (err) {
            error.NativeGkrLegacyTruthUnsupported => null,
            else => return err,
        };
        defer if (native_plan) |*plan_| plan_.deinit();
        if (d.family == .keccak) {
            for (try TruthShapes.shapesForDeclaration(d), 0..) |shape, part| {
                const w = shape.widths();
                const local = shape.localWidth();
                try parts.append(a, .{ .kind = @tagName(shape.kind), .log = shape.log_size, .fixed_cols = w[0], .native_terms = if (native_plan) |plan_| plan_.roster.components[part].terms else @splat(0), .composition_split = if (native_plan) |plan_| plan_.spans[part].split else 1, .main_cols = w[1], .local_cols = local, .global_cols = w[2] - local, .global_relation = if (w[2] > local) "kio" else "none", .local_queries = shape.instance().queries, .global_queries = if (shape.kind == .keccak) shape.keccak_policy.ioLookups() else 0, .queries_exact = true });
            }
        } else {
            const desc = try V3.descriptorForDeclaration(d);
            // v3 batches pack two fractions per inverse column: queries ~ 2 x batches (estimate).
            try parts.append(a, .{ .kind = @tagName(d.family), .log = desc.log_size, .fixed_cols = desc.shape.fixed, .native_terms = if (native_plan) |plan_| plan_.roster.components[0].terms else @splat(0), .composition_split = if (native_plan) |plan_| plan_.spans[0].split else 1, .main_cols = desc.shape.main, .local_cols = desc.shape.byte_batches * 8, .global_cols = desc.shape.wire_batches * 8, .global_relation = "wire", .local_queries = 2 * desc.shape.byte_batches, .global_queries = 2 * desc.shape.wire_batches });
        }
        var main_cells: u64 = 0;
        var inter_cells: u64 = 0;
        for (parts.items) |p| {
            const rows = @as(u64, 1) << @intCast(p.log);
            main_cells += rows * p.main_cols;
            inter_cells += rows * (p.local_cols + p.global_cols);
        }
        out.* = .{ .native_supported = native_plan != null, .family = @tagName(d.family), .calls = d.calls, .logs = d.logs, .parts = try parts.toOwnedSlice(a), .main_cells = main_cells, .inter_cells = inter_cells };
    }
    const json = try std.json.Stringify.valueAlloc(a, .{
        .schema = "rv64-native-gkr-census/v1",
        .scope = "declaration-only committed native INTER cells per component (own-height, pre-LDE, M31 base cells); OM31 columns count as 8 base columns",
        .protocol = "RV64-SERVICES-CPU-GKR-TRUTH-CLASSIC-OM31-V3",
        .rom_log = rom_log,
        .cpus = cpus,
        .truths = truths,
    }, .{ .whitespace = .indent_1 });
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
}
