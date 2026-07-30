//! Per-run resolution of a captured AIR program's mask reads.
//!
//! The template interpreter re-executes the whole instruction stream once per
//! four-row group, and every `trace_col` / `preprocessed_col` instruction used
//! to re-derive, on every group, facts that depend only on the instruction:
//! which commitment tree and column it names, where that column's values live,
//! and what lifting shift maps an evaluation-domain position onto them. Those
//! are resolved once per evaluated range here.
//!
//! The second redundancy this removes is per-column index derivation. The
//! bit-reversed circle-domain offset map depends only on `(row, offset)`, not
//! on the column, so all read sites sharing a mask offset share one mapped
//! lane-position vector. Captured Cairo components use two distinct offsets
//! against tens of read sites per group.
//!
//! Admission is structural: the plan is derived from the instruction stream's
//! own opcodes and immediates. Nothing inspects a workload name, path, digest,
//! or component identity.

const std = @import("std");
const eval = @import("../../witness/eval_program.zig");

/// A read site, in the order its instruction appears in `program.base_insts`.
pub fn Site(comptime ResolvedColumn: type) type {
    return struct {
        column: ResolvedColumn,
        offset_slot: u32,
    };
}

pub fn Plan(comptime ResolvedColumn: type) type {
    return struct {
        const Self = @This();

        /// Distinct mask offsets, in first-appearance order.
        offsets: []i32,
        /// One entry per read instruction, in stream order.
        sites: []Site(ResolvedColumn),

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.sites);
            allocator.free(self.offsets);
            self.* = undefined;
        }
    };
}

pub fn build(
    comptime ResolvedColumn: type,
    allocator: std.mem.Allocator,
    program: eval.Program,
    context: *const anyopaque,
    resolve: *const fn (
        context: *const anyopaque,
        interaction: u8,
        column: u32,
    ) anyerror!ResolvedColumn,
) !Plan(ResolvedColumn) {
    var read_count: usize = 0;
    for (program.base_insts) |instruction| {
        if (isRead(instruction)) read_count += 1;
    }

    const offsets = try allocator.alloc(i32, read_count);
    errdefer allocator.free(offsets);
    var offset_count: usize = 0;

    const sites = try allocator.alloc(Site(ResolvedColumn), read_count);
    errdefer allocator.free(sites);
    var cursor: usize = 0;

    for (program.base_insts) |instruction| {
        if (!isRead(instruction)) continue;
        var slot: usize = offset_count;
        for (offsets[0..offset_count], 0..) |offset, index| {
            if (offset == instruction.imm) {
                slot = index;
                break;
            }
        }
        if (slot == offset_count) {
            offsets[offset_count] = instruction.imm;
            offset_count += 1;
        }
        sites[cursor] = .{
            .column = try resolve(context, instruction.interaction, instruction.a),
            .offset_slot = @intCast(slot),
        };
        cursor += 1;
    }

    // Right-size rather than sub-slice. `deinit` frees `offsets`, and freeing a
    // sub-slice of an allocation is invalid: a checking allocator rejects it
    // outright and a non-checking one silently mismatches the length. Captured
    // Cairo components share mask offsets across tens of read sites, so
    // `offset_count < read_count` is the normal case, not an edge case. The
    // `errdefer` above stays correct: a failed `realloc` leaves `offsets` valid.
    const trimmed = try allocator.realloc(offsets, offset_count);
    return .{
        .offsets = trimmed,
        .sites = sites,
    };
}

fn isRead(instruction: eval.BaseInst) bool {
    return instruction.op == .trace_col or instruction.op == .preprocessed_col;
}

test "read plan: sites keep stream order and share one slot per offset" {
    const allocator = std.testing.allocator;
    const Resolved = struct { interaction: u8, column: u32 };
    const Resolver = struct {
        fn resolve(
            _: *const anyopaque,
            interaction: u8,
            column: u32,
        ) anyerror!Resolved {
            return .{ .interaction = interaction, .column = column };
        }
    };
    const program = eval.Program{
        .allocator = allocator,
        .header = .{
            .flags = 0,
            .semantic_hash = 0,
            .capability_bits = 0,
            .n_interactions = 3,
            .n_base_params = 0,
            .n_ext_params = 0,
            .n_constraints = 0,
            .max_base_regs = 4,
            .max_ext_regs = 0,
            .domain_log_size = 4,
        },
        .base_consts = &.{},
        .ext_consts = &.{},
        .base_insts = @constCast(&[_]eval.BaseInst{
            .{ .op = .trace_col, .interaction = 1, .dst = 0, .a = 5, .b = 0, .imm = 0 },
            .{ .op = .add, .interaction = 0, .dst = 1, .a = 0, .b = 0, .imm = 0 },
            .{ .op = .trace_col, .interaction = 1, .dst = 2, .a = 6, .b = 0, .imm = -1 },
            .{ .op = .preprocessed_col, .interaction = 0, .dst = 3, .a = 7, .b = 0, .imm = 0 },
        }),
        .ext_insts = &.{},
        .constraint_roots = &.{},
    };

    var dummy: u8 = 0;
    var plan = try build(
        Resolved,
        allocator,
        program,
        @ptrCast(&dummy),
        Resolver.resolve,
    );
    defer plan.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), plan.offsets.len);
    try std.testing.expectEqual(@as(i32, 0), plan.offsets[0]);
    try std.testing.expectEqual(@as(i32, -1), plan.offsets[1]);
    try std.testing.expectEqual(@as(usize, 3), plan.sites.len);
    try std.testing.expectEqual(@as(u32, 5), plan.sites[0].column.column);
    try std.testing.expectEqual(@as(u32, 0), plan.sites[0].offset_slot);
    try std.testing.expectEqual(@as(u32, 6), plan.sites[1].column.column);
    try std.testing.expectEqual(@as(u32, 1), plan.sites[1].offset_slot);
    try std.testing.expectEqual(@as(u32, 7), plan.sites[2].column.column);
    try std.testing.expectEqual(@as(u32, 0), plan.sites[2].offset_slot);
    try std.testing.expectEqual(@as(u8, 0), plan.sites[2].column.interaction);
}
