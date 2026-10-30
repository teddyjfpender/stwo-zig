//! Compact offsets for the exact original caller projection equations.
const std = @import("std");
const Layout = @import("block_v7_caller_active_layout_v1.zig").Layout;
const P = @import("blake3_ethereum_sha_profile.zig");
const Old = @import("block_v5_caller_fused_schedule_v1.zig");
const Tables = @import("block_v5_precompile_lookup_source_v1.zig");
const External = @import("block_execution_external_trace_v2.zig");
pub const Schedule = Old.Schedule;
pub fn derive(a: std.mem.Allocator, statement: *const P.admission.Statement, steps: u32, frame: @import("../air/block/memory_event.zig").Frame) !Schedule {
    const layout = try Layout.derive(statement, steps);
    var out = try Schedule.init(a, statement, steps, frame, 1);
    errdefer out.deinit();
    const fixed = try layout.columnLogs(a, 0);
    errdefer a.free(fixed);
    const main = try layout.columnLogs(a, 1);
    errdefer a.free(main);
    for (out.program) |*slot| {
        if (slot.kind == .signer and !layout.active[13]) return error.OmittedActiveCallerDependency;
        if (slot.kind == .keccak and !layout.active[0]) return error.OmittedActiveCallerDependency;
        slot.main_offset = try layout.map(1, slot.main_offset, slot.main_columns);
        if (slot.fixed_selector_offset) |offset| slot.fixed_selector_offset = try layout.map(0, offset, 1);
    }
    var retained: std.ArrayList(Tables.Slot) = .empty;
    defer retained.deinit(a);
    for (out.tables) |original| {
        // Padded zero-call SHA rows emit lookup requests in the full roster.
        // The active protocol omits both those AIRs and their projections;
        // its producer must use active lookup registration as well.
        if (@intFromEnum(original.source) >= @intFromEnum(Tables.Kind.sha_source) and !layout.active[14]) {
            if (statement.sha.call_count != 0) return error.OmittedActiveCallerDependency;
            continue;
        }
        // The old empty signer table slots have no requests; their AIR is
        // omitted only under the independently authenticated zero call count.
        if (original.source == .signer and !layout.active[13]) {
            // Slot.n_rows counts the padded domain, not live calls.
            // The independently admitted caller descriptor owns liveness.
            if (statement.ethereum.components[13].n_rows != 0) return error.OmittedActiveCallerDependency;
            continue;
        }
        if (original.source == .keccak and !layout.active[0]) {
            if (statement.ethereum.components[0].n_rows != 0) return error.OmittedActiveCallerDependency;
            continue;
        }
        var slot = original;
        slot.fixed_offset = try layout.map(0, slot.fixed_offset, slot.fixed_width);
        slot.main_offset = try layout.map(1, slot.main_offset, slot.width);
        try retained.append(a, slot);
    }
    const tables = try retained.toOwnedSlice(a);
    a.free(out.tables);
    out.tables = tables;
    for (out.memory) |*slot| {
        if (slot.kind == .signer and !layout.active[13]) return error.OmittedActiveCallerDependency;
        if (slot.kind == .keccak and !layout.active[0]) return error.OmittedActiveCallerDependency;
        slot.main_offset = try layout.map(1, slot.main_offset, slot.mainWidth());
        // Descriptor fixed fields for signer are unused. Canonical zero still
        // keeps them bounded and stable rather than mapping an omitted range.
        slot.fixed_offset = if (slot.kind == .signer) 0 else try layout.map(0, slot.fixed_offset, 1);
    }
    var masks = try @import("block_execution_external_batch_v2.zig").masks(a, out.memory, fixed.len, main.len);
    errdefer masks.deinit(a);
    for (out.program) |slot| {
        if (slot.fixed_selector_offset) |offset| masks.fixed[offset] = true;
        @memset(masks.main[slot.main_offset..][0..slot.main_columns], true);
    }
    for (out.tables) |slot| {
        @memset(masks.fixed[slot.fixed_offset..][0..slot.fixed_width], true);
        @memset(masks.main[slot.main_offset..][0..slot.width], true);
    }
    out.masks.deinit(a);
    out.masks = masks;
    a.free(out.fixed);
    a.free(out.main);
    out.fixed = fixed;
    out.main = main;
    out.split = @max(2, @import("block_v5_precompile_lookup_algebra_v1.zig").compositionSplit(out.tables));
    return out;
}
