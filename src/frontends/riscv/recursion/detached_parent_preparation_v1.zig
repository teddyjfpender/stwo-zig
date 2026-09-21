//! Assemble the two genuinely verified child witnesses into one parent cohort.
//! Admission topology is explicit. Every temporary child/graph/row owner can be
//! destroyed when this returns: PreparedV1 owns the complete immutable snapshot.
const recursion = struct {
    const detached_parent_components_v1 = @import("detached_parent_components_v1.zig");
    const detached_parent_prepared_v1 = @import("detached_parent_prepared_v1.zig");
    const detached_parent_protocol_v1 = @import("detached_parent_protocol_v1.zig");
};
const std = @import("std");
const core = @import("stwo_core");
const child_mod = @import("detached_child_capture_v1.zig");
const prefix_mod = @import("detached_prefix_preparation_v1.zig");
const transcript_mod = @import("detached_pcs_rows_v1.zig");
const pcs_mod = @import("detached_pcs_preparation_v1.zig");
const boundary_mod = @import("detached_boundary_preparation_v1.zig");
const composition_mod = @import("detached_composition_preparation_v1.zig");
const statement_mod = @import("detached_parent_statement_preparation_v1.zig");
const arithmetic_mod = @import("detached_parent_arithmetic_v1.zig");
const base_mod = @import("detached_parent_base_rows_v1.zig");
const cohort = recursion.detached_parent_prepared_v1;
const protocol = recursion.detached_parent_protocol_v1;
const Manifest = recursion.detached_parent_components_v1.manifest_mod.Manifest;
const command = @import("detached_segment_command_v1.zig");
pub const ProfileV1 = struct {
    sections: [2]boundary_mod.SectionProfileV1,
    memory: [2]boundary_mod.MemoryProfileV1,
};
pub const TINY_MEMORY_PROFILE_V1 = ProfileV1{
    .sections = .{ .{ .counts = .{ 1, 1, 0, 1 } }, .{ .counts = .{ 1, 1, 1, 1 } } },
    .memory = .{ .{ .entry_addresses = &.{1048832}, .exit_addresses = &.{1048832} }, .{ .entry_addresses = &.{1048832}, .exit_addresses = &.{1048832} } },
};
/// A pair later in the same job has retained entry clocks on both children.
/// This topology is explicitly admitted, never inferred from candidate words.
pub const TINY_MEMORY_CONTINUATION_PROFILE_V1 = ProfileV1{
    .sections = .{ .{ .counts = .{ 1, 1, 1, 1 } }, .{ .counts = .{ 1, 1, 1, 1 } } },
    .memory = TINY_MEMORY_PROFILE_V1.memory,
};
pub const Prepared = struct {
    cohort: *cohort.PreparedV1,
    expected: protocol.ExpectedV1,
    child_key_sha256: [2][32]u8,
    preparation_ns: u64,
    publication_mode: protocol.PublicationMode,
    pub fn deinit(self: *Prepared) void {
        self.cohort.deinit();
        self.* = undefined;
    }
};
pub fn prepare(allocator: std.mem.Allocator, children: [2]*const child_mod.OwnedV1, profile: ProfileV1) !Prepared {
    return prepareWithMode(allocator, children, profile, .root, null);
}
pub fn prepareWithMode(allocator: std.mem.Allocator, children: [2]*const child_mod.OwnedV1, profile: ProfileV1, mode: protocol.PublicationMode, admitted_manifest: ?*const Manifest) !Prepared {
    return prepareFor(.segment, allocator, children, profile, mode, admitted_manifest);
}
pub fn prepareParents(allocator: std.mem.Allocator, children: [2]*const child_mod.ParentOwnedV1, mode: protocol.PublicationMode, admitted_manifest: ?*const Manifest) !Prepared {
    return prepareFor(.parent, allocator, children, null, mode, admitted_manifest);
}
fn prepareFor(comptime family: child_mod.Family, allocator: std.mem.Allocator, children: [2]*const child_mod.OwnedFor(family), profile: ?ProfileV1, mode: protocol.PublicationMode, admitted_manifest: ?*const Manifest) !Prepared {
    var timer = try std.time.Timer.start();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var prefixes: [2]*const prefix_mod.OwnedV1 = undefined;
    var transcripts: [2]*const transcript_mod.OwnedV1 = undefined;
    var checks: [2]*const pcs_mod.OwnedV1 = undefined;
    var boundaries: [2]*const boundary_mod.OwnedV1 = undefined;
    var compositions: [2]*const composition_mod.OwnedV1 = undefined;
    for (children, 0..) |child, i| {
        const lane: u32 = @intCast(i + 1);
        var phase = try std.time.Timer.start();
        prefixes[i] = try prefix_mod.OwnedV1.init(a, child, lane);
        const prefix_ns = phase.lap();
        transcripts[i] = try transcript_mod.OwnedV1.init(a, child, prefixes[i], lane);
        const transcript_ns = phase.lap();
        checks[i] = try pcs_mod.OwnedV1.init(a, child, lane);
        const pcs_ns = phase.lap();
        boundaries[i] = if (family == .segment) try boundary_mod.OwnedV1.init(a, child, profile.?.sections[i], profile.?.memory[i]) else try boundary_mod.OwnedV1.initParent(a, child);
        const boundary_ns = phase.lap();
        compositions[i] = try composition_mod.OwnedV1.init(a, child);
        std.debug.print("DETACHED_PARENT_CHILD_PHASE lane={d} prefix_ns={d} transcript_ns={d} pcs_ns={d} boundary_ns={d} composition_ns={d}\n", .{ lane, prefix_ns, transcript_ns, pcs_ns, boundary_ns, phase.read() });
        std.debug.print("DETACHED_PARENT_CHILD lane={d} preparation_ns={d}\n", .{ lane, timer.read() });
    }
    const statement = if (family == .segment) try statement_mod.OwnedV1.initWithMode(a, boundaries[0], boundaries[1], mode) else try statement_mod.OwnedV1.initParents(a, boundaries[0], boundaries[1], mode);
    if (@import("builtin").is_test and family == .parent) {
        const rejected = try statement_mod.testStatementRejections(statement);
        std.debug.print("DETACHED_PARENT_RECURSIVE_STATEMENT rejected={d} host_admission_bypassed=true\n", .{rejected});
    }
    const arithmetic = try arithmetic_mod.OwnedV1.init(allocator, .{ .composition = compositions, .boundary = boundaries, .pcs = checks }, statement);
    defer arithmetic.deinit();
    const base = try base_mod.OwnedV1.init(a, prefixes, transcripts, checks);
    var logical = base.logicalRows();
    const graph = arithmetic.view();
    inline for (.{ 11, 12, 13, 14, 30, 31, 32 }) |row| {
        const index = cohort.logicalIndex(row);
        if (logical[index].len != 0) return error.DetachedParentDuplicateRowAuthority;
        logical[index] = graph.logical[index];
    }
    var calls: std.ArrayList(cohort.ProviderCall) = .empty;
    try calls.appendSlice(a, base.providerCalls());
    try calls.appendSlice(a, graph.provider);
    var logical_bytes: usize = 0;
    inline for (cohort.LOGICAL_ROWS, 0..) |entry, index| {
        const bytes = logical[index].len * entry.Air.LOGICAL_INPUT_COUNT * @sizeOf(core.fields.m31.M31);
        logical_bytes += bytes;
        std.debug.print("DETACHED_PARENT_ROW row={d} rows={d} logical_bytes={d}\n", .{ @intFromEnum(entry.row), logical[index].len, bytes });
    }
    std.debug.print("DETACHED_PARENT_PREPARATION rows_bytes={d} providers={d} graph_ns={d} snapshot_pending=true\n", .{ logical_bytes, calls.items.len, timer.read() });
    const prepared = try cohort.PreparedV1.initForManifest(allocator, logical, calls.items, admitted_manifest);
    errdefer prepared.deinit();
    return .{ .cohort = prepared, .expected = graph.parent_words, .child_key_sha256 = .{ children[0].keySha256(), children[1].keySha256() }, .preparation_ns = timer.read(), .publication_mode = mode };
}
