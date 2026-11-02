//! Diagnostic provenance of the existing ordered FIXED roster. No coefficients,
//! key, request values or proof are constructed. Signatures hash LOGS ONLY and
//! are never key/verification authority; equal logs can hide different programs.
const std = @import("std");
const G = @import("../../../word16_execution/geometry.zig");
const Wire = @import("../wire.zig");
const Types = @import("../types.zig");
const Meta = @import("shape_metadata.zig");
const Truth = @import("truth_components.zig");
pub const Dependence = enum { guest_program, universal_table, universal_selectors, geometry_schedule, provider_program_schedule };
pub const Part = struct {
    role: []const u8,
    dependence: Dependence,
    log: u32,
    columns: usize,
    used_columns: usize,
    native_bytes: u64,
    unused_native_bytes: u64,
};
pub const Report = struct {
    allocator: std.mem.Allocator,
    parts: []Part,
    ordered_column_logs: []u32,
    /// A physical ordered-log diagnostic, NOT a content/key identity.
    ordered_log_signature: [64]u8,
    native_bytes: u64,
    unused_native_bytes: u64,
    request_value_columns: usize = 0,
    pub fn jsonStringify(self: Report, writer: anytype) !void {
        try writer.write(.{ .parts = self.parts, .ordered_column_logs = self.ordered_column_logs, .ordered_log_signature = self.ordered_log_signature, .native_bytes = self.native_bytes, .unused_native_bytes = self.unused_native_bytes, .request_value_columns = self.request_value_columns, .scope = "source-derived diagnostic; no coefficient values hashed; not key or verification authority" });
    }
    pub fn deinit(self: *Report) void {
        self.allocator.free(self.parts);
        self.allocator.free(self.ordered_column_logs);
        self.* = undefined;
    }
};
fn part(role: []const u8, dependence: Dependence, log: u32, columns: usize, used: usize) !Part {
    if (log > 22 or used > columns) return error.InvalidFixedSourceMetadata;
    const bytes = try std.math.mul(u64, @as(u64, 1) << @intCast(log), 4);
    return .{ .role = role, .dependence = dependence, .log = log, .columns = columns, .used_columns = used, .native_bytes = try std.math.mul(u64, bytes, columns), .unused_native_bytes = try std.math.mul(u64, bytes, columns - used) };
}
fn finish(a: std.mem.Allocator, parts: []Part) !Report {
    var columns: usize = 0;
    var native: u64 = 0;
    var unused: u64 = 0;
    for (parts) |p| {
        columns = try std.math.add(usize, columns, p.columns);
        native = try std.math.add(u64, native, p.native_bytes);
        unused = try std.math.add(u64, unused, p.unused_native_bytes);
    }
    const logs = try a.alloc(u32, columns);
    errdefer a.free(logs);
    var at: usize = 0;
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("rv64-diagnostic-ordered-fixed-logs/v1\x00");
    var word: [8]u8 = undefined;
    std.mem.writeInt(u64, &word, columns, .little);
    h.update(&word);
    for (parts) |p| {
        @memset(logs[at..][0..p.columns], p.log);
        at += p.columns;
        for (0..p.columns) |_| {
            std.mem.writeInt(u64, &word, p.log, .little);
            h.update(&word);
        }
    }
    return .{ .allocator = a, .parts = parts, .ordered_column_logs = logs, .ordered_log_signature = std.fmt.bytesToHex(h.finalResult(), .lower), .native_bytes = native, .unused_native_bytes = unused };
}
pub fn cpu(a: std.mem.Allocator, program_log: u32, declaration: Wire.CpuDeclaration) !Report {
    // Only the qualified worker scope can supply fixed provenance here.
    try @import("bulk_scope.zig").declaration(declaration);
    try declaration.geometry.validate();
    var list: std.ArrayList(Part) = .empty;
    defer list.deinit(a);
    for (G.shapesForProgramLog(program_log, declaration.geometry)) |s| {
        if (s.widths[0] == 0) continue;
        const dependence: Dependence = switch (s.role) {
            .rom => .guest_program,
            .boundary => .universal_selectors,
            .shift_table, .and_table, .range16, .range8, .selection => .universal_table,
            else => .geometry_schedule,
        };
        const used = (try Meta.forOrigin(.{ .core = s.role })).widths[0];
        try list.append(a, try part(@tagName(s.role), dependence, s.log, s.widths[0], used));
    }
    for (std.enums.values(Types.Family)) |family| if (declaration.bridges.at(family)) |log| {
        const used = (try Meta.forOrigin(.{ .bridge = family })).widths[0];
        const name: []const u8 = switch (family) {
            .keccak => "keccak_bridge",
            .add => "add_bridge",
            .double => "double_bridge",
            // Rejected by the v2 scope admission above.
            else => return error.GkrV3ServiceUnsupported,
        };
        try list.append(a, try part(name, if (family == .keccak) .geometry_schedule else .provider_program_schedule, log, Types.widths(family)[0], used));
    };
    inline for (Types.bulk_kinds) |kind| if (declaration.bridges.bulk.at(kind)) |log| {
        const width = (try Meta.forOrigin(.{ .bulk = kind })).widths[0];
        try list.append(a, try part(@tagName(kind), if (kind == .jtab) .universal_table else .geometry_schedule, log, width, width));
    };
    const parts = try list.toOwnedSlice(a);
    errdefer a.free(parts);
    return finish(a, parts);
}
pub fn truth(a: std.mem.Allocator, declaration: Wire.TruthDeclaration) !Report {
    const shapes = try Truth.shapesForDeclaration(declaration);
    const parts = try a.alloc(Part, shapes.len);
    errdefer a.free(parts);
    for (shapes, parts) |shape, *p| p.* = try part(@tagName(shape.kind), switch (shape.kind) {
        .chi, .xor5, .bytes => .universal_table,
        .keccak, .product, .linear => .provider_program_schedule,
    }, shape.log_size, shape.widths()[0], shape.widths()[0]);
    return finish(a, parts);
}
