//! Independently derived compact/public-root bridge selectors. Counts/checksums
//! never substitute genuine child verification or source completeness.
const std = @import("std");
const core = @import("stwo_core");
const Owner = @import("block_v5_heterogeneous_scoped_owner_v1.zig");
const Scoped = @import("block_v5_heterogeneous_scoped_plan_v1.zig");
const Semantic = @import("block_v5_global_join_semantic_plan_v1.zig");
const Source = @import("block_v5_heterogeneous_scoped_public_source_v1.zig");
const Raw = @import("air/block_v5_global_join_source_values_v1.zig");
const Norm = @import("block_v5_global_public_export_normalizer_v1.zig");
pub const Limits = struct { max_windows: usize = 4096, max_native_fields: usize = 4096, semantic: Semantic.Limits = .{} };
pub const Window = struct { registers: u32, native_fields: []const Raw.Field, terms: [3]@import("block_v5_global_public_export_bus_v1.zig").ExportCell, cycles: Norm.WindowLayout };
pub const Plan = struct {
    allocator: std.mem.Allocator,
    windows: []Window,
    program: u32,
    known_residual: u32,
    digest: [32]u8,
    pinned_digest: [32]u8,
    pub const complete_block_authority = false;
    pub fn deinit(self: *Plan) void {
        for (self.windows) |window| self.allocator.free(window.native_fields);
        self.allocator.free(self.windows);
        self.* = undefined;
    }
    pub fn identity(self: *const Plan, owner: *const Owner.Owner, public: *const Source.Source) [32]u8 {
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x42354743, 0x4d503150, 1, @intCast(self.windows.len), self.program, self.known_residual });
        channel.mixRoot(owner.pinned_identity);
        channel.mixRoot(public.expected_id);
        channel.mixRoot(public.fresh.normalized.public_input_digest);
        channel.mixRoot(public.fresh.normalization_source);
        for (self.windows, 0..) |window, index| {
            channel.mixU32s(&.{ @intCast(index), window.registers, @intCast(window.native_fields.len) });
            for (window.native_fields) |field| {
                channel.mixU32s(&.{ field.child, @intFromEnum(std.meta.activeTag(field.form)) });
                switch (field.form) {
                    .felt => |felt| channel.mixU32s(&.{ felt.frame, felt.index }),
                    .words => |words| for (words) |word| channel.mixU32s(&.{ word.frame, word.word }),
                }
            }
            for (window.terms) |term| channel.mixU32s(&.{ term.window, @intFromEnum(term.kind), term.frame, term.index, term.first_cell });
            inline for (std.meta.fields(Norm.WindowLayout)) |field| {
                const coordinate = @field(window.cycles, field.name);
                channel.mixU32s(&.{@intFromBool(coordinate != null)});
                if (coordinate) |part| channel.mixU32s(&.{ part.frame, part.first_cell, part.word_count });
            }
        }
        return channel.digestBytes();
    }
    pub fn validate(self: *const Plan, owner: *const Owner.Owner, public: *const Source.Source) !void {
        try public.validate();
        if (!std.meta.eql(self.digest, self.pinned_digest) or !std.meta.eql(self.digest, self.identity(owner, public))) return error.UntrustedScopedPublicBridgeRecipe;
        if (self.windows.len != public.public.fields.len) return error.UntrustedScopedPublicBridgeCensus;
        // Source/policy binding was independently established by init, while
        // each current descriptor/term remains checked against the genuine
        // new-root normalized invocation recipe.
        for (self.windows, 0..) |window, index| {
            if (window.registers != try requirement(owner, .{ .kind = .registers, .scope = @intCast(index), .coordinate = 0 }) or
                !std.meta.eql(window.terms, try public.fresh.normalized.exportTerms(@intCast(index))) or
                !std.meta.eql(window.cycles, try public.fresh.normalized.window(@intCast(index)))) return error.UntrustedScopedPublicBridgeRecipe;
        }
        if (self.program != try requirement(owner, .{ .kind = .program, .scope = 0, .coordinate = 0 }) or self.known_residual != try requirement(owner, .{ .kind = .accounting, .scope = 0, .coordinate = 10 })) return error.UntrustedScopedPublicBridgeRecipe;
    }
};
pub fn requirement(owner: *const Owner.Owner, key: Scoped.Key) !u32 {
    var found: ?u32 = null;
    for (owner.scoped.requirements, 0..) |required, index| if (std.meta.eql(required.key, key)) {
        if (found != null) return error.UntrustedScopedPublicBridgeRecipe;
        found = @intCast(index);
    };
    return found orelse error.MissingScopedPublicBridgeScope;
}
pub fn init(a: std.mem.Allocator, owner: *const Owner.Owner, public: *const Source.Source, limits: Limits) !Plan {
    var lease = try owner.borrow();
    defer lease.deinit();
    try public.validate();
    const policy = public.public.policy.original;
    try policy.validate();
    if (!std.meta.eql(policy.plan.pinned_digest, owner.pins.coverage) or !std.meta.eql(policy.plan.meta.seal_digest, owner.pins.source) or policy.plan.meta.recipe != owner.pins.recipe or policy.children.len != owner.full.children.len) return error.UnpairedScopedPublicSource;
    for (policy.children, owner.full.children) |*actual, *expected| if (!std.meta.eql(actual.seal, expected.seal)) return error.UnpairedScopedPublicSource;
    if (public.public.fields.len == 0 or public.public.fields.len > limits.max_windows) return error.ScopedPublicBridgeResourceLimit;
    var semantic = try Semantic.derive(a, owner.full, limits.semantic);
    defer semantic.deinit();
    if (semantic.execution_count != public.public.fields.len) return error.UntrustedScopedPublicBridgeCensus;
    const windows = try a.alloc(Window, semantic.execution_count);
    var initialized: usize = 0;
    errdefer {
        for (windows[0..initialized]) |window| a.free(window.native_fields);
        a.free(windows);
    }
    var total_fields: usize = 0;
    for (windows, 0..) |*window, index| {
        var fields: std.ArrayList(Raw.Field) = .empty;
        defer fields.deinit(a);
        for (semantic.exports) |entry| if (entry.role == .native_compensation and entry.owner == index) try fields.append(a, entry.field);
        if (fields.items.len != 1) return error.UntrustedScopedPublicBridgeCensus;
        total_fields = try std.math.add(usize, total_fields, fields.items.len);
        if (total_fields > limits.max_native_fields) return error.ScopedPublicBridgeResourceLimit;
        const register_id = try requirement(owner, .{ .kind = .registers, .scope = @intCast(index), .coordinate = 0 });
        const term_cells = try public.fresh.normalized.exportTerms(@intCast(index));
        const cycle_cells = try public.fresh.normalized.window(@intCast(index));
        window.* = .{ .registers = register_id, .native_fields = try fields.toOwnedSlice(a), .terms = term_cells, .cycles = cycle_cells };
        initialized += 1;
    }
    var result = Plan{ .allocator = a, .windows = windows, .program = try requirement(owner, .{ .kind = .program, .scope = 0, .coordinate = 0 }), .known_residual = try requirement(owner, .{ .kind = .accounting, .scope = 0, .coordinate = 10 }), .digest = undefined, .pinned_digest = undefined };
    result.digest = result.identity(owner, public);
    result.pinned_digest = result.digest;
    return result;
}
