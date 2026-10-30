//! Bounded views over one reconstructed, root-authenticated public roster.
//! No proof/claim authority is minted here, and no alternate Values frames are
//! reconstructed. Decoded records, children and admission owners outlive us.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Sources = @import("block_v6_recursive_sources_v1.zig");
const Global = @import("block_v6_global_public_closure_v1.zig");
const Source = @import("block_v6_source_public_closure_v1.zig");
const PageProof = @import("block_v5_memory_source_unified_page_proof_v1.zig");
const PageAdmission = @import("block_v5_memory_source_page_recursive_admission_v1.zig");
const Mixed = @import("../recursion/block_v6_mixed_direct_public_v1.zig");
const Types = @import("../recursion/block_v6_mixed_claim_types_v1.zig");
const Providers = Mixed.Provider;
const Range = Providers.Definition(.range16).Bus.Values;
const Lane = Providers.Definition(.ram_lanes).Bus.Values;
const Lookup = Providers.Definition(.native_lookup).Bus.Values;
const Program = Providers.Definition(.program_table).Bus.Values;
pub const Pages = struct {
    context: *const PageProof.Context,
    raw: []const PageAdmission.ForKind(.raw).Prepared,
    fold: []const PageAdmission.ForKind(.fold).Prepared,
};
pub const Limits = struct { max_children: usize = Mixed.MAX_CHILDREN, max_metadata_bytes: usize = 16 << 20 };
pub const Owner = struct {
    a: std.mem.Allocator,
    budget: *engine.host_budget_allocator.SharedHostBudget,
    executions: []Global.Execution = &.{},
    callers: []Global.Extension = &.{},
    program: Program = undefined,
    lookup: []Lookup = &.{},
    ranges: []Range = &.{},
    lanes: []Lane = &.{},
    raw: []Source.Page(.raw) = &.{},
    fold: []Source.Page(.fold) = &.{},

    pub fn create(backing: std.mem.Allocator, sources: *const Sources.Owner, pages: Pages, records: []const Types.Record, children: []const Mixed.Child, limits: Limits) !*Owner {
        if (limits.max_children == 0 or limits.max_children > Mixed.MAX_CHILDREN or limits.max_metadata_bytes < @sizeOf(Owner) or
            records.len != children.len or children.len > limits.max_children) return error.CompletePublicInputResourceLimit;
        try (Mixed.Values{ .children = children }).validate();
        try sources.require();
        const catalog = if (sources.callers) |*value| value else return error.IncompleteCompletePublicAdmissions;
        if (pages.raw.len != pages.context.raw.len or pages.fold.len != pages.context.fold.len or
            !std.meta.eql(sources.roster.sealed, pages.context.base)) return error.UntrustedCompletePublicPageScope;
        const expected_count = try std.math.add(usize, sources.executions.len, try std.math.add(usize, try std.math.mul(usize, 2, catalog.entries.len), try std.math.add(usize, 1, try std.math.add(usize, sources.ranges.len, try std.math.add(usize, sources.lanes.len, try std.math.add(usize, sources.lookups.len, try std.math.add(usize, pages.raw.len, pages.fold.len)))))));
        if (expected_count != children.len) return error.IncompleteCompletePublicRoster;
        const budget = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(backing, limits.max_metadata_bytes);
        const a = budget.allocator();
        const self = a.create(Owner) catch |err| {
            budget.destroy();
            return err;
        };
        self.* = .{ .a = a, .budget = budget };
        errdefer self.deinit();
        self.executions = try a.alloc(Global.Execution, sources.executions.len);
        self.callers = try a.alloc(Global.Extension, catalog.entries.len);
        self.ranges = try a.alloc(Range, sources.ranges.len);
        self.lanes = try a.alloc(Lane, sources.lanes.len);
        self.lookup = try a.alloc(Lookup, sources.lookups.len);
        self.raw = try a.alloc(Source.Page(.raw), pages.raw.len);
        self.fold = try a.alloc(Source.Page(.fold), pages.fold.len);
        var cursor = Cursor{ .records = records, .children = children };
        for (sources.executions, self.executions, 0..) |*admitted, *entry, index| {
            if (admitted.native.index != index) return error.UntrustedCompletePublicNativeIndex;
            const child = try cursor.take(.{ .native = .{ .index = @intCast(index), .template = admitted.template_id } });
            entry.* = .{ .admitted = admitted, .public = child.native.value };
        }
        for (sources.ranges, self.ranges) |*admitted, *value| value.* = (try cursor.take(providerExpected(.range16, admitted))).provider.range16;
        for (sources.lanes, self.lanes) |*admitted, *value| value.* = (try cursor.take(providerExpected(.ram_lanes, admitted))).provider.ram_lanes;
        const program = if (sources.program) |*value| value else return error.MissingCompletePublicProgram;
        self.program = (try cursor.take(providerExpected(.program_table, program))).provider.program_table;
        for (sources.lookups, self.lookup) |*admitted, *value| value.* = (try cursor.take(providerExpected(.native_lookup, admitted))).provider.native_lookup;
        for (catalog.entries, self.callers) |admitted, *entry| {
            const pair = admitted.admissions;
            if (pair.arithmetic.binding.execution_index != admitted.index or pair.fused.binding.execution_index != admitted.index) return error.UntrustedCompletePublicCallerIndex;
            entry.admitted = pair;
            entry.arithmetic = (try cursor.take(.{ .auxiliary = .{ .family = .caller_arithmetic, .index = admitted.index, .template = pair.arithmetic.template_id } })).auxiliary.value.caller_arithmetic;
        }
        for (catalog.entries, self.callers) |admitted, *entry| {
            entry.fused = (try cursor.take(.{ .auxiliary = .{ .family = .caller_fused, .index = admitted.index, .template = admitted.admissions.fused.template_id } })).auxiliary.value.caller_fused;
        }
        for (pages.raw, pages.context.raw, self.raw, 0..) |*admitted, pin, *entry, index| {
            if (!std.meta.eql(admitted.pin, pin) or admitted.pin.raw.page.index != index) return error.UntrustedCompletePublicPageIndex;
            const position = cursor.next;
            const child = try cursor.take(.{ .auxiliary = .{ .family = .source_raw, .index = @intCast(index), .template = admitted.template_id } });
            const record = records[position];
            try requirePageScope(admitted, pages.context);
            entry.* = .{ .admitted = admitted, .claims = record.claim.source_raw, .public = child.auxiliary.value.source_raw };
        }
        for (pages.fold, pages.context.fold, self.fold, 0..) |*admitted, pin, *entry, index| {
            if (!std.meta.eql(admitted.pin, pin) or admitted.pin.page.index != index) return error.UntrustedCompletePublicPageIndex;
            const position = cursor.next;
            const child = try cursor.take(.{ .auxiliary = .{ .family = .source_fold, .index = @intCast(index), .template = admitted.template_id } });
            const record = records[position];
            try requirePageScope(admitted, pages.context);
            entry.* = .{ .admitted = admitted, .claims = record.claim.source_fold, .public = child.auxiliary.value.source_fold };
        }
        try cursor.finish();
        return self;
    }
    pub fn input(self: *const Owner) Global.Input {
        return .{ .executions = self.executions, .callers = self.callers, .program = self.program, .lookup = self.lookup, .source = .{ .raw = self.raw, .fold = self.fold, .lanes = self.lanes, .ranges = self.ranges } };
    }
    /// Frees views only. Original frames/claims/admissions have separate owners.
    pub fn deinit(self: *Owner) void {
        const a = self.a;
        a.free(self.fold);
        a.free(self.raw);
        a.free(self.lanes);
        a.free(self.ranges);
        a.free(self.lookup);
        a.free(self.callers);
        a.free(self.executions);
        const budget = self.budget;
        a.destroy(self);
        budget.destroy();
    }
};
fn providerExpected(comptime family: Providers.Family, admitted: *const Providers.Definition(family).Prepared) Mixed.Expected {
    return .{ .provider = .{ .family = family, .index = Providers.Definition(family).index(admitted), .template = admitted.template_id, .sealed = admitted.sealed.digest, .roots = if (family == .ram_lanes) admitted.pin.roots else admitted.roots } };
}
fn requirePageScope(admitted: anytype, context: *const PageProof.Context) !void {
    const original = admitted.context;
    if (!std.meta.eql(original.base, context.base) or !std.meta.eql(original.sealed, context.sealed) or
        !std.meta.eql(original.admitted.identity, context.admitted.identity) or !std.meta.eql(original.independent_digest, context.independent_digest) or
        !std.meta.eql(original.epoch.after_draw_digest, context.epoch.after_draw_digest)) return error.UntrustedCompletePublicPageScope;
}
const Cursor = struct {
    records: []const Types.Record,
    children: []const Mixed.Child,
    next: usize = 0,
    fn take(self: *Cursor, expected: Mixed.Expected) !Mixed.Child {
        if (self.next >= self.children.len or self.next >= self.records.len) return error.IncompleteCompletePublicRoster;
        const child = self.children[self.next];
        try Types.require(self.records[self.next], expected);
        if (!std.meta.eql(child.expected(), expected)) return error.UntrustedCompletePublicChild;
        self.next += 1;
        return child;
    }
    fn finish(self: Cursor) !void {
        if (self.next != self.children.len or self.next != self.records.len) return error.ExtraCompletePublicChild;
    }
};

test "complete public inputs reject missing and extra roster entries before any value conversion" {
    var cursor = Cursor{ .records = &.{}, .children = &.{} };
    const expected: Mixed.Expected = .{ .native = .{ .index = 0, .template = @splat(1) } };
    try std.testing.expectError(error.IncompleteCompletePublicRoster, cursor.take(expected));
    try cursor.finish();
    const records = [_]Types.Record{.{ .index = 1, .claim = .{ .program_table = @import("stwo_core").fields.qm31.QM31.zero() } }};
    cursor.records = &records;
    try std.testing.expectError(error.ExtraCompletePublicChild, cursor.finish());
}
test "complete public inputs reject changed record family and duplicate index" {
    var first: Mixed.Child = .{ .native = .{ .index = 0, .value = undefined } };
    first.native.value.template = @splat(1);
    const children = [_]Mixed.Child{ first, first };
    const record = Types.Record{ .index = 0, .claim = .{ .native = undefined } };
    const records = [_]Types.Record{ record, record };
    var cursor = Cursor{ .records = &records, .children = &children };
    _ = try cursor.take(.{ .native = .{ .index = 0, .template = @splat(1) } });
    try std.testing.expectError(error.UntrustedMixedClaimRoster, cursor.take(.{ .native = .{ .index = 1, .template = @splat(1) } }));
    try std.testing.expectError(error.UntrustedMixedClaimRoster, cursor.take(.{ .provider = .{ .family = .program_table, .index = 0, .template = @splat(1), .sealed = @splat(2), .roots = @splat(@splat(3)) } }));
}
test "complete public inputs compile exact reconstructed admission adapter" {
    const Fn = *const fn (std.mem.Allocator, *const Sources.Owner, Pages, []const Types.Record, []const Mixed.Child, Limits) anyerror!*Owner;
    var function: Fn = &Owner.create;
    const pointer: *volatile Fn = &function;
    std.mem.doNotOptimizeAway(pointer.*);
}
