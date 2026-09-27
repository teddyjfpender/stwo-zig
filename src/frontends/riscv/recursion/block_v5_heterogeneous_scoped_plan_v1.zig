//! Independently admitted exact scope recipe. This does not authenticate
//! endpoint/source descriptors or manufacture a complete-block result.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Full = @import("block_v5_heterogeneous_policy_v1.zig").Policy;
const Coverage = @import("../prover/block_v5_recursive_coverage_plan_v1.zig");
const Global = @import("air/block_v5_global_join_composition_v1.zig");
const Semantic = @import("block_v5_global_join_semantic_plan_v1.zig");
const Raw = @import("air/block_v5_global_join_source_values_v1.zig");
const Pairing = @import("air/block_v5_heterogeneous_pairing_v1.zig");
pub const VERSION: u32 = 1;
/// Selected by the independent typed producer/receiver, never a proof field.
pub const Recipe = enum(u32) { complete = 0, requesters = 1 };
pub fn includes(recipe: Recipe, physical: Coverage.Physical) bool {
    return recipe == .complete or switch (physical.kind) {
        .ram_lanes, .range16 => false,
        else => true,
    };
}

pub const Kind = enum(u32) { state, registers, lookup, transition, program, accounting, pairing, open, public_auth };
pub const Key = struct { kind: Kind, scope: u32, coordinate: u32 };
pub const Selection = union(enum) {
    felt: Global.Ref,
    byte: struct { child: u32, cell: u32, part: u2 },
    words: struct { child: u32, selectors: [4]Raw.Word },
    pub fn child(self: Selection) u32 {
        return switch (self) {
            .felt => |ref| ref.child,
            .byte => |ref| ref.child,
            .words => |ref| ref.child,
        };
    }
};
pub const Term = struct { selection: Selection, negative: bool = false };
pub const Disposition = enum(u32) { zero_when_complete, retain };
pub const Requirement = struct { key: Key, terms: []const Term, disposition: Disposition };
pub const Limits = struct { max_requirements: usize = 131072, max_terms: usize = 1 << 20, max_owned_bytes: usize = 256 << 20, semantic: Semantic.Limits = .{} };
pub const Plan = struct {
    recipe: Recipe = .complete,
    budget: *@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
    arena: std.heap.ArenaAllocator,
    full: Full,
    mapping: Global.MappingPin,
    semantic: Semantic.Derived,
    requirements: []const Requirement,
    limits: Limits,
    digest: [32]u8,
    pub const semantic_source_authority_pending = true;
    pub const terminal_public_authority_pending = true;
    pub fn deinit(self: *Plan) void {
        self.semantic.deinit();
        self.arena.deinit();
        self.budget.destroy();
        self.* = undefined;
    }
    pub fn validate(self: *const Plan) !void {
        try self.full.validate();
        try self.semantic.validateAgainst(self.full);
        if (!std.meta.eql(self.mapping.plan, self.semantic.seal)) return error.UntrustedScopedSummaryPlan;
        var expected_arena = std.heap.ArenaAllocator.init(self.budget.allocator());
        defer expected_arena.deinit();
        const expected = try normativeRequirements(expected_arena.allocator(), self.full, &self.semantic, self.limits, self.recipe);
        try requireNormative(self.requirements, expected);
        if (!std.meta.eql(self.mapping.coverage, self.full.plan.pinned_digest) or !std.meta.eql(self.mapping.source_seal, self.full.plan.meta.seal_digest) or self.requirements.len == 0 or self.requirements.len > self.limits.max_requirements or !std.meta.eql(self.digest, self.identity())) return error.UntrustedScopedSummaryPlan;
        var terms: usize = 0;
        for (self.requirements, 0..) |requirement, index| {
            if (index > 0 and !less({}, self.requirements[index - 1], requirement)) return error.InvalidScopedSummaryCensus;
            terms = try std.math.add(usize, terms, requirement.terms.len);
            var seen = std.AutoHashMap(Selection, void).init(self.budget.allocator());
            defer seen.deinit();
            for (requirement.terms) |term| {
                _ = try self.value(term.selection);
                const entry = try seen.getOrPut(term.selection);
                if (entry.found_existing) return error.DuplicateScopedSummaryContribution;
            }
            for (requirement.terms, 0..) |term, at| if (at > 0 and requirement.terms[at - 1].selection.child() > term.selection.child()) return error.InvalidScopedSummaryCensus;
        }
        if (terms > self.limits.max_terms) return error.ScopedSummaryResourceLimit;
    }
    pub fn value(self: *const Plan, selection: Selection) !Q {
        const ordinal = selection.child();
        if (ordinal >= self.full.children.len) return error.InvalidScopedSummarySelection;
        const source = &self.full.children[ordinal];
        return switch (selection) {
            .byte => |ref| block: {
                if (ref.cell >= source.cells.len or source.cells[ref.cell][ref.part].v > 255) return error.InvalidScopedSummarySelection;
                break :block Q.fromBase(source.cells[ref.cell][ref.part]);
            },
            .words => |ref| block: {
                const read = try Raw.read(&.{.{ .frames = source.frames, .cells = source.cells }}, .{ .child = 0, .form = .{ .words = ref.selectors } });
                break :block read.value;
            },
            .felt => |ref| block: {
                if (ref.kind != source.physical.kind or ref.index != source.physical.index or ref.frame >= source.frames.len) return error.InvalidScopedSummarySelection;
                const frame = source.frames[ref.frame];
                const values = switch (frame.operation) {
                    .felts => |values| values,
                    else => return error.InvalidScopedSummarySelection,
                };
                if (ref.felt >= values.len) return error.InvalidScopedSummarySelection;
                const first = try std.math.add(usize, frame.first, try std.math.mul(usize, ref.felt, 4));
                if (first > source.cells.len or source.cells.len - first < 4) return error.InvalidScopedSummarySelection;
                for (values[ref.felt].toM31Array(), 0..) |limb, component| {
                    if (limb.v >= core.fields.m31.Modulus) return error.NoncanonicalScopedSummary;
                    for (source.cells[first + component], 0..) |byte, part| if (byte.v != ((limb.v >> @as(u5, @intCast(8 * part))) & 255)) return error.MutatedScopedSummarySource;
                }
                break :block values[ref.felt];
            },
        };
    }
    pub fn identity(self: *const Plan) [32]u8 {
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x42355a44, VERSION }); // B5ZD
        // Preserve the original complete recipe grammar; the new requester
        // recipe cannot relabel an old scoped plan or reuse its setup key.
        if (self.recipe != .complete) channel.mixU32s(&.{ 0x52515452, @intFromEnum(self.recipe) });
        channel.mixRoot(self.mapping.plan);
        channel.mixRoot(self.mapping.coverage);
        channel.mixRoot(self.mapping.source_seal);
        channel.mixU64(self.requirements.len);
        for (self.requirements) |requirement| {
            channel.mixU32s(&.{ @intFromEnum(requirement.key.kind), requirement.key.scope, requirement.key.coordinate, @intFromEnum(requirement.disposition) });
            channel.mixU64(requirement.terms.len);
            for (requirement.terms) |term| {
                channel.mixU32s(&.{ @intFromEnum(std.meta.activeTag(term.selection)), @intFromBool(term.negative) });
                switch (term.selection) {
                    .felt => |ref| channel.mixU32s(&.{ ref.child, @intFromEnum(ref.kind), ref.index, ref.frame, ref.felt }),
                    .byte => |ref| channel.mixU32s(&.{ ref.child, ref.cell, ref.part }),
                    .words => |ref| {
                        channel.mixU32s(&.{ref.child});
                        for (ref.selectors) |word| channel.mixU32s(&.{ word.frame, word.word });
                    },
                }
            }
        }
        return channel.digestBytes();
    }
    pub fn contains(descendants: []const u32, ordinal: u32) bool {
        return std.sort.binarySearch(u32, descendants, ordinal, struct {
            fn order(key: u32, item: u32) std.math.Order {
                return std.math.order(key, item);
            }
        }.order) != null;
    }
    pub fn participates(requirement: Requirement, descendants: []const u32) bool {
        for (requirement.terms) |term| if (contains(descendants, term.selection.child())) return true;
        return false;
    }
    pub fn complete(requirement: Requirement, descendants: []const u32) bool {
        for (requirement.terms) |term| if (!contains(descendants, term.selection.child())) return false;
        return true;
    }
    pub fn termsFor(requirement: Requirement, ordinal: u32) []const Term {
        var left: usize = 0;
        var right = requirement.terms.len;
        while (left < right) {
            const middle = left + (right - left) / 2;
            if (requirement.terms[middle].selection.child() < ordinal) left = middle + 1 else right = middle;
        }
        const first = left;
        right = requirement.terms.len;
        while (left < right) {
            const middle = left + (right - left) / 2;
            if (requirement.terms[middle].selection.child() <= ordinal) left = middle + 1 else right = middle;
        }
        return requirement.terms[first..left];
    }
};
const Collector = struct {
    a: std.mem.Allocator,
    limits: Limits,
    keys: std.AutoHashMap(Key, usize),
    list: std.ArrayList(Requirement) = .empty,
    vectors: std.ArrayList(std.ArrayList(Term)) = .empty,
    terms: usize = 0,
    fn add(self: *Collector, key: Key, disposition: Disposition) !usize {
        const found = try self.keys.getOrPut(key);
        if (found.found_existing) {
            const index = found.value_ptr.*;
            if (self.list.items[index].disposition != disposition) return error.InvalidScopedSummaryCensus;
            return index;
        }
        if (self.list.items.len >= self.limits.max_requirements) return error.ScopedSummaryResourceLimit;
        const index = self.list.items.len;
        found.value_ptr.* = index;
        try self.list.append(self.a, .{ .key = key, .terms = &.{}, .disposition = disposition });
        try self.vectors.append(self.a, .empty);
        return index;
    }
    fn term(self: *Collector, key: Key, disposition: Disposition, selection: Selection, negative: bool) !void {
        const index = try self.add(key, disposition);
        self.terms = try std.math.add(usize, self.terms, 1);
        if (self.terms > self.limits.max_terms) return error.ScopedSummaryResourceLimit;
        try self.vectors.items[index].append(self.a, .{ .selection = selection, .negative = negative });
    }
    fn field(self: *Collector, full: Full, entry: Semantic.Export) !Selection {
        _ = self;
        if (entry.field.child >= full.children.len) return error.InvalidScopedSummarySelection;
        const original = full.children[entry.field.child];
        return switch (entry.field.form) {
            .felt => |field_ref| .{ .felt = .{ .child = entry.field.child, .kind = original.physical.kind, .index = original.physical.index, .frame = field_ref.frame, .felt = field_ref.index } },
            .words => |selectors| .{ .words = .{ .child = entry.field.child, .selectors = selectors } },
        };
    }
    fn accounting(self: *Collector, coordinate: u32, selection: Selection) !void {
        try self.term(.{ .kind = .accounting, .scope = 0, .coordinate = coordinate }, .retain, selection, false);
        // Coordinate 10 is the KNOWN residual only. Missing public program
        // and register compensation are explicit obligations, never zero.
        try self.term(.{ .kind = .accounting, .scope = 0, .coordinate = 10 }, .retain, selection, coordinate == 7);
    }
};
fn less(_: void, left: Requirement, right: Requirement) bool {
    if (left.key.kind != right.key.kind) return @intFromEnum(left.key.kind) < @intFromEnum(right.key.kind);
    if (left.key.scope != right.key.scope) return left.key.scope < right.key.scope;
    return left.key.coordinate < right.key.coordinate;
}
fn requireNormative(received: []const Requirement, expected: []const Requirement) !void {
    if (received.len != expected.len) return error.UntrustedScopedSummaryRecipe;
    for (received, expected) |left, right| {
        if (!std.meta.eql(left.key, right.key) or left.disposition != right.disposition or left.terms.len != right.terms.len) return error.UntrustedScopedSummaryRecipe;
        for (left.terms, right.terms) |actual, canonical| if (!std.meta.eql(actual, canonical)) return error.UntrustedScopedSummaryRecipe;
    }
}
fn normativeRequirements(a: std.mem.Allocator, full: Full, semantic: *const Semantic.Derived, limits: Limits, recipe: Recipe) ![]const Requirement {
    var collected = Collector{ .a = a, .limits = limits, .keys = std.AutoHashMap(Key, usize).init(a) };
    const group_of = try a.alloc(u32, semantic.execution_count);
    @memset(group_of, std.math.maxInt(u32));
    for (0..semantic.execution_count) |execution| {
        _ = try collected.add(.{ .kind = .state, .scope = @intCast(execution), .coordinate = 0 }, .zero_when_complete);
        // Without the separately authenticated window compensation these
        // exact original register claims remain OPEN per execution.
        _ = try collected.add(.{ .kind = .registers, .scope = @intCast(execution), .coordinate = 0 }, .retain);
    }
    for (semantic.groups) |group| {
        for (0..group.execution_count) |local| {
            const execution = try std.math.add(usize, group.first_execution, local);
            if (execution >= group_of.len or group_of[execution] != std.math.maxInt(u32)) return error.InvalidScopedSummaryCensus;
            group_of[execution] = group.index;
        }
        for (0..@import("../air/lookups/tables/schema.zig").KIND_COUNT) |kind| _ = try collected.add(.{ .kind = .lookup, .scope = group.index, .coordinate = @intCast(kind) }, .zero_when_complete);
    }
    for (group_of) |group| if (group == std.math.maxInt(u32)) return error.InvalidScopedSummaryCensus;
    _ = try collected.add(.{ .kind = .transition, .scope = 0, .coordinate = 0 }, if (recipe == .requesters) .retain else .zero_when_complete);
    _ = try collected.add(.{ .kind = .program, .scope = 0, .coordinate = 0 }, .retain);
    for ([_]u32{ 0, 1, 3, 4, 5, 6, 7, 9, 10 }) |coordinate| _ = try collected.add(.{ .kind = .accounting, .scope = 0, .coordinate = coordinate }, .retain);
    for (semantic.exports) |entry| {
        if (entry.field.child >= full.children.len) return error.InvalidScopedSummarySelection;
        if (!includes(recipe, full.children[entry.field.child].physical)) continue;
        const selection = try collected.field(full, entry);
        switch (entry.role) {
            .native_compensation, .native_state, .caller_state => {
                try collected.term(.{ .kind = .state, .scope = entry.owner, .coordinate = 0 }, .zero_when_complete, selection, false);
                // Keep the native term separately for the original PUBLIC
                // tuple equation. It is already part of native_open and must
                // NEVER be added a second time to accounting.
                if (recipe == .requesters and entry.role == .native_compensation)
                    try collected.term(.{ .kind = .public_auth, .scope = entry.owner, .coordinate = 32 }, .retain, selection, false);
            },
            .table_request, .byte_request => {
                if (entry.owner >= group_of.len) return error.InvalidScopedSummaryCensus;
                const kind = if (entry.role == .byte_request) @intFromEnum(@import("../air/lookups/tables/schema.zig").Kind.range_check_8_8) else entry.coordinate;
                try collected.term(.{ .kind = .lookup, .scope = group_of[entry.owner], .coordinate = kind }, .zero_when_complete, selection, false);
                if (entry.role == .byte_request) try collected.accounting(9, selection);
            },
            .table_provider => {
                try collected.term(.{ .kind = .lookup, .scope = entry.owner, .coordinate = entry.coordinate }, .zero_when_complete, selection, false);
                try collected.accounting(4, selection);
            },
            .transition_request, .ram_transition => try collected.term(.{ .kind = .transition, .scope = 0, .coordinate = 0 }, if (recipe == .requesters) .retain else .zero_when_complete, selection, false),
            .program_request, .program_provider => {
                try collected.term(.{ .kind = .program, .scope = 0, .coordinate = 0 }, .retain, selection, false);
                if (entry.role == .program_provider) try collected.accounting(3, selection);
            },
            .register_memory, .register_clock_memory => try collected.term(.{ .kind = .registers, .scope = entry.owner, .coordinate = 0 }, .retain, selection, false),
            .native_open => try collected.accounting(0, selection),
            .caller_open => try collected.accounting(1, selection),
            .ordinary_memory_opposite => try collected.accounting(5, selection),
            .external_memory_opposite => try collected.accounting(6, selection),
            .auxiliary_clock => try collected.accounting(7, selection),
            .ram_link, .ram_initial, .ram_endpoint, .ram_range, .range_provider => try collected.term(.{ .kind = .open, .scope = @intFromEnum(entry.role), .coordinate = entry.coordinate }, .retain, selection, false),
        }
    }
    if (recipe == .requesters) {
        // Original capacity PUBLIC digest invocation, not a search for equal
        // hashes. These bytes must be linked to the later tuple preimage AIR.
        for (full.children, full.expected, 0..) |child, expected, ordinal| {
            if (child.physical.kind != .native_arithmetic) continue;
            const admitted = switch (expected) {
                .capacity_v1 => |typed| typed.admitted,
                else => return error.UnsupportedRequesterNativeProtocol,
            };
            const digest = @import("../prover/block_v5_native_public_admission_v1.zig").publicDigest(&admitted.shape.public_data);
            if (child.frames.len <= 9 or child.frames[9].operation != .root or
                !std.meta.eql(child.frames[9].operation.root, digest)) return error.UntrustedRequesterPublicDigest;
            if (child.physical.index == 0) {
                if (child.frames.len <= 4 or child.frames[4].operation != .root or
                    !std.meta.eql(child.frames[4].operation.root, admitted.sealed.digest)) return error.UntrustedRequesterSeal;
                for (0..32) |byte| try collected.term(.{ .kind = .public_auth, .scope = 0, .coordinate = @intCast(33 + byte) }, .retain, .{ .byte = .{ .child = @intCast(ordinal), .cell = child.frames[4].first + @as(u32, @intCast(byte / 4)), .part = @intCast(byte % 4) } }, false);
            }
            for (0..32) |byte| try collected.term(.{ .kind = .public_auth, .scope = child.physical.index, .coordinate = @intCast(byte) }, .retain, .{ .byte = .{ .child = @intCast(ordinal), .cell = child.frames[9].first + @as(u32, @intCast(byte / 4)), .part = @intCast(byte % 4) } }, false);
        }
    }
    const pairs = try Pairing.pairs(a, full);
    for (pairs, 0..) |pair, index| for (0..8) |cell| for (0..4) |part| {
        const key = Key{ .kind = .pairing, .scope = @intCast(index), .coordinate = @intCast(4 * cell + part) };
        try collected.term(key, .zero_when_complete, .{ .byte = .{ .child = pair.left, .cell = pair.left_cell + @as(u32, @intCast(cell)), .part = @intCast(part) } }, false);
        try collected.term(key, .zero_when_complete, .{ .byte = .{ .child = pair.right, .cell = pair.right_cell + @as(u32, @intCast(cell)), .part = @intCast(part) } }, true);
    };
    for (collected.list.items, collected.vectors.items) |*requirement, *vector| {
        requirement.terms = try vector.toOwnedSlice(a);
        std.mem.sort(Term, @constCast(requirement.terms), {}, struct {
            fn order(_: void, left: Term, right: Term) bool {
                return left.selection.child() < right.selection.child();
            }
        }.order);
    }
    const requirements = try collected.list.toOwnedSlice(a);
    std.mem.sort(Requirement, requirements, {}, less);
    return requirements;
}
pub fn ForRecipe(comptime recipe: Recipe) type {
    return struct {
        pub fn init(backing: std.mem.Allocator, full: Full, limits: Limits) !Plan {
            return initRecipe(recipe, backing, full, limits);
        }
    };
}
pub const init = ForRecipe(.complete).init;
fn initRecipe(comptime recipe: Recipe, backing: std.mem.Allocator, full: Full, limits: Limits) !Plan {
    if (limits.max_owned_bytes == 0) return error.ScopedSummaryResourceLimit;
    // Semantic.derive selects normative frame/slot ordinals from each genuine
    // typed child policy. No caller-supplied Global.Plan chooses coordinates.
    var semantic = try Semantic.derive(backing, full, limits.semantic);
    errdefer semantic.deinit();
    const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.create(backing, limits.max_owned_bytes);
    errdefer budget.destroy();
    var arena = std.heap.ArenaAllocator.init(budget.allocator());
    errdefer arena.deinit();
    const requirements = try normativeRequirements(arena.allocator(), full, &semantic, limits, recipe);
    var result = Plan{ .recipe = recipe, .budget = budget, .arena = arena, .full = full, .mapping = .{ .plan = semantic.seal, .coverage = full.plan.pinned_digest, .source_seal = full.plan.meta.seal_digest }, .semantic = semantic, .requirements = requirements, .limits = limits, .digest = undefined };
    result.digest = result.identity();
    try result.validate();
    return result;
}
/// Pure comparison of independently derived metadata; no proof authority.
pub const testing = struct {
    pub const requireNormativeRecipe = requireNormative;
};
