//! Independently reconstructed exact physical/logical coverage and pair policy.
//! Coverage equality is admission only. No source or complete-block authority.
const std = @import("std");
const Coverage = @import("../prover/block_v5_recursive_coverage_plan_v1.zig");
const Frames = @import("block_v5_heterogeneous_child_frames_v1.zig");
const Definitions = @import("block_v5_heterogeneous_leaf_definition_v1.zig");
const Span = @import("block_v5_pc_clock_span_v1.zig");
pub const Expected = union(Coverage.Subtype) {
    native_v3: Frames.PolicyForSubtype(.native_v3),
    capacity_v1: Frames.PolicyForSubtype(.capacity_v1),
    native_fused_v2: void,
    capacity_fused_v1: Frames.PolicyForSubtype(.capacity_fused_v1),
    caller_family11_v1: Frames.PolicyForSubtype(.caller_family11_v1),
    caller_fused_v1: Frames.PolicyForSubtype(.caller_fused_v1),
    ram_lanes_v1: Frames.PolicyForSubtype(.ram_lanes_v1),
    range16_v1: Frames.PolicyForSubtype(.range16_v1),
    rom_v1: Frames.PolicyForSubtype(.rom_v1),
    six_table_lookup_v1: Frames.PolicyForSubtype(.six_table_lookup_v1),
    pub fn normalize(self: Expected, a: std.mem.Allocator, plan: *const Coverage.Plan, ordinal: u32) !Frames.Child {
        try plan.requireExact(plan.meta);
        return self.normalizeAfterExact(a, plan, ordinal);
    }
    /// Private kernel for a batch whose immutable coverage was checked once.
    /// The original typed leaf admission and normalization still run in full.
    fn normalizeAfterExact(self: Expected, a: std.mem.Allocator, plan: *const Coverage.Plan, ordinal: u32) !Frames.Child {
        if (ordinal >= plan.meta.physical.len or std.meta.activeTag(self) != plan.meta.physical[ordinal].subtype) return error.HeterogeneousLeafFamilyMismatch;
        return switch (self) {
            .native_fused_v2 => error.MissingGenuineNativeV3FusedAdapter,
            inline else => |policy| policy.normalize(a, plan.meta.physical[ordinal], plan.meta.recipe, plan.meta.seal_digest),
        };
    }
    pub fn verify(self: Expected, a: std.mem.Allocator, bytes: []const u8, plan: *const Coverage.Plan, ordinal: u32) !Frames.Fresh {
        try plan.requireExact(plan.meta);
        if (ordinal >= plan.meta.physical.len or std.meta.activeTag(self) != plan.meta.physical[ordinal].subtype) return error.HeterogeneousLeafFamilyMismatch;
        return switch (self) {
            .native_fused_v2 => error.MissingGenuineNativeV3FusedAdapter,
            inline else => |policy| policy.verify(a, bytes, plan.meta.physical[ordinal], plan.meta.recipe, plan.meta.seal_digest),
        };
    }
    pub fn requireNativeAbsence(self: Expected) !void {
        return switch (self) {
            .native_v3 => |policy| policy.requireNativeAbsence(),
            .capacity_v1 => |policy| policy.requireNativeAbsence(),
            else => error.InvalidHeterogeneousAbsence,
        };
    }
};
pub const Policy = struct {
    plan: *const Coverage.Plan,
    children: []const Frames.Child,
    /// Actual typed independently admitted leaf setups, never transported keys.
    expected: []const Expected,
    pub fn validate(self: Policy) !void {
        try self.plan.requireExact(self.plan.meta);
        const meta = self.plan.meta;
        if (self.children.len != meta.physical.len or self.expected.len != self.children.len) return error.IncompleteHeterogeneousCoverage;
        for (self.children, meta.physical, self.expected, 0..) |*child, expected, leaf_policy, ordinal| {
            try child.validate();
            var independently = try leaf_policy.normalizeAfterExact(child.arena.child_allocator, self.plan, @intCast(ordinal));
            defer independently.deinit();
            if (!std.meta.eql(child.seal, independently.seal)) return error.UntrustedHeterogeneousLeafPolicy;
            if (!std.meta.eql(child.physical, expected) or child.recipe != meta.recipe or !std.meta.eql(child.source_seal, meta.seal_digest) or !std.meta.eql(child.key.config, meta.security.recursive) or !std.meta.eql(child.key.context.child_config, meta.security.base)) return error.UntrustedHeterogeneousCoverage;
            if (Definitions.kindRuntime(expected.subtype) != expected.kind) return error.HeterogeneousLeafFamilyMismatch;
            if (child.link) |link| {
                const native = try self.find(.native_arithmetic, expected.index);
                const native_link = native.link orelse return error.MissingHeterogeneousPair;
                if (!std.meta.eql(link.execution, native_link.execution)) return error.UnpairedHeterogeneousExecution;
                if (expected.kind == .native_arithmetic) {
                    if (!std.meta.eql(expected.instance_id, link.execution) or !std.meta.eql(expected.roots, link.roots)) return error.UnpairedHeterogeneousExecution;
                } else if (expected.kind == .native_fused) {
                    try requireSameRoots(link, native_link);
                    if (link.frame == null or native_link.frame == null or !std.meta.eql(link.frame, native_link.frame)) return error.UnpairedHeterogeneousFrame;
                } else {
                    const arithmetic = try self.find(.caller_arithmetic, expected.index);
                    const arithmetic_link = arithmetic.link orelse return error.MissingHeterogeneousPair;
                    try requireSameRoots(link, arithmetic_link);
                    if (!std.meta.eql(link.caller_key, arithmetic_link.caller_key) or !std.meta.eql(link.caller_instance, arithmetic_link.caller_instance) or link.caller_key == null or link.caller_instance == null) return error.UnpairedHeterogeneousCaller;
                    if (!std.meta.eql(arithmetic.physical.instance_id, arithmetic_link.caller_instance.?)) return error.UnpairedHeterogeneousCaller;
                    if (expected.kind == .caller_fused and (link.frame == null or native_link.frame == null or !std.meta.eql(link.frame, native_link.frame))) return error.UnpairedHeterogeneousFrame;
                }
            } else switch (expected.kind) {
                .native_arithmetic, .native_fused, .caller_arithmetic, .caller_fused => return error.MissingHeterogeneousPair,
                else => {},
            }
        }
        for (meta.mappings, meta.logical) |mapping, logical| switch (mapping) {
            .unassigned => return error.IncompleteHeterogeneousCoverage,
            .physical => |ordinal| {
                if (ordinal >= self.children.len) return error.IncompleteHeterogeneousCoverage;
                const physical = self.children[ordinal].physical;
                if (logical.index != physical.index) return error.UntrustedHeterogeneousCoverage;
            },
            .native_typed_absence => |index| {
                if ((logical.family != .program_request and logical.family != .execution_sidecar) or logical.index != index) return error.InvalidHeterogeneousAbsence;
                _ = try self.find(.native_arithmetic, index);
                var admitted_absence = false;
                for (self.children, self.expected) |child, leaf_policy| if (child.physical.kind == .native_arithmetic and child.physical.index == index) {
                    try leaf_policy.requireNativeAbsence();
                    admitted_absence = true;
                };
                if (!admitted_absence) return error.InvalidHeterogeneousAbsence;
                for (self.children) |child| if (child.physical.kind == .native_fused and child.physical.index == index) return error.InvalidHeterogeneousAbsence;
            },
        };
        // Recheck after all leaf work rather than rehashing the entire roster
        // once per leaf. Public normalize/verify retain their own boundary.
        try self.plan.requireExact(self.plan.meta);
        _ = try self.nativeSpan();
    }
    pub fn find(self: Policy, kind: Coverage.Kind, index: u32) !*const Frames.Child {
        var found: ?*const Frames.Child = null;
        for (self.children) |*child| if (child.physical.kind == kind and child.physical.index == index) {
            if (found != null) return error.DuplicateHeterogeneousLeaf;
            found = child;
        };
        return found orelse error.MissingHeterogeneousPair;
    }
    pub fn nativeSpan(self: Policy) !Span.Span {
        var output: ?Span.Span = null;
        var count: u32 = 0;
        for (self.children) |child| if (child.span) |span| {
            if (child.physical.kind != .native_arithmetic or span.first_index != count or span.segment_count != 1) return error.UntrustedHeterogeneousNativeSpan;
            output = if (output) |previous| try Span.merge(&.{ previous, span }) else span;
            count += 1;
        };
        const span = output orelse return error.MissingHeterogeneousNativeSpan;
        if (count != span.job_segment_count or span.first_index != 0 or span.segment_count != count) return error.IncompleteHeterogeneousNativeSpan;
        return span;
    }
};
fn requireSameRoots(left: Frames.Link, right: Frames.Link) !void {
    if (!std.meta.eql(left.roots, right.roots)) return error.UnpairedHeterogeneousRoots;
}
/// Exactly-once sink bookkeeping. It does not verify or authenticate a leaf.
/// The caller can mark only AFTER Expected.verify returns a scoped Fresh.
pub const Census = struct {
    a: std.mem.Allocator,
    used: []bool,
    pub fn init(a: std.mem.Allocator, plan: *const Coverage.Plan) !Census {
        try plan.requireExact(plan.meta);
        const used = try a.alloc(bool, plan.meta.physical.len);
        @memset(used, false);
        return .{ .a = a, .used = used };
    }
    pub fn deinit(self: *Census) void {
        self.a.free(self.used);
        self.* = undefined;
    }
    pub fn mark(self: *Census, plan: *const Coverage.Plan, ordinal: u32, fresh: *const Frames.Fresh) !void {
        try plan.requireExact(plan.meta);
        try fresh.child.validate();
        if (ordinal >= self.used.len or self.used.len != plan.meta.physical.len or !std.meta.eql(fresh.child.physical, plan.meta.physical[ordinal]) or !std.meta.eql(fresh.child.source_seal, plan.meta.seal_digest)) return error.UntrustedHeterogeneousCoverage;
        if (self.used[ordinal]) return error.DuplicateHeterogeneousLeaf;
        self.used[ordinal] = true;
    }
    pub fn requireComplete(self: Census) !void {
        for (self.used) |used| if (!used) return error.IncompleteHeterogeneousCoverage;
    }
};
