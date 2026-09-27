//! Independently admitted ORIGINAL raw/fold PAGE transcript preprocessing.
//! Owns only normative count routing and trusted fixed emission; no channel,
//! nonce, accepted capture, private value, proof MAIN or verifier token exists.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Semantic = @import("../prover/block_v5_memory_source_page_semantic_columns_v1.zig");
const Native = @import("block_v5_memory_source_page_recursive_fixed_v1.zig");
const Profiles = @import("block_v5_native_fixed_pcs_profile_v1.zig");
const Admission = @import("../prover/block_v5_memory_source_page_recursive_admission_v1.zig");
const LayoutModule = @import("air/block_v5_memory_source_page_fixed_layout_v1.zig");
const Sink = @import("air/blake3_fixed_operation_recorder_v1.zig");
const Schema = @import("air/blake3_pcs_operation_schema_v1.zig");
const Plan = @import("air/blake3_transcript_plan.zig").Plan;
const Roots = @import("air/blake3_root_sources.zig");
const Universal = @import("air/universal_challenges.zig");
pub const Limits = struct { layout: LayoutModule.Limits = .{}, sink: Sink.Limits = .{} };
pub fn ForKind(comptime kind: Semantic.Kind) type {
    const Family = Native.ForKind(kind);
    const Admitted = Admission.ForKind(kind).Prepared;
    const Profile = Profiles.ForPage(kind);
    return struct {
        pub const Owned = struct {
            const Self = @This();
            allocator: std.mem.Allocator,
            lease: ?*Budget,
            fixed: Plan,
            layout: LayoutModule.Layout,
            shape_id: [32]u8,
            template_id: [32]u8,
            retry_capacity: u32,
            limits: Limits,
            pub const fixed_setup_only = true;
            pub const commitment_trees = 10;
            pub const complete_family_setup = false;
            pub fn derive(a: std.mem.Allocator, admitted: *const Admitted, expected: [32]u8, native: *const Family.Owned, public_claims: Semantic.Claims, capacity: u32, limits: Limits) !Self {
                var profile = try Profile.derive(native, admitted, expected, public_claims);
                const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
                errdefer if (lease) |owner| owner.destroy();
                var layout = try LayoutModule.derive(kind, a, admitted, native.native.original.graph, public_claims, limits.layout);
                errdefer layout.deinit();
                var fixed = try recordForLayout(a, &layout, &profile, capacity, limits.sink);
                errdefer fixed.deinit();
                try profile.validate();
                return .{ .allocator = a, .lease = lease, .fixed = fixed, .layout = layout, .shape_id = profile.seal, .template_id = expected, .retry_capacity = capacity, .limits = limits };
            }
            pub fn validateAgainst(self: *const Self, admitted: *const Admitted, expected: [32]u8, native: *const Family.Owned, public_claims: Semantic.Claims) !void {
                try self.fixed.validate();
                var cold = try Self.derive(self.allocator, admitted, expected, native, public_claims, self.retry_capacity, self.limits);
                defer cold.deinit();
                if (!std.meta.eql(self.shape_id, cold.shape_id) or !std.meta.eql(self.template_id, cold.template_id) or !std.meta.eql(self.fixed.id, cold.fixed.id) or !std.meta.eql(self.fixed.config, cold.fixed.config) or self.layout.word_count != cold.layout.word_count or self.layout.field_count != cold.layout.field_count or self.layout.component_claim_first != cold.layout.component_claim_first or !std.meta.eql(self.layout.roots_offset, cold.layout.roots_offset)) return error.UntrustedPageRecursiveFixedTranscript;
                try equalSteps(self.layout.first, cold.layout.first);
                try equalSteps(self.layout.claims, cold.layout.claims);
            }
            pub fn deinit(self: *Self) void {
                const lease = self.lease;
                self.fixed.deinit();
                self.layout.deinit();
                self.* = undefined;
                if (lease) |owner| owner.destroy();
            }
            pub fn requireComplete(_: *const Self) error{MissingPageRecursiveFixedPublicSourcesAndContext}!void {
                return error.MissingPageRecursiveFixedPublicSourcesAndContext;
            }
        };
        /// Structural emitter only; the genuine owner above independently
        /// validates native policy/profile at both boundaries. No proposed Plan
        /// can supply transcript provenance to that constructor.
        pub fn recordForLayout(a: std.mem.Allocator, layout: *const LayoutModule.Layout, profile: anytype, capacity: u32, limits: Sink.Limits) !Plan {
            if (@TypeOf(profile.*).commitment_trees != 10) @compileError("PAGE requires its exact ten commitments");
            try profile.validate();
            try Universal.requireDrawSchema();
            if (capacity == 0 or limits.max_operations == 0 or limits.max_routed_words == 0) return error.InvalidBlake3Transcript;
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const temp = arena.allocator();
            var r = Sink.Recorder{ .a = temp, .limits = limits };
            try layout.record(&r, layout.first, LayoutModule.publicCircuit(kind));
            try r.skipCommittedRootsFor(8);
            try r.universalPairs(0, Universal.RELATION_COUNT);
            try layout.record(&r, layout.claims, LayoutModule.publicCircuit(kind));
            try r.suffix(.{ .commitment = .{ .slot = 8, .source = try Roots.caller(8) } });
            var suffix: std.ArrayList(Schema.Operation) = .empty;
            try Schema.appendPcsSuffix(temp, &suffix, profile.config, profile.deepProfile(), profile.friProfile(), 10);
            for (suffix.items) |operation| try r.suffix(operation);
            try r.check();
            return Plan.initCompact(a, .{ .namespace = 1_000_000, .attempt_capacity = capacity }, r.operations.items);
        }
    };
}
fn equalSteps(actual: []const @import("air/block_v5_recursive_statement_frames_v1.zig").Step, expected: @TypeOf(actual)) !void {
    if (actual.len != expected.len) return error.UntrustedPageRecursiveFixedTranscript;
    for (actual, expected) |a, e| if (!std.meta.eql(a, e)) return error.UntrustedPageRecursiveFixedTranscript;
}
