//! Full original PAGE raw/fold verifier fixed roster and public schedule.
//! Cold original admission, not a capture or received key, selects setup.
//! Fresh original verification and whole-source/block closure remain separate.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const NativeModule = @import("block_v5_memory_source_page_recursive_fixed_v1.zig");
const Shape = @import("block_v5_memory_source_page_recursive_shape_v1.zig");
const Semantic = @import("../prover/block_v5_memory_source_page_semantic_columns_v1.zig");
const Transcript = @import("block_v5_memory_source_page_recursive_fixed_transcript_v1.zig");
const Pcs = @import("block_v5_native_recursive_fixed_pcs_v1.zig");
const Sources = @import("block_v5_memory_source_page_recursive_fixed_sources_v1.zig");
const Public = @import("block_v5_memory_source_page_recursive_fixed_public_v1.zig");
const OriginalRoster = @import("block_v5_recursive_parent_fixed_roster_v1.zig");
const Assembly = @import("block_v5_recursive_parent_fixed_assembly_v1.zig");
const Storage = @import("air/blake3_parent_row_storage.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
pub const Limits = struct {
    max_bytes: usize = 2 << 30,
    native: Shape.Limits = .{},
    transcript: Transcript.Limits = .{},
};
pub fn ForKind(comptime kind: Semantic.Kind) type {
    const Native = NativeModule.ForKind(kind);
    const TypedTranscript = Transcript.ForKind(kind);
    const TypedPcs = Pcs.ForPage(kind);
    const TypedSources = Sources.ForKind(kind);
    const TypedPublic = Public.ForKind(kind);
    const Admission = @import("../prover/block_v5_memory_source_page_recursive_admission_v1.zig").ForKind(kind);
    const Bus = @import("block_v5_memory_source_page_recursive_public_bus_v1.zig").ForKind(kind);
    const Protocol = @import("block_v5_reusable_memory_source_page_parent_protocol_v1.zig").ForKind(kind);
    return struct {
        pub const Owned = struct {
            const Self = @This();
            allocator: std.mem.Allocator,
            budget: *Budget,
            fixed: Storage.FixedTuple(false),
            wires: []Bus.Wire,
            context: Base.Context,
            profile: Base.Profile,
            retry_capacity: u32,
            limits: Limits,
            shape_id: [32]u8,
            pub const fixed_setup_only = true;
            pub const complete_family_setup = true;
            pub const reusable_across_instances = false;
            pub const complete_block_authority = false;
            pub const whole_family_live_parity_qualified = false;
            pub fn derive(backing: std.mem.Allocator, admitted: *const Admission.Prepared, expected: [32]u8, public_claims: Semantic.Claims, capacity: u32, profile: Base.Profile, limits: Limits) !Self {
                @setEvalBranchQuota(20_000);
                if (capacity == 0 or limits.max_bytes == 0) return error.PageFixedRosterResourceLimit;
                try admitted.validate(expected);
                if (!std.meta.eql(admitted.config, profile.config())) return error.PageFixedRosterSecurityMismatch;
                const budget = try Budget.createRetainingParent(backing, limits.max_bytes);
                errdefer budget.destroy();
                const a = budget.allocator();
                const native = try Native.Owned.derive(a, admitted, expected, public_claims, limits.native);
                defer native.deinit();
                var transcript = try TypedTranscript.Owned.derive(a, admitted, expected, native, public_claims, capacity, limits.transcript);
                defer transcript.deinit();
                const pcs = try TypedPcs.derive(a, native, admitted, expected, public_claims, &transcript);
                defer pcs.deinit();
                const sources = try TypedSources.derive(a, native, admitted, expected, public_claims, &transcript);
                defer sources.deinit();
                var public = try TypedPublic.Owned.derive(a, native, admitted, expected, public_claims, &transcript);
                defer public.deinit();
                const selectors = try Assembly.selectorsForGraphs(a, &native.deep_graph, &native.fri_graph);
                const fixed = try OriginalRoster.compileOriginalRoster(a, sources, null, pcs.openings, pcs.ports, &transcript.fixed, &pcs.paths, &native.arithmetic, selectors, &native.deep_graph);
                errdefer inline for (0..Storage.Airs.len) |i| a.free(fixed[i]);
                const wires = try a.dupe(Bus.Wire, public.wires);
                errdefer a.free(wires);
                const context = Base.Context{ .child_key_id = expected, .child_config = admitted.config, .graph_ids = .{ native.composition.circuit.identity_digest, native.deep_graph.graph().identity_digest, native.fri_graph.graph().identity_digest }, .transcript_plan_id = transcript.fixed.id };
                _ = try Base.contextIdentity(context);
                _ = try Bus.scheduleDigest(wires);
                try admitted.validate(expected);
                return .{ .allocator = a, .budget = budget, .fixed = fixed, .wires = wires, .context = context, .profile = profile, .retry_capacity = capacity, .limits = limits, .shape_id = transcript.shape_id };
            }
            pub fn validateAgainst(self: *const Self, admitted: *const Admission.Prepared, expected: [32]u8, public_claims: Semantic.Claims, capacity: u32, profile: Base.Profile, limits: Limits) !void {
                if (self.retry_capacity != capacity or self.profile != profile or !std.meta.eql(self.limits, limits)) return error.UntrustedPageFixedRoster;
                var original = try Self.derive(self.allocator, admitted, expected, public_claims, capacity, profile, limits);
                defer original.deinit();
                if (!std.meta.eql(self.context, original.context) or !std.meta.eql(self.shape_id, original.shape_id) or self.wires.len != original.wires.len) return error.UntrustedPageFixedRoster;
                for (self.wires, original.wires) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedPageFixedRoster;
                inline for (0..Storage.Airs.len) |i| {
                    if (self.fixed[i].len != original.fixed[i].len) return error.UntrustedPageFixedRoster;
                    for (self.fixed[i], original.fixed[i]) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedPageFixedRoster;
                }
            }
            /// Only actual original live Prepared instances may establish this
            /// parity. No fixture capture/admission or private MAIN is created.
            pub fn validateLive(self: *const Self, live: *Bus.Prepared) !void {
                try live.recursive.rows.partitionHashRows();
                if (!std.meta.eql(self.context, live.recursive.context) or self.wires.len != live.wires.len) return error.UntrustedPageFixedRoster;
                for (self.wires, live.wires) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedPageFixedRoster;
                inline for (0..Storage.Airs.len) |i| {
                    if (self.fixed[i].len != live.recursive.rows.fixed[i].len) return error.UntrustedPageFixedRoster;
                    for (self.fixed[i], live.recursive.rows.fixed[i]) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedPageFixedRoster;
                }
            }
            pub fn deinit(self: *Self) void {
                const a = self.allocator;
                const budget = self.budget;
                a.free(self.wires);
                inline for (0..Storage.Airs.len) |i| a.free(self.fixed[i]);
                self.* = undefined;
                budget.destroy();
            }
        };
        pub fn ForBackend(comptime Backend: type) type {
            return struct {
                pub const KeyAndSchedule = struct {
                    allocator: std.mem.Allocator,
                    key: Protocol.Key,
                    wires: []Bus.Wire,
                    allocation_owner: ?*Budget = null,
                    pub fn deinit(self: *@This()) void {
                        const lease = self.allocation_owner;
                        self.allocator.free(self.wires);
                        self.* = undefined;
                        if (lease) |owner| owner.destroy();
                    }
                };
                /// No caller-supplied fixed rows enter this constructor. The
                /// cold admitted owner is committed once and released before
                /// any native proof decoding; only key and routing escape.
                pub fn deriveKeyAndScheduleForPolicy(a: std.mem.Allocator, admitted: *const Admission.Prepared, expected: [32]u8, public_claims: Semantic.Claims, capacity: u32, profile: Base.Profile, limits: Limits) !KeyAndSchedule {
                    var owned = try Owned.derive(a, admitted, expected, public_claims, capacity, profile, limits);
                    defer owned.deinit();
                    const base = try Parent.ForBackend(Backend).deriveKeyFromFixed(a, owned.fixed, owned.context, profile);
                    const key = try Protocol.Key.fromGeometry(base, owned.wires);
                    _ = try key.identity();
                    const wires = try a.dupe(Bus.Wire, owned.wires);
                    errdefer a.free(wires);
                    try admitted.validate(expected);
                    const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
                    return .{ .allocator = a, .key = key, .wires = wires, .allocation_owner = lease };
                }
                pub fn deriveKey(a: std.mem.Allocator, owned: *const Owned, admitted: *const Admission.Prepared, expected: [32]u8, public_claims: Semantic.Claims, capacity: u32, profile: Base.Profile, limits: Limits) !Protocol.Key {
                    try owned.validateAgainst(admitted, expected, public_claims, capacity, profile, limits);
                    const base = try Parent.ForBackend(Backend).deriveKeyFromFixed(a, owned.fixed, owned.context, profile);
                    const key = try Protocol.Key.fromGeometry(base, owned.wires);
                    _ = try key.identity();
                    return key;
                }
            };
        }
    };
}
