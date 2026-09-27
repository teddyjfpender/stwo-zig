//! Full original native RAM/range verifier fixed roster and public schedule.
//! Independently admitted native policy supplies expected setup. Fresh proof
//! verification is separate; whole-family live parity remains to be qualified.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Word = @import("block_v5_word_recursive_fixed_v1.zig");
const Transcript = @import("block_v5_word_recursive_fixed_transcript_v1.zig");
const Pcs = @import("block_v5_native_recursive_fixed_pcs_v1.zig");
const Sources = @import("block_v5_word_recursive_fixed_sources_v1.zig");
const Public = @import("block_v5_word_recursive_fixed_public_v1.zig");
const OriginalRoster = @import("block_v5_recursive_parent_fixed_roster_v1.zig");
const Assembly = @import("block_v5_recursive_parent_fixed_assembly_v1.zig");
const Storage = @import("air/blake3_parent_row_storage.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
pub const Limits = struct {
    max_bytes: usize = 2 << 30,
    native: Word.Limits = .{},
    transcript: Transcript.Limits = .{},
};
pub fn ForFamily(comptime family: @import("air/block_v5_word_recursive_shape_composition_v1.zig").Family) type {
    const Native = Word.ForFamily(family);
    const TypedTranscript = Transcript.ForFamily(family);
    const TypedPcs = Pcs.ForWord(family);
    const TypedSources = Sources.ForFamily(family);
    const TypedPublic = Public.ForFamily(family);
    const Admission = if (family == .ram_lanes) @import("../prover/block_v5_ram_lanes_recursive_admission_v1.zig") else @import("../prover/block_v5_range16_recursive_admission_v1.zig");
    const Bus = if (family == .ram_lanes) @import("block_v5_ram_lanes_recursive_public_bus_v1.zig") else @import("block_v5_range16_recursive_public_bus_v1.zig");
    const Protocol = if (family == .ram_lanes) @import("block_v5_reusable_ram_lanes_parent_protocol_v1.zig") else @import("block_v5_reusable_range16_parent_protocol_v1.zig");
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
            pub const complete_block_authority = false;
            pub const whole_family_live_parity_qualified = false;
            pub fn derive(backing: std.mem.Allocator, admitted: *const Admission.Prepared, expected: [32]u8, capacity: u32, profile: Base.Profile, limits: Limits) !Self {
                @setEvalBranchQuota(20_000);
                if (capacity == 0 or limits.max_bytes == 0) return error.WordFixedRosterResourceLimit;
                try admitted.validate(expected);
                if (!std.meta.eql(admitted.config, profile.config())) return error.WordFixedRosterSecurityMismatch;
                const budget = try Budget.createRetainingParent(backing, limits.max_bytes);
                errdefer budget.destroy();
                const a = budget.allocator();
                const native = try Native.Owned.derive(a, admitted, expected, limits.native);
                defer native.deinit();
                var transcript = try TypedTranscript.Owned.derive(a, admitted, expected, native.shape, capacity, limits.transcript);
                defer transcript.deinit();
                const pcs = try TypedPcs.derive(a, native, admitted, expected, &transcript);
                defer pcs.deinit();
                const sources = try TypedSources.derive(a, native, admitted, expected, &transcript);
                defer sources.deinit();
                var public = try TypedPublic.Owned.derive(a, native, admitted, expected, &transcript);
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
                return .{ .allocator = a, .budget = budget, .fixed = fixed, .wires = wires, .context = context, .profile = profile, .retry_capacity = capacity, .limits = limits, .shape_id = native.shape.seal };
            }
            pub fn validateAgainst(self: *const Self, admitted: *const Admission.Prepared, expected: [32]u8, capacity: u32, profile: Base.Profile, limits: Limits) !void {
                if (self.retry_capacity != capacity or self.profile != profile or !std.meta.eql(self.limits, limits)) return error.UntrustedWordFixedRoster;
                var original = try Self.derive(self.allocator, admitted, expected, capacity, profile, limits);
                defer original.deinit();
                if (!std.meta.eql(self.context, original.context) or !std.meta.eql(self.shape_id, original.shape_id) or self.wires.len != original.wires.len) return error.UntrustedWordFixedRoster;
                for (self.wires, original.wires) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedWordFixedRoster;
                inline for (0..Storage.Airs.len) |i| {
                    if (self.fixed[i].len != original.fixed[i].len) return error.UntrustedWordFixedRoster;
                    for (self.fixed[i], original.fixed[i]) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedWordFixedRoster;
                }
            }
            /// Only actual original live Prepared instances may establish this
            /// parity. No fixture capture/admission or private MAIN is created.
            pub fn validateLive(self: *const Self, live: *Bus.Prepared) !void {
                try live.recursive.rows.partitionHashRows();
                if (!std.meta.eql(self.context, live.recursive.context) or self.wires.len != live.wires.len) return error.UntrustedWordFixedRoster;
                for (self.wires, live.wires) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedWordFixedRoster;
                inline for (0..Storage.Airs.len) |i| {
                    if (self.fixed[i].len != live.recursive.rows.fixed[i].len) return error.UntrustedWordFixedRoster;
                    for (self.fixed[i], live.recursive.rows.fixed[i]) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedWordFixedRoster;
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
                    pub fn deinit(self: *@This()) void {
                        self.allocator.free(self.wires);
                        self.* = undefined;
                    }
                };
                /// The owner is constructed and consumed entirely in this
                /// call, so no caller-supplied mutable fixed roster needs cold
                /// reconstruction. The original admission is checked on both
                /// sides of the commitment. Only key/public routing escapes.
                pub fn deriveKeyAndScheduleForPolicy(a: std.mem.Allocator, admitted: *const Admission.Prepared, expected: [32]u8, capacity: u32, profile: Base.Profile, limits: Limits) !KeyAndSchedule {
                    var owned = try Owned.derive(a, admitted, expected, capacity, profile, limits);
                    defer owned.deinit();
                    const base = try Parent.ForBackend(Backend).deriveKeyFromFixed(a, owned.fixed, owned.context, profile);
                    const key = try Protocol.Key.fromGeometry(base, owned.wires);
                    _ = try key.identity();
                    const wires = try a.dupe(Bus.Wire, owned.wires);
                    errdefer a.free(wires);
                    try admitted.validate(expected);
                    return .{ .allocator = a, .key = key, .wires = wires };
                }
                pub fn deriveKey(a: std.mem.Allocator, owned: *const Owned, admitted: *const Admission.Prepared, expected: [32]u8, capacity: u32, profile: Base.Profile, limits: Limits) !Protocol.Key {
                    try owned.validateAgainst(admitted, expected, capacity, profile, limits);
                    const base = try Parent.ForBackend(Backend).deriveKeyFromFixed(a, owned.fixed, owned.context, profile);
                    const key = try Protocol.Key.fromGeometry(base, owned.wires);
                    _ = try key.identity();
                    return key;
                }
            };
        }
    };
}
