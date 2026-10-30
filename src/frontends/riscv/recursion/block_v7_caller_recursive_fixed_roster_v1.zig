//! Complete independent fixed verifier roster for the original joint caller
//! STARK. This setup code is not a proof or complete execution closure.
//! Shared implementation: default and finite active caller families.
pub fn For(comptime Policy: type) type {
    return struct {
        const std = @import("std");
        const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
        const Native = Policy.Fixed;
        const Profile = Policy.FixedProfile;
        const Transcript = Policy.FixedTranscript;
        const Statement = Policy.Statement;
        const Storage = @import("air/blake3_parent_row_storage.zig");
        const Namespace = @import("air/block_v5_recursive_fixed_namespace_v1.zig");
        const Assembly = @import("block_v5_recursive_parent_fixed_assembly_v1.zig");
        const Sources = @import("air/block_v5_recursive_parent_fixed_sources_v1.zig").ForPieces(void).Owned;
        const Pcs = @import("block_v5_native_recursive_fixed_pcs_v1.zig").ForCommitments(6).Owned;
        const Roster = @import("block_v5_recursive_parent_fixed_roster_v1.zig");
        const Base = @import("blake3_execution_parent_protocol.zig");
        const Routing = Policy.Public.API;
        pub const Wire = Routing.Wire;
        pub const Limits = struct { shared_epoch: bool = false, max_bytes: usize = 4 << 30, native: Native.Limits = .{}, transcript: @import("air/blake3_fixed_operation_recorder_v1.zig").Limits = .{}, max_public_wires: usize = 1 << 20 };
        pub const Owned = struct {
            shared_epoch: ?@import("air/blake3_transcript_witness.zig").StatePorts = null,
            allocator: std.mem.Allocator,
            budget: *Budget,
            fixed: Storage.FixedTuple(false),
            wires: []Wire,
            context: Base.Context,
            namespace: Namespace.Plan,
            pub const fixed_setup_only = true;
            pub const complete_family_setup = true;
            pub const whole_family_live_parity_qualified = false;
            pub const complete_block_authority = false;
            pub fn derive(backing: std.mem.Allocator, input: Profile.Input, capacity: u32, limits: Limits) !Owned {
                if (limits.max_bytes == 0 or capacity == 0) return error.JointFixedResourceLimit;
                const budget = try Budget.createRetainingParent(backing, limits.max_bytes);
                errdefer budget.destroy();
                errdefer if (std.process.hasEnvVarConstant("STWO_V7_WINDOW_PROFILE")) {
                    const usage = budget.snapshot();
                    std.debug.print("V7_WINDOW_NESTED_FAILURE phase=caller_fixed_roster active={} limit={d} peak={d} live={d} exceeded={}\n", .{ Policy.active, usage.limit, usage.peak_live_bytes, usage.live_bytes, usage.exceeded });
                };
                const a = budget.allocator();
                const native = try Native.Owned.derive(a, input, limits.native);
                defer native.deinit();
                return finish(a, budget, native, capacity, limits);
            }
            /// Opt-in independent setup using a compiler capsule retained for later
            /// captured witness evaluation. No producer graph enters this API.
            pub fn deriveFromCapsule(backing: std.mem.Allocator, capsule: *const Policy.Capsule.Capsule, capacity: u32, limits: Limits) !Owned {
                if (limits.max_bytes == 0 or capacity == 0) return error.JointFixedResourceLimit;
                const budget = try Budget.createRetainingParent(backing, limits.max_bytes);
                errdefer budget.destroy();
                errdefer if (std.process.hasEnvVarConstant("STWO_V7_WINDOW_PROFILE")) {
                    const usage = budget.snapshot();
                    std.debug.print("V7_WINDOW_NESTED_FAILURE phase=caller_fixed_roster active={} limit={d} peak={d} live={d} exceeded={}\n", .{ Policy.active, usage.limit, usage.peak_live_bytes, usage.live_bytes, usage.exceeded });
                };
                return finish(budget.allocator(), budget, capsule.compiler(), capacity, limits);
            }
            fn finish(a: std.mem.Allocator, budget: *Budget, native: *const Native.Owned, capacity: u32, limits: Limits) !Owned {
                const borrowed = native.transcript != null and !limits.shared_epoch and std.meta.eql(limits.transcript, @as(@TypeOf(limits.transcript), .{}));
                var transcript = if (borrowed) blk: {
                    const cached = native.transcript.?;
                    if (cached.config.attempt_capacity != capacity) return error.CallerTranscriptCapacityMismatch;
                    try cached.validate();
                    break :blk cached;
                } else try Transcript.deriveWithShared(a, &native.profile.admitted, &native.profile.arithmetic, &native.profile.claims, capacity, limits.transcript, limits.shared_epoch);
                defer if (!borrowed) transcript.deinit();
                const pcs = try Pcs.compile(a, native.profile, &native.deep_graph, &native.fri_graph, &transcript);
                defer pcs.deinit();
                const sources = try Sources.compileJointCaller(a, native.profile, &native.composition, &native.deep_graph, &native.fri_graph, &transcript);
                defer sources.deinit();
                const selectors = try Assembly.selectorsForGraphs(a, &native.deep_graph, &native.fri_graph);
                const fixed = try Roster.compileOriginalRoster(a, sources, null, pcs.openings, pcs.ports, &transcript, &pcs.paths, &native.arithmetic, selectors, &native.deep_graph);
                errdefer inline for (0..Storage.Airs.len) |i| a.free(fixed[i]);
                var namespace = try Namespace.prepareForArithmetic(a, fixed, 1, .{ .plan = &native.arithmetic.plan, .reference = native.arithmetic.reference, .kind = .segment_leaf });
                errdefer namespace.deinit();
                try namespace.requireIndependentMainPort();
                var statement = try Statement.init(a, &native.profile.admitted, &native.profile.arithmetic, &native.profile.claims);
                defer statement.deinit();
                const public = try Policy.Public.publicInputs(a, &native.profile.admitted, &native.profile.arithmetic, &native.profile.claims);
                defer a.free(public);
                const wires = try Routing.collectFixedSchedule(a, &transcript, &native.composition, statement.words.len, public.len, 3, @intCast(native.profile.config.fri_config.n_queries), limits.max_public_wires);
                errdefer a.free(wires);
                const context = Base.Context{ .child_key_id = native.profile.seal, .child_config = native.profile.config, .graph_ids = .{ native.composition.circuit.identity_digest, native.deep_graph.graph().identity_digest, native.fri_graph.graph().identity_digest }, .transcript_plan_id = transcript.id };
                _ = try Base.contextIdentity(context);
                return .{ .shared_epoch = transcript.fixed.resumed_state, .allocator = a, .budget = budget, .fixed = fixed, .wires = wires, .context = context, .namespace = namespace };
            }
            /// Differential guard against the separately emitted genuine verifier.
            /// This compares every fixed equation/port, not merely a proposed digest.
            pub fn validateLive(self: *const Owned, live: *Policy.Preparation.Prepared) !void {
                try live.recursive.rows.partitionHashRows();
                try self.namespace.validateLive(&live.recursive.rows);
                if (!std.meta.eql(self.context, live.recursive.context) or self.wires.len != live.wires.len) return error.UntrustedJointFixedRoster;
                for (self.wires, live.wires) |got, want| if (!std.meta.eql(got, want)) return error.UntrustedJointFixedRoster;
                inline for (0..Storage.Airs.len) |i| {
                    if (self.fixed[i].len != live.recursive.rows.fixed[i].len) return error.UntrustedJointFixedRoster;
                    for (self.fixed[i], live.recursive.rows.fixed[i]) |got, want| if (!std.meta.eql(got, want)) return error.UntrustedJointFixedRoster;
                }
            }
            pub fn deinit(self: *Owned) void {
                const budget = self.budget;
                self.namespace.deinit();
                self.allocator.free(self.wires);
                inline for (0..Storage.Airs.len) |i| self.allocator.free(self.fixed[i]);
                self.* = undefined;
                budget.destroy();
            }
        };

        pub fn ForBackend(comptime Backend: type) type {
            return struct {
                pub const KeyAndSchedule = struct {
                    allocator: std.mem.Allocator,
                    key: Policy.ParentProtocol.Key,
                    wires: []Wire,
                    expected: [1]Policy.ParentProtocol.Bus.Expected,
                    pub fn deinit(self: *@This()) void {
                        self.allocator.free(self.wires);
                        self.* = undefined;
                    }
                };
                /// Receiver-owned expected key; no producer rows, proposed verifier key
                /// or successful capture enters this derivation.
                pub fn deriveKeyAndSchedule(a: std.mem.Allocator, input: Profile.Input, capacity: u32, parent_profile: Base.Profile, limits: Limits) !KeyAndSchedule {
                    try Policy.Proof.ForBackend(Backend).requireFixedRoot(a, input.pin);
                    var owned = try Owned.derive(a, input, capacity, limits);
                    defer owned.deinit();
                    const base = try @import("blake3_execution_parent_proof.zig").ForBackend(Backend).deriveKeyFromFixed(a, owned.fixed, owned.context, parent_profile);
                    const expected = [1]Policy.ParentProtocol.Bus.Expected{.{ .profile = owned.context.child_key_id, .epoch = input.epoch.digest, .roots = input.pin.roots ++ .{input.pin.access_root} }};
                    const key = try Policy.ParentProtocol.Key.fromGeometry(base, owned.wires, &expected);
                    return .{ .allocator = a, .key = key, .wires = try a.dupe(Wire, owned.wires), .expected = expected };
                }
            };
        }
    };
}
