//! Strategy-based shared parent verifier; no original equations duplicated.
const Family = @import("block_v8_endpoint_recursive_source_v1.zig").Family;
pub fn For(comptime family: Family) type {
    return With(@import("block_v8_endpoint_recursive_adapter_v1.zig").For(family));
}
pub fn With(comptime Adapter: type) type {
    return struct {
        // One admitted endpoint original and its complete symbolic ledger become one
        // recursive verifier. Every public operand is supplied by independent metadata.
        const std = @import("std");
        const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
        const Profile = Adapter.Profile;
        const Whole = Adapter.Original;
        const Parent = @import("blake3_execution_parent_preparation.zig");
        const Public = Adapter.Public;
        pub const Limits = struct { max_bytes: usize = 8 << 30, max_public_wires: usize = 1 << 20 };
        pub const Prepared = struct {
            allocator: std.mem.Allocator,
            budget: *Budget,
            recursive: Parent.Prepared,
            wires: []Public.Wire,
            values: Public.Values,
            pub fn deinit(self: *Prepared) void {
                self.recursive.deinit();
                self.allocator.free(self.wires);
                self.values.deinit();
                self.budget.destroy();
                self.* = undefined;
            }
        };
        pub fn prepare(backing: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Whole.VerifiedCapture, capacity: u32, limits: Limits) !Prepared {
            if (capacity == 0 or limits.max_bytes == 0 or limits.max_public_wires == 0) return error.EndpointPreparationResourceLimit;
            const budget = try Budget.createRetainingParent(backing, limits.max_bytes);
            errdefer budget.destroy();
            const a = budget.allocator();
            var values = try Public.reconstruct(a, profile);
            errdefer values.deinit();
            var planned = try plan(a, profile, capture, capacity);
            defer planned.deinit();
            const wires = try Public.collect(a, profile, capture, &planned.state.?.composition, &planned.transcript.?, values, limits.max_public_wires);
            errdefer a.free(wires);
            const emitted = try planned.emit();
            defer emitted.deinit();
            var recursive = try emitted.finishReleasingRows();
            errdefer recursive.deinit();
            return .{ .allocator = a, .budget = budget, .recursive = recursive, .wires = wires, .values = values };
        }
        pub fn plan(a: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Whole.VerifiedCapture, capacity: u32) !Parent.Planned {
            if (capacity == 0) return error.EndpointPreparationResourceLimit;
            try profile.requireCapture(capture);
            const self = try a.create(Parent.State);
            errdefer a.destroy(self);
            self.allocator = a;
            self.row_sources_released = false;
            self.composition = try Adapter.Composition.prepare(a, profile, capture);
            errdefer self.composition.deinit();
            var transcript = try Adapter.Transcript.replay(a, profile, capture, capacity);
            errdefer transcript.deinit();
            const pcs = try Adapter.Pcs.prepare(a, profile, capture, &transcript);
            self.deep = pcs.deep;
            errdefer self.deep.deinit();
            self.fri = pcs.fri;
            errdefer self.fri.deinit();
            self.roots = pcs.roots;
            errdefer self.roots.deinit();
            self.payloads = try @import("air/blake3_execution_payloads.zig").prepare(a, &self.composition, &transcript, &self.deep, 1500, 1502, 5_000_012);
            errdefer self.payloads.deinit();
            const pairs = Profile.RELATION_PAIRS;
            self.challenges = try @import("air/blake3_execution_challenges.zig").prepareForAdmittedRelations(pairs, 949, a, &self.composition, &transcript, &self.deep, &self.fri, .{ 1500, 1502, 1504 }, 5_000_003);
            errdefer self.challenges.deinit();
            self.terminal = try @import("air/blake3_native_terminal_encoding.zig").prepareColumns(a, &transcript, &self.fri, 1504);
            errdefer self.terminal.deinit();
            self.queries = try @import("air/blake3_native_queries.zig").prepare(a, &transcript, &self.deep, &self.fri);
            errdefer self.queries.deinit();
            const layout = try @import("blake3_native_hash_layout.zig").Layout.initForBoundedCommitments(profile.shape.columns.len, a, try transcript.hashCounts(), &capture.proof);
            self.context = .{ .child_key_id = profile.seal, .child_config = Adapter.epoch(profile).config, .graph_ids = .{ self.composition.circuit.identity_digest, self.deep.graph.graph().identity_digest, self.fri.graph.graph().identity_digest }, .transcript_plan_id = transcript.plan.id };
            return .{ .state = self, .transcript = transcript, .layout = layout, .proof = &capture.proof, .union_path_commitments = profile.shape.columns.len };
        }
    };
}
