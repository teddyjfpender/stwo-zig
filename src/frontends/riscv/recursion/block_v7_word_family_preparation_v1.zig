//! Shared four-tree, 53-relation original-verifier plumbing. Finite typed
//! definitions supply equations/framing; no captured metadata selects code.
pub fn For(comptime D: type) type {
    return struct {
        //! Dedicated finite joint-memory adapter. Reuses the exact original graph,
        //! transcript, hash-path and opening emitters; no generic native-only span or
        //! aggregate-sum receipt supplies authority for this different protocol.
        const std = @import("std");
        const core = @import("stwo_core");
        const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
        const Profile = D.Profile;
        const Joint = D.Capture;
        const Parent = @import("blake3_execution_parent_preparation.zig");
        const Public = D.Public;
        pub const Limits = struct { shared_epoch: bool = false, max_bytes: usize = 4 << 30, max_public_wires: usize = 1 << 20 };
        pub const Prepared = struct {
            shared_epoch: ?@import("air/blake3_transcript_witness.zig").StatePorts = null,
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
        pub fn prepare(backing: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Joint.VerifiedCapture, capacity: u32, limits: Limits) !Prepared {
            if (capacity == 0 or limits.max_bytes == 0 or limits.max_public_wires == 0) return error.JointPreparationResourceLimit;
            const budget = try Budget.createRetainingParent(backing, limits.max_bytes);
            errdefer budget.destroy();
            const a = budget.allocator();
            var values = try Public.reconstruct(a, profile);
            errdefer values.deinit();
            var planned = try planWithShared(a, profile, capture, capacity, limits.shared_epoch);
            defer planned.deinit();
            const state = planned.state.?;
            for (state.composition.sources, state.composition.inputs) |source, value| if (source == .public_input) {
                if (source.public_input >= values.public.len or !value.eql(values.public[source.public_input])) return error.UntrustedJointPublicFrame;
            };
            const wires = try Public.API.collectFixedSchedule(a, &planned.transcript.?.plan, &state.composition, values.statement.words.len, values.public.len, 2, @intCast(profile.config.fri_config.n_queries), limits.max_public_wires);
            errdefer a.free(wires);
            const shared_epoch = planned.transcript.?.plan.fixed.resumed_state;
            const emitted = try planned.emit();
            defer emitted.deinit();
            var recursive = try emitted.finishReleasingRows();
            errdefer recursive.deinit();
            return .{ .shared_epoch = shared_epoch, .allocator = a, .budget = budget, .recursive = recursive, .wires = wires, .values = values };
        }
        /// The capture remains borrowed until Planned.emit/deinit, matching the shared
        /// original parent lifecycle. Admission is independently rederived first.
        pub fn plan(a: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Joint.VerifiedCapture, capacity: u32) !Parent.Planned {
            return planWithShared(a, profile, capture, capacity, false);
        }
        pub fn planWithShared(a: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Joint.VerifiedCapture, capacity: u32, shared_epoch: bool) !Parent.Planned {
            try profile.validate();
            const self = try a.create(Parent.State);
            errdefer a.destroy(self);
            self.allocator = a;
            self.row_sources_released = false;
            self.composition = try composition(a, profile, capture);
            errdefer self.composition.deinit();
            self.deep = try deep(a, profile, capture);
            errdefer self.deep.deinit();
            self.fri = try @import("air/blake3_native_fri.zig").prepareCaptured(a, &capture.proof, profile.config, &self.deep, 1502, 1504);
            errdefer self.fri.deinit();
            var transcript = try D.Transcript.planReplay(a, profile, capture, capacity);
            errdefer transcript.deinit();
            if (shared_epoch) try @import("air/block_v7_shared_epoch_transcript_v1.zig").substitute(a, &transcript, profile.input.epoch, false);
            self.payloads = try @import("air/blake3_execution_payloads.zig").prepare(a, &self.composition, &transcript, &self.deep, 1500, 1502, 5_000_012);
            errdefer self.payloads.deinit();
            self.challenges = try @import("air/blake3_execution_challenges.zig").prepareForRelations(53, a, &self.composition, &transcript, &self.deep, &self.fri, .{ 1500, 1502, 1504 }, 5_000_003);
            errdefer self.challenges.deinit();
            self.terminal = try @import("air/blake3_native_terminal_encoding.zig").prepareColumns(a, &transcript, &self.fri, 1504);
            errdefer self.terminal.deinit();
            self.queries = try @import("air/blake3_native_queries.zig").prepare(a, &transcript, &self.deep, &self.fri);
            errdefer self.queries.deinit();
            self.roots = try roots(a, profile, capture, &transcript);
            errdefer self.roots.deinit();
            const layout = try @import("blake3_native_hash_layout.zig").Layout.init(a, try transcript.hashCounts(), &capture.proof);
            self.context = .{ .child_key_id = profile.seal, .child_config = profile.config, .graph_ids = .{ self.composition.circuit.identity_digest, self.deep.graph.graph().identity_digest, self.fri.graph.graph().identity_digest }, .transcript_plan_id = transcript.plan.id };
            return .{ .state = self, .transcript = transcript, .layout = layout, .proof = &capture.proof, .page_paths = false };
        }
        fn composition(a: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Joint.VerifiedCapture) !@import("air/blake3_execution_composition.zig").Prepared {
            const C = @import("air/blake3_execution_composition.zig");
            var compiled = try D.Equation.compile(a, profile);
            errdefer compiled.deinit();
            var arena = std.heap.ArenaAllocator.init(a);
            errdefer arena.deinit();
            const temp = arena.allocator();
            const inputs = try D.Inputs.composition(temp, profile, &compiled, &capture.proof);
            const values = try temp.alloc(core.fields.qm31.QM31, compiled.circuit.nodes.len);
            try compiled.circuit.evaluateInto(inputs, values);
            const sources = try temp.dupe(C.Source, compiled.sources);
            var result = C.Prepared{ .arena = arena, .circuit = compiled.circuit, .inputs = inputs, .sources = sources, .values = values, .key_id = profile.seal, .capture_seal = capture.final_channel.digestBytes(), .seal = undefined };
            result.seal = result.identity();
            // Transfer the graph; source metadata now belongs to Prepared's arena.
            a.free(compiled.sources);
            if (compiled.budget) |lease| lease.destroy();
            return result;
        }
        fn deep(a: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Joint.VerifiedCapture) !@import("air/blake3_native_deep.zig").Prepared {
            var inputs = try @import("pcs_arithmetic_capture.zig").Owned.init(a, profile.deepProfile(), &capture.proof);
            errdefer inputs.deinit();
            var graph = try @import("air/pcs_deep_circuit.zig").build(a, profile.deepProfile());
            errdefer graph.deinit();
            const evaluation = try graph.evaluate(a, inputs.inputs);
            return .{ .graph = graph, .inputs = inputs, .evaluation = evaluation };
        }
        fn roots(a: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Joint.VerifiedCapture, transcript: *const @import("air/blake3_native_transcript.zig").Planned) !@import("air/blake3_execution_roots.zig").Prepared {
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            var filtered: std.ArrayList(@TypeOf(transcript.plan.fixed.root_reads[0])) = .empty;
            for (transcript.plan.fixed.root_reads) |receipt| if (receipt.source.circuit == @import("air/blake3_root_sources.zig").CIRCUIT) try filtered.append(arena.allocator(), receipt);
            var pcs = transcript.*;
            pcs.plan.fixed.root_reads = filtered.items;
            var result = try @import("air/blake3_execution_roots.zig").prepareCapturedExternal(a, &capture.proof, profile.input.roots[0], profile.config, &pcs, 2);
            result.external_key = true;
            result.external_main = true;
            return result;
        }
    };
}
