//! Dedicated finite joint-caller adapter. Reuses the exact original graph,
//! transcript, hash-path and opening emitters; no generic native-only span or
//! aggregate-sum receipt supplies authority for this different protocol.
//! Shared implementation: default and finite active caller families.
pub fn For(comptime Policy: type) type {
    return struct {
        const std = @import("std");
        const core = @import("stwo_core");
        const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
        const Admission = Policy.Admission;
        const Capture = Policy.Capture;
        const Parent = @import("blake3_execution_parent_preparation.zig");
        const Public = Policy.Public;
        const PhaseClock = struct {
            clock: ?std.time.Timer,
            reused: bool,
            fn init(reused: bool) PhaseClock {
                return .{ .clock = if (std.process.hasEnvVarConstant("STWO_RISCV_PARENT_PREPARATION_PROFILE")) std.time.Timer.start() catch null else null, .reused = reused };
            }
            fn lap(self: *PhaseClock, name: []const u8) void {
                if (self.clock) |*clock| std.debug.print("V7_CALLER_PREPARATION phase={s} ns={d} compiled_reuse={}\n", .{ name, clock.lap(), self.reused });
            }
        };
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
        pub fn prepare(backing: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, capacity: u32, limits: Limits) !Prepared {
            return prepareMode(backing, admitted, capture, capacity, limits, null);
        }
        pub fn prepareFromCapsule(backing: std.mem.Allocator, capsule: *const Policy.Capsule.Capsule, capture: *const Capture.VerifiedCapture, capacity: u32, limits: Limits) !Prepared {
            return prepareMode(backing, capsule.admitted(), capture, capacity, limits, capsule);
        }
        fn prepareMode(backing: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, capacity: u32, limits: Limits, capsule: ?*const Policy.Capsule.Capsule) !Prepared {
            if (capacity == 0 or limits.max_bytes == 0 or limits.max_public_wires == 0) return error.JointPreparationResourceLimit;
            const budget = try Budget.createRetainingParent(backing, limits.max_bytes);
            errdefer budget.destroy();
            const a = budget.allocator();
            var values = try Public.reconstruct(a, admitted, &capture.original.arithmetic, &capture.original.claims);
            errdefer values.deinit();
            var phases = PhaseClock.init(capsule != null);
            var planned = try planMode(a, admitted, capture, capacity, limits.shared_epoch, capsule);
            phases.lap("plan");
            defer planned.deinit();
            const state = planned.state.?;
            for (state.composition.sources, state.composition.inputs) |source, value| if (source == .public_input) {
                if (source.public_input >= values.public.len or !value.eql(values.public[source.public_input])) return error.UntrustedJointPublicFrame;
            };
            const wires = try Public.API.collectFixedSchedule(a, &planned.transcript.?.plan, &state.composition, values.statement.words.len, values.public.len, 3, @intCast(admitted.arithmetic.config.fri_config.n_queries), limits.max_public_wires);
            errdefer a.free(wires);
            const shared_epoch = planned.transcript.?.plan.fixed.resumed_state;
            phases.lap("public_schedule");
            const emitted = try planned.emit();
            phases.lap("emit");
            defer emitted.deinit();
            var recursive = if (capsule) |compiled| try emitted.finishReleasingRowsWithArithmetic(&compiled.compiler().arithmetic) else try emitted.finishReleasingRows();
            errdefer recursive.deinit();
            phases.lap("assembly");
            return .{ .shared_epoch = shared_epoch, .allocator = a, .budget = budget, .recursive = recursive, .wires = wires, .values = values };
        }
        /// The capture remains borrowed until Planned.emit/deinit, matching the shared
        /// original parent lifecycle. Admission is independently rederived first.
        pub fn plan(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, capacity: u32) !Parent.Planned {
            return planWithShared(a, admitted, capture, capacity, false);
        }
        pub fn planWithShared(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, capacity: u32, shared_epoch: bool) !Parent.Planned {
            return planMode(a, admitted, capture, capacity, shared_epoch, null);
        }
        pub fn planFromCapsule(a: std.mem.Allocator, capsule: *const Policy.Capsule.Capsule, capture: *const Capture.VerifiedCapture, capacity: u32, shared_epoch: bool) !Parent.Planned {
            return planMode(a, capsule.admitted(), capture, capacity, shared_epoch, capsule);
        }
        fn planMode(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, capacity: u32, shared_epoch: bool, capsule: ?*const Policy.Capsule.Capsule) !Parent.Planned {
            var phases = PhaseClock.init(capsule != null);
            if (capsule == null) try capture.validate(admitted, admitted.template_id);
            const self = try a.create(Parent.State);
            errdefer a.destroy(self);
            self.allocator = a;
            self.row_sources_released = false;
            self.composition = if (capsule) |compiled| try compiled.prepareComposition(a, capture) else try Policy.Composition.prepare(a, admitted, capture, admitted.template_id);
            errdefer self.composition.deinit();
            phases.lap("composition");
            self.deep = if (capsule) |compiled| try compiled.prepareDeep(a, capture) else try deep(a, admitted, capture);
            errdefer self.deep.deinit();
            phases.lap("deep");
            self.fri = if (capsule) |compiled| try @import("air/blake3_native_fri.zig").prepareCapturedWithGraph(a, &capture.original.proof, admitted.arithmetic.config, &self.deep, 1502, 1504, &compiled.compiler().fri_graph) else try @import("air/blake3_native_fri.zig").prepareCaptured(a, &capture.original.proof, admitted.arithmetic.config, &self.deep, 1502, 1504);
            errdefer self.fri.deinit();
            phases.lap("fri");
            const compiled_transcript = if (!shared_epoch and capsule != null and capsule.?.compiler().transcript != null) &capsule.?.compiler().transcript.? else null;
            var transcript = try Policy.Transcript.planReplayWithCompiled(a, admitted, capture, admitted.template_id, capacity, compiled_transcript);
            errdefer transcript.deinit();
            if (shared_epoch) try @import("air/block_v7_shared_epoch_transcript_v1.zig").substitute(a, &transcript, admitted.epoch, true);
            phases.lap("transcript_plan");
            self.payloads = try @import("air/blake3_execution_payloads.zig").prepare(a, &self.composition, &transcript, &self.deep, 1500, 1502, 5_000_012);
            errdefer self.payloads.deinit();
            self.challenges = try @import("air/blake3_execution_challenges.zig").prepareForRelations(67, a, &self.composition, &transcript, &self.deep, &self.fri, .{ 1500, 1502, 1504 }, 5_000_003);
            errdefer self.challenges.deinit();
            self.terminal = try @import("air/blake3_native_terminal_encoding.zig").prepareColumns(a, &transcript, &self.fri, 1504);
            errdefer self.terminal.deinit();
            self.queries = try @import("air/blake3_native_queries.zig").prepare(a, &transcript, &self.deep, &self.fri);
            errdefer self.queries.deinit();
            self.roots = try roots(a, admitted, capture, &transcript);
            errdefer self.roots.deinit();
            const layout = try @import("blake3_native_hash_layout.zig").Layout.initForCommitments(6, a, try transcript.hashCounts(), &capture.original.proof);
            phases.lap("links");
            self.context = .{ .child_key_id = admitted.template_id, .child_config = admitted.arithmetic.config, .graph_ids = .{ self.composition.circuit.identity_digest, self.deep.graph.graph().identity_digest, self.fri.graph.graph().identity_digest }, .transcript_plan_id = transcript.plan.id };
            return .{ .state = self, .transcript = transcript, .layout = layout, .proof = &capture.original.proof, .joint_caller_paths = true };
        }
        fn deep(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture) !@import("air/blake3_native_deep.zig").Prepared {
            var shape = try Policy.Shape.derive(a, admitted);
            defer shape.deinit();
            var inputs = try @import("pcs_arithmetic_capture.zig").Owned.init(a, shape.deepProfile(), &capture.original.proof);
            errdefer inputs.deinit();
            var graph = try @import("air/pcs_deep_circuit.zig").build(a, shape.deepProfile());
            errdefer graph.deinit();
            const evaluation = try graph.evaluate(a, inputs.inputs);
            return .{ .graph = graph, .inputs = inputs, .evaluation = evaluation };
        }
        fn roots(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, transcript: *const @import("air/blake3_native_transcript.zig").Planned) !@import("air/blake3_execution_roots.zig").Prepared {
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            var filtered: std.ArrayList(@TypeOf(transcript.plan.fixed.root_reads[0])) = .empty;
            for (transcript.plan.fixed.root_reads) |receipt| if (receipt.source.circuit == @import("air/blake3_root_sources.zig").CIRCUIT) try filtered.append(arena.allocator(), receipt);
            var pcs = transcript.*;
            pcs.plan.fixed.root_reads = filtered.items;
            var result = try @import("air/blake3_execution_roots.zig").prepareCapturedExternalFor(6, a, &capture.original.proof, admitted.source.roots[0], admitted.arithmetic.config, &pcs, 3);
            result.external_key = true;
            result.external_main = true;
            return result;
        }
    };
}
