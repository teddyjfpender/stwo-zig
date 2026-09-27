//! Diagnostic fixture plumbing for separately proved native and same-root
//! execution-sidecar receipts. No host-only receipt is accepted as authority.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Column = engine.pcs.ColumnEvaluation;
const segment_mod = @import("blake3_segment_execution.zig");
const native_api = @import("blake3_execution_proof.zig").ForBackend(Cpu);
const sidecar = @import("block_execution_sidecar_batch_v2.zig");
const sidecar_api = sidecar.ForBackend(Cpu);
const trace_mod = @import("block_execution_sidecar_trace_v2.zig");
const counter_mod = @import("../air/lookups/tables/counter.zig");
const seal_mod = @import("block_memory_source_seal_v2.zig");
const v3 = @import("../recursion/blake3_block_execution_span_v3.zig");
const parent = @import("../recursion/blake3_execution_parent_proof.zig");
const Segment = @import("../runner/result.zig").SegmentResult;

pub const Fixture = struct {
    allocator: std.mem.Allocator,
    owner: segment_mod.Owner,
    slots: []sidecar.Slot,
    traces: []trace_mod.Trace,
    inputs: []sidecar.Input,
    counter: counter_mod.Counter,
    first: sidecar_api.FirstRound,
    native_key_id: [32]u8,
    receipt: ?sidecar.VerifiedExecutionReceipt = null,

    pub fn init(a: std.mem.Allocator, segment: *const Segment, index: u32, config: core.pcs.PcsConfig) !Fixture {
        var owner = try segment_mod.Owner.initCompact(a, segment);
        errdefer owner.deinit();
        const native = owner.native;
        const prepared = try native_api.PreparedVerifier.initCompact(
            a,
            &native.statement,
            try owner.admission(),
            config,
            native.compact_ranges.?.plan,
        );
        defer prepared.deinit();
        const frame = @import("../air/block/memory_event.zig").Frame{
            .clock_frame = .leaf_local,
            .global_first_cycle = segment.global_first_cycle,
            .cycle_count = @intCast(segment.cycle_count),
        };
        const slots = try sidecar.slotsFromStatement(a, &native.statement, frame);
        errdefer a.free(slots);
        const traces = try a.alloc(trace_mod.Trace, slots.len);
        errdefer a.free(traces);
        const inputs = try a.alloc(sidecar.Input, slots.len);
        errdefer a.free(inputs);
        var initialized: usize = 0;
        errdefer for (traces[0..initialized]) |*trace| trace.deinit();
        for (slots, inputs, 0..) |slot, *input, slot_index| {
            var offset: usize = 0;
            var component: ?usize = null;
            for (native.statement.component_descs[0..native.statement.n_components], 0..) |desc, i| {
                if (offset == slot.main_offset and desc.family == slot.family) {
                    component = i;
                    break;
                }
                offset += desc.n_columns;
            }
            traces[slot_index] = try trace_mod.Trace.init(
                a,
                slot.family,
                &native.opcode_columns.components[
                    component orelse
                        return error.MissingExecutionSlotComponent
                ],
                slot.slot,
                slot.log_size,
                frame,
            );
            initialized += 1;
            input.* = .{ .descriptor = slot, .trace = &traces[slot_index] };
        }
        var fixed: std.ArrayList(Column) = .empty;
        defer fixed.deinit(a);
        try fixed.appendSlice(a, native.preprocessed.items);
        try fixed.appendSlice(a, owner.hashes.preprocessed());
        var main: std.ArrayList(Column) = .empty;
        defer main.deinit(a);
        try main.appendSlice(a, native.main.items);
        try main.appendSlice(a, &native.compact_ranges.?.columns);
        try main.appendSlice(a, try owner.hashes.main());
        var counter = try counter_mod.Counter.init(a, .range_check_8_8);
        errdefer counter.deinit(a);
        const first = try sidecar_api.commitFirstRound(
            a,
            fixed.items,
            main.items,
            inputs,
            slots,
            &counter,
            index,
            prepared.id,
            config,
        );
        return .{
            .allocator = a,
            .owner = owner,
            .slots = slots,
            .traces = traces,
            .inputs = inputs,
            .counter = counter,
            .first = first,
            .native_key_id = prepared.id,
        };
    }

    pub fn deinit(self: *Fixture) void {
        const a = self.allocator;
        if (self.receipt) |*receipt| receipt.deinit(a);
        self.first.deinit(a);
        self.counter.deinit(a);
        for (self.traces) |*trace| trace.deinit();
        a.free(self.traces);
        a.free(self.inputs);
        a.free(self.slots);
        self.owner.deinit();
        self.* = undefined;
    }

    pub fn entries(self: *const Fixture, index: u32) [2]seal_mod.FirstRoundEntry {
        return .{
            .{ .family = .execution, .index = index, .roots = self.first.roots[0..2].* },
            .{ .family = .execution_sidecar_witness, .index = index, .roots = .{ self.first.roots[2], @splat(0) } },
        };
    }

    pub fn proveLeaf(
        self: *Fixture,
        segment: *const Segment,
        job: @import("../recursion/span_statement_blake3.zig").JobContext,
        seal: seal_mod.SourceSeal,
        config: core.pcs.PcsConfig,
        profile: parent.protocol.Profile,
    ) !parent.tree.Node {
        const a = self.allocator;
        if (!std.meta.eql(config, profile.config()))
            return error.ExecutionParentSecurityMismatch;
        var native_owner = try segment_mod.Owner.initCompact(a, segment);
        defer native_owner.deinit();
        const native = native_owner.native;
        const verifier = try native_api.PreparedVerifier.initCompact(
            a,
            &native.statement,
            try native_owner.admission(),
            config,
            native.compact_ranges.?.plan,
        );
        defer verifier.deinit();
        if (!std.mem.eql(u8, &verifier.id, &self.native_key_id))
            return error.ExecutionKeyMismatch;
        const proved = try native_api.proveCompact(
            a,
            native,
            native_owner.hashes,
            try native_owner.admission(),
            config,
        );
        var captured = try native_api.verifyPreparedCaptureOwned(
            a,
            proved.proof,
            verifier,
            verifier.id,
        );
        defer captured.deinit();
        const roots = captured.proof.commitments[0..2].*;
        if (!std.meta.eql(roots, self.first.roots[0..2].*))
            return error.ExecutionSidecarRootMismatch;
        const proof = try sidecar_api.prove(
            a,
            &self.first,
            self.inputs,
            self.slots,
            seal,
            segment.segment_index,
            verifier.id,
            roots,
            self.first.roots[2],
        );
        var receipt = try sidecar_api.verifyOwned(
            a,
            proof,
            seal,
            segment.segment_index,
            verifier.id,
            self.slots,
            self.first.fixed_logs,
            self.first.main_logs,
            roots,
            self.first.roots[2],
            config,
        );
        errdefer receipt.deinit(a);
        const statement = try v3.leaf(job, segment);
        var prepared = try v3.prepare(
            a,
            verifier,
            &captured,
            verifier.id,
            2,
            statement,
            seal,
            self.first.roots[2],
            &receipt,
        );
        defer prepared.deinit();
        const Api = parent.ForBackend(Cpu);
        const key = try Api.deriveKeyWithProfile(a, &prepared, profile);
        const admission = try parent.protocol.Admission.init(key, try key.identity());
        const plan = try Api.Plan.init(a, &prepared.rows, admission);
        defer plan.deinit();
        var outer = try plan.prove(a, &prepared.rows);
        const bytes = try parent.codec.encode(a, &outer, &admission);
        errdefer a.free(bytes);
        var node = try parent.tree.Node.verifyOwned(
            &outer,
            admission,
            admission.expected_id,
            statement,
        );
        node.transport_bytes = bytes;
        node.transport_allocator = a;
        self.receipt = receipt;
        return node;
    }
};
