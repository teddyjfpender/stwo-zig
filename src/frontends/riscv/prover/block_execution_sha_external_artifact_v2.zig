//! Two-phase SHA block producer with both opcode and external caller access
//! sidecars. All three first-round roots are available before SourceSeal v4.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const Column = engine.pcs.ColumnEvaluation;
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Native = @import("blake3_ethereum_sha_proof.zig");
const Opcode = @import("block_execution_sha_artifact_v2.zig");
const external = @import("block_execution_external_trace_v2.zig");
const batch = @import("block_execution_external_batch_v2.zig");
const receiver = @import("block_execution_external_receiver_v2.zig");
const frame_mod = @import("../air/block/memory_event.zig");
const counter_mod = @import("../air/lookups/tables/counter.zig");
const seal_mod = @import("block_memory_source_seal_v2.zig");

pub const Serialized = struct {
    opcode: Opcode.Serialized,
    external_stark: []u8,
    external_claims: []batch.Claim,
    pub fn opcodeWire(self: *const Serialized) @import("block_execution_batch_receiver_v2.zig").Wire {
        return self.opcode.wire();
    }
    pub fn externalWire(self: *const Serialized) receiver.Wire {
        return .{ .native_artifact = self.opcode.native_artifact,
            .external_stark = self.external_stark, .external_claims = self.external_claims };
    }
    pub fn externalSidecarWire(self: *const Serialized) receiver.SidecarWire {
        return .{ .external_stark = self.external_stark, .external_claims = self.external_claims };
    }
    pub fn deinit(self: *Serialized, a: std.mem.Allocator) void {
        self.opcode.deinit(a); a.free(self.external_stark); a.free(self.external_claims); self.* = undefined;
    }
};

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Self = @This();
        const NativeApi = Native.ForBackend(Backend);
        const Api = batch.ForBackend(Backend);
        const Prepared = NativeApi.PreparedVerifier;
        allocator: std.mem.Allocator,
        arena: std.heap.ArenaAllocator,
        opcode: Opcode.ForBackend(Backend),
        extension_main: @import("guest_precompile/ethereum_sha_columns.zig").Main,
        slots: []external.Descriptor,
        traces: []external.Trace,
        inputs: []batch.Input,
        counter: counter_mod.Counter,
        first: Api.FirstRound,
        instance_index: u32,
        native_key_id: [32]u8,

        pub fn init(a: std.mem.Allocator, owner: *Profile.Witness, prepared: *Prepared,
            frame: frame_mod.Frame, instance_index: u32, config: core.pcs.PcsConfig) !Self {
            var opcode = try Opcode.ForBackend(Backend).init(a, owner, prepared, frame, instance_index, config);
            errdefer opcode.deinit();
            var arena = std.heap.ArenaAllocator.init(a);
            errdefer arena.deinit();
            const scratch = arena.allocator();
            var fixed: std.ArrayList(Column) = .empty;
            try fixed.appendSlice(scratch, owner.native.preprocessed.items);
            try fixed.appendSlice(scratch, owner.hashes.preprocessed());
            try fixed.appendSlice(scratch, try Profile.preprocessed(scratch, &owner.statement));
            var extension_main = try Profile.mainWitness(a, owner);
            errdefer extension_main.deinit(a);
            var main: std.ArrayList(Column) = .empty;
            try main.appendSlice(scratch, owner.native.main.items);
            if (owner.native.compact_ranges) |ranges| try main.appendSlice(scratch, &ranges.columns);
            try main.appendSlice(scratch, try owner.hashes.main());
            try main.appendSlice(scratch, extension_main.columns);
            const slots = try external.descriptorsFromStatement(a, &owner.statement,
                prepared.logs[0], prepared.logs[1], frame);
            errdefer a.free(slots);
            if (slots.len == 0) return error.NoExternalCallerAccesses;
            const traces = try a.alloc(external.Trace, slots.len);
            errdefer a.free(traces);
            const inputs = try a.alloc(batch.Input, slots.len);
            errdefer a.free(inputs);
            var initialized: usize = 0;
            errdefer for (traces[0..initialized]) |*trace| trace.deinit();
            for (slots, inputs, 0..) |slot, *input, i| {
                traces[i] = try external.Trace.init(a, slot, fixed.items, main.items);
                initialized += 1;
                input.* = .{ .descriptor = slot, .trace = &traces[i] };
            }
            var active_events: u64 = 0;
            for (traces) |*trace| {
                for (0..trace.domainSize()) |logical| active_events += @intFromBool((try trace.row(logical)).active);
            }
            if (active_events != try external.expectedEventCount(&owner.statement))
                return error.ExternalCallerCensusMismatch;
            var counter = try counter_mod.Counter.init(a, .range_check_8_8);
            errdefer counter.deinit(a);
            var first = try Api.commitFirstRound(a, fixed.items, main.items, inputs, slots,
                &counter, instance_index, prepared.id, config);
            errdefer first.deinit(a);
            if (!std.meta.eql(first.roots[0..2].*, opcode.native_roots)) return error.ExternalNativeRootMismatch;
            return .{ .allocator = a, .arena = arena, .opcode = opcode, .extension_main = extension_main,
                .slots = slots, .traces = traces, .inputs = inputs, .counter = counter,
                .first = first, .instance_index = instance_index, .native_key_id = prepared.id };
        }
        pub fn nativeRoots(self: *const Self) [2]suite.Hasher.Hash { return self.opcode.native_roots; }
        pub fn opcodeWitnessRoot(self: *const Self) suite.Hasher.Hash { return self.opcode.witnessRoot(); }
        pub fn externalWitnessRoot(self: *const Self) suite.Hasher.Hash { return self.first.roots[2]; }
        pub fn opcodeEventCount(self: *const Self) u64 { return self.opcode.event_count; }
        pub fn externalEventCount(self: *const Self) !u64 {
            var total: u64 = 0;
            for (self.traces) |*trace| {
                for (0..trace.domainSize()) |logical| total += @intFromBool((try trace.row(logical)).active);
            }
            return total;
        }
        pub fn opcodeCounter(self: *const Self) *const counter_mod.Counter { return &self.opcode.counter; }
        pub fn externalCounter(self: *const Self) *const counter_mod.Counter { return &self.counter; }
        pub fn deinit(self: *Self) void {
            const a = self.allocator;
            self.first.deinit(a); self.counter.deinit(a);
            for (self.traces) |*trace| trace.deinit();
            a.free(self.inputs); a.free(self.traces); a.free(self.slots);
            self.extension_main.deinit(a); self.arena.deinit(); self.opcode.deinit(); self.* = undefined;
        }
        pub fn proveAndSerialize(self: *Self, owner: *Profile.Witness, prepared: *Prepared,
            sealed: seal_mod.SourceSeal, pool: *engine.work_pool.WorkPool) !Serialized {
            if (!sealed.extension_rosters_bound or !std.meta.eql(prepared.id, self.native_key_id))
                return error.UnboundExternalFirstRound;
            var proof = try Api.prove(self.allocator, &self.first, self.inputs, self.slots, sealed,
                self.instance_index, self.native_key_id, self.nativeRoots(), self.externalWitnessRoot());
            defer proof.deinit(self.allocator);
            var writer = std.Io.Writer.Allocating.init(self.allocator);
            defer writer.deinit();
            try @import("interop_postcard").serializeProof(suite.Hasher, &writer.writer, proof.stark);
            const bytes = try self.allocator.dupe(u8, writer.written());
            errdefer self.allocator.free(bytes);
            const claims = try self.allocator.dupe(batch.Claim, proof.claims);
            errdefer self.allocator.free(claims);
            const opcode = try self.opcode.proveAndSerialize(owner, prepared, sealed, pool);
            return .{ .opcode = opcode, .external_stark = bytes, .external_claims = claims };
        }
    };
}
