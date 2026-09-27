//! Two-phase producer for one Ethereum-SHA execution segment and its
//! same-root block memory-access sidecar. The first phase exposes every root
//! and the exact counter before SourceSeal; the second proves after sealing.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const Column = engine.pcs.ColumnEvaluation;
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Native = @import("blake3_ethereum_sha_proof.zig");
const Sidecar = @import("block_execution_sidecar_batch_v2.zig");
const trace_mod = @import("block_execution_sidecar_trace_v2.zig");
const frame_mod = @import("../air/block/memory_event.zig");
const counter_mod = @import("../air/lookups/tables/counter.zig");
const seal_mod = @import("block_memory_source_seal_v2.zig");

pub const Serialized = struct {
    native_artifact: []u8,
    sidecar_stark: []u8,
    sidecar_claims: []Sidecar.Claim,

    pub fn wire(self: *const Serialized) @import("block_execution_batch_receiver_v2.zig").Wire {
        return .{ .native_artifact = self.native_artifact, .sidecar_stark = self.sidecar_stark, .sidecar_claims = self.sidecar_claims };
    }
    pub fn deinit(self: *Serialized, a: std.mem.Allocator) void {
        a.free(self.native_artifact);
        a.free(self.sidecar_stark);
        a.free(self.sidecar_claims);
        self.* = undefined;
    }
};

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const NativeApi = Native.ForBackend(Backend);
        const SidecarApi = Sidecar.ForBackend(Backend);
        const Prepared = NativeApi.PreparedVerifier;
        const Digest = suite.Hasher.Hash;
        const Self = @This();

        allocator: std.mem.Allocator,
        slots: []Sidecar.Slot,
        traces: []trace_mod.Trace,
        inputs: []Sidecar.Input,
        counter: counter_mod.Counter,
        sidecar_first: ?SidecarApi.FirstRound,
        native_roots: [2]Digest,
        event_count: u64,
        instance_index: u32,
        native_key_id: [32]u8,

        /// `frame` is the independently pinned leaf span's global clock frame.
        /// `event_count` is a preseal census; the sidecar AIR re-proves it.
        pub fn init(
            a: std.mem.Allocator,
            owner: *Profile.Witness,
            prepared: *Prepared,
            frame: frame_mod.Frame,
            instance_index: u32,
            config: core.pcs.PcsConfig,
        ) !Self {
            if (frame.clock_frame != .leaf_local or frame.cycle_count != owner.native.statement.public_data.clock or
                !std.meta.eql(config, prepared.config)) return error.InvalidShaSidecarFrame;
            try prepared.validate(prepared.id);
            const slots = try Sidecar.slotsFromStatement(a, &owner.native.statement, frame);
            errdefer a.free(slots);
            const traces = try a.alloc(trace_mod.Trace, slots.len);
            errdefer a.free(traces);
            const inputs = try a.alloc(Sidecar.Input, slots.len);
            errdefer a.free(inputs);
            var initialized: usize = 0;
            errdefer for (traces[0..initialized]) |*trace| trace.deinit();

            var events: u64 = 0;
            for (slots, inputs, 0..) |slot, *input, index| {
                var offset: usize = 0;
                var source_index: ?usize = null;
                for (owner.native.statement.component_descs[0..owner.native.statement.n_components], 0..) |desc, component| {
                    if (offset == slot.main_offset and desc.family == slot.family) {
                        source_index = component;
                        break;
                    }
                    offset += desc.n_columns;
                }
                traces[index] = try trace_mod.Trace.init(a, slot.family, &owner.native.opcode_columns.components[source_index orelse return error.MissingShaExecutionSlot], slot.slot, slot.log_size, frame);
                initialized += 1;
                input.* = .{ .descriptor = slot, .trace = &traces[index] };
                for (0..traces[index].domainSize()) |logical| {
                    if ((try traces[index].row(logical)).active) events = try std.math.add(u64, events, 1);
                }
            }

            var counter = try counter_mod.Counter.init(a, .range_check_8_8);
            errdefer counter.deinit(a);
            if (slots.len == 0) {
                var native_first = try NativeApi.commitFirstRound(a, owner, prepared, prepared.id);
                defer native_first.deinit(a);
                return .{
                    .allocator = a, .slots = slots, .traces = traces, .inputs = inputs,
                    .counter = counter, .sidecar_first = null, .native_roots = native_first.roots,
                    .event_count = 0, .instance_index = instance_index, .native_key_id = prepared.id,
                };
            }
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const scratch = arena.allocator();
            var fixed: std.ArrayList(Column) = .empty;
            try fixed.appendSlice(scratch, owner.native.preprocessed.items);
            try fixed.appendSlice(scratch, owner.hashes.preprocessed());
            try fixed.appendSlice(scratch, try Profile.preprocessed(scratch, &owner.statement));
            var extension_main = try Profile.mainWitness(a, owner);
            defer extension_main.deinit(a);
            var main: std.ArrayList(Column) = .empty;
            try main.appendSlice(scratch, owner.native.main.items);
            if (owner.native.compact_ranges) |ranges| try main.appendSlice(scratch, &ranges.columns);
            try main.appendSlice(scratch, try owner.hashes.main());
            try main.appendSlice(scratch, extension_main.columns);

            var sidecar_first = try SidecarApi.commitFirstRound(a, fixed.items, main.items, inputs, slots, &counter, instance_index, prepared.id, config);
            errdefer sidecar_first.deinit(a);
            var native_first = try NativeApi.commitFirstRound(a, owner, prepared, prepared.id);
            defer native_first.deinit(a);
            if (!std.meta.eql(native_first.roots, sidecar_first.roots[0..2].*)) return error.ShaSidecarNativeRootMismatch;
            return .{
                .allocator = a, .slots = slots, .traces = traces, .inputs = inputs, .counter = counter,
                .sidecar_first = sidecar_first, .native_roots = native_first.roots,
                .event_count = events, .instance_index = instance_index, .native_key_id = prepared.id,
            };
        }

        pub fn witnessRoot(self: *const Self) Digest {
            return if (self.sidecar_first) |first| first.roots[2] else Sidecar.emptyWitnessRoot();
        }
        pub fn deinit(self: *Self) void {
            const a = self.allocator;
            if (self.sidecar_first) |*first| first.deinit(a);
            self.counter.deinit(a);
            for (self.traces) |*trace| trace.deinit();
            a.free(self.inputs);
            a.free(self.traces);
            a.free(self.slots);
            self.* = undefined;
        }

        /// Both encoded proofs are receiver-ready. The caller seals the native,
        /// witness, execution-table and other block roots before this call.
        pub fn proveAndSerialize(self: *Self, owner: *Profile.Witness, prepared: *Prepared, sealed: seal_mod.SourceSeal, pool: *engine.work_pool.WorkPool) !Serialized {
            if (!sealed.bound_rosters or self.instance_index >= sealed.execution_instance_count or
                !std.meta.eql(prepared.id, self.native_key_id)) return error.UnboundShaSidecarFirstRound;
            const sidecar_bytes, const claims = if (self.sidecar_first) |*first| blk: {
                var sidecar_proof = try SidecarApi.prove(self.allocator, first, self.inputs, self.slots, sealed, self.instance_index, self.native_key_id, self.native_roots, self.witnessRoot());
                defer sidecar_proof.deinit(self.allocator);
                var writer = std.Io.Writer.Allocating.init(self.allocator);
                defer writer.deinit();
                try @import("interop_postcard").serializeProof(suite.Hasher, &writer.writer, sidecar_proof.stark);
                const bytes = try self.allocator.dupe(u8, writer.written());
                errdefer self.allocator.free(bytes);
                break :blk .{ bytes, try self.allocator.dupe(Sidecar.Claim, sidecar_proof.claims) };
            } else blk: {
                if (self.slots.len != 0 or self.event_count != 0) return error.InvalidEmptyExecutionSidecar;
                const bytes = try self.allocator.alloc(u8, 0);
                errdefer self.allocator.free(bytes);
                break :blk .{ bytes, try self.allocator.alloc(Sidecar.Claim, 0) };
            };
            errdefer self.allocator.free(sidecar_bytes);
            errdefer self.allocator.free(claims);
            var native_proved = try NativeApi.proveReplaying(self.allocator, owner, prepared, self.native_key_id, self.native_roots, pool);
            defer native_proved.proof.deinit(self.allocator);
            const native_bytes = try Native.codec.encode(self.allocator, &native_proved.proof, prepared, self.native_key_id);
            return .{ .native_artifact = native_bytes, .sidecar_stark = sidecar_bytes, .sidecar_claims = claims };
        }
    };
}
