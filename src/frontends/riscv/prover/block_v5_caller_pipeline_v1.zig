//! Two-pass caller production from the driver's already-live segment. Physical
//! proposals carry no proof authority and retain no witness or PCS storage.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Family = @import("block_v5_precompile_family_proof_v1.zig");
const Batch = @import("block_v5_precompile_batch_v1.zig");
const Protocol = @import("block_v5_precompile_protocol_v1.zig");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Witness = @import("block_v5_precompile_witness_v1.zig").Witness;
const Program = @import("block_v5_program_extension_proof_v1.zig");
const FusedStage = @import("block_v5_caller_fused_stage_v1.zig");
const Fused = @import("block_v5_caller_fused_proof_v1.zig");
const State = @import("block_v5_precompile_state_request_proof_v1.zig");
const Lookup = @import("block_v5_precompile_lookup_proof_v1.zig");
const LookupStage = @import("block_v5_precompile_lookup_stage_v1.zig");
const External = @import("block_v5_external_memory_sidecar_proof_v1.zig");
const ExternalStage = @import("block_v5_caller_external_stage_v1.zig");
const ExternalSource = @import("block_execution_external_trace_v2.zig");
const Bytes = @import("block_v5_memory_byte_demand_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Tables = @import("../air/lookups/tables/mod.zig");
const Frame = @import("../air/block/memory_event.zig").Frame;
const Segment = @import("../runner/mod.zig").EthereumShaSegmentResult;
const Staged = @import("block_v5_caller_columns_stage_v1.zig");
pub const ReadonlyCollection = struct { selection: @import("block_v5_readonly_input_selection_v1.zig").Pins, input: []const u8, limits: @import("block_v5_caller_readonly_protocol_v1.zig").Limits = .{}, counter_groups: ?*@import("block_v5_readonly_input_counter_collection_v2.zig").Owned = null };
pub const Limits = struct { max_metadata_bytes: usize, max_external_slots: usize, register_custody_mode: u32 = 0, readonly: ?ReadonlyCollection = null };
pub const Staging = struct { dir: std.fs.Dir, name: []const u8, limits: Staged.Limits, pin_out: *Staged.Pin };
/// Successful callbacks consume proof ownership; errors leave it with producer.
pub const Sink = struct {
    context: *anyopaque,
    put_caller: *const fn (*anyopaque, u32, *Family.Proof) anyerror!void,
    put_fused: ?*const fn (*anyopaque, u32, *Fused.Proof) anyerror!void = null,
    put_readonly_fused: ?*const fn (*anyopaque, u32, *@import("block_v5_caller_readonly_proof_v1.zig").Proof) anyerror!void = null,
    // Explicit old fixture callbacks are never dispatched by this canonical pipeline.
    put_program: ?*const fn (*anyopaque, u32, *Program.Proof) anyerror!void = null,
    put_state: ?*const fn (*anyopaque, u32, *State.Proof) anyerror!void = null,
    put_tables: ?*const fn (*anyopaque, u32, *Lookup.Proof) anyerror!void = null,
    put_memory: ?*const fn (*anyopaque, u32, *External.Proof) anyerror!void = null,
};
pub const Bound = struct {
    proposal: Proposal,
    record: Batch.Record,
    family11: Seal.Entry,
    family12: Seal.Entry,
    family13: Seal.Entry,
    pub fn require(self: *const Bound, a: std.mem.Allocator) !void {
        const expected = try self.proposal.lateBind(a, self.record.execution.instance_id);
        if (!std.meta.eql(self.*, expected)) return error.ChangedV5BoundCaller;
    }
};
/// Fully value-owned metadata: no caller/runner slices or proofs survive.
pub const Proposal = struct {
    register_custody_mode: u32 = 0,
    readonly_physical: ?@import("block_v5_caller_readonly_stage_v1.zig").Physical = null,
    readonly_authority: ?@import("block_v5_caller_readonly_protocol_v1.zig").Authority = null,
    statement: Profile.admission.Statement,
    total_steps: u32,
    index: u32,
    frame: Frame,
    config: core.pcs.PcsConfig,
    key_id: [32]u8,
    roots: Seal.Roots,
    witness_root: [32]u8,
    byte_demand: Bytes.Demand,
    byte_snapshot: [32]u8,
    counter_snapshots: [Tables.schema.KIND_COUNT][32]u8,
    caller_max_requests: [Tables.schema.KIND_COUNT]u64,
    pub fn deinit(self: *Proposal) void {
        self.* = undefined;
    }
    pub fn lateBind(self: *const Proposal, a: std.mem.Allocator, native_instance_id: [32]u8) !Bound {
        const bound = try FusedStage.lateBind(a, self.*, native_instance_id);
        return .{ .proposal = bound.proposal, .record = bound.record, .family11 = bound.family11, .family12 = bound.family12, .family13 = bound.family13 };
    }
};
fn requireFrame(segment: *const Segment, frame: Frame) !void {
    if (frame.clock_frame != segment.base.clock_frame or frame.global_first_cycle != segment.base.global_first_cycle or
        frame.cycle_count != segment.base.cycle_count or frame.cycle_count == 0) return error.UntrustedV5CallerFrame;
}
fn registerCounters(a: std.mem.Allocator, witness: *const Witness, segment: *const Segment, counters: *Tables.counter.Set) !void {
    if (@import("block_v5_precompile_protocol_v1.zig").circuit_profile.localZeroCustody()) return @import("block_v5_caller_columns_stage_v1.zig").registerCounters(a, witness, counters);
    try (@import("../air/guest_precompile/ethereum_lookup_registration.zig").Context{ .keccak = segment.extension.keccakf_calls.records(), .recovery = segment.extension.signer_recovery_calls.records() }).register(counters);
    try @import("../air/guest_precompile/sha256_lookup_registration.zig").register(a, &witness.sha_rows, counters);
}
fn snapshots(counters: *const Tables.counter.Set) [Tables.schema.KIND_COUNT][32]u8 {
    var result: [Tables.schema.KIND_COUNT][32]u8 = undefined;
    for (&counters.counters, &result) |*counter, *digest| digest.* = @import("../air/block/memory_range_interaction_v2.zig").counterSnapshot(counter);
    return result;
}
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Api = Family.ForBackend(Backend);
        const Producer = Batch.ForBackend(Backend);
        const Memory = ExternalStage.ForBackend(Backend);
        pub const Hooks = struct {
            context: *anyopaque,
            on_caller_proof: *const fn (*anyopaque, std.mem.Allocator, Producer.WarmCaller, *const Family.Proof) anyerror!void,
        };
        pub fn collectSegment(a: std.mem.Allocator, segment: *const Segment, index: u32, frame: Frame, config: core.pcs.PcsConfig, limits: Limits, global: *Tables.counter.Set) !Proposal {
            return collectSegmentWithStaging(a, segment, index, frame, config, limits, global, null);
        }
        /// Optional publication writes the already-owned complete witness. It
        /// does not initialize a second caller witness or retain its PCS.
        pub fn collectSegmentWithStaging(a: std.mem.Allocator, segment: *const Segment, index: u32, frame: Frame, config: core.pcs.PcsConfig, limits: Limits, global: *Tables.counter.Set, staging: ?Staging) !Proposal {
            try @import("block_v5_execution_recipe_v1.zig").canonical.requireMode(limits.register_custody_mode);
            try requireFrame(segment, frame);
            if (limits.max_metadata_bytes < @sizeOf(Proposal)) return error.V5CallerProposalLimit;
            var witness = try Witness.initSegment(a, segment);
            defer witness.deinit();
            if (Profile.externalCount(&witness.statement) == 0) return error.EmptyV5CallerProposal;
            var physical = try Api.commitPhysicalFirstRound(a, &witness, witness.total_steps, config);
            defer physical.deinit(a);
            var counters = try Tables.counter.Set.init(a);
            defer counters.deinit(a);
            try registerCounters(a, &witness, segment, &counters);
            const bounds = try @import("block_v5_precompile_table_demand_v1.zig").fromStatement(a, &witness.statement, witness.total_steps, config);
            // Check signed physical arithmetic demand before byte requests join.
            for (counters.counters, bounds) |counter, bound| {
                var mass: u64 = 0;
                for (counter.values) |weight| mass = try std.math.add(u64, mass, @min(weight.toU32(), core.fields.m31.Modulus - weight.toU32()));
                if (mass > bound) return error.V5CallerCounterDemandExceeded;
            }
            if (limits.readonly != null and limits.register_custody_mode != 1) return error.InvalidV5CallerReadonlyMode;
            var original: ?Memory.Prepared = null;
            defer if (original) |*owned| owned.deinit(a);
            var classified: ?@import("block_v5_caller_readonly_stage_v1.zig").ForBackend(Backend).Prepared = null;
            defer if (classified) |*owned| owned.deinit(a);
            if (limits.readonly) |selected| {
                classified = try @import("block_v5_caller_readonly_stage_v1.zig").ForBackend(Backend).Prepared.initPhysicalWithCounter(a, &physical, &witness.statement, witness.total_steps, frame, selected.selection, selected.input, selected.limits, counters.get(.range_check_8_8));
                if (classified.?.traces.len > limits.max_external_slots) return error.V5CallerProposalLimit;
            } else {
                original = try Memory.Prepared.initForMode(a, &physical, &witness.statement, frame, index, counters.get(.range_check_8_8), limits.register_custody_mode);
                if (original.?.slots.len > limits.max_external_slots) return error.V5CallerProposalLimit;
            }
            const witness_root = if (classified) |value| value.first.roots[2] else original.?.first.roots[2];
            const byte_demand = if (classified) |value| value.byte_demand else original.?.byte_demand;
            const byte_snapshot = if (classified) |value| value.byte_snapshot else original.?.byte_snapshot;
            const proposal = Proposal{ .register_custody_mode = limits.register_custody_mode, .statement = witness.statement, .total_steps = witness.total_steps, .index = index, .frame = frame, .config = config, .key_id = physical.key_id, .roots = physical.roots, .witness_root = witness_root, .byte_demand = byte_demand, .byte_snapshot = byte_snapshot, .readonly_physical = if (classified) |value| value.physical else null, .counter_snapshots = snapshots(&counters), .caller_max_requests = bounds };
            if (limits.readonly) |selected| if (selected.counter_groups) |groups| try groups.appendCaller(index, classified.?.physical, classified.?.metadata);
            // All validation/allocation precedes this transactional merge.
            for (global.counters, counters.counters) |target, source| if (target.kind != source.kind or target.values.len != source.values.len) return error.InvalidV5CallerCounters;
            if (staging) |output| {
                const descriptor = Staged.Descriptor.fromProposal(&proposal);
                output.pin_out.* = try Staged.write(a, output.dir, output.name, &witness, &descriptor, output.limits);
            }
            for (&global.counters, counters.counters) |*target, source| {
                for (target.values, source.values) |*dst, value| dst.* = dst.add(value);
            }
            return proposal;
        }
        pub fn proveSegment(a: std.mem.Allocator, segment: *const Segment, bound: *const Bound, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, pool: *engine.work_pool.WorkPool, sink: Sink, hooks: ?Hooks) !void {
            try requireSink(bound, sink);
            try requireFrame(segment, bound.proposal.frame);
            try requireBound(a, bound, sealed, pins, entries);
            var witness = try Witness.initSegment(a, segment);
            defer witness.deinit();
            var counters = try Tables.counter.Set.init(a);
            defer counters.deinit(a);
            try registerCounters(a, &witness, segment, &counters);
            var context = Context{ .bound = bound, .sink = sink, .hooks = hooks, .counters = &counters };
            try Producer.proveWitnessWithHooks(a, &bound.record, &witness, bound.proposal.config, .{ .context = sink.context, .accept = sink.put_caller }, sealed, pins, entries, pool, .{ .context = &context, .on_first_round = Context.warm, .on_proof = Context.proved });
        }
        /// No live RawSegment or second guest execution. All caller/private
        /// matrices and signed counters come from pinned staged cells; mandatory
        /// physical recommit is reused by the original warm proof transaction.
        pub fn proveStaged(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, file_pin: Staged.Pin, bound: *const Bound, limits: Staged.Limits, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, pool: *engine.work_pool.WorkPool, sink: Sink, hooks: ?Hooks) !void {
            try requireSink(bound, sink);
            try requireBound(a, bound, sealed, pins, entries);
            const descriptor = Staged.Descriptor.fromProposal(&bound.proposal);
            var prepared = try Staged.ForBackend(Backend).load(a, dir, name, &descriptor, file_pin, limits);
            defer prepared.deinit(a);
            var first = try prepared.first.bind(bound.record.execution.index, bound.record.execution.instance_id);
            defer first.deinit(a);
            var context = Context{ .bound = bound, .sink = sink, .hooks = hooks, .counters = &prepared.owner.counters };
            try Producer.proveFirstRoundWithHooks(a, &bound.record, &prepared.owner.witness, &first, bound.proposal.config, .{ .context = sink.context, .accept = sink.put_caller }, sealed, pins, entries, pool, .{ .context = &context, .on_first_round = Context.warm, .on_proof = Context.proved });
        }
        fn requireSink(bound: *const Bound, sink: Sink) !void {
            if (bound.proposal.readonly_physical != null) {
                if (sink.put_readonly_fused == null or bound.proposal.readonly_authority == null) return error.MissingV5CallerReadonlyFusionSink;
            } else if (sink.put_fused == null or bound.proposal.readonly_authority != null) return error.MissingV5CanonicalCallerFusionSink;
        }
        fn requireBound(a: std.mem.Allocator, bound: *const Bound, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry) !void {
            try bound.require(a);
            if (bound.proposal.register_custody_mode != sealed.register_custody_mode) return error.MixedV5CallerMemoryScope;
            try sealed.require(pins, entries);
            if (bound.proposal.readonly_physical != null and std.mem.allEqual(u8, &sealed.readonly_roster_digest, 0)) return error.MissingReadonlyInputRoster;
            inline for (.{ bound.family11, bound.family12, bound.family13 }) |expected| {
                var found = false;
                for (entries) |entry| if (entry.family == expected.family and entry.index == expected.index) {
                    if (!std.meta.eql(entry, expected)) return error.UntrustedV5CallerPipelineRoster;
                    found = true;
                };
                if (!found) return error.MissingV5CallerPipelineRoster;
            }
        }
        const Context = struct {
            bound: *const Bound,
            sink: Sink,
            hooks: ?Hooks,
            counters: *Tables.counter.Set,
            fn warm(raw: *anyopaque, a: std.mem.Allocator, caller: Producer.WarmCaller) !void {
                const self: *Context = @ptrCast(@alignCast(raw));
                // The versioned composite binds original caller cells and both
                // membership/read providers in one freshly verified quotient.
                if (self.bound.proposal.readonly_physical) |expected| {
                    const authority = self.bound.proposal.readonly_authority orelse return error.MissingV5CallerReadonlyAuthority;
                    var memory = try @import("block_v5_caller_readonly_stage_v1.zig").ForBackend(Backend).Prepared.init(a, caller.first, self.bound.proposal.frame, authority);
                    defer memory.deinit(a);
                    try memory.registerCounter(a, self.counters.get(.range_check_8_8));
                    if (!std.meta.eql(memory.physical, expected) or !std.meta.eql(snapshots(self.counters), self.bound.proposal.counter_snapshots)) return error.V5CallerPhysicalReplayMismatch;
                    var readonly_stage = @import("block_v5_caller_readonly_stage_v1.zig").ForBackend(Backend){ .sink = .{ .context = self.sink.context, .put_fused = self.sink.put_readonly_fused orelse return error.MissingV5CallerReadonlyFusionSink }, .frame = self.bound.proposal.frame, .authority = authority, .expected = expected };
                    try readonly_stage.provePreparedWarm(a, &memory, caller);
                    return;
                }
                // Recheck every physical counter snapshot before any publish.
                var memory = try Memory.Prepared.initForMode(a, caller.first, &caller.record.statement, self.bound.proposal.frame, caller.record.execution.index, &self.counters.counters[@intFromEnum(Tables.schema.Kind.range_check_8_8)], caller.sealed.register_custody_mode);
                defer memory.deinit(a);
                if (!std.meta.eql(memory.first.roots[2], self.bound.proposal.witness_root) or !std.meta.eql(memory.byte_snapshot, self.bound.proposal.byte_snapshot) or !std.meta.eql(snapshots(self.counters), self.bound.proposal.counter_snapshots)) return error.V5CallerPhysicalReplayMismatch;
                var fused = FusedStage.ForBackend(Backend){
                    .sink = .{ .context = self.sink.context, .put_fused = self.sink.put_fused orelse return error.MissingV5CanonicalCallerFusionSink },
                    .frame = self.bound.proposal.frame,
                    .expected_witness_root = self.bound.proposal.witness_root,
                    .expected_byte_snapshot = self.bound.proposal.byte_snapshot,
                };
                try fused.provePreparedWarm(a, &memory, caller);
            }
            fn proved(raw: *anyopaque, a: std.mem.Allocator, caller: Producer.WarmCaller, proof: *const Family.Proof) !void {
                const self: *Context = @ptrCast(@alignCast(raw));
                if (self.hooks) |callbacks| try callbacks.on_caller_proof(callbacks.context, a, caller, proof);
            }
        };
    };
}
