//! Replayable native-v5/program/sorted-memory family producer.
//! The canonical native-v3 branch produces word-v4/range16 memory. All PCS state
//! is scoped to one execution or memory instance; outputs are proofs for
//! staging, never block authority. Precompile, endpoint and recursion stages
//! are separate explicit obligations and cannot be substituted by v4 leaves.
const std = @import("std");
const core = @import("stwo_core");
const NativeV2 = @import("block_v5_native_execution_proof_v1.zig");
const NativeV3 = @import("block_v5_native_execution_proof_v3.zig");
const Owner = @import("blake3_execution_trace.zig").Owner;
const Plan = @import("blake3_commitment_plan.zig");
const LegacyCatalog = @import("block_v5_native_template_catalog_v1.zig");
const ProgramModule = @import("block_v5_program_first_round_v1.zig");
const Request = @import("block_v5_program_request_proof_v1.zig");
const Table = @import("block_v5_program_table_proof_v1.zig");
const Memory = @import("block_v5_memory_batch_artifact_v1.zig");
const WordMemory = @import("block_v5_word_memory_artifact_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Profile = @import("../isa/execution_profile.zig").ExecutionProfile;

pub const Replay = ReplayFor(false, false);
pub const LightweightReplay = ReplayFor(true, false);
pub const ExecutionSource = SourceFor(false, false);
pub const LightweightExecutionSource = SourceFor(true, false);
pub const ExecutionSink = SinkFor(false, false);
pub const LightweightExecutionSink = SinkFor(true, false);
fn NativeFor(comptime lightweight: bool, comptime capacity: bool) type {
    return if (capacity) @import("block_v5_native_capacity_proof_v1.zig") else if (lightweight) NativeV3 else NativeV2;
}
fn ReplayFor(comptime lightweight: bool, comptime capacity: bool) type {
    return struct {
        const Self = @This();
        pub const capacity_native = capacity;
        owner: *Owner,
        native_limits: if (capacity) @import("block_v5_native_capacity_proof_v1.zig").Limits else void = if (capacity) .{} else {},
        admission: if (lightweight) @import("block_v5_native_public_admission_v1.zig").Admission else Plan.Admission,
        profile: Profile,
        context: *anyopaque,
        /// Releases the owned runner/trace and any borrowed admission data.
        release: *const fn (*anyopaque, *Self) void,
        pub fn deinit(self: *Self) void {
            self.release(self.context, self);
            self.* = undefined;
        }
    };
}
fn SourceFor(comptime lightweight: bool, comptime capacity: bool) type {
    return struct {
        context: *anyopaque,
        load: *const fn (*anyopaque, u32) anyerror!ReplayFor(lightweight, capacity),
    };
}
fn SinkFor(comptime lightweight: bool, comptime capacity: bool) type {
    if (capacity) return struct {
        context: *anyopaque,
        native: *const fn (*anyopaque, u32, *@import("block_v5_native_capacity_proof_v1.zig").Proof) anyerror!void,
        table: *const fn (*anyopaque, *Table.Proof) anyerror!void,
    };
    return struct {
        context: *anyopaque,
        /// Success transfers ownership; failure leaves it with this producer.
        native: *const fn (*anyopaque, u32, *NativeFor(lightweight, capacity).Proof) anyerror!void,
        request: *const fn (*anyopaque, u32, *Request.Proof) anyerror!void,
        table: *const fn (*anyopaque, *Table.Proof) anyerror!void,
    };
}
/// Native production admits actual global memory metadata, without borrowing
/// a particular sorted-family PCS/trace or fabricating an artifact instance.
pub const MemoryPlan = struct { config: core.pcs.PcsConfig, plan_digest: [32]u8 };
pub const ProducedFamilies = struct {
    execution_count: u32,
    program_fetches: u64,
    memory_events: u64,
    seal_digest: [32]u8,
    /// These fields state producer coverage, not verified authority.
    global_native_lookup_stage_present: bool = false,
    precompile_stage_present: bool = false,
    endpoint_stage_present: bool = false,
    recursive_stage_present: bool = false,
};
/// Execution coverage only. Independent global jobs must finish separately;
/// this result deliberately carries no memory/provider coverage fields.
pub const ProducedExecutions = struct {
    execution_count: u32,
    program_fetches: u64,
    seal_digest: [32]u8,
};

pub fn ForBackend(comptime Backend: type) type {
    return ForNativeBackend(Backend, false, false);
}
/// Explicit no-custody native-v3 production. The remaining families still
/// have their own independently sealed stages and fresh closure obligations.
pub fn ForLightweightBackend(comptime Backend: type) type {
    return ForNativeBackend(Backend, true, false);
}
pub fn ForCapacity(comptime capacity: bool) type {
    return struct {
        pub const LightweightReplay = ReplayFor(true, capacity);
        pub const LightweightExecutionSource = SourceFor(true, capacity);
        pub const LightweightExecutionSink = SinkFor(true, capacity);
        pub fn ForBackend(comptime Backend: type) type {
            return ForNativeBackend(Backend, true, capacity);
        }
    };
}
fn ForNativeBackend(comptime Backend: type, comptime lightweight: bool, comptime capacity: bool) type {
    const Catalog = if (capacity) @import("block_v5_native_capacity_catalog_v1.zig") else LegacyCatalog;
    const Program = ProgramModule.ForCapacity(capacity);
    const MemoryProducer = if (lightweight) WordMemory else Memory;
    const MemorySource = if (lightweight) WordMemory.Source else Memory.TraceSource;
    const MemorySink = if (lightweight) WordMemory.Sink else Memory.ProofSink;
    return struct {
        const Native = NativeFor(lightweight, capacity);
        pub const WarmExecution = struct {
            index: u32,
            replay: *const ReplayFor(lightweight, capacity),
            first: *Native.ForBackend(Backend).FirstRound,
            sealed: Seal.Sealed,
            pins: Seal.Pins,
            entries: []const Seal.Entry,
            catalog: Catalog.Admission,
        };
        /// Same-root side stages borrow immutable commitments before native
        /// proving consumes the scheme. A proof callback can freshly verify a
        /// clone and publish a recursive leaf while the replay owner is live.
        /// Callbacks borrow all inputs; neither may consume the native scheme
        /// or proof. Callback-owned side state must be released on failure by
        /// its enclosing stage. Success does not grant verifier authority.
        pub const Hooks = struct {
            context: *anyopaque,
            /// Selects the exact B5FP sealed program-request protocol. This is
            /// admitted against the native shape/catalog before the callback;
            /// it cannot suppress a separately sealed B5PR obligation.
            fused_program_requests: bool = false,
            /// A staged source may move its freshly recommitted first round
            /// into this producer. The same root/catalog checks below still
            /// apply, and the producer releases it before the replay owner.
            prepare_first_round: ?*const fn (*anyopaque, std.mem.Allocator, *const ReplayFor(lightweight, capacity), u32) anyerror!Native.ForBackend(Backend).FirstRound = null,
            on_first_round: ?*const fn (*anyopaque, std.mem.Allocator, WarmExecution) anyerror!void = null,
            on_proof: ?*const fn (*anyopaque, std.mem.Allocator, WarmExecution, *const Native.Proof) anyerror!void = null,
        };
        pub fn prove(
            a: std.mem.Allocator,
            program: *const Program.ForBackend(Backend),
            memory: *const MemoryProducer.ForBackend(Backend),
            pins: Seal.Pins,
            entries: []const Seal.Entry,
            sealed: Seal.Sealed,
            catalog: Catalog.Admission,
            executions: SourceFor(lightweight, capacity),
            output: SinkFor(lightweight, capacity),
            memory_source: MemorySource,
            memory_sink: MemorySink,
        ) !ProducedFamilies {
            return proveWithHooks(a, program, memory, pins, entries, sealed, catalog, executions, output, memory_source, memory_sink, null);
        }
        pub fn proveWithHooks(
            a: std.mem.Allocator,
            program: *const Program.ForBackend(Backend),
            memory: *const MemoryProducer.ForBackend(Backend),
            pins: Seal.Pins,
            entries: []const Seal.Entry,
            sealed: Seal.Sealed,
            catalog: Catalog.Admission,
            executions: SourceFor(lightweight, capacity),
            output: SinkFor(lightweight, capacity),
            memory_source: MemorySource,
            memory_sink: MemorySink,
            hooks: ?Hooks,
        ) !ProducedFamilies {
            const produced = try proveExecutionsWithHooks(a, program, memory, pins, entries, sealed, catalog, executions, output, hooks);
            var table_proof = try program.proveTable(sealed.programSeal());
            var owns_table = true;
            defer if (owns_table) table_proof.deinit(a);
            try output.table(output.context, &table_proof);
            owns_table = false;
            try memory.prove(a, memory_source, memory_sink, pins, entries, sealed.digest, sealed);
            return .{ .execution_count = produced.execution_count, .program_fetches = produced.program_fetches, .memory_events = if (lightweight) memory.plan.total_events else memory.total_events, .seal_digest = produced.seal_digest };
        }
        pub fn proveExecutionsWithHooks(
            a: std.mem.Allocator,
            program: *const Program.ForBackend(Backend),
            memory: *const MemoryProducer.ForBackend(Backend),
            pins: Seal.Pins,
            entries: []const Seal.Entry,
            sealed: Seal.Sealed,
            catalog: Catalog.Admission,
            executions: SourceFor(lightweight, capacity),
            output: SinkFor(lightweight, capacity),
            hooks: ?Hooks,
        ) !ProducedExecutions {
            return proveExecutionsWithMemoryPlanHooks(a, program, .{ .config = memory.config, .plan_digest = memory.plan_digest }, pins, entries, sealed, catalog, executions, output, hooks);
        }
        pub fn proveExecutionsWithMemoryPlanHooks(
            a: std.mem.Allocator,
            program: *const Program.ForBackend(Backend),
            memory: MemoryPlan,
            pins: Seal.Pins,
            entries: []const Seal.Entry,
            sealed: Seal.Sealed,
            catalog: Catalog.Admission,
            executions: SourceFor(lightweight, capacity),
            output: SinkFor(lightweight, capacity),
            hooks: ?Hooks,
        ) !ProducedExecutions {
            const fused = if (hooks) |callbacks| callbacks.fused_program_requests else false;
            if (capacity and !fused) return error.CapacityFusedProgramStageRequired;
            if (fused and (!lightweight or hooks.?.on_first_round == null))
                return error.V5FusedProgramStageRequired;
            try sealed.require(pins, entries);
            if (program.next != sealed.execution_instance_count or
                !std.meta.eql(try catalog.digest(), pins.native_template_catalog_digest) or
                !std.meta.eql(memory.plan_digest, pins.memory_plan_digest) or
                !std.meta.eql(memory.config, pins.config) or
                program.config == null or !std.meta.eql(program.config.?, pins.config))
                return error.UntrustedV5BlockProducerPlan;
            if (!lightweight and (pins.counts[@intFromEnum(Seal.Family.precompile) - 1] != 0 or
                pins.counts[@intFromEnum(Seal.Family.program_extension_request) - 1] != 0))
                return error.V5BlockPrecompileStageRequired;
            for (program.executionEntries()) |entry| try requireEntry(entries, entry);
            for (program.requestEntries()) |entry| try requireEntry(entries, entry);
            if (lightweight) for (program.extensionEntries()) |entry| try requireEntry(entries, entry);
            const table_plan = try program.census.smallestTablePlan(program.next, program.expected_fetches orelse return error.IncompleteV5BlockProducerPlan);
            if (!std.meta.eql(try table_plan.digest(), pins.program_plan_digest))
                return error.UntrustedV5BlockProducerPlan;
            try requireEntry(entries, .{ .family = .program, .index = 0, .instance_id = try Table.instanceId(table_plan), .roots = program.table_roots orelse return error.IncompleteV5BlockProducerPlan });
            for (0..program.next) |index| {
                const ordinal: u32 = @intCast(index);
                var replay = try executions.load(executions.context, ordinal);
                defer replay.deinit();
                if (!replay.owner.native_only_v5 or (!lightweight and replay.owner.external_retirements != 0) or
                    program.legacy_request_ids[index]) return error.LegacyV5ExecutionForbidden;
                var native_first = if (hooks != null and hooks.?.prepare_first_round != null)
                    try hooks.?.prepare_first_round.?(hooks.?.context, a, &replay, ordinal)
                else if (capacity)
                    try Native.ForBackend(Backend).commitFirstRound(a, replay.owner, replay.admission, pins.config, replay.profile, ordinal, replay.native_limits)
                else
                    try Native.ForBackend(Backend).commitFirstRound(a, replay.owner, replay.admission, pins.config, replay.profile, ordinal);
                defer native_first.deinit(a);
                if (!std.meta.eql(native_first.entry(), program.executionEntries()[index]) or
                    !std.meta.eql(native_first.template_id, program.native_key_ids[index]))
                    return error.ChangedV5BlockExecutionReplay;
                try catalog.admit(pins, sealed, ordinal, native_first.template, native_first.template_id);
                if (lightweight) {
                    if (fused) {
                        const FusedSource = if (capacity) @import("block_v5_native_capacity_fused_source_v1.zig") else @import("block_v5_native_projection_fused_source_v1.zig");
                        const FusedProof = if (capacity) @import("block_v5_native_capacity_fused_proof_v1.zig") else @import("block_v5_native_projection_fused_proof_v2.zig");
                        const AccessSource = @import("block_execution_sidecar_batch_v2.zig");
                        const fused_slots = try FusedSource.slotsFromShapeForMode(a, &replay.owner.statement, replay.owner.external_retirements, sealed.register_custody_mode);
                        defer a.free(fused_slots);
                        const frame = @import("../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = replay.admission.context.first_cycle, .cycle_count = replay.owner.statement.public_data.clock };
                        const access_slots = if (capacity)
                            try FusedSource.memorySlots(a, &replay.owner.statement, replay.owner.external_retirements, frame, sealed.register_custody_mode)
                        else
                            try AccessSource.slotsFromStatementForMode(a, &replay.owner.statement, frame, sealed.register_custody_mode);
                        defer a.free(access_slots);
                        const access_entry = try findEntry(entries, .execution_sidecar, ordinal);
                        const empty_entry: ?Seal.Entry = if (access_slots.len != 0) null else if (capacity)
                            try FusedSource.emptyEntry(a, &replay.owner.statement, replay.owner.external_retirements, frame, native_first.entry(), 0, sealed.register_custody_mode)
                        else
                            try @import("block_v5_empty_opcode_memory_v1.zig").firstRoundEntryForMode(a, &replay.owner.statement, frame, native_first.entry(), 0, sealed.register_custody_mode);
                        try FusedProof.admit(sealed, pins, entries, ordinal, native_first.template_id, native_first.instance_id, native_first.roots, access_entry.roots[0], frame, fused_slots, access_slots, empty_entry);
                    }
                }
                const warm = WarmExecution{ .index = ordinal, .replay = &replay, .first = &native_first, .sealed = sealed, .pins = pins, .entries = entries, .catalog = catalog };
                if (hooks) |callbacks| if (callbacks.on_first_round) |callback| {
                    try callback(callbacks.context, a, warm);
                    if (!native_first.owns_scheme or native_first.scheme.trees.items.len != 2 or
                        !std.meta.eql(native_first.entry(), program.executionEntries()[index]))
                        return error.ChangedV5BlockWarmExecution;
                };
                if (!capacity and !fused) {
                    const slots = try Request.slotsFromStatement(a, &replay.owner.statement);
                    defer a.free(slots);
                    if (slots.len == 0) {
                        if (!lightweight) return error.EmptyProgramRequestRoster;
                        try @import("block_v5_empty_program_request_v1.zig").validateShape(&replay.owner.statement, replay.owner.external_retirements);
                        // The sealed empty request entry is derived from the exact
                        // native shape; no arbitrary zero-claim STARK is emitted.
                    } else {
                        var request_first = try Request.ForBackend(Backend).borrowFirstRound(a, &native_first.scheme, replay.owner.main.items, slots, native_first.template_id, ordinal);
                        defer request_first.deinit(a);
                        if (!std.meta.eql(request_first.roots, program.requestEntries()[index].roots))
                            return error.ChangedV5BlockRequestReplay;
                        var request_proof = try Request.ForBackend(Backend).prove(a, &request_first, replay.owner.main.items, slots, sealed.programSeal(), native_first.template_id, ordinal, native_first.roots);
                        var owns_request = true;
                        defer if (owns_request) request_proof.deinit(a);
                        try output.request(output.context, ordinal, &request_proof);
                        owns_request = false;
                    }
                }
                var native_proof = try Native.ForBackend(Backend).proveWithCatalog(a, &native_first, sealed, pins, entries, catalog);
                var owns_native = true;
                defer if (owns_native) native_proof.deinit(a);
                if (hooks) |callbacks| if (callbacks.on_proof) |callback|
                    try callback(callbacks.context, a, warm, &native_proof);
                try output.native(output.context, ordinal, &native_proof);
                owns_native = false;
            }
            return .{ .execution_count = program.next, .program_fetches = table_plan.expected_fetches, .seal_digest = sealed.digest };
        }
    };
}

fn requireEntry(entries: []const Seal.Entry, expected: Seal.Entry) !void {
    if (!std.meta.eql(try findEntry(entries, expected.family, expected.index), expected)) return error.UntrustedV5BlockProducerRoot;
}
fn findEntry(entries: []const Seal.Entry, family: Seal.Family, index: u32) !Seal.Entry {
    var found: ?Seal.Entry = null;
    for (entries) |entry| if (entry.family == family and entry.index == index) {
        if (found != null) return error.DuplicateV5BlockProducerRoot;
        found = entry;
    };
    return found orelse error.MissingV5BlockProducerRoot;
}
