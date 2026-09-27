//! B5CF1: one caller projection/access STARK, beside the fresh arithmetic STARK.
//! Independent ROM/state/table/register/transition/byte claims remain open.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Column = engine.pcs.ColumnEvaluation;
const Schedule = @import("block_v5_caller_fused_schedule_v1.zig").Schedule;
const ScheduleModule = @import("block_v5_caller_fused_schedule_v1.zig");
const Adapter = @import("block_v5_caller_fused_component_v1.zig");
const Composite = @import("block_v5_composite_pcs_v1.zig");
const Family = @import("block_v5_precompile_family_proof_v1.zig");
const Protocol = @import("block_v5_precompile_protocol_v1.zig");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Program = @import("block_v5_program_extension_proof_v1.zig");
const ProgramSlots = @import("block_v5_program_extension_slots_v1.zig");
const State = @import("block_v5_precompile_state_request_proof_v1.zig");
const Table = @import("block_v5_precompile_lookup_proof_v1.zig");
const Algebra = @import("block_v5_precompile_lookup_algebra_v1.zig");
const External = @import("block_v5_external_memory_sidecar_proof_v1.zig");
const ExternalSource = @import("block_execution_external_trace_v2.zig");
const Selected = @import("block_v5_committed_projection_columns_v1.zig");
const Integer = @import("block_execution_integer_bridge_v2.zig");
const Eval = @import("block_v5_opcode_sidecar_eval_v1.zig");
const Range = @import("block_execution_byte_range_v2.zig");
const Transition = @import("block_execution_transition_interaction_v2.zig");
const UniversalMemory = @import("block_v5_opcode_memory_interaction_v1.zig");
const WordTransition = @import("block_v5_word_execution_transition_v1.zig");
const Word = @import("block_v5_word_memory_protocol_v1.zig");
const Bus = @import("block_memory_relation_v2.zig");
const Framework = @import("../recursion/air/framework_interaction.zig");
const Canonical = @import("../recursion/air/universal_provider_relations.zig");
const Frame = @import("../air/block/memory_event.zig").Frame;
const Seal = @import("block_v5_source_seal_v1.zig");
pub const TAG: u32 = 0x42354346; // B5CF
pub const VERSION: u32 = 1;
pub const Proof = struct {
    stark: suite.Proof,
    program_claims: []Program.Claim,
    state_claims: []Program.Claim,
    table_claims: []Algebra.Claim,
    memory_claims: []External.Claim,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        freeClaims(a, self);
        self.* = undefined;
    }
};
pub const Verified = struct {
    program: Program.VerifiedReceipt,
    state: State.Receipt,
    tables: Table.Receipt,
    memory: External.Verified,
    pub fn deinit(self: *Verified, a: std.mem.Allocator) void {
        self.memory.deinit(a);
        self.* = undefined;
    }
};
/// Small owned claim frames only; no arithmetic matrices, PCS leases or source
/// proof arrays are retained by a captured verifier.
pub const ClaimFrames = struct {
    program_claims: []Program.Claim,
    state_claims: []Program.Claim,
    table_claims: []Algebra.Claim,
    memory_claims: []External.Claim,
    pub fn deinit(self: *ClaimFrames, a: std.mem.Allocator) void {
        a.free(self.program_claims);
        a.free(self.state_claims);
        a.free(self.table_claims);
        a.free(self.memory_claims);
        self.* = undefined;
    }
    pub fn clone(a: std.mem.Allocator, source: anytype) !ClaimFrames {
        const program = try a.dupe(Program.Claim, source.program_claims);
        errdefer a.free(program);
        const state = try a.dupe(Program.Claim, source.state_claims);
        errdefer a.free(state);
        const tables = try a.dupe(Algebra.Claim, source.table_claims);
        errdefer a.free(tables);
        const memory = try a.dupe(External.Claim, source.memory_claims);
        return .{ .program_claims = program, .state_claims = state, .table_claims = tables, .memory_claims = memory };
    }
};
pub const VerifiedCapture = struct {
    allocator: std.mem.Allocator,
    proof: core.verifier.ProofCapture(suite.Hasher),
    claims: ClaimFrames,
    relations: Profile.Relations,
    word: Word.Challenges,
    memory_challenges: Bus.Challenges,
    final_channel: suite.Channel,
    config: core.pcs.PcsConfig,
    frame: Frame,
    mode: u32,
    instance_id: [32]u8,
    receipt: Verified,
    seal: [32]u8,
    pub fn deinit(self: *VerifiedCapture) void {
        self.proof.deinit(self.allocator);
        self.claims.deinit(self.allocator);
        self.receipt.deinit(self.allocator);
        self.* = undefined;
    }
    /// Transport consistency only. Full original proof verification and
    /// independent policy admission are the authority, never this checksum.
    pub fn identity(self: *const VerifiedCapture) [32]u8 {
        var domain: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash("stwo-zig/block-v5/caller-fused-capture/v1\x00", &domain, .{});
        var channel = suite.Channel{};
        channel.mixRoot(domain);
        channel.mixRoot(@import("proof_capture_sha256.zig").compute(&self.proof));
        channel.mixRoot(self.instance_id);
        self.config.mixInto(&channel);
        channel.mixU32s(&.{ self.mode, @intFromEnum(self.frame.clock_frame), self.frame.cycle_count });
        channel.mixU64(self.frame.global_first_cycle);
        Family.mixBinding(&channel, self.receipt.state.binding);
        channel.mixRoot(self.receipt.memory.witness_root);
        channel.mixFelts(&.{ self.receipt.program.sum, self.receipt.state.sum, self.receipt.tables.register_memory_sum, self.receipt.memory.transition_sum, self.receipt.memory.universal_sum });
        channel.mixFelts(&self.receipt.tables.claims);
        channel.mixU64(self.receipt.program.fetch_count);
        channel.mixU64(self.receipt.state.caller_count);
        channel.mixU64(self.receipt.tables.memory_event_count);
        channel.mixU64(self.receipt.memory.event_count);
        for (self.receipt.memory.range_claims) |range| channel.mixFelts(&range);
        mixCaptureClaims(&channel, self.claims);
        for (self.relations.sha.elements) |element| channel.mixFelts(&.{ element.z, element.alpha });
        const extension_draws = self.relations.draws();
        channel.mixFelts(&extension_draws);
        for (self.word.universal_prefix.elements) |element| channel.mixFelts(&.{ element.z, element.alpha });
        inline for (.{ "transition", "link", "initial", "endpoint", "range16" }) |field| {
            const element = @field(self.word, field);
            channel.mixFelts(&.{ element.z, element.alpha });
        }
        for (self.memory_challenges.universal_prefix.elements) |element| channel.mixFelts(&.{ element.z, element.alpha });
        inline for (.{ "transition", "link", "initial" }) |field| {
            const element = @field(self.memory_challenges, field);
            channel.mixFelts(&.{ element.z, element.alpha });
        }
        channel.mixRoot(self.final_channel.digestBytes());
        channel.mixU64(self.final_channel.n_draws);
        return channel.digestBytes();
    }
    pub fn validateAfterFreshCaller(self: *const VerifiedCapture, a: std.mem.Allocator, fresh: *const Family.OpenReceipt, statement: *const Profile.admission.Statement, total_steps: u32, frame: Frame, witness: [32]u8, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry) !void {
        return self.validateAgainstBinding(a, fresh.binding, statement, total_steps, frame, witness, sealed, pins, entries);
    }
    /// Capture consistency and binding admission only; it never verifies or
    /// exports arithmetic authority for an independently proposed caller.
    pub fn validateAgainstBinding(self: *const VerifiedCapture, a: std.mem.Allocator, binding: Protocol.CallerBinding, statement: *const Profile.admission.Statement, total_steps: u32, frame: Frame, witness: [32]u8, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry) !void {
        try Protocol.validate(statement, total_steps, pins.config);
        if (!std.meta.eql(binding.caller_key_id, try Protocol.keyId(statement, total_steps, pins.config, binding.first_roots[0]))) return error.UntrustedV5CallerCompositeKey;
        var schedule = try Schedule.init(a, statement, total_steps, frame, sealed.register_custody_mode);
        defer schedule.deinit();
        try admit(binding, witness, frame, &schedule, sealed, pins, entries);
        var claim_channel = suite.Channel{};
        try mixClaims(&claim_channel, binding, &schedule, self.claims.program_claims, self.claims.state_claims, self.claims.table_claims, self.claims.memory_claims);
        if (self.proof.commitments.len != 5 or !std.meta.eql(self.proof.commitments[0..3].*, .{ binding.first_roots[0], binding.first_roots[1], witness }) or
            !std.meta.eql(self.config, pins.config) or !std.meta.eql(self.frame, frame) or self.mode != sealed.register_custody_mode or
            !std.meta.eql(self.instance_id, instanceId(binding, witness, frame, self.mode, &schedule)) or
            !std.meta.eql(self.seal, self.identity()) or !std.meta.eql(self.relations, try Protocol.drawRelations(a, sealed)) or
            !std.meta.eql(self.word, try Word.Challenges.draw(a, sealed)) or !std.meta.eql(self.memory_challenges, try Bus.Challenges.draw(a, sealed))) return error.InvalidV5CallerCompositeCapture;
        const logs = try schedule.interactionLogs();
        defer a.free(logs);
        const witness_logs = try schedule.witnessLogs();
        defer a.free(witness_logs);
        const expected_logs = [_][]const u32{ schedule.fixed, schedule.main, witness_logs, logs };
        if (self.proof.column_log_sizes.len != 5) return error.InvalidV5CallerCompositeCapture;
        for (expected_logs, 0..) |expected, i| if (!std.mem.eql(u32, self.proof.column_log_sizes[i], expected)) return error.InvalidV5CallerCompositeCapture;
        var expected = try receipts(a, &self.claims, &schedule, binding, witness, sealed);
        const expected_ranges = expected.memory.range_claims;
        defer a.free(expected_ranges);
        if (self.receipt.memory.range_claims.len != expected_ranges.len) return error.InvalidV5CallerCompositeCapture;
        for (self.receipt.memory.range_claims, expected_ranges) |actual, value| if (!std.meta.eql(actual, value)) return error.InvalidV5CallerCompositeCapture;
        expected.memory.range_claims = self.receipt.memory.range_claims;
        if (!std.meta.eql(self.receipt, expected)) return error.InvalidV5CallerCompositeCapture;
    }
};
fn mixCaptureClaims(channel: *suite.Channel, claims: ClaimFrames) void {
    channel.mixU64(claims.program_claims.len);
    channel.mixU64(claims.state_claims.len);
    channel.mixU64(claims.table_claims.len);
    channel.mixU64(claims.memory_claims.len);
    inline for (.{ claims.program_claims, claims.state_claims }) |partition| for (partition) |claim| {
        channel.mixU64(claim.fetch_count);
        channel.mixFelts(&.{claim.sum});
    };
    for (claims.table_claims) |claim| {
        channel.mixU64(claim.row_count);
        channel.mixFelts(&.{claim.sum});
    }
    for (claims.memory_claims) |claim| {
        channel.mixU64(claim.active_count);
        channel.mixFelts(&.{ claim.transition_sum, claim.universal_sum });
        channel.mixFelts(&claim.range_claims);
    }
}

fn freeClaims(a: std.mem.Allocator, proof: *Proof) void {
    a.free(proof.program_claims);
    a.free(proof.state_claims);
    a.free(proof.table_claims);
    a.free(proof.memory_claims);
}
pub fn firstChannel(binding: Protocol.CallerBinding, witness: [32]u8, frame: Frame, mode: u32, schedule: *const Schedule) suite.Channel {
    var channel = suite.Channel{};
    mixFirst(&channel, binding, witness, frame, mode, schedule);
    return channel;
}
/// Original first-phase framing shared by recursive statement recording.
pub fn mixFirst(channel: anytype, binding: Protocol.CallerBinding, witness: [32]u8, frame: Frame, mode: u32, schedule: *const Schedule) void {
    channel.mixU32s(&.{ TAG, VERSION, 1, binding.execution_index, mode, @intFromEnum(frame.clock_frame), frame.cycle_count });
    channel.mixU64(frame.global_first_cycle);
    channel.mixRoot(binding.caller_key_id);
    channel.mixRoot(binding.caller_instance_id);
    channel.mixRoot(binding.execution_instance_id);
    for (binding.first_roots) |root| channel.mixRoot(root);
    channel.mixRoot(witness);
    channel.mixRoot(Word.abiId());
    ScheduleModule.mix(channel, schedule);
}

pub fn instanceId(binding: Protocol.CallerBinding, witness: [32]u8, frame: Frame, mode: u32, schedule: *const Schedule) [32]u8 {
    var channel = firstChannel(binding, witness, frame, mode, schedule);
    return channel.digestBytes();
}
pub fn entry(binding: Protocol.CallerBinding, witness: [32]u8, frame: Frame, mode: u32, schedule: *const Schedule) Seal.Entry {
    return .{ .family = .program_extension_request, .index = binding.execution_index, .roots = binding.first_roots, .instance_id = instanceId(binding, witness, frame, mode, schedule) };
}
pub fn admit(binding: Protocol.CallerBinding, witness: [32]u8, frame: Frame, schedule: *const Schedule, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry) !void {
    try Protocol.admit(binding, sealed, pins, entries);
    if (frame.cycle_count == 0 or frame.clock_frame != .leaf_local) return error.InvalidV5CallerCompositeFrame;
    if (!std.meta.eql(try find(entries, .program_extension_request, binding.execution_index), entry(binding, witness, frame, sealed.register_custody_mode, schedule))) return error.UntrustedV5CallerCompositeEntry;
    const memory = External.packedEntry(binding.execution_instance_id, binding.caller_instance_id, binding.caller_key_id, binding.first_roots, witness, binding.execution_index, schedule.memory);
    if (!std.meta.eql(try find(entries, .execution_external_sidecar, binding.execution_index), memory)) return error.UntrustedV5CallerCompositeAccess;
}
fn find(entries: []const Seal.Entry, family: Seal.Family, index: u32) !Seal.Entry {
    var found: ?Seal.Entry = null;
    for (entries) |item| if (item.family == family and item.index == index) {
        if (found != null) return error.DuplicateV5CallerCompositeEntry;
        found = item;
    };
    return found orelse error.MissingV5CallerCompositeEntry;
}
pub fn proofChannel(a: std.mem.Allocator, sealed: Seal.Sealed) !suite.Channel {
    var channel = sealed.sharedChannel();
    _ = try Word.Challenges.drawFromChannel(a, &channel);
    channel.mixU32s(&.{ TAG, VERSION, 3 });
    channel.mixRoot(sealed.digest);
    return channel;
}
pub fn mixClaims(channel: anytype, binding: Protocol.CallerBinding, schedule: *const Schedule, program: []const Program.Claim, state: []const Program.Claim, tables: []const Algebra.Claim, memory: []const External.Claim) !void {
    if (program.len != schedule.program.len or state.len != schedule.program.len or tables.len != schedule.tables.len or memory.len != schedule.memory.len) return error.InvalidV5CallerCompositeClaims;
    channel.mixU32s(&.{ TAG, VERSION, 2, binding.execution_index, @intCast(program.len), @intCast(state.len), @intCast(tables.len), @intCast(memory.len) });
    channel.mixRoot(binding.caller_key_id);
    channel.mixRoot(binding.caller_instance_id);
    channel.mixRoot(binding.execution_instance_id);
    inline for (.{ program, state }, 0..) |claims, partition| {
        channel.mixU32s(&.{@intCast(partition)});
        for (schedule.program, claims) |slot, claim| {
            if (claim.fetch_count != slot.active_calls or !Canonical.secureIsCanonical(&claim.sum)) return error.InvalidV5CallerCompositeClaims;
            channel.mixU64(claim.fetch_count);
            channel.mixFelts(&.{claim.sum});
        }
    }
    for (schedule.tables, tables) |slot, claim| {
        if (claim.row_count != slot.n_rows or !Canonical.secureIsCanonical(&claim.sum)) return error.InvalidV5CallerCompositeClaims;
        channel.mixU64(claim.row_count);
        channel.mixFelts(&.{claim.sum});
    }
    var events: u64 = 0;
    for (schedule.memory, memory) |slot, claim| {
        if (claim.active_count > (@as(u64, 1) << @intCast(slot.log_size)) or !Canonical.secureIsCanonical(&claim.transition_sum) or !Canonical.secureIsCanonical(&claim.universal_sum)) return error.InvalidV5CallerCompositeClaims;
        events = try std.math.add(u64, events, claim.active_count);
        channel.mixU64(claim.active_count);
        channel.mixFelts(&.{ claim.transition_sum, claim.universal_sum });
        for (claim.range_claims) |part| {
            if (!Canonical.secureIsCanonical(&part)) return error.InvalidV5CallerCompositeClaims;
            channel.mixFelts(&.{part});
        }
    }
    if (events != schedule.rw_events) return error.UntrustedV5CallerCompositeEventCensus;
}
/// Metadata assembly shared by the original verifier and its recursive replay.
/// Source claims are proposals until the complete original verifier succeeds.
pub const Components = struct {
    a: std.mem.Allocator,
    program: []Adapter.Program,
    tables: []Adapter.Tables,
    memory: []Adapter.Memory,
    pub fn init(a: std.mem.Allocator, schedule: *const Schedule, proof: anytype, relations: *const Profile.Relations, challenges: *const Bus.Challenges, word: *const Word.Challenges, logs: []const u32, witness_logs: []const u32, mode: u32) !Components {
        const program = try a.alloc(Adapter.Program, schedule.program.len * 2);
        errdefer a.free(program);
        const tables = try a.alloc(Adapter.Tables, schedule.tables.len);
        errdefer a.free(tables);
        const memory = try a.alloc(Adapter.Memory, schedule.memory.len);
        errdefer a.free(memory);
        for (schedule.program, 0..) |slot, i| inline for (.{ proof.program_claims, proof.state_claims }, 0..) |claims, partition| {
            program[partition * schedule.program.len + i] = try (Adapter.Program{ .composition_split = schedule.split, .inner = .{ .projection = if (partition == 0) .program else .state, .slot = slot, .fixed_logs = schedule.fixed, .main_logs = schedule.main, .root_owner = false, .interaction_offset = (partition * schedule.program.len + i) * 4, .interaction_logs = logs, .claim = claims[i].sum, .relations = &relations.sha } }).init();
        };
        for (schedule.tables, proof.table_claims, tables, 0..) |slot, claim, *component, i| component.* = try (Adapter.Tables{ .composition_split = schedule.split, .inner = .{ .slot = slot, .fixed_logs = schedule.fixed, .main_logs = schedule.main, .root_owner = false, .interaction_offset = (schedule.program.len * 2 + i) * 4, .interaction_logs = logs, .claim = claim.sum, .relations = relations, .source_owner = schedule.owner, .composition_split = schedule.split } }).init();
        for (schedule.memory, proof.memory_claims, memory, 0..) |slot, claim, *component, i| component.* = try (Adapter.Memory{ .composition_split = schedule.split, .inner = .{ .register_custody_mode = mode, .family = .base_alu_imm, .slot = slot.slot, .external_source = slot, .log_size = slot.log_size, .base_clock = try Integer.baseClockFromPublicFrame(slot.frame), .fixed_logs = schedule.fixed, .main_logs = schedule.main, .witness_logs = witness_logs, .interaction_logs = logs, .root_owner = i == 0, .fixed_open_mask = schedule.masks.fixed, .main_open_mask = schedule.masks.main, .shared_keccak_state_offset = schedule.masks.state_offset, .main_offset = slot.main_offset, .witness_offset = i * Integer.COLUMN_COUNT, .interaction_offset = schedule.projectionCount() * 4 + i * Eval.INTERACTION_COUNT, .transition_claim = claim.transition_sum, .transition_count = claim.active_count, .range_claims = claim.range_claims, .challenges = challenges, .v5_packed = .{ .elements = word }, .v5_universal = .{ .claim = claim.universal_sum, .elements = word.universal_prefix.get(.memory_access) } } }).init();
        return .{ .a = a, .program = program, .tables = tables, .memory = memory };
    }
    pub fn deinit(self: *Components) void {
        self.a.free(self.memory);
        self.a.free(self.tables);
        self.a.free(self.program);
    }
    fn prover(self: *Components) ![]engine.air.component_prover.ComponentProver {
        const out = try self.a.alloc(engine.air.component_prover.ComponentProver, self.memory.len + self.program.len + self.tables.len);
        var i: usize = 0;
        for (self.memory) |*c| {
            out[i] = c.asProverComponent();
            i += 1;
        }
        for (self.program) |*c| {
            out[i] = c.asProverComponent();
            i += 1;
        }
        for (self.tables) |*c| {
            out[i] = c.asProverComponent();
            i += 1;
        }
        return out;
    }
    pub fn verifier(self: *Components) ![]core.air.components.Component {
        const out = try self.a.alloc(core.air.components.Component, self.memory.len + self.program.len + self.tables.len);
        var i: usize = 0;
        for (self.memory) |*c| {
            out[i] = c.asVerifierComponent();
            i += 1;
        }
        for (self.program) |*c| {
            out[i] = c.asVerifierComponent();
            i += 1;
        }
        for (self.tables) |*c| {
            out[i] = c.asVerifierComponent();
            i += 1;
        }
        return out;
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub const FirstRound = External.ForPackedBackend(Backend).FirstRound;
        /// Consumes only the independently leased access prefix. Caller trees
        /// remain owned and usable for the arithmetic proof after return.
        pub fn proveForCallerFirstRound(a: std.mem.Allocator, first: *FirstRound, inputs: []const External.Input, caller: *Family.ForBackend(Backend).FirstRound, frame: Frame, witness: [32]u8, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry) !Proof {
            if (!caller.owns_scheme or caller.scheme.trees.items.len != 2 or !first.owns_scheme or first.scheme.trees.items.len != 3 or !std.meta.eql(first.scheme.config, pins.config) or !std.meta.eql(caller.config, pins.config)) return error.UntrustedV5CallerCompositePhase;
            const binding = caller.binding(sealed);
            try Protocol.validate(&caller.witness.statement, caller.total_steps, pins.config);
            try @import("block_v5_precompile_witness_v1.zig").validateAdmission(a, &caller.witness.statement);
            if (!std.meta.eql(caller.key_id, try Protocol.keyId(&caller.witness.statement, caller.total_steps, pins.config, caller.roots[0])) or !std.meta.eql(caller.entry().instance_id, binding.caller_instance_id)) return error.UntrustedV5CallerCompositeKey;
            var schedule = try Schedule.init(a, &caller.witness.statement, caller.total_steps, frame, sealed.register_custody_mode);
            defer schedule.deinit();
            try admit(binding, witness, frame, &schedule, sealed, pins, entries);
            if (!std.mem.eql(u32, first.fixed_logs, schedule.fixed) or !std.mem.eql(u32, first.main_logs, schedule.main) or !std.meta.eql(first.roots, .{ binding.first_roots[0], binding.first_roots[1], witness }) or inputs.len != schedule.memory.len or first.snapshots.len != inputs.len) return error.UntrustedV5CallerCompositePrefix;
            try Selected.validateTrees(&caller.scheme, schedule.fixed, schedule.main);
            for (0..2) |tree| {
                const own = caller.scheme.trees.items[tree].columns;
                const leased = first.scheme.trees.items[tree].columns;
                if (own.len != leased.len) return error.UnsharedV5CallerCompositePrefix;
                for (own, leased) |left, right| if (left.values.ptr != right.values.ptr or left.values.len != right.values.len or left.log_size != right.log_size) return error.UnsharedV5CallerCompositePrefix;
            }
            var roots = try first.scheme.roots(a);
            defer roots.deinit(a);
            if (roots.items.len != 3 or !std.meta.eql(roots.items[0..3].*, first.roots)) return error.UntrustedV5CallerCompositePrefix;
            const ranges = try schedule.projectionRanges();
            defer a.free(ranges);
            var columns = try Selected.Columns.init(a, &caller.scheme, schedule.fixed, schedule.main, ranges);
            defer columns.deinit(a);
            const relations = try Protocol.drawRelations(a, sealed);
            const word = try Word.Challenges.draw(a, sealed);
            const challenges = try Bus.Challenges.draw(a, sealed);
            var proof = Proof{ .stark = undefined, .program_claims = try a.alloc(Program.Claim, schedule.program.len), .state_claims = &.{}, .table_claims = &.{}, .memory_claims = &.{} };
            errdefer freeClaims(a, &proof);
            proof.state_claims = try a.alloc(Program.Claim, schedule.program.len);
            proof.table_claims = try a.alloc(Algebra.Claim, schedule.tables.len);
            proof.memory_claims = try a.alloc(External.Claim, schedule.memory.len);
            var interaction: std.ArrayList(Column) = .empty;
            defer {
                for (interaction.items) |column| a.free(column.values);
                interaction.deinit(a);
            }
            for (schedule.program, 0..) |slot, i| inline for (.{ .program, .state }, 0..) |projection, part| {
                const generated = try generateProgram(a, columns.fixed, columns.main, slot, &relations.sha, projection);
                const claim = Program.Claim{ .sum = generated.claim, .fetch_count = slot.active_calls };
                if (part == 0) proof.program_claims[i] = claim else proof.state_claims[i] = claim;
                try appendOwned(a, &interaction, slot.log_size, generated.columns);
            };
            for (schedule.tables, proof.table_claims) |slot, *claim| {
                const generated = try Algebra.generate(a, columns.fixed, columns.main, slot, &relations, schedule.owner);
                claim.* = .{ .sum = generated.claim, .row_count = slot.n_rows };
                try appendOwned(a, &interaction, slot.log_size, generated.columns);
            }
            for (inputs, schedule.memory, proof.memory_claims, first.snapshots) |input, slot, *claim, snapshot| {
                if (!std.meta.eql(input.descriptor, slot) or !std.meta.eql(input.trace.descriptor, slot)) return error.UntrustedV5CallerCompositeInputs;
                const rows = try a.alloc(Transition.Row, input.trace.domainSize());
                defer a.free(rows);
                const memory_rows = try a.alloc(UniversalMemory.Row, input.trace.domainSize());
                defer a.free(memory_rows);
                for (rows, memory_rows, 0..) |*row, *memory_row, i| {
                    row.* = try input.trace.row(i);
                    memory_row.* = try UniversalMemory.rowFromPair(try input.trace.pairAt(i));
                }
                var t = try WordTransition.generate(a, &word, rows, slot.log_size);
                defer t.deinit(a);
                var b = try Range.generate(a, input.trace, word.universal_prefix.get(.range_check_8_8), snapshot);
                defer b.deinit(a);
                var m = try UniversalMemory.generate(a, word.universal_prefix.get(.memory_access), memory_rows, slot.log_size);
                defer m.deinit(a);
                claim.* = .{ .transition_sum = t.claim, .universal_sum = m.claim, .range_claims = b.claims, .active_count = t.count };
                try appendCopies(a, &interaction, slot.log_size, &t.columns);
                try appendCopies(a, &interaction, slot.log_size, &b.columns);
                try appendCopies(a, &interaction, slot.log_size, &m.columns);
            }
            const logs = try schedule.interactionLogs();
            defer a.free(logs);
            const witness_logs = try schedule.witnessLogs();
            defer a.free(witness_logs);
            var components = try Components.init(a, &schedule, &proof, &relations, &challenges, &word, logs, witness_logs, sealed.register_custody_mode);
            defer components.deinit();
            var cache = try @import("block_v5_quotient_column_cache_v1.zig").Cache.init(a);
            defer cache.deinit();
            for (components.memory) |*component| component.inner.quotient_cache = &cache;
            const handles = try components.prover();
            defer a.free(handles);
            var channel = try proofChannel(a, sealed);
            channel.mixRoot(instanceId(binding, witness, frame, sealed.register_custody_mode, &schedule));
            try mixClaims(&channel, binding, &schedule, proof.program_claims, proof.state_claims, proof.table_claims, proof.memory_claims);
            proof.stark = try Composite.prove(Backend, a, first, interaction.items, handles, &channel);
            errdefer proof.stark.deinit(a);
            if (caller.scheme.trees.items.len != 2 or !caller.owns_scheme) return error.ChangedV5CallerCompositeSourceOwner;
            return proof;
        }
        /// Internal already-fresh caller seam. Upper Receiver.verifyOwned must
        /// be used by detached loaders; arbitrary receipts are not authority.
        pub fn verifyAfterFreshCaller(a: std.mem.Allocator, received: Proof, fresh: *const Family.OpenReceipt, statement: *const Profile.admission.Statement, total_steps: u32, frame: Frame, witness: [32]u8, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry) !Verified {
            return verifyInternal(false, true, a, &received, fresh, statement, total_steps, frame, witness, sealed, pins, entries);
        }
        pub fn verifyCaptureOwnedAfterFreshCaller(a: std.mem.Allocator, received: Proof, fresh: *const Family.OpenReceipt, statement: *const Profile.admission.Statement, total_steps: u32, frame: Frame, witness: [32]u8, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry) !VerifiedCapture {
            return verifyInternal(true, true, a, &received, fresh, statement, total_steps, frame, witness, sealed, pins, entries);
        }
        /// Internal scoped seam only: detached callers use the combined real
        /// arithmetic+fused capture entry, not a caller-supplied receipt.
        pub fn verifyCaptureBorrowedAfterFreshCaller(a: std.mem.Allocator, received: *const Proof, fresh: *const Family.OpenReceipt, statement: *const Profile.admission.Statement, total_steps: u32, frame: Frame, witness: [32]u8, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry) !VerifiedCapture {
            return verifyInternal(true, false, a, received, fresh, statement, total_steps, frame, witness, sealed, pins, entries);
        }
        fn verifyInternal(comptime capture: bool, comptime take: bool, a: std.mem.Allocator, received: *const Proof, fresh: *const Family.OpenReceipt, statement: *const Profile.admission.Statement, total_steps: u32, frame: Frame, witness: [32]u8, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry) !(if (capture) VerifiedCapture else Verified) {
            var proof = received.*;
            var owns_stark = take;
            var owns_claims = take;
            defer if (owns_stark) proof.stark.deinit(a);
            defer if (owns_claims) freeClaims(a, &proof);
            try Protocol.validate(statement, total_steps, pins.config);
            if (!std.meta.eql(fresh.binding.caller_key_id, try Protocol.keyId(statement, total_steps, pins.config, fresh.binding.first_roots[0]))) return error.UntrustedV5CallerCompositeKey;
            var schedule = try Schedule.init(a, statement, total_steps, frame, sealed.register_custody_mode);
            defer schedule.deinit();
            try admit(fresh.binding, witness, frame, &schedule, sealed, pins, entries);
            var channel = try proofChannel(a, sealed);
            channel.mixRoot(instanceId(fresh.binding, witness, frame, sealed.register_custody_mode, &schedule));
            try mixClaims(&channel, fresh.binding, &schedule, proof.program_claims, proof.state_claims, proof.table_claims, proof.memory_claims);
            const relations = try Protocol.drawRelations(a, sealed);
            const word = try Word.Challenges.draw(a, sealed);
            const challenges = try Bus.Challenges.draw(a, sealed);
            const logs = try schedule.interactionLogs();
            defer a.free(logs);
            const witness_logs = try schedule.witnessLogs();
            defer a.free(witness_logs);
            var components = try Components.init(a, &schedule, &proof, &relations, &challenges, &word, logs, witness_logs, sealed.register_custody_mode);
            defer components.deinit();
            const handles = try components.verifier();
            defer a.free(handles);
            var result = try receipts(a, &proof, &schedule, fresh.binding, witness, sealed);
            errdefer result.deinit(a);
            const roots = .{ fresh.binding.first_roots[0], fresh.binding.first_roots[1], witness };
            const first_channel = firstChannel(fresh.binding, witness, frame, sealed.register_custody_mode, &schedule);
            if (capture) {
                var frames = if (take) ClaimFrames{ .program_claims = proof.program_claims, .state_claims = proof.state_claims, .table_claims = proof.table_claims, .memory_claims = proof.memory_claims } else try ClaimFrames.clone(a, &proof);
                var owns_frames = !take;
                errdefer if (owns_frames) frames.deinit(a);
                const captured = if (take) owned: {
                    owns_stark = false;
                    break :owned try Composite.verifyCaptureOwned(a, proof.stark, roots, pins.config, schedule.fixed, schedule.main, witness_logs, logs, handles, first_channel, &channel);
                } else try Composite.verifyCaptureBorrowed(a, &proof.stark, roots, pins.config, schedule.fixed, schedule.main, witness_logs, logs, handles, first_channel, &channel);
                owns_frames = false;
                owns_claims = false;
                var verified = VerifiedCapture{ .allocator = a, .proof = captured.proof, .claims = frames, .relations = relations, .word = word, .memory_challenges = challenges, .final_channel = captured.final_channel, .config = pins.config, .frame = frame, .mode = sealed.register_custody_mode, .instance_id = instanceId(fresh.binding, witness, frame, sealed.register_custody_mode, &schedule), .receipt = result, .seal = undefined };
                verified.seal = verified.identity();
                return verified;
            } else {
                owns_stark = false;
                try Composite.verifyOwned(a, proof.stark, roots, pins.config, schedule.fixed, schedule.main, witness_logs, logs, handles, first_channel, &channel);
                return result;
            }
        }
    };
}
fn appendOwned(a: std.mem.Allocator, out: *std.ArrayList(Column), log: u32, values: [4][]M) !void {
    errdefer for (values) |column| a.free(column);
    try out.ensureUnusedCapacity(a, 4);
    for (values) |column| out.appendAssumeCapacity(.{ .log_size = log, .values = column });
}
fn appendCopies(a: std.mem.Allocator, out: *std.ArrayList(Column), log: u32, columns: anytype) !void {
    for (columns) |values| {
        const copy = try a.dupe(M, values);
        errdefer a.free(copy);
        try out.append(a, .{ .log_size = log, .values = copy });
    }
}
fn generateProgram(a: std.mem.Allocator, fixed: []const Column, main: []const Column, slot: ProgramSlots.Slot, relations: *const @import("../recursion/air/universal_challenges.zig").UniversalRelations, comptime projection: @import("block_v5_program_extension_component_v1.zig").Projection) !Algebra.Generated {
    const size = @as(usize, 1) << @intCast(slot.log_size);
    var columns: [4][]M = undefined;
    var initialized: usize = 0;
    errdefer for (columns[0..initialized]) |column| a.free(column);
    for (&columns) |*column| {
        column.* = try a.alloc(M, size);
        initialized += 1;
    }
    const terms = try a.alloc(Q, size);
    defer a.free(terms);
    for (0..size) |logical| {
        const physical = Framework.committedRow(logical, slot.log_size);
        var row: [@import("block_v5_precompile_lookup_source_v1.zig").MAX_MAIN]Q = undefined;
        for (row[0..slot.main_columns], main[slot.main_offset..][0..slot.main_columns]) |*value, column| {
            if (column.values.len != size or column.log_size != slot.log_size) return error.InvalidV5CallerCompositeColumns;
            value.* = Q.fromBase(column.values[physical]);
        }
        var fixed_row: [1]Q = undefined;
        const fixed_slice: []const Q = if (slot.fixed_selector_offset) |offset| blk: {
            if (fixed[offset].values.len != size or fixed[offset].log_size != slot.log_size) return error.InvalidV5CallerCompositeColumns;
            fixed_row[0] = Q.fromBase(fixed[offset].values[physical]);
            break :blk &fixed_row;
        } else &.{};
        if (projection == .program) {
            const request = try @import("block_v5_program_extension_source_v1.zig").fromCommittedCaller(slot.kind, fixed_slice, row[0..slot.main_columns]);
            terms[logical] = request.numerator.mul(try (try relations.get(.program_access).combineSecure(&request.tuple)).inv());
        } else {
            const state = try @import("block_v5_precompile_state_request_source_v1.zig").fromCommittedCaller(slot.kind, fixed_slice, row[0..slot.main_columns]);
            const bus = relations.get(.registers_state);
            terms[logical] = state.active.mul((try (try bus.combineSecure(&state.emitted)).inv()).sub(try (try bus.combineSecure(&state.consumed)).inv()));
        }
    }
    var claim = Q.zero();
    for (terms) |term| claim = claim.add(term);
    const shift = try claim.divM31(M.fromCanonical(@intCast(size)));
    var running = Q.zero();
    for (terms, 0..) |term, logical| {
        running = running.add(term).sub(shift);
        for (&columns, running.toM31Array()) |*values, limb| values.*[Framework.committedRow(logical, slot.log_size)] = limb;
    }
    return .{ .columns = columns, .claim = claim };
}
fn receipts(a: std.mem.Allocator, proof: anytype, schedule: *const Schedule, binding: Protocol.CallerBinding, witness: [32]u8, sealed: Seal.Sealed) !Verified {
    var program = Q.zero();
    var state = Q.zero();
    var count: u64 = 0;
    for (proof.program_claims, proof.state_claims) |p, s| {
        program = program.add(p.sum);
        state = state.add(s.sum);
        count = try std.math.add(u64, count, p.fetch_count);
    }
    var tables: [@import("../air/lookups/tables/schema.zig").KIND_COUNT]Q = @splat(Q.zero());
    var registers = Q.zero();
    for (schedule.tables, proof.table_claims) |slot, claim| {
        if (slot.table == .register_memory) registers = registers.add(claim.sum) else tables[@intFromEnum(slot.table)] = tables[@intFromEnum(slot.table)].add(claim.sum);
    }
    const ranges = try a.alloc(Range.Claims, proof.memory_claims.len);
    errdefer a.free(ranges);
    var transition = Q.zero();
    var universal = Q.zero();
    var events: u64 = 0;
    for (proof.memory_claims, ranges) |claim, *range| {
        transition = transition.add(claim.transition_sum);
        universal = universal.add(claim.universal_sum);
        events = try std.math.add(u64, events, claim.active_count);
        range.* = claim.range_claims;
    }
    var program_channel = sealed.programSeal().sharedChannel();
    return .{ .program = .{ .sum = program, .fetch_count = count, .precompile_roots = binding.first_roots, .precompile_instance_id = binding.caller_instance_id, .execution_instance_id = binding.execution_instance_id, .sealed_channel_digest = program_channel.digestBytes() }, .state = .{ .sum = state, .caller_count = count, .binding = binding }, .tables = .{ .claims = tables, .memory_event_count = schedule.all_memory_events, .register_memory_sum = registers, .binding = binding }, .memory = .{ .packed_transition = true, .instance_index = binding.execution_index, .transition_sum = transition, .universal_sum = universal, .event_count = events, .range_claims = ranges, .caller_roots = binding.first_roots, .witness_root = witness, .execution_instance_id = binding.execution_instance_id, .caller_instance_id = binding.caller_instance_id, .sealed_digest = sealed.digest } };
}
