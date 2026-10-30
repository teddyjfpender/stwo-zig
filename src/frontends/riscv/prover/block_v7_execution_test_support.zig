//! Shared actual-execution fixtures; no proving or admission policy lives here.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Native = @import("block_v7_native_proof_v1.zig");
const Stage = @import("block_v5_native_memory_stage_v1.zig");
const Physical = @import("block_v5_cpu_native_root_proposal_v1.zig").ForBackend(Cpu);
const Owner = @import("blake3_execution_trace.zig").Owner;
const IO = @import("blake3_segment_public.zig").Owned;
const Tables = @import("../air/lookups/tables/mod.zig");
pub const Segment = struct {
    a: std.mem.Allocator,
    io: IO,
    owner: *Owner,
    physical: Physical.PhysicalFirstRound,
    source: Stage.Traces,
    first: Native.For(Cpu).First,
    pin: Native.Pin,
    pub fn init(a: std.mem.Allocator, segment: *const @import("../runner/result.zig").SegmentResult, config: core.pcs.PcsConfig, root: [32]u8, index: u32, profile: @import("../isa/execution_profile.zig").ExecutionProfile, external: u32, counters: *Tables.counter.Set) !Segment {
        return initWithSourceLimits(a, segment, config, root, index, profile, external, counters, .{ .max_slots = 100, .max_witness_cells = 1 << 20, .max_metadata_bytes = 1 << 20, .register_custody_mode = 1 });
    }
    /// Test sizing is explicit; the original trace builder still checks every
    /// cell and the caller's allocator enforces its whole-process byte budget.
    pub fn initWithSourceLimits(a: std.mem.Allocator, segment: *const @import("../runner/result.zig").SegmentResult, config: core.pcs.PcsConfig, root: [32]u8, index: u32, profile: @import("../isa/execution_profile.zig").ExecutionProfile, external: u32, counters: *Tables.counter.Set, limits: Stage.Limits) !Segment {
        return initWithFixedRetention(a, segment, config, root, index, profile, external, counters, limits, false, null);
    }
    pub fn initForUnion(a: std.mem.Allocator, segment: *const @import("../runner/result.zig").SegmentResult, config: core.pcs.PcsConfig, root: [32]u8, index: u32, profile: @import("../isa/execution_profile.zig").ExecutionProfile, external: u32, counters: *Tables.counter.Set, limits: Stage.Limits) !Segment {
        return initWithFixedRetention(a, segment, config, root, index, profile, external, counters, limits, true, null);
    }
    pub fn initProfiled(a: std.mem.Allocator, segment: *const @import("../runner/result.zig").SegmentResult, config: core.pcs.PcsConfig, root: [32]u8, index: u32, profile: @import("../isa/execution_profile.zig").ExecutionProfile, external: u32, counters: *Tables.counter.Set, limits: Stage.Limits, recorder: ?*@import("stwo_prover_engine").stage_profile.Recorder) !Segment {
        return initWithFixedRetention(a, segment, config, root, index, profile, external, counters, limits, false, recorder);
    }
    fn initWithFixedRetention(a: std.mem.Allocator, segment: *const @import("../runner/result.zig").SegmentResult, config: core.pcs.PcsConfig, root: [32]u8, index: u32, profile: @import("../isa/execution_profile.zig").ExecutionProfile, external: u32, counters: *Tables.counter.Set, limits: Stage.Limits, retain_fixed: bool, recorder: ?*@import("stwo_prover_engine").stage_profile.Recorder) !Segment {
        const Phase = @import("stwo_prover_engine").stage_profile.StageScope;
        var witness_phase = try Phase.begin(recorder, "native_witness", "Native execution and opcode witness");
        defer witness_phase.end();
        if (limits.register_custody_mode != 1) return error.InvalidFixtureCustody;
        var io = try IO.init(a, segment);
        errdefer io.deinit();
        io.data.program_root = .{ .bytes = root };
        io.data.initial_rw_root = null;
        io.data.final_rw_root = null;
        io.data.io_entries.input_len = 0;
        io.data.io_entries.input_words = &.{};
        io.data.io_entries.output_len = 0;
        io.data.io_entries.output_words = &.{};
        const owner = try Owner.initWithExternal(a, &segment.execution_trace, io.data, &segment.state_chain_tracker, external);
        errdefer owner.deinit();
        try owner.sealNativeOnly();
        counters.mergeFrom(&owner.opcode_columns.lookup_counters.?);
        witness_phase.end();
        var commitment_phase = try Phase.begin(recorder, "native_first_commitment", "Native fixed and main first commitments");
        defer commitment_phase.end();
        var physical = try Physical.commitPhysicalWithFixedRetention(a, owner, config, profile, index, retain_fixed);
        errdefer physical.deinit(a);
        commitment_phase.end();
        var access_phase = try Phase.begin(recorder, "native_access_witness", "Native access witness");
        defer access_phase.end();
        const frame = @import("../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = segment.global_first_cycle, .cycle_count = @intCast(segment.cycle_count) };
        var source = try Stage.Traces.init(a, owner, frame, limits);
        errdefer source.deinit();
        access_phase.end();
        var access_commit = try Phase.begin(recorder, "native_access_commitment", "Native access commitment and source leases");
        defer access_commit.end();
        var first = if (source.slots.len != 0)
            try Stage.ForBackend(Cpu).borrow(a, &physical.scheme, source.inputs, source.slots, counters.get(.range_check_8_8), index, physical.template_id)
        else
            try @import("block_v5_native_projection_fused_stage_v2.zig").ForBackend(Cpu).borrowProjectionFirstRound(a, &physical.scheme, @splat(0));
        errdefer first.deinit(a);
        return .{ .a = a, .io = io, .owner = owner, .physical = physical, .source = source, .first = first, .pin = .{ .index = index, .shape = &owner.statement, .frame = frame, .template = physical.template, .roots = physical.roots, .access_root = first.roots[2], .expected_events = try source.census() } };
    }
    pub fn deinit(self: *Segment) void {
        self.first.deinit(self.a);
        self.source.deinit();
        self.physical.deinit(self.a);
        self.owner.deinit();
        self.io.deinit();
    }
};
pub fn roundTrip(a: std.mem.Allocator, proof: *core.proof_suites.Blake3.Proof) !void {
    const wire = @import("interop_postcard");
    var writer = std.Io.Writer.Allocating.init(a);
    defer writer.deinit();
    try wire.serializeProof(core.proof_suites.Blake3.Hasher, &writer.writer, proof.*);
    var reader = std.io.fixedBufferStream(writer.written());
    const fresh = try wire.deserializeProof(core.proof_suites.Blake3.Hasher, a, reader.reader());
    proof.deinit(a);
    proof.* = fresh;
    try std.testing.expectEqual(writer.written().len, reader.pos);
}
