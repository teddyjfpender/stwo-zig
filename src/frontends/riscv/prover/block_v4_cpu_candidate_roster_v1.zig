//! Read-only, host-derived native-key proposal. None of these bytes are proof
//! authority until an independent party pins the manifest hash and verifies
//! every block proof against it.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const source_mod = @import("block_v4_cpu_runner_source.zig");
const host_preflight = @import("block_v4_cpu_host_preflight_v1.zig");
const profile = @import("blake3_ethereum_sha_profile.zig");
const NativeInputs = @import("block_v4_cpu_native_key_snapshot.zig").Snapshot;
const Native = @import("blake3_ethereum_sha_proof.zig").ForBackend(Cpu);
const v3 = @import("../recursion/blake3_block_execution_span_v3.zig");
const trusted_manifest = @import("block_v4_cpu_trusted_manifest_v1.zig");
const parent = @import("../recursion/blake3_execution_parent_protocol.zig");
const exact_root = @import("../recursion/blake3_exact_root_aggregate.zig");

pub const Input = struct {
    elf: []const u8,
    public_input: []const u8,
    oracle: []const u8,
    schedule_json: []const u8,
    expected_schedule_sha256: ?[32]u8 = null,
    max_segment_cycles: u32,
    host_limit_bytes: usize = 16 * 1024 * 1024 * 1024,
    progress: ?*const fn (completed: u32, total: u32) void = null,
    /// Diagnostic only: stop after this many keys and publish no candidate.
    probe_prefix_keys: ?u32 = null,
    /// Diagnostic only: replay every preceding segment but prepare just this
    /// one key, then publish no candidate.
    probe_only_index: ?u32 = null,
};

pub const Report = struct {
    scope: []const u8 = "proposal_only_host_replay_no_proof_authority",
    format_version: u32 = 1,
    proof_verified: bool = false,
    geometry_admitted: bool = false,
    externally_pinned: bool = false,
    base_seal_derivation: []const u8 = "SHA256(stwo-zig/block-v4/candidate-base-seal/v1, source SHA256s, max cycles LE, segment count LE, length-prefixed canonical RootStatement M31 words LE)",
    manifest_sha256: [32]u8,
    elf_sha256: [32]u8,
    input_sha256: [32]u8,
    oracle_sha256: [32]u8,
    schedule_sha256: [32]u8,
    segment_count: u32,
    total_cycles: u64,
    max_segment_cycles: u32,
    elf_bytes: usize,
    input_bytes: usize,
    oracle_bytes: usize,
    schedule_bytes: usize,
    elapsed_ns: u64,
    tracked_work_peak_bytes: usize,
};

pub const Candidate = struct {
    a: std.mem.Allocator,
    wire: trusted_manifest.Wire,
    keys: [][32]u8,
    report: Report,

    pub fn deinit(self: *Candidate) void {
        self.a.free(self.keys);
        self.* = undefined;
    }

    /// Writes a candidate manifest, then its scoped report. The files are
    /// exclusive and never named `complete`; a failed report removes the
    /// manifest so a partial proposal cannot be mistaken for a pair.
    pub fn write(self: *const Candidate, dir: std.fs.Dir) !void {
        const manifest_bytes = try std.json.Stringify.valueAlloc(self.a, self.wire, .{});
        defer self.a.free(manifest_bytes);
        if (!std.meta.eql(source_mod.sha256(manifest_bytes), self.report.manifest_sha256))
            return error.CandidateManifestChanged;
        var manifest = try dir.createFile("candidate-trusted-v1.json", .{ .exclusive = true });
        defer manifest.close();
        errdefer dir.deleteFile("candidate-trusted-v1.json") catch {};
        try manifest.writeAll(manifest_bytes);
        try manifest.sync();
        const report_bytes = try std.json.Stringify.valueAlloc(self.a, self.report, .{});
        defer self.a.free(report_bytes);
        var report = try dir.createFile("candidate-roster-report-v1.json", .{ .exclusive = true });
        defer report.close();
        errdefer dir.deleteFile("candidate-roster-report-v1.json") catch {};
        try report.writeAll(report_bytes);
        try report.sync();
    }
};

pub fn derive(output_a: std.mem.Allocator, input: Input) !Candidate {
    if (input.max_segment_cycles == 0 or input.schedule_json.len == 0 or input.schedule_json.len > 1024 * 1024)
        return error.InvalidCandidateSchedule;
    var timer = try std.time.Timer.start();
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(output_a, input.host_limit_bytes);
    defer budget.destroy();
    const a = budget.allocator();
    const config: core.pcs.PcsConfig = parent.Profile.csp_q70_pow26.config();
    const elf_hash = source_mod.sha256(input.elf);
    const input_hash = source_mod.sha256(input.public_input);
    const oracle_hash = source_mod.sha256(input.oracle);
    const schedule_hash = source_mod.sha256(input.schedule_json);
    if (input.expected_schedule_sha256) |expected| {
        if (!std.meta.eql(expected, schedule_hash)) return error.UntrustedCandidateSchedule;
    }

    // Endpoint pins are proposals from public host preflight here. A future
    // receiver derives them from independently admitted job/source pins.
    const planned = try host_preflight.run(a, input.elf, input.public_input, input.oracle, input.max_segment_cycles);
    if (input.progress != null) reportBudget(budget, "first-preflight", 0);
    var parsed = try std.json.parseFromSlice([]u32, a, input.schedule_json, .{ .allocate = .alloc_always });
    defer parsed.deinit();
    if (parsed.value.len == 0 or parsed.value.len > 1024) return error.InvalidCandidateSchedule;
    const schedule = try @import("../runner/balanced_schedule.zig").Schedule.initExplicitExact(planned.last.cycle, input.max_segment_cycles, planned.required_terminal_cycles, parsed.value);
    const job = try v3.initJobFromEndpoints(config, planned.first, planned.last, schedule.segments, planned.first.machine.rw_memory);
    const pins = source_mod.Pins{
        .elf_sha256 = elf_hash,
        .input_sha256 = input_hash,
        .oracle_sha256 = oracle_hash,
        .initial_rw_root = planned.first.machine.rw_memory,
        .program_root = planned.first.program,
        .schedule_json_sha256 = schedule_hash,
        .expected_job = job,
    };
    var source = try source_mod.Source.initWithSchedule(a, input.elf, input.public_input, input.oracle, input.max_segment_cycles, config, pins, input.schedule_json);
    defer source.deinit();
    if (input.progress != null) reportBudget(budget, "source-preflight", 0);
    const keys = try output_a.alloc([32]u8, source.schedule.segments);
    errdefer output_a.free(keys);
    if (input.probe_prefix_keys) |prefix| {
        if (prefix == 0 or prefix > source.schedule.segments) return error.InvalidCandidateProbePrefix;
    }
    if (input.probe_only_index) |target| {
        if (target >= source.schedule.segments or input.probe_prefix_keys != null)
            return error.InvalidCandidateProbeIndex;
    }
    {
        var reader = try source.openPass(.first);
        defer reader.deinit();
        for (keys, 0..) |*key, index| {
            {
                var segment = (reader.next() catch |err| {
                    std.log.err("candidate segment {d} replay failed: {s}", .{ index, @errorName(err) });
                    if (input.progress != null) reportBudget(budget, "replay-error", index);
                    return err;
                }) orelse return error.CandidateSegmentMissing;
                defer segment.deinit();
                if (segment.base.segment_index != @as(u32, @intCast(index))) return error.CandidateSegmentOrder;
                if (input.probe_only_index) |target| {
                    if (index != @as(usize, target)) continue;
                }
                if (input.progress != null) reportBudget(budget, "segment-loaded", index);
                var owner = profile.Witness.initCompactSegment(a, &segment) catch |err| {
                    std.log.err("candidate segment {d} witness failed: {s}", .{ index, @errorName(err) });
                    if (input.progress != null) reportBudget(budget, "witness-error", index);
                    return err;
                };
                var owner_live = true;
                defer if (owner_live) owner.deinit();
                if (input.progress != null) reportBudget(budget, "witness-ready", index);
                var snapshot = NativeInputs.init(a, &owner) catch |err| {
                    std.log.err("candidate segment {d} verifier snapshot failed: {s}", .{ index, @errorName(err) });
                    return err;
                };
                defer snapshot.deinit();
                owner.deinit();
                owner_live = false;
                if (input.progress != null) reportBudget(budget, "witness-released", index);
                const prepared = Native.PreparedVerifier.initCompact(a, &snapshot.native, snapshot.extension, snapshot.admission(), config, snapshot.ranges) catch |err| {
                    std.log.err("candidate segment {d} native key failed: {s}", .{ index, @errorName(err) });
                    if (input.progress != null) reportBudget(budget, "native-key-error", index);
                    return err;
                };
                defer prepared.deinit();
                key.* = prepared.id;
                if (input.progress != null) reportBudget(budget, "native-key-ready", index);
            }
            if (input.progress != null) reportBudget(budget, "segment-released", index);
            if (input.progress) |callback| callback(@intCast(index + 1), source.schedule.segments);
            if (input.probe_prefix_keys) |prefix| {
                if (index + 1 == @as(usize, prefix)) return error.CandidatePrefixProbeComplete;
            }
            if (input.probe_only_index != null) return error.CandidateTargetProbeComplete;
        }
        if ((try reader.next()) != null) return error.CandidateSegmentOverflow;
    }
    const base_digest = try deriveBaseSeal(pins, input.max_segment_cycles, job);
    const wire = trusted_manifest.Wire{
        .format_version = trusted_manifest.FORMAT_VERSION,
        .trusted = .{
            .job = job,
            .base_seal = .{ .digest = base_digest, .instance_count = source.schedule.segments },
            .native_key_ids = keys,
            .outer_key_id = @splat(0),
            .forest_roster_digest = @splat(0),
        },
        .source = pins,
    };
    try trusted_manifest.admit(wire, config);
    const manifest_bytes = try std.json.Stringify.valueAlloc(a, wire, .{});
    defer a.free(manifest_bytes);
    const report = Report{
        .manifest_sha256 = source_mod.sha256(manifest_bytes),
        .elf_sha256 = elf_hash,
        .input_sha256 = input_hash,
        .oracle_sha256 = oracle_hash,
        .schedule_sha256 = schedule_hash,
        .segment_count = source.schedule.segments,
        .total_cycles = planned.last.cycle,
        .max_segment_cycles = input.max_segment_cycles,
        .elf_bytes = input.elf.len,
        .input_bytes = input.public_input.len,
        .oracle_bytes = input.oracle.len,
        .schedule_bytes = input.schedule_json.len,
        .elapsed_ns = timer.read(),
        .tracked_work_peak_bytes = budget.snapshot().peak_live_bytes,
    };
    return .{ .a = output_a, .wire = wire, .keys = keys, .report = report };
}

fn reportBudget(budget: *engine.host_budget_allocator.SharedHostBudget, stage: []const u8, index: usize) void {
    const snapshot = budget.snapshot();
    std.debug.print("BLOCK_V4_CANDIDATE_MEMORY stage={s} index={d} live={d} peak={d} limit={d}\n", .{
        stage, index, snapshot.live_bytes, snapshot.peak_live_bytes, snapshot.limit,
    });
}

pub fn deriveBaseSeal(pins: source_mod.Pins, max_segment_cycles: u32, job: @import("../recursion/span_statement_blake3.zig").JobContext) ![32]u8 {
    const schedule_hash = pins.schedule_json_sha256 orelse return error.InvalidCandidateSchedule;
    const words = try (try exact_root.expectedRoot(job)).statement.canonicalWords();
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-v4/candidate-base-seal/v1\x00");
    hash.update(&pins.elf_sha256);
    hash.update(&pins.input_sha256);
    hash.update(&pins.oracle_sha256);
    hash.update(&schedule_hash);
    var count: [4]u8 = undefined;
    std.mem.writeInt(u32, &count, max_segment_cycles, .little);
    hash.update(&count);
    std.mem.writeInt(u32, &count, job.segment_count, .little);
    hash.update(&count);
    std.mem.writeInt(u32, &count, words.len, .little);
    hash.update(&count);
    for (words) |word| {
        std.mem.writeInt(u32, &count, word.toU32(), .little);
        hash.update(&count);
    }
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

test "candidate roster derives exact small key sequence and provisional manifest" {
    const a = std.testing.allocator;
    var instructions: [20]u32 = @splat(0x00000013);
    instructions[0] = 0x00100137;
    instructions[1] = 0x00100193;
    instructions[13] = 0x00312223;
    instructions[14] = 0x00312423;
    instructions[17] = 0x00312023;
    instructions[18] = 0x0000006f;
    instructions[19] = @import("../isa/sha256_compression_v1.zig").encode(5, 6);
    const elf = @import("../runner/guest_precompile/test_elf.zig").buildReleaseProgram(instructions.len, &instructions, 0, .rv32im_zkvm_ethereum_sha_v1);
    const oracle = [_]u8{1};
    const input = Input{ .elf = &elf, .public_input = &.{}, .oracle = &oracle, .schedule_json = "[5,4,4,5]", .expected_schedule_sha256 = source_mod.sha256("[5,4,4,5]"), .max_segment_cycles = 6 };
    var wrong_schedule = input;
    wrong_schedule.expected_schedule_sha256 = @splat(0);
    try std.testing.expectError(error.UntrustedCandidateSchedule, derive(a, wrong_schedule));
    var candidate = try derive(a, input);
    defer candidate.deinit();
    try std.testing.expectEqual(@as(usize, 4), candidate.keys.len);
    try std.testing.expectEqual(@as(u32, 4), candidate.report.segment_count);
    try std.testing.expectEqualStrings("proposal_only_host_replay_no_proof_authority", candidate.report.scope);
    try std.testing.expectEqual(@as([32]u8, @splat(0)), candidate.wire.trusted.outer_key_id);
    try std.testing.expectEqual(@as([32]u8, @splat(0)), candidate.wire.trusted.forest_roster_digest);
    var changed = candidate.wire.source;
    changed.input_sha256[0] ^= 1;
    try std.testing.expect(!std.meta.eql(candidate.wire.trusted.base_seal.digest, try deriveBaseSeal(changed, input.max_segment_cycles, candidate.wire.trusted.job)));
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try candidate.write(tmp.dir);
    var admitted = try trusted_manifest.read(a, tmp.dir, "candidate-trusted-v1.json", candidate.report.manifest_sha256);
    defer admitted.deinit();
    try admitted.admitInputs(input.elf, input.public_input, input.oracle, input.schedule_json);
    // The memory-saving path must produce the same key as the original direct
    // witness-borrowed verifier preparation for this admitted fixture.
    var source = try source_mod.Source.initWithSchedule(a, input.elf, input.public_input, input.oracle, 6, parent.Profile.csp_q70_pow26.config(), candidate.wire.source, input.schedule_json);
    defer source.deinit();
    var reader = try source.openPass(.first);
    defer reader.deinit();
    var segment = (try reader.next()) orelse return error.CandidateSegmentMissing;
    defer segment.deinit();
    var owner = try profile.Witness.initCompactSegment(a, &segment);
    defer owner.deinit();
    const direct = try Native.PreparedVerifier.initCompact(a, &owner.native.statement, owner.statement, try owner.admission(), parent.Profile.csp_q70_pow26.config(), owner.native.compact_ranges.?.plan);
    defer direct.deinit();
    try std.testing.expectEqual(candidate.keys[0], direct.id);
    try std.testing.expectError(error.PathAlreadyExists, candidate.write(tmp.dir));
}
