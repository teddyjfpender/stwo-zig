//! Geometry-only diagnostic from genuinely collected canonical admissions.
//! No original proof, verifier-success token, PoW or parent proof is produced.
//! Native/caller scalar claims are shape-only proposals: those values are public
//! inputs, not fixed graph constants. PAGE semantic constants use the exact
//! original proposal equations over authenticated operand-file replays.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Sources = @import("../block_v6_recursive_sources_v1.zig");
const Pages = @import("../block_v6_source_recursive_admissions_v1.zig");
const Job = @import("../block_v5_cpu_source_pages_v1.zig").Job;
const Storage = @import("../../recursion/air/blake3_parent_row_storage.zig");
const Base = @import("../../recursion/blake3_execution_parent_protocol.zig");
const Providers = @import("../../recursion/block_v6_provider_fixed_singletons_v1.zig");
const Native = @import("../../recursion/block_v6_partitioned_fixed_roster_v1.zig");
const Fused = @import("../../recursion/block_v6_caller_fused_auxiliary_fixed_v1.zig");
const PageFixed = @import("../../recursion/block_v6_page_auxiliary_fixed_v1.zig");
const Semantic = @import("../block_v5_memory_source_page_semantic_columns_v1.zig");
const Claims = @import("../block_v5_memory_source_page_claim_proposal_v1.zig");
const RawReplay = @import("../block_v5_memory_source_packed_sha_replay_v1.zig").ForBackend(Cpu);
const FoldReplay = @import("../block_v5_memory_source_fold_premix_v1.zig").ForBackend(Cpu);
const Count = [Storage.Airs.len]usize;
const PROFILE: Base.Profile = .csp_q70_pow26;
const PIECE_LIMIT: usize = 16 << 30;
const BATCH_RETAINED_LIMIT: usize = 4 << 30;
const Stats = struct {
    fixed_bytes: usize = 0,
    padded_main_bytes: usize = 0,
    padded_fixed_bytes: usize = 0,
    padded_interaction_bytes: usize = 0,
    max_log: u32 = 1,
};
fn stats(unpartitioned: Count) !Stats {
    var counts = unpartitioned;
    const Partition = @import("../../recursion/air/blake3_g_partition.zig");
    var has_shards = false;
    inline for (Partition.SHARDS[1..]) |i| has_shards = has_shards or counts[i] != 0;
    if (!has_shards and counts[0] > 1 << 20) {
        const geometry = try Partition.geometry(counts[0]);
        inline for (Partition.SHARDS, 0..) |slot, i| counts[slot] = geometry.counts[i];
    }
    var result = Stats{};
    inline for (Storage.Airs, 0..) |Air, i| {
        const n = counts[i];
        const log: u32 = if (n < 2) 1 else std.math.log2_int_ceil(usize, n);
        if (log > 30) return error.GeometryCensusDomainLimit;
        const padded = @as(usize, 1) << @intCast(log);
        result.max_log = @max(result.max_log, log);
        result.fixed_bytes = try std.math.add(usize, result.fixed_bytes, try std.math.mul(usize, n, @sizeOf(Storage.FixedRow(Air))));
        result.padded_main_bytes = try std.math.add(usize, result.padded_main_bytes, try std.math.mul(usize, padded, Air.PHYSICAL_MAIN_COLUMN_COUNT * @sizeOf(M)));
        result.padded_interaction_bytes = try std.math.add(usize, result.padded_interaction_bytes, try std.math.mul(usize, padded, Air.INTERACTION_COLUMN_COUNT * @sizeOf(M)));
        result.padded_fixed_bytes = try std.math.add(usize, result.padded_fixed_bytes, try std.math.mul(usize, padded, @sizeOf(Storage.FixedRow(Air))));
    }
    return result;
}
fn combine(a: Count, b: Count) !Count {
    var out: Count = undefined;
    for (&out, a, b) |*n, left, right| n.* = try std.math.add(usize, left, right);
    return out;
}
const Report = struct {
    total: Count = @splat(0),
    source: Count = @splat(0),
    batch: Count = @splat(0),
    batch_first: usize = 0,
    batch_count: usize = 0,
    batch_ordinal: usize = 0,
    children: usize = 0,
    fn finishBatch(self: *@This()) !void {
        if (self.batch_count == 0) return;
        const s = try stats(self.batch);
        std.debug.print("CENSUS_BATCH,{d},{d},{d},{d},{d},{d},{d},{d},{any}\n", .{ self.batch_ordinal, self.batch_first, self.batch_count, s.fixed_bytes, s.padded_main_bytes, s.padded_fixed_bytes, s.padded_interaction_bytes, s.max_log, try std.math.add(usize, s.fixed_bytes, s.padded_main_bytes) <= BATCH_RETAINED_LIMIT });
        self.batch_ordinal += 1;
        self.batch_first += self.batch_count;
        self.batch_count = 0;
        self.batch = @splat(0);
    }
    fn append(self: *@This(), family: []const u8, index: usize, piece: anytype, is_source: bool) !void {
        var counts: Count = undefined;
        inline for (0..Storage.Airs.len) |i| counts[i] = piece.fixed[i].len;
        const s = try stats(counts);
        const budget = if (@hasField(@TypeOf(piece.*), "budget")) piece.budget else piece.original.budget;
        const usage = budget.snapshot();
        const namespace_count = if (@hasField(@TypeOf(piece.*), "namespace")) piece.namespace.original.old.len else piece.namespace_ids.len;
        std.debug.print("CENSUS_CHILD,{s},{d},{d},{d},{d},{d},{d},{d},{d},{d},{d}\n", .{ family, index, s.fixed_bytes, s.padded_main_bytes, s.padded_fixed_bytes, s.padded_interaction_bytes, s.max_log, piece.wires.len, namespace_count, usage.live_bytes, usage.peak_live_bytes });
        inline for (Storage.Airs, 0..) |Air, i| std.debug.print("CENSUS_COHORT,{s},{d},{d},{d},{d},{d}\n", .{ family, index, i, counts[i], Air.PHYSICAL_MAIN_COLUMN_COUNT, Air.LOGICAL_INPUT_COUNT - Air.PHYSICAL_MAIN_COLUMN_COUNT });
        const proposed = try combine(self.batch, counts);
        const p = try stats(proposed);
        if (self.batch_count > 0 and (self.batch_count == 64 or try std.math.add(usize, p.fixed_bytes, p.padded_main_bytes) > BATCH_RETAINED_LIMIT)) try self.finishBatch();
        self.batch = try combine(self.batch, counts);
        self.batch_count += 1;
        self.total = try combine(self.total, counts);
        if (is_source) self.source = try combine(self.source, counts);
        self.children += 1;
    }
    fn finish(self: *@This()) !void {
        try self.finishBatch();
        const all = try stats(self.total);
        const source = try stats(self.source);
        std.debug.print("CENSUS_TOTAL,{d},{d},{d},{d},{d},{d},{d}\n", .{ self.children, self.batch_ordinal, all.fixed_bytes, all.padded_main_bytes, all.padded_fixed_bytes, all.padded_interaction_bytes, all.max_log });
        std.debug.print("CENSUS_SOURCE,{d},{d},{d},{d},{d}\n", .{ source.fixed_bytes, source.padded_main_bytes, source.padded_fixed_bytes, source.padded_interaction_bytes, source.max_log });
    }
};
pub fn run(a: std.mem.Allocator, sources: *const Sources.Owner, pages: *const Pages.Owner, job: *Job) !void {
    try sources.require();
    if (!std.meta.eql(sources.roster.pins.config, PROFILE.config()) or !std.meta.eql(pages.context.raw_plan.config, PROFILE.config()) or job.phase != .sealed) return error.CanonicalGeometryCensusRequiresCanonicalAdmissions;
    std.debug.print("CENSUS_BOUNDARY canonical=true queries=70 pow_bits=26 proofs=0 authority=false memory=charged_allocator_not_rss batch_limit_retained_bytes={d} peak_model=not_total_prover_peak\n", .{BATCH_RETAINED_LIMIT});
    std.debug.print("CENSUS_ADMISSION native_provider_live={d} native_provider_peak={d} page_live={d} page_peak={d}\n", .{ sources.budget.snapshot().live_bytes, sources.budget.snapshot().peak_live_bytes, pages.budget.snapshot().live_bytes, pages.budget.snapshot().peak_live_bytes });
    var report = Report{};
    for (sources.executions, 0..) |*admitted, index| {
        std.debug.print("CENSUS_START native {d}\n", .{index});
        const Projection = @import("../block_v5_native_projection_fused_proof_v2.zig").Claim;
        const Memory = @import("../block_v5_opcode_memory_sidecar_proof_v1.zig").Claim;
        const projection = try a.alloc(Projection, admitted.projections.len);
        defer a.free(projection);
        const memory = try a.alloc(Memory, admitted.slots.len);
        defer a.free(memory);
        for (projection, admitted.projections) |*claim, slot| claim.* = .{ .sum = Q.zero(), .row_count = slot.n_rows };
        for (memory) |*claim| claim.* = .{ .transition_sum = Q.zero(), .universal_sum = Q.zero(), .range_claims = @splat(Q.zero()), .active_count = 0 };
        var piece = try Native.Owned.derive(a, admitted, .{ .projection = projection, .memory = memory }, 2, PROFILE, .{ .max_bytes = PIECE_LIMIT, .native = .{ .max_bytes = 2 << 30 } });
        defer piece.deinit();
        try report.append("native", index, &piece, false);
    }
    inline for (.{ .range16, .ram_lanes }) |family| {
        const admitted_list = switch (family) {
            .range16 => sources.ranges,
            .ram_lanes => sources.lanes,
            .native_lookup => sources.lookups,
            else => unreachable,
        };
        for (admitted_list, 0..) |*admitted, index| {
            std.debug.print("CENSUS_START {s} {d}\n", .{ @tagName(family), index });
            var piece = try Providers.ForFamily(family).Owned.derive(a, admitted, admitted.template_id, {}, 2, PROFILE, .{ .max_bytes = PIECE_LIMIT });
            defer piece.deinit();
            try report.append(@tagName(family), index, &piece, false);
        }
    }
    if (sources.program) |*admitted| {
        std.debug.print("CENSUS_START program_table 0\n", .{});
        var piece = try Providers.ForFamily(.program_table).Owned.derive(a, admitted, admitted.template_id, {}, 2, PROFILE, .{ .max_bytes = PIECE_LIMIT });
        defer piece.deinit();
        try report.append("program_table", 0, &piece, false);
    }
    for (sources.lookups, 0..) |*admitted, index| {
        std.debug.print("CENSUS_START native_lookup {d}\n", .{index});
        var piece = try Providers.ForFamily(.native_lookup).Owned.derive(a, admitted, admitted.template_id, {}, 2, PROFILE, .{ .max_bytes = PIECE_LIMIT });
        defer piece.deinit();
        try report.append("native_lookup", index, &piece, false);
    }
    for (sources.callers.?.entries) |entry| {
        {
            const admitted = &entry.admissions.arithmetic;
            std.debug.print("CENSUS_START caller_arithmetic {d}\n", .{entry.index});
            var piece = try Providers.CallerArithmetic.Owned.derive(a, admitted, admitted.template_id, {}, 2, PROFILE, .{ .max_bytes = PIECE_LIMIT, .native = .{ .max_bytes = 4 << 30 } });
            defer piece.deinit();
            try report.append("caller_arithmetic", entry.index, &piece, false);
        }
    }
    for (sources.callers.?.entries) |entry| {
        {
            const admitted = &entry.admissions.fused;
            std.debug.print("CENSUS_START caller_fused {d}\n", .{entry.index});
            const Frames = @import("../block_v5_caller_fused_proof_v1.zig").ClaimFrames;
            var frames: Frames = undefined;
            frames.program_claims = try a.alloc(std.meta.Child(@FieldType(Frames, "program_claims")), admitted.schedule.program.len);
            defer a.free(frames.program_claims);
            frames.state_claims = try a.alloc(std.meta.Child(@FieldType(Frames, "state_claims")), admitted.schedule.program.len);
            defer a.free(frames.state_claims);
            frames.table_claims = try a.alloc(std.meta.Child(@FieldType(Frames, "table_claims")), admitted.schedule.tables.len);
            defer a.free(frames.table_claims);
            frames.memory_claims = try a.alloc(std.meta.Child(@FieldType(Frames, "memory_claims")), admitted.schedule.memory.len);
            defer a.free(frames.memory_claims);
            for (admitted.schedule.program, frames.program_claims, frames.state_claims) |slot, *program, *state| {
                program.* = .{ .sum = Q.zero(), .fetch_count = slot.active_calls };
                state.* = program.*;
            }
            for (admitted.schedule.tables, frames.table_claims) |slot, *claim| claim.* = .{ .sum = Q.zero(), .row_count = slot.n_rows };
            var remaining = admitted.schedule.rw_events;
            for (admitted.schedule.memory, frames.memory_claims) |slot, *claim| {
                const count = @min(remaining, @as(u64, 1) << @intCast(slot.log_size));
                claim.* = .{ .transition_sum = Q.zero(), .universal_sum = Q.zero(), .range_claims = @splat(Q.zero()), .active_count = count };
                remaining -= count;
            }
            if (remaining != 0) return error.GeometryCensusMemoryCensus;
            var piece = try Fused.Owned.derive(a, admitted, admitted.template_id, frames, 2, PROFILE, .{ .max_bytes = PIECE_LIMIT, .native = .{ .max_bytes = 4 << 30 } });
            defer piece.deinit();
            try report.append("caller_fused", entry.index, &piece, false);
        }
    }
    inline for (.{ Semantic.Kind.raw, Semantic.Kind.fold }) |kind| {
        const admissions = if (kind == .raw) pages.raw else pages.fold;
        for (admissions, 0..) |*admitted, index| {
            std.debug.print("CENSUS_START source_{s} {d}\n", .{ @tagName(kind), index });
            const claims = try pageClaims(kind, a, job, index);
            var piece = try PageFixed.ForKind(kind).Owned.derive(a, admitted, admitted.template_id, claims, 2, PROFILE, .{ .max_bytes = PIECE_LIMIT });
            defer piece.deinit();
            try report.append(if (kind == .raw) "source_raw" else "source_fold", index, &piece, true);
        }
    }
    try report.finish();
}
fn rawRead(raw: *anyopaque, group: Semantic.Group, logical: u32, column: u32) !M {
    const owner: *RawReplay.Owner = @ptrCast(@alignCast(raw));
    const matrix: struct { values: []const M, log: u32 } = switch (group) {
        .source => blk: {
            const source = &owner.raw.?.columns.?;
            if (column >= @import("../block_v5_memory_source_batch_raw_schema_v1.zig").MAIN_COUNT) return error.InvalidSourcePageCell;
            break :blk .{ .values = source.mainColumn(column), .log = source.page.row_log };
        },
        .capture => blk: {
            if (column >= owner.cores.?.captures.columns.len) return error.InvalidSourcePageCell;
            const capture = owner.cores.?.captures.columns[column];
            break :blk .{ .values = capture.values, .log = capture.log_size };
        },
    };
    if (logical >= matrix.values.len) return error.InvalidSourcePageCell;
    return matrix.values[@import("../../air/block/memory_component_trace.zig").committedRow(logical, matrix.log)];
}
fn pageClaims(comptime kind: Semantic.Kind, a: std.mem.Allocator, job: *Job, index: usize) !Semantic.Claims {
    var path: [96]u8 = undefined;
    const file = try @import("../block_v5_memory_source_page_job_v1.zig").name(&path, kind, @intCast(index), false);
    if (kind == .raw) {
        const record = job.raws[index];
        const owner = try RawReplay.replayWithSetup(a, job.dir, file, &job.admitted.source, job.raw_plan, record.pin, record.stored, job.limits.proof.raw, job.sha_setup.?);
        defer owner.deinit() catch @panic("geometry census RAW lease");
        return Claims.raw(&job.admitted, record.pin.raw.page, .{ .context = owner, .read = rawRead }, job.context.?.epoch.challenges);
    } else {
        const record = job.folds[index];
        const owner = try FoldReplay.replay(a, job.dir, file, &job.admitted, job.fold_plan, record.pin, record.stored, job.blake_setup.?, job.limits.proof.fold);
        defer owner.deinit() catch @panic("geometry census FOLD lease");
        return Claims.fold(&job.admitted, owner.descriptors, owner.semanticReader(), job.context.?.epoch.challenges);
    }
}
