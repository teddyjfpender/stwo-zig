//! Bounded preflight/replay and complete native recursive proof delivery.
//! A preflight is never proof evidence; every replay leaf is proved and folded.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("runner/mod.zig");
const statement = @import("prover/blake3_segment_statement.zig");
const parent = @import("recursion/blake3_execution_parent_proof.zig");
const spans = @import("recursion/span_statement_blake3.zig");
const Folder = @import("recursion/blake3_stream_prover.zig").ForBackend(Cpu);
const preflight_mod = @import("prover/blake3_execution_preflight.zig");
const exact_output = @import("ethereum_block_exact_output.zig");

/// Sequential wall-clock intervals; pool work is included in its enclosing stage.
/// Leaf preparation currently combines native proving and recursive witness work.
const StageTimes = struct {
    preflight: u64 = 0,
    replay_execution: u64 = 0,
    witness_preparation: u64 = 0,
    verifier_preparation: u64 = 0,
    leaf_proof_and_recursive_witness: u64 = 0,
    recursive_proving_and_aggregation: u64 = 0,
    final_root_verification: u64 = 0,
    memory_witness_transport: u64 = 0,
};

pub fn main() !void {
    const backing = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(backing);
    defer std.process.argsFree(backing, args);
    if (args.len < 8 or args.len > 13) return error.ExpectedElfInputOracleMaxCyclesProofReportProfileOptionalPairing;
    var pair_leaves = false;
    var joint = false;
    var memory_witness = false;
    var exact = false;
    var selected: ?u32 = null;
    var schedule_path: ?[]const u8 = null;
    for (args[8..]) |option| {
        if (std.mem.eql(u8, option, "paired") and !pair_leaves) {
            pair_leaves = true;
        } else if (std.mem.eql(u8, option, "joint") and !joint) {
            joint = true;
        } else if (std.mem.eql(u8, option, "memory-witness") and !memory_witness) {
            memory_witness = true;
        } else if (std.mem.eql(u8, option, "exact") and !exact) {
            exact = true;
        } else if (std.mem.startsWith(u8, option, "segment=") and selected == null) {
            selected = try std.fmt.parseInt(u32, option[8..], 10);
        } else if (std.mem.startsWith(u8, option, "schedule=") and schedule_path == null) {
            schedule_path = option[9..];
        } else return error.InvalidQualificationMode;
    }
    if (pair_leaves and selected != null) return error.InvalidQualificationMode;
    if (selected != null and memory_witness) return error.InvalidQualificationMode;
    const profile: parent.protocol.Profile = if (std.mem.eql(u8, args[7], "canonical")) .csp_q70_pow26 else if (std.mem.eql(u8, args[7], "diagnostic")) .diagnostic_q8_pow0 else return error.InvalidProfile;
    if (joint and (!pair_leaves or selected != null or profile != .csp_q70_pow26)) return error.InvalidQualificationMode;
    if (exact and (joint or profile != .csp_q70_pow26)) return error.InvalidQualificationMode;
    const limit = try std.fmt.parseInt(u32, args[4], 10);
    if (limit == 0 or limit > 1 << 22) return error.InvalidSegmentBudget;
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(backing, 48 * 1024 * 1024 * 1024);
    defer budget.destroy();
    const a = budget.allocator();
    errdefer std.debug.print("BLOCK_STREAM failure peak_bytes={d}\n", .{budget.snapshot().peak_live_bytes});
    var schedule_override: ?@import("runner/segment_schedule_override.zig").Owned = if (schedule_path) |path| try @import("runner/segment_schedule_override.zig").Owned.read(a, path) else null;
    defer if (schedule_override) |*owned| owned.deinit();
    const override = if (schedule_override) |*owned| owned else null;
    const elf = try std.fs.cwd().readFileAlloc(a, args[1], 32 * 1024 * 1024);
    defer a.free(elf);
    const input = try std.fs.cwd().readFileAlloc(a, args[2], 64 * 1024 * 1024);
    defer a.free(input);
    const oracle = try std.fs.cwd().readFileAlloc(a, args[3], 1024 * 1024);
    defer a.free(oracle);
    switch (try runner.elf_loader.requestedExecutionProfile(elf)) {
        .rv32im_zkvm_ethereum_v1 => try runForProfile(.rv32im_zkvm_ethereum_v1, a, budget, args, elf, input, oracle, limit, profile, pair_leaves, joint, memory_witness, exact, selected, override),
        .rv32im_zkvm_ethereum_sha_v1 => try runForProfile(.rv32im_zkvm_ethereum_sha_v1, a, budget, args, elf, input, oracle, limit, profile, pair_leaves, joint, memory_witness, exact, selected, override),
        else => return error.UnsupportedEthereumBlockProfile,
    }
}
fn runForProfile(comptime execution_profile: @import("isa/execution_profile.zig").ExecutionProfile, a: std.mem.Allocator, budget: *engine.host_budget_allocator.SharedHostBudget, args: []const [:0]u8, elf: []const u8, input: []const u8, oracle: []const u8, limit: u32, profile: parent.protocol.Profile, pair_leaves: bool, joint: bool, memory_witness: bool, exact: bool, selected: ?u32, override: ?*const @import("runner/segment_schedule_override.zig").Owned) !void {
    const sha = execution_profile == .rv32im_zkvm_ethereum_sha_v1;
    const Owner = if (sha) @import("prover/blake3_ethereum_witness.zig").ShaOwner else @import("prover/blake3_ethereum_witness.zig").Owner;
    const Api = if (sha) @import("prover/blake3_ethereum_sha_proof.zig").ForBackend(Cpu) else @import("prover/blake3_ethereum_proof.zig").ForBackend(Cpu);
    const Pipeline = if (sha) @import("prover/blake3_segment_parent.zig").ForEthereumShaBackend(Cpu) else @import("prover/blake3_segment_parent.zig").ForEthereumBackend(Cpu);
    const Session = if (sha) runner.EthereumShaExecutionSession else runner.EthereumExecutionSession;
    var timer = try std.time.Timer.start();
    var pre = try preflight_mod.runEthereumForProfile(execution_profile, a, elf, input, oracle, limit);
    if (override) |owned| {
        pre.schedule = if (exact) try owned.scheduleExact(pre.last.cycle, limit, pre.required_terminal_cycles) else try owned.schedule(pre.last.cycle, limit, pre.required_terminal_cycles);
    } else if (exact) {
        pre.schedule = try @import("runner/balanced_schedule.zig").Schedule.initExactWithTerminalSuffix(pre.last.cycle, limit, pre.required_terminal_cycles);
    }
    if (joint and pre.schedule.segments != 2) return error.InvalidJointManifestScope;
    if (selected) |index| if (index >= pre.schedule.segments) return error.InvalidSegmentIndex;
    const preflight_ns = timer.read();
    var stages = StageTimes{ .preflight = preflight_ns };
    std.debug.print("BLOCK_STREAM required_terminal_cycles={d} terminal_leaf_cycles={d}\n", .{ pre.required_terminal_cycles, try pre.schedule.budget(pre.schedule.segments - 1) });
    const job = try statement.initJobFromEndpoints(profile.config(), pre.first, pre.last, pre.schedule.segments);
    std.debug.print("BLOCK_STREAM preflight_cycles={d} proof_segments={d} preflight_ns={d}\n", .{ pre.last.cycle, pre.schedule.segments, preflight_ns });
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 16, .backing_allocator = a });
    defer pool.deinit();
    var folder = Folder{
        .allocator = a,
        .pool = &pool,
        .preparation_limit = 32 * 1024 * 1024 * 1024,
        .worker_options = .{ .worker_count = 16, .host_byte_limit = 40 * 1024 * 1024 * 1024, .retained_scratch_limit = 64 * 1024 * 1024 },
        .profile = profile,
        .retain_root_artifact = !exact,
        .retain_exact_forest_artifacts = exact,
    };
    defer folder.deinit();
    var frontier = try @import("recursion/blake3_stream_frontier.zig").Frontier.init(job);
    defer frontier.deinit();
    var stage_start = timer.read();
    var session = try Session.init(a, elf, .{ .input = input, .strict_completion = true, .stop_on_halt_flag = true, .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var current = try session.startSegment(try pre.schedule.budget(0));
    stages.replay_execution += timer.read() - stage_start;
    var live = true;
    defer if (live) current.deinit();
    const memory_path = if (memory_witness) try std.fmt.allocPrint(a, "{s}.memory-spool", .{args[6]}) else null;
    defer if (memory_path) |path| a.free(path);
    if (memory_path) |path| try std.fs.cwd().makeDir(path);
    defer if (memory_path) |path| std.fs.cwd().deleteTree(path) catch {};
    var memory_dir: ?std.fs.Dir = if (memory_path) |path| try std.fs.cwd().openDir(path, .{}) else null;
    defer if (memory_dir) |*dir| dir.close();
    var memory_replay: ?@import("prover/block_memory_replay.zig").Replay = if (memory_dir) |dir|
        try @import("prover/block_memory_replay.zig").Replay.initFromSnapshot(a, dir, current.base.entry_cpu.regs, &current.base.rw_memory, 1 << 18)
    else
        null;
    defer if (memory_replay) |*replay| replay.deinit();
    if (memory_replay) |*replay| {
        if (!std.meta.eql(try replay.initialRwRoot(), job.complete.initial_state.rw_memory))
            return error.BlockInitialRwRootMismatch;
    }
    var proved: u32 = 0;
    // Sizing qualification replays the same schedule and proves one actual leaf
    // with full custody. It never publishes a complete-block artifact.
    if (selected) |index| {
        stage_start = timer.read();
        while (proved < index) : (proved += 1) {
            const next = current.base.continuation orelse return error.MissingContinuation;
            current.deinit();
            live = false;
            current = try session.resumeSegment(next, try pre.schedule.budget(proved + 1));
            live = true;
        }
        stages.replay_execution += timer.read() - stage_start;
    }
    while (proved < pre.schedule.segments) {
        const batch: u32 = if (pair_leaves and pre.schedule.segments - proved >= 2) 2 else 1;
        var continuation = current.base.continuation;
        var fold = blk: {
            var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
            defer binding.deinit();
            var owners: [2]Owner = undefined;
            var owners_live: [2]bool = @splat(false);
            defer for (&owners, owners_live) |*owner, owned| {
                if (owned) owner.deinit();
            };
            var keys: [2]?*Api.PreparedVerifier = @splat(null);
            defer for (keys) |key| {
                if (key) |owned| owned.deinit();
            };
            var statements: [2]spans.SpanStatement = undefined;
            for (0..batch) |j| {
                const i = proved + @as(u32, @intCast(j));
                if (current.base.segment_index != i or current.base.global_first_cycle != try pre.schedule.firstCycle(i) or current.base.cycle_count != try pre.schedule.budget(i)) return error.ReplayScheduleMismatch;
                const last = i == pre.schedule.segments - 1;
                if (current.base.isComplete() != last) return error.ReplayCompletionMismatch;
                if (last and !std.mem.eql(u8, current.base.output orelse return error.MissingOutput, oracle)) return error.ReplayOutputMismatch;
                stage_start = timer.read();
                statements[j] = try statement.leaf(a, job, &current.base);
                if (selected != null) std.debug.print("BLOCK_SEGMENT stage=witness_start elapsed_ns={d} peak_bytes={d}\n", .{ timer.read(), budget.snapshot().peak_live_bytes });
                owners[j] = try Owner.initCompactSegment(a, &current);
                owners_live[j] = true;
                stages.witness_preparation += timer.read() - stage_start;
                if (selected != null) std.debug.print("BLOCK_SEGMENT stage=witness_done elapsed_ns={d} peak_bytes={d}\n", .{ timer.read(), budget.snapshot().peak_live_bytes });
                stage_start = timer.read();
                keys[j] = try Api.PreparedVerifier.initCompact(a, &owners[j].native.statement, owners[j].statement, try owners[j].admission(), profile.config(), owners[j].native.compact_ranges.?.plan);
                stages.verifier_preparation += timer.read() - stage_start;
                if (selected != null) std.debug.print("BLOCK_SEGMENT stage=key_done elapsed_ns={d} peak_bytes={d}\n", .{ timer.read(), budget.snapshot().peak_live_bytes });
                continuation = current.base.continuation;
                if (memory_replay) |*replay| try replay.appendResult(&current.base);
                // Owners copy all trace, memory and public-I/O data they need.
                // Release each runner segment before starting the next one.
                current.deinit();
                live = false;
                if (j + 1 < batch) {
                    stage_start = timer.read();
                    current = try session.resumeSegment(continuation orelse return error.MissingContinuation, try pre.schedule.budget(i + 1));
                    stages.replay_execution += timer.read() - stage_start;
                    live = true;
                }
            }
            const leaf_start = timer.read();
            defer stages.leaf_proof_and_recursive_witness += timer.read() - leaf_start;
            if (batch == 1) break :blk parent.aggregation.Fold{
                .prepared = try Pipeline.prepareWithPool(a, &owners[0], keys[0].?, keys[0].?.id, statements[0], 2, &pool),
                .statement = statements[0],
            };
            // This canonical API independently proves/verifies both executions,
            // consumes both owners even on failure, and shares their final hash
            // layout. No single-child recursive wrappers are materialized.
            owners_live = @splat(false);
            if (joint) {
                const admission = @import("prover/block_execution_admission.zig");
                const context = try admission.context(statements, profile.config());
                const admissions = [2]@import("prover/block_commitment_manifest.zig").Admission{
                    try admission.derive(keys[0].?, keys[0].?.id, statements[0], execution_profile, 0),
                    try admission.derive(keys[1].?, keys[1].?.id, statements[1], execution_profile, 1),
                };
                break :blk try Pipeline.preparePairOwnedWithManifest(a, .{ &owners[0], &owners[1] }, .{ keys[0].?, keys[1].? }, .{ keys[0].?.id, keys[1].?.id }, statements, context, admissions, 2, &pool);
            }
            break :blk try Pipeline.preparePairOwnedWithPool(a, .{ &owners[0], &owners[1] }, .{ keys[0].?, keys[1].? }, .{ keys[0].?.id, keys[1].?.id }, statements, 2, &pool);
        };
        defer fold.deinit();
        if (selected != null) std.debug.print("BLOCK_SEGMENT stage=recursive_witness_done elapsed_ns={d} peak_bytes={d}\n", .{ timer.read(), budget.snapshot().peak_live_bytes });
        stage_start = timer.read();
        var node = try folder.provePrepared(&fold.prepared, fold.statement);
        var node_live = true;
        defer if (node_live) node.deinit();
        if (selected != null) {
            try node.validate();
            stages.recursive_proving_and_aggregation += timer.read() - stage_start;
            const report = try std.json.Stringify.valueAlloc(a, .{
                .complete_execution_proof_verified = false,
                .segment_recursive_proof_verified = true,
                .explicit_segment_schedule = override != null,
                .scope = "one scheduled execution leaf and full-custody recursive wrapper; excludes tree aggregation",
                .execution_profile = @tagName(execution_profile),
                .canonical = profile == .csp_q70_pow26,
                .queries = profile.config().fri_config.n_queries,
                .pow_bits = profile.config().pow_bits,
                .segments = pre.schedule.segments,
                .segment_index = proved,
                .cycles = try pre.schedule.budget(proved),
                .global_first_cycle = try pre.schedule.firstCycle(proved),
                .stage_ns = stages,
                .total_ns = timer.read(),
                .peak_bytes = budget.snapshot().peak_live_bytes,
                .statement = node.statement,
                .admission = node.admission,
            }, .{ .whitespace = .indent_2 });
            defer a.free(report);
            try writeNew(args[6], report);
            return;
        }
        try frontier.push(&node, &folder);
        node_live = false;
        stages.recursive_proving_and_aggregation += timer.read() - stage_start;
        proved += batch;
        std.debug.print("BLOCK_STREAM proved_segments={d}/{d} paired={any} retained_nodes={d} peak_bytes={d} elapsed_ns={d}\n", .{ proved, pre.schedule.segments, pair_leaves, frontier.retainedNodes(), budget.snapshot().peak_live_bytes, timer.read() });
        if (proved < pre.schedule.segments) {
            stage_start = timer.read();
            current = try session.resumeSegment(continuation orelse return error.MissingContinuation, try pre.schedule.budget(proved));
            stages.replay_execution += timer.read() - stage_start;
            live = true;
        }
    }
    var memory_rows: ?u64 = null;
    var memory_instances: ?u64 = null;
    var memory_initial_sources: ?[4]u64 = null;
    if (memory_replay) |*replay| {
        stage_start = timer.read();
        const admitted = replay.spooler.event_count;
        var sorted = try replay.finish();
        defer sorted.deinit();
        var instances = try @import("air/block/memory_instance.zig").Partitioner.init(&sorted, admitted, 1 << 20);
        const SourceCensus = struct {
            replay: *@import("prover/block_memory_replay.zig").Replay,
            previous_space: ?u1 = null,
            previous_address: u32 = 0,
            counts: [4]u64 = @splat(0),
            fn append(pointer: *anyopaque, item: @import("air/block/memory_transition.zig").Transition, _: ?@import("air/block/memory_order.zig").Row) anyerror!void {
                const self: *@This() = @ptrCast(@alignCast(pointer));
                if (self.previous_space == null or self.previous_space.? != item.space or self.previous_address != item.address) {
                    const source = try self.replay.sourceFor(item.space, item.address);
                    self.counts[@intFromEnum(source)] += 1;
                    self.previous_space = item.space;
                    self.previous_address = item.address;
                }
            }
        };
        var census = SourceCensus{ .replay = replay };
        const sink = @import("air/block/memory_instance.zig").Sink{ .context = &census, .append = SourceCensus.append };
        var count: u64 = 0;
        while (try instances.next(sink)) |_| count += 1;
        memory_rows = admitted;
        memory_instances = count;
        memory_initial_sources = census.counts;
        stages.memory_witness_transport = timer.read() - stage_start;
    }
    if (exact) {
        stage_start = timer.read();
        var forest = try frontier.takeExactForest();
        defer forest.deinit();
        const complete = try forest.validate();
        const published = try exact_output.publish(a, args[5], &forest);
        stages.final_root_verification = timer.read() - stage_start;
        const total_ns = timer.read();
        const report = try std.json.Stringify.valueAlloc(a, .{
            .complete_execution_proof_verified = true,
            .complete_execution_forest_verified = true,
            .single_recursive_root = false,
            .separate_memory_proof_verified = false,
            .verification_scope = "in-process exact-count V2 forest; standalone receiver requires independently supplied roster digest pin; existing per-leaf memory custody",
            .execution_profile = @tagName(execution_profile),
            .paired_execution_leaves = pair_leaves,
            .explicit_segment_schedule = override != null,
            .memory_witness_only = memory_witness,
            .memory_event_rows = memory_rows,
            .memory_instances = memory_instances,
            .memory_initial_sources = memory_initial_sources,
            .recursive_proof_jobs = recursiveProofJobs(pre.schedule.segments, pair_leaves),
            .canonical = true,
            .queries = profile.config().fri_config.n_queries,
            .pow_bits = profile.config().pow_bits,
            .segments = pre.schedule.segments,
            .cycles = complete.cycle_count,
            .total_ns = total_ns,
            .stage_ns = stages,
            .proof_count = published.proof_count,
            .proof_bytes = published.proof_bytes,
            .roster_digest = published.roster_digest,
            .peak_bytes = budget.snapshot().peak_live_bytes,
            .elf_sha256 = digest(elf),
            .input_sha256 = digest(input),
            .output_sha256 = digest(oracle),
            .job = job,
        }, .{ .whitespace = .indent_2 });
        defer a.free(report);
        try writeNew(args[6], report);
        return;
    }
    stage_start = timer.read();
    var root = try frontier.takeRoot();
    defer root.deinit();
    _ = try root.root();
    if (!std.meta.eql(root.statement.job, job)) return error.UnexpectedRootJob;
    var artifact = try folder.takeRootArtifact();
    defer artifact.deinit();
    var restored = try artifact.verify(a, root.admission, root.admission.expected_id);
    defer restored.deinit();
    if (!std.meta.eql(try root.root(), try restored.root())) return error.RootRoundtripMismatch;
    stages.final_root_verification = timer.read() - stage_start;
    const total_ns = timer.read();
    const report = try std.json.Stringify.valueAlloc(a, .{
        .complete_execution_proof_verified = true,
        .execution_profile = @tagName(execution_profile),
        .paired_execution_leaves = pair_leaves,
        .joint_execution_manifest = joint,
        .single_recursive_root = true,
        .separate_memory_proof_verified = false,
        .memory_witness_only = memory_witness,
        .memory_event_rows = memory_rows,
        .memory_instances = memory_instances,
        .memory_initial_sources = memory_initial_sources,
        .explicit_segment_schedule = override != null,
        .recursive_proof_jobs = recursiveProofJobs(pre.schedule.segments, pair_leaves),
        .canonical = profile == .csp_q70_pow26,
        .queries = profile.config().fri_config.n_queries,
        .pow_bits = profile.config().pow_bits,
        .segments = pre.schedule.segments,
        .cycles = pre.last.cycle,
        .required_terminal_cycles = pre.required_terminal_cycles,
        .terminal_leaf_cycles = try pre.schedule.budget(pre.schedule.segments - 1),
        .preflight_ns = preflight_ns,
        .total_ns = total_ns,
        .timing_scope = "preflight through fresh root verification; excludes file loading, report/proof writes and final teardown",
        .stage_ns = stages,
        .proof_bytes = artifact.bytes.len,
        .execution_cycles_per_second = @as(f64, @floatFromInt(pre.last.cycle)) * std.time.ns_per_s / @as(f64, @floatFromInt(total_ns)),
        .peak_bytes = budget.snapshot().peak_live_bytes,
        .elf_sha256 = digest(elf),
        .input_sha256 = digest(input),
        .output_sha256 = digest(oracle),
        .proof_sha256 = digest(artifact.bytes),
        .statement = root.statement,
        // A receiver must independently pin this admission; the JSON itself
        // does not establish program identity or verification-key authority.
        .admission = root.admission,
    }, .{ .whitespace = .indent_2 });
    defer a.free(report);
    try writeNew(args[5], artifact.bytes);
    try writeNew(args[6], report);
}
fn recursiveProofJobs(segments: u32, paired: bool) u64 {
    const count: u64 = segments;
    if (!paired) return count * 2 - 1;
    const initial_roots = (count + 1) / 2;
    return initial_roots * 2 - 1;
}
fn digest(bytes: []const u8) [64]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &out, .{});
    return std.fmt.bytesToHex(out, .lower);
}
fn writeNew(path: []const u8, bytes: []const u8) !void {
    var file = try std.fs.cwd().createFile(path, .{ .exclusive = true });
    defer file.close();
    try file.writeAll(bytes);
    try file.sync();
}
