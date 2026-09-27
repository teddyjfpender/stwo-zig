//! Produce a provisional block-v4 CPU proof bundle from an independently
//! pinned candidate manifest. Final policy hashes must be selected by the
//! caller before a detached verifier may admit this bundle.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const cli = @import("prover/block_v4_cpu_cli_contract_v1.zig");
const manifest = @import("prover/block_v4_cpu_trusted_manifest_v1.zig");
const streaming = @import("prover/block_v4_cpu_streaming_produce.zig");
const leaf_stage = @import("prover/block_v4_cpu_incremental_leaf_stage.zig");
const forest_stage = @import("prover/block_v4_cpu_incremental_forest_stage.zig");
const parallel_forest = @import("prover/block_v4_cpu_parallel_forest_stage.zig");
const outer_stage = @import("prover/block_v4_cpu_incremental_outer_stage.zig");
const rebind = @import("prover/block_v4_cpu_complete_pin_rebind_v1.zig");
const bundle = @import("prover/block_v4_cpu_bundle_snapshot_v1.zig");
const policy = @import("prover/block_v4_cpu_trusted_recursion_v1.zig");
const rss = @import("prover/block_v4_cpu_cli_rss_v1.zig");
const parent = @import("recursion/blake3_execution_parent_protocol.zig");

const FINAL_PROPOSAL = "block-v4-final-manifest-proposal-v1.json";
const REPORT = "block-v4-producer-report-v1.json";
const GiB: usize = 1024 * 1024 * 1024;

const Context = struct {
    a: std.mem.Allocator,
    budget: *engine.host_budget_allocator.SharedHostBudget,
    total_timer: *std.time.Timer,
    dir: std.fs.Dir,
    candidate: *const manifest.Owned,
    candidate_sha256: [32]u8,
    pool: *engine.work_pool.WorkPool,
    binding: *engine.work_pool.ScopedPoolBinding,
    binding_active: *bool,
    requested_forest_lanes: usize,

    fn proveSerialForest(self: *Context, leaves: *const leaf_stage.Capture) !forest_stage.Stage {
        return forest_stage.prove(self.a, self.dir, leaves, self.candidate.trusted().job, self.pool, .{
            .profile = .csp_q70_pow26,
            .preparation_limit = 24 * GiB,
            .worker_options = .{ .worker_count = 4, .host_byte_limit = 24 * GiB, .retained_scratch_limit = 64 * 1024 * 1024 },
        });
    }

    fn produce(self: *Context, product: streaming.Product) !void {
        var timer = try std.time.Timer.start();
        var leaves = try leaf_stage.verifyAndStage(self.a, product, self.candidate.trusted(), parent.Profile.csp_q70_pow26.config(), self.dir, .csp_q70_pow26);
        defer leaves.deinit(self.a);
        const core_leaf_ns = timer.read();
        self.binding.deinit();
        self.binding_active.* = false;

        timer.reset();
        var forest_lanes_used: usize = 1;
        var forest_fallback: ?[]const u8 = null;
        var forest_peak: ?usize = null;
        var forest: forest_stage.Stage = undefined;
        const host = self.budget.snapshot();
        if (self.requested_forest_lanes == 2 and host.limit - host.live_bytes >= 36 * GiB) {
            var metrics: parallel_forest.Metrics = undefined;
            forest = parallel_forest.prove(self.a, self.dir, &leaves.staged, self.candidate.trusted().job, .{
                .profile = .csp_q70_pow26,
                .lane_count = 2,
                .total_host_limit = 32 * GiB,
                .preparation_limit_per_lane = 8 * GiB,
                .parent_worker_options = .{ .worker_count = 2, .host_byte_limit = 8 * GiB, .retained_scratch_limit = 64 * 1024 * 1024 },
                .metrics = &metrics,
            }) catch |err| switch (err) {
                error.OutOfMemory, error.ParentWorkerHostBudgetExceeded => blk: {
                    forest_fallback = "parallel_parent_host_budget";
                    break :blk try self.proveSerialForest(&leaves.staged);
                },
                else => return err,
            };
            if (forest_fallback == null) {
                forest_lanes_used = metrics.lane_count;
                forest_peak = metrics.tracked_peak_bytes;
            }
        } else {
            if (self.requested_forest_lanes == 2) forest_fallback = "insufficient_tracked_host_headroom";
            forest = try self.proveSerialForest(&leaves.staged);
        }
        defer forest.deinit();
        const forest_ns = timer.read();

        timer.reset();
        const outer = try outer_stage.prove(self.a, self.dir, &leaves.staged, &forest, self.candidate.trusted().job, .{
            .profile = .csp_q70_pow26,
            .preparation_limit = 24 * 1024 * 1024 * 1024,
        });
        const outer_ns = timer.read();

        var final_trusted = self.candidate.trusted();
        final_trusted.outer_key_id = outer.admission.expected_id;
        final_trusted.forest_roster_digest = forest.digest;
        const final_wire = manifest.Wire{
            .format_version = manifest.FORMAT_VERSION,
            .trusted = final_trusted,
            .source = self.candidate.sourcePins(),
        };
        const final_json = try std.json.Stringify.valueAlloc(self.a, final_wire, .{});
        defer self.a.free(final_json);
        var final_file = try self.dir.createFile(FINAL_PROPOSAL, .{ .exclusive = true });
        defer final_file.close();
        try final_file.writeAll(final_json);
        try final_file.sync();
        const final_sha256 = @import("prover/block_v4_cpu_runner_source.zig").sha256(final_json);
        var final = try manifest.read(self.a, self.dir, FINAL_PROPOSAL, final_sha256);
        defer final.deinit();

        const roots = try forest.rootDescriptors(self.a);
        defer self.a.free(roots);
        const rebound = try rebind.finalizeCompletePins(self.a, product, self.candidate, &final, &leaves.verified_core, roots, outer.admission);
        const policy_sha256 = try policy.writeProposed(self.a, self.dir, final_trusted.job, &leaves.staged, &forest, &outer);
        const bundle_sha256 = try bundle.write(self.a, self.dir, rebound.product, &leaves.staged, &forest, &outer, self.candidate_sha256, final_sha256);
        const report_json = try std.json.Stringify.valueAlloc(self.a, .{
            .scope = "provisional proof bundle; detached verification requires caller-pinned final manifest and recursion policy",
            .complete_block_verified = false,
            .segments = final_trusted.job.segment_count,
            .total_ns = self.total_timer.read(),
            .producer_ns = product.elapsed_ns,
            .memory_second_pass_ns = product.memory_second_pass_ns,
            .execution_second_pass_ns = product.execution_second_pass_ns,
            .core_and_recursive_leaf_ns = core_leaf_ns,
            .forest_ns = forest_ns,
            .forest_lanes_requested = self.requested_forest_lanes,
            .forest_lanes_used = forest_lanes_used,
            .forest_fallback = forest_fallback,
            .forest_scoped_peak_bytes = forest_peak,
            .outer_ns = outer_ns,
            .outer_preparation_peak_bytes = outer.preparation_peak_bytes,
            .tracked_peak_bytes = self.budget.snapshot().peak_live_bytes,
            .peak_rss_bytes = try rss.peakBytes(),
            .staged_core_payload_bytes = try product.payloadBytes(),
            .leaf_proof_count = leaves.staged.next,
            .dyadic_proof_count = forest.parents.len,
            .forest_root_count = forest.roots.len,
            .candidate_manifest_sha256 = std.fmt.bytesToHex(self.candidate_sha256, .lower),
            .proposed_final_manifest_sha256 = std.fmt.bytesToHex(final_sha256, .lower),
            .proposed_recursion_policy_sha256 = std.fmt.bytesToHex(policy_sha256, .lower),
            .bundle_sha256 = std.fmt.bytesToHex(bundle_sha256, .lower),
        }, .{ .whitespace = .indent_2 });
        defer self.a.free(report_json);
        var report = try self.dir.createFile(REPORT, .{ .exclusive = true });
        defer report.close();
        try report.writeAll(report_json);
        try report.writeAll("\n");
        try report.sync();
        try std.fs.File.stdout().writeAll(report_json);
        try std.fs.File.stdout().writeAll("\n");
    }
};

pub fn main() !void {
    const backing = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(backing);
    defer std.process.argsFree(backing, args);
    const parsed = try cli.Arguments.parse(args[1..]);
    const lane_text: ?[]u8 = std.process.getEnvVarOwned(backing, "STWO_BLOCK_V4_FOREST_LANES") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (lane_text) |value| backing.free(value);
    const requested_forest_lanes = if (lane_text) |value|
        std.fmt.parseInt(usize, value, 10) catch return error.InvalidBlockV4ForestLaneCount
    else
        1;
    if (requested_forest_lanes < 1 or requested_forest_lanes > 2)
        return error.InvalidBlockV4ForestLaneCount;
    const host = try engine.host_budget_allocator.SharedHostBudget.create(backing, 40 * 1024 * 1024 * 1024);
    defer host.destroy();
    const a = host.allocator();
    var total_timer = try std.time.Timer.start();
    var preflight = try cli.load(a, std.fs.cwd(), parsed);
    defer preflight.deinit(a);
    try std.fs.cwd().makeDir(parsed.output_dir);
    var output = try std.fs.cwd().openDir(parsed.output_dir, .{});
    defer output.close();
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    var binding_active = true;
    defer if (binding_active) binding.deinit();
    var context = Context{
        .a = a,
        .budget = host,
        .total_timer = &total_timer,
        .dir = output,
        .candidate = &preflight.manifest,
        .candidate_sha256 = parsed.manifest_sha256,
        .pool = &pool,
        .binding = &binding,
        .binding_active = &binding_active,
        .requested_forest_lanes = requested_forest_lanes,
    };
    try streaming.withProducedContext(a, output, &pool, &preflight.source, preflight.trusted(), parent.Profile.csp_q70_pow26.config(), .{}, &context, Context.produce);
}
