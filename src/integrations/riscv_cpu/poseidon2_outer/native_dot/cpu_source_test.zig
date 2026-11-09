//! Retained small CPU source; explicit opt-in physical leaf qualification.
//! Default remains source-only. No R7 recursive/root admission.
const std = @import("std");
const Core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const Runtime = @import("../pure_p2_op_runtime.zig");
const Bundle = @import("../pure_p2_op_bundle.zig");
const Protocol = @import("../pure_p2_worker_protocol.zig");
const V = @import("../../rv64_recursion/om31_poseidon/mod.zig");
const CPU = @import("../pure_p2_cpu_leaf_test.zig");
const R6 = @import("../native_omul/census.zig");
const L = @import("../layout.zig");
const MR = @import("../native_omul/row.zig");
const D = @import("row.zig");
pub const Counts = struct {
    raw: [8]u64,
    rows: [8]usize,
    logs: [8]u32,
    main_cells: u64 = 0,
    fixed_cells: u64 = 0,
    interaction_cells: u64 = 0,
    total_native_cells: u64 = 0,
    dot_calls: usize,
    dot_terms: usize,
    pub fn derive(owner: *const V.common.PoseidonContext) !Counts {
        const raw = try owner.rawCountsForNativeDot();
        var out = Counts{ .raw = raw, .rows = undefined, .logs = undefined, .dot_calls = owner.native_dot_calls.items.len, .dot_terms = 0 };
        for (owner.native_dot_calls.items) |call| out.dot_terms += call.terms.len;
        for (raw, 0..) |n, i| {
            out.rows[i] = try std.math.ceilPowerOfTwo(usize, @max(if (i == 4) @as(usize, 65536) else 16, std.math.cast(usize, n) orelse return error.R7CountOverflow));
            out.logs[i] = @intCast(std.math.log2_int(usize, out.rows[i]));
            const main: usize = if (i < 5) L.FACTS[i].main else if (i == 5) MR.MAIN else if (i == 6) D.MAIN else @import("input_row.zig").MAIN;
            const fixed: usize = if (i < 5) L.FACTS[i].fixed else if (i == 5) MR.FIXED else if (i == 6) D.FIXED else @import("input_row.zig").FIXED;
            const inter: usize = if (i < 5) L.FACTS[i].classic_interaction else if (i == 5) MR.INTER else if (i == 6) D.INTER else @import("input_row.zig").INTER;
            out.main_cells += out.rows[i] * main;
            out.fixed_cells += out.rows[i] * fixed;
            out.interaction_cells += out.rows[i] * inter;
        }
        out.total_native_cells = out.main_cells + out.fixed_cells + out.interaction_cells;
        return out;
    }
};
const State = struct { callbacks: usize = 0, old: ?R6.Census = null, r7: ?Counts = null, golden: ?[]const u8, golden_parity: bool = false, output_parity: bool = false, phases: CPU.CompleteCounts = .{}, old_masks: [4]usize = @splat(0), old_sample_refs: usize = 0 };
fn cpu(raw: ?*anyopaque, a: std.mem.Allocator, v: Bundle.CpuVerified) !void {
    const state: *State = @ptrCast(@alignCast(raw orelse return error.R7MissingState));
    if (v.ordinal != 0 or v.setup.materials.geometry.cpu_log != 20 or v.request.base.cpu.steps > 1 << 20) return error.R7SourceGateNeedsPinnedSmallBlock;
    var native = try Protocol.W.Wire.decodeProofBytesBinary(a, v.encoded.bytes);
    defer native.deinit(a);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const shape = try @import("../../rv64_recursion/om31_native/cpu_capture.zig").geometryForOp(arena.allocator(), v.setup, v.key.profile.config());
    const values = try V.proof.fromNative(arena.allocator(), &native, v.capture, &shape);
    const local = v.stage_one.local orelse return error.MissingReceipt;
    const view = CPU.ShapeView{ .op_span = v.span, .setup = v.setup, .request = v.request, .first = v.first_ids, .expected = v.expected, .key = v.key, .manifest = v.manifest.digest, .main = native.commitment_scheme_proof.commitments.items[1], .receipt = local.receipt, .claims = v.encoded.claims, .child = local.proof, .shape = &shape, .values = &values };
    {
        var mul = @import("../native_omul/scope.zig").begin();
        defer mul.deinit();
        var old = try view.buildForProving(a);
        defer old.deinit();
        const raw_counts = try old.rawCounts();
        try std.testing.expectEqualDeep([5]u64{ 30606, 3992911, 2258, 68060, 65536 }, raw_counts);
        try std.testing.expectEqual(@as(usize, 132725), old.native_mul_calls.items.len);
        state.old = try R6.derive(raw_counts, old.native_mul_calls.items.len);
        if (state.golden) |golden_path| {
            var key = try @import("../native_omul/authority.zig").Key.init(a, &old, v.key.profile);
            defer key.deinit();
            const identity = std.fmt.bytesToHex(key.base.identity, .lower);
            try std.testing.expectEqualStrings("08b8ba82d49d15b413a4a8aac76671dcb0f0712a0f6211bb22f1972173eb0d91", &identity);
            const outer_shape = try @import("../native_omul/capture.zig").geometry(arena.allocator(), &key);
            for (outer_shape.mask_offsets, &state.old_masks) |tree, *n| for (tree) |offsets| {
                n.* += offsets.len;
            };
            state.old_sample_refs = (try @import("../../rv64_recursion/om31_native/shape.zig").SamplePlan.init(arena.allocator(), &outer_shape)).n_samples;
            const expected = try view.expectedOutput(a);
            const proof = try @import("../native_omul/proof.zig").prove(a, &old, &key, &expected);
            defer a.free(proof);
            const golden = try std.fs.cwd().readFileAlloc(a, golden_path, 16 << 20);
            defer a.free(golden);
            try std.testing.expectEqualSlices(u8, golden, proof);
            try @import("../native_omul/proof.zig").verify(a, &key, &expected, proof);
            state.golden_parity = true;
        }
    }
    if (std.posix.getenv("STWO_OP_R7_CPU_PHYSICAL")) |path| {
        state.r7 = try @import("cpu_physical.zig").run(a, view, path, &state.phases);
        state.output_parity = true;
    } else {
        var owner = try @import("cpu_source.zig").build(a, view, false, &state.phases);
        defer owner.deinit();
        try std.testing.expect(try owner.isCircuitValid());
        const expected = try view.expectedOutput(a);
        for (owner.base.circuit.output.items[1..], expected) |id, output| try std.testing.expect(owner.base.get(.{ .idx = id }).eql(output));
        state.output_parity = true;
        state.r7 = try Counts.derive(&owner);
    }
    state.callbacks += 1;
}
test "OP R7 actual small CPU source lowering and unchanged R6 golden proof" {
    const config_path = std.posix.getenv("STWO_OP_R7_CPU_CONFIG") orelse return error.SkipZigTest;
    const native_path = std.posix.getenv("STWO_OP_R7_CPU_NATIVE") orelse return error.MissingOpNativeDirectory;
    const report_path = std.posix.getenv("STWO_OP_R7_CPU_REPORT") orelse return error.MissingR7Report;
    const a = std.testing.allocator;
    const raw = try std.fs.cwd().readFileAlloc(a, config_path, 16384);
    defer a.free(raw);
    const config = try std.json.parseFromSlice(@import("../../rv64_ethereum_request.zig").Config, a, raw, .{});
    defer config.deinit();
    if (config.value.max_steps > 10_000_000 or config.value.batch_steps != 1 << 20 or !std.mem.eql(u8, config.value.input_sha256, "610ca2169a1f3b8aa25f354a81325f2b448d1644947828bce6c5c3bfd3d42887")) return error.R7SourceGateNeedsPinnedSmallBlock;
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, 32 << 30);
    defer budget.destroy();
    var pool: Engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var state = State{ .golden = std.posix.getenv("STWO_OP_R7_CPU_GOLDEN") };
    try Runtime.verifyDirectoryWithHooks(budget.allocator(), config.value, native_path, .op_target_b4_q72_p0_fold4_v1, .{}, .{ .fragments = .{ .context = &state, .cpu = cpu } });
    try std.testing.expectEqual(@as(usize, 1), state.callbacks);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    var r7_masks = state.old_masks;
    if (state.golden_parity) for (&r7_masks, [_]usize{ 12, 29, 48, 0 }) |*n, extra| {
        n.* += extra;
    };
    const json = try std.json.Stringify.valueAlloc(a, .{ .schema = "op-r7-actual-small-cpu-source-v1", .old = state.old.?, .r7 = state.r7.?, .r6_golden_proof_exact = state.golden_parity, .native_bundle_fresh_received = true, .same_public_output = state.output_parity, .old_declared_masks = state.old_masks, .r7_declared_masks = r7_masks, .old_sample_refs = state.old_sample_refs, .r7_sample_refs = if (state.golden_parity) state.old_sample_refs + 113 else 0, .masks_derived_from_physical_role_layouts_without_r7_key_construction = true, .r7_source_only = std.posix.getenv("STWO_OP_R7_CPU_PHYSICAL") == null, .r7_physical_cpu_leaf_proved = std.posix.getenv("STWO_OP_R7_CPU_PHYSICAL") != null, .heavy_run = false, .production_admission = false, .peak_live_bytes = budget.snapshot().peak_live_bytes, .phases = state.phases }, .{ .whitespace = .indent_2 });
    defer a.free(json);
    var file = try std.fs.cwd().createFile(report_path, .{});
    defer file.close();
    try file.writeAll(json);
    std.debug.print("OP_R7_CPU_SOURCE {s}\n", .{json});
}

// Artifact inspection never proves again; the physical producer and fresh
// source receiver gate must have succeeded before this audit is meaningful.
test "OP R7 persisted CPU physical artifact opening census" {
    const path = std.posix.getenv("STWO_OP_R7_CPU_AUDIT") orelse return error.SkipZigTest;
    const a = std.testing.allocator;
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    const encoded = try dir.readFileAlloc(a, "leaf.bin", 16 << 20);
    defer a.free(encoded);
    const P = @import("outer_proof.zig");
    try std.testing.expectEqualStrings("STP27I02", encoded[0..8]);
    var proof = try P.Wire.decodeProofBytesBinary(a, encoded[P.HEADER_BYTES..]);
    defer proof.deinit(a);
    var masks: [4]usize = @splat(0);
    var columns: [4]usize = @splat(0);
    var refs: usize = 0;
    var shifted: usize = 0;
    try std.testing.expectEqual(@as(usize, 4), proof.commitment_scheme_proof.sampled_values.items.len);
    for (proof.commitment_scheme_proof.sampled_values.items, &masks, &columns) |tree, *n, *cols| {
        cols.* = tree.len;
        for (tree) |values| {
            n.* += values.len;
            if (values.len == 2) shifted += 1;
        }
        refs += n.*;
    }
    try std.testing.expectEqualDeep([4]usize{ 108, 550, 368, 16 }, masks);
    try std.testing.expectEqual(@as(usize, 1042), refs);
    try std.testing.expectEqual(@as(usize, 1114), refs + shifted);
    const json = try std.json.Stringify.valueAlloc(a, .{ .schema = "op-r7-physical-opening-census-v2", .source = "durable physical proof sampled_values after fresh source reception", .masks = masks, .columns = columns, .mask_sample_values = refs, .deep_sample_plan_terms = refs + shifted, .pcs = proof.commitment_scheme_proof.config, .root_only_accepted = false }, .{ .whitespace = .indent_2 });
    defer a.free(json);
    try @import("../../rv64_ethereum_batch_receipt.zig").writeExclusive(dir, "openings.json", json);
}
