//! Allocation-free-with-respect-to-trace geometry diagnostic. Legacy bundle
//! declarations are inputs to a COST MODEL, never verification authority.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const R = @import("../roster.zig");
const P = @import("../protocol.zig");
const Wire = @import("../wire.zig");
const RP = @import("retention_plan.zig");
const Resident = @import("resident_layout.zig");
const FixedSource = @import("fixed_source_metadata.zig");
const TP = @import("truth_retention.zig");
const W = @import("worker_protocol.zig");
const KR = @import("../../keccak/shared/roster.zig");
const SR = @import("../../secp/roster.zig");
const Input = struct { cpus: []struct { declaration: Wire.CpuDeclaration, request: Wire.CompactRequest }, truths: []struct { declaration: Wire.TruthDeclaration }, memory_words: u32 };
const Totals = struct {
    coefficient_bytes: u64 = 0,
    new_interaction_bytes: u64 = 0,
    legacy_fixed_bytes: u64 = 0,
    legacy_interaction_bytes: u64 = 0,
    binding_bytes: u64 = 0,
    global_metadata_bytes: u64 = 0,
    main_merkle_node_bytes: u64 = 0,
    main_merkle_descriptor_bytes: u64 = 0,
    local_proof_reserve_bytes: u64 = 0,
    owner_header_bytes: u64 = 0,
    coefficient_only_retained_bytes: u64 = 0,
    fully_parked_retained_bytes: u64 = 0,
    coefficient_disk_bytes: u64 = 0,
    host_streaming_node_bytes: u64 = 0,
    host_streaming_disk_bytes: u64 = 0,
    max_host_streaming_mapping_bytes: u64 = 0,
    fully_parked_disk_upper_bytes: u64 = 0,
    max_gkr_peak_bytes: u64 = 0,
    max_global_output_bytes: u64 = 0,
    max_stage1_task_bytes: u64 = 0,
    max_stage2_task_bytes: u64 = 0,
    max_fully_parked_mapping_upper_bytes: u64 = 0,
    fn record(self: *@This(), p: RP.RetentionPlan) !void {
        // Descriptor count encodes the committed tree's max-log+1. Host native
        // streaming commit calls compactForQueries and prunes four bottom levels.
        const log = p.main_merkle_descriptor_bytes / @sizeOf([]W.H.Hash) - 1;
        const retained_log = if (log >= 20) log - 4 else log;
        const actual_branch_nodes = ((@as(usize, 1) << @intCast(retained_log + 1)) - 1) * @sizeOf(W.H.Hash);
        self.host_streaming_node_bytes += actual_branch_nodes;
        const host_mapping = try engine.file_backed_allocator.ReservedFile.roundedLength(128 + p.coefficient_bytes + actual_branch_nodes);
        self.host_streaming_disk_bytes += host_mapping;
        self.max_host_streaming_mapping_bytes = @max(self.max_host_streaming_mapping_bytes, host_mapping);
        inline for (.{ "coefficient_bytes", "binding_bytes", "global_metadata_bytes", "main_merkle_node_bytes", "main_merkle_descriptor_bytes", "local_proof_reserve_bytes", "owner_header_bytes" }) |name| @field(self, name) = try std.math.add(u64, @field(self, name), @field(p, name));
        self.new_interaction_bytes += p.binding_bytes + p.global_output_bytes;
        self.coefficient_only_retained_bytes += p.parked_retained_bytes;
        self.fully_parked_retained_bytes += p.parked_retained_bytes - p.main_merkle_node_bytes;
        self.coefficient_disk_bytes += try engine.file_backed_allocator.ReservedFile.roundedLength(p.coefficient_bytes);
        const mapped = try engine.file_backed_allocator.ReservedFile.roundedLength(128 + p.coefficient_bytes + p.main_merkle_node_bytes);
        self.fully_parked_disk_upper_bytes += mapped;
        self.max_fully_parked_mapping_upper_bytes = @max(self.max_fully_parked_mapping_upper_bytes, mapped);
        self.max_gkr_peak_bytes = @max(self.max_gkr_peak_bytes, p.gkr_peak_bytes);
        self.max_global_output_bytes = @max(self.max_global_output_bytes, p.global_output_bytes);
        self.max_stage1_task_bytes = @max(self.max_stage1_task_bytes, p.stage1_task_bytes);
        self.max_stage2_task_bytes = @max(self.max_stage2_task_bytes, p.stage2_task_bytes);
    }
};
pub fn main() !void {
    const a = std.heap.page_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 4) return error.ExpectedBundlePathRomLogBlowup;
    const rom_log = try std.fmt.parseInt(u32, args[2], 10);
    const blowup = try std.fmt.parseInt(u32, args[3], 10);
    if (rom_log < 5 or rom_log > 22 or blowup < 1 or blowup > 2) return error.InvalidDiagnosticGeometry;
    const bytes = try std.fs.cwd().readFileAlloc(a, args[1], 16 << 20);
    defer a.free(bytes);
    var input = try std.json.parseFromSlice(Input, a, bytes, .{ .ignore_unknown_fields = true });
    defer input.deinit();
    const data = input.value;
    // Only lengths are used by the cost authority. No cell contents or witness
    // rows are built, no setup keys or proving trees are constructed.
    const cells = try a.alloc(A.memory.closed_ram.types.Cell, data.memory_words);
    defer a.free(cells);
    const config = W.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.ForField(W.O).FriConfig.init(0, blowup, 12) };
    const plans = try a.alloc(RP.RetentionPlan, data.cpus.len + data.truths.len);
    defer a.free(plans);
    const resident = try a.alloc(Resident.Contract, plans.len);
    defer a.free(resident);
    const fixed_source = try a.alloc(FixedSource.Report, plans.len);
    var fixed_done: usize = 0;
    defer {
        for (fixed_source[0..fixed_done]) |*value| value.deinit();
        a.free(fixed_source);
    }
    var totals = Totals{};
    for (data.cpus, 0..) |entry, i| {
        fixed_source[i] = try FixedSource.cpu(a, rom_log, entry.declaration);
        fixed_done += 1;
        var setup: R.CpuSetup = undefined;
        setup.materials.geometry = entry.declaration.geometry;
        setup.materials.program.log_size = rom_log;
        setup.bridges = entry.declaration.bridges;
        const r = entry.request;
        const request = P.Request{ .calls = r.calls, .base = .{ .cpu = r.cpu, .epoch = r.epoch, .division_requests = r.division_requests, .multiplication_requests = r.multiplication_requests, .memory = .{ .epoch = r.memory_epoch, .ls_count = r.ls_count, .initial = if (i == 0) cells else &.{}, .terminal = if (i + 1 == data.cpus.len) cells else &.{} } } };
        for (0..3) |tree| {
            if (tree == 1) continue;
            const legacy = try setup.logs(a, tree);
            defer a.free(legacy);
            for (legacy) |log| {
                const amount = (@as(u64, 1) << @intCast(log)) * 4;
                if (tree == 0) totals.legacy_fixed_bytes += amount else totals.legacy_interaction_bytes += amount;
            }
        }
        plans[i] = try RP.forCpu(a, &setup, request, config, std.math.maxInt(usize), std.math.maxInt(usize));
        try totals.record(plans[i]);
        resident[i] = try Resident.forCpu(a, &setup, request, config);
    }
    for (data.truths, 0..) |entry, i| {
        fixed_source[data.cpus.len + i] = try FixedSource.truth(a, entry.declaration);
        fixed_done += 1;
        const t = entry.declaration;
        var k: KR.TruthSetup = undefined;
        var s: SR.TruthSetup = undefined;
        const truth: R.Truth = if (t.family == .keccak) blk: {
            k.log = t.logs[0];
            break :blk .{ .keccak = .{ .setup = &k, .first_id = t.first_id, .calls = t.calls } };
        } else blk: {
            s.kind = if (t.family == .add) .add else .double;
            s.logs = t.logs;
            break :blk .{ .secp = .{ .setup = &s, .first_id = t.first_id, .calls = t.calls } };
        };
        for (0..3) |tree| {
            if (tree == 1) continue;
            const legacy = try truth.logs(a, tree);
            defer a.free(legacy);
            for (legacy) |log| {
                const amount = (@as(u64, 1) << @intCast(log)) * 4;
                if (tree == 0) totals.legacy_fixed_bytes += amount else totals.legacy_interaction_bytes += amount;
            }
        }
        plans[data.cpus.len + i] = try TP.forTruth(a, truth, config, std.math.maxInt(usize));
        try totals.record(plans[data.cpus.len + i]);
        resident[data.cpus.len + i] = try Resident.forTruth(a, truth, config);
    }
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const request_copy_bytes = 2 * @as(u64, data.memory_words) * @sizeOf(A.memory.closed_ram.types.Cell) + data.cpus.len * @sizeOf(P.Request);
    const output = try std.json.Stringify.valueAlloc(a, .{ .scope = "shape-only admission model; no witness, setup or proof constructed; declarations are NOT verification authority", .bundle_sha256 = std.fmt.bytesToHex(digest, .lower), .rom_log = rom_log, .blowup = blowup, .cpu_workers = data.cpus.len, .truth_workers = data.truths.len, .totals = totals, .coordinator_request_copy_bytes = request_copy_bytes, .manifest_reserve_bytes = @import("manifest_wire.zig").MAX_BYTES, .fully_parked_frontend_total_bytes = totals.fully_parked_retained_bytes + request_copy_bytes + @import("manifest_wire.zig").MAX_BYTES, .physical_native_cells = .{ .fixed = totals.legacy_fixed_bytes / 4, .main = totals.coefficient_bytes / 4, .new_interaction = totals.new_interaction_bytes / 4, .old_interaction = totals.legacy_interaction_bytes / 4, .new_main_inter = (totals.coefficient_bytes + totals.new_interaction_bytes) / 4, .old_main_inter = (totals.coefficient_bytes + totals.legacy_interaction_bytes) / 4, .new_with_perproof_fixed = (totals.legacy_fixed_bytes + totals.coefficient_bytes + totals.new_interaction_bytes) / 4, .old_with_perproof_fixed = (totals.legacy_fixed_bytes + totals.coefficient_bytes + totals.legacy_interaction_bytes) / 4, .scope = "native M31 committed cells, excluding GKR working facts/planes andLDE; immutableFIXEDreferences counted perproof for baseline parity, not rehash work" }, .merkle_model = "main_merkle_node_bytes is unpruned bound; host_streaming_node_bytes follows current CpuBackend streaming compactForQueries bottom4 pruning at committedlog>=20; runtime parkingPlan/counter remains measurement authority", .outside_model = "immutable setup, original capture/advice inventory, source-construction and PCS transient scratch, allocator/kernel/RSS; mapping length is NOT RSS", .workers = plans, .resident_layout_contracts = resident, .fixed_source_metadata = fixed_source, .resident_scope = "explicit retained-coefficients + own-height LDE + full-nodes policy; FIXED independently shared; excludes allocator/kernel/source metadata and PCS extra scratch; not GPU admission or kernel qualification" }, .{ .whitespace = .indent_2 });
    defer a.free(output);
    try std.fs.File.stdout().writeAll(output);
    try std.fs.File.stdout().writeAll("\n");
}
