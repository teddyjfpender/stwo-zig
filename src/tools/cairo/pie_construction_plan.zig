//! Select contiguous, capacity-admitted Cairo PIE candidates for a CUDA leaf
//! proving campaign. The upstream service must bake and authenticate each
//! candidate; this tool never invents or concatenates Starknet OS executions.
const std = @import("std");
const partition = @import("pie_partition.zig");

const Manifest = struct {
    schema: []const u8,
    blocks: []const partition.Block,
    candidates: []const InputCandidate,
};

const InputCandidate = struct {
    pie: []const u8,
    first_block: u64,
    last_block: u64,
    initial_root: []const u8,
    final_root: []const u8,
    input_sha256: []const u8,
    estimated_ingress_and_cairo_ms: ?u64 = null,
};

const GeometryReport = struct {
    schema: []const u8,
    pie: []const u8,
    input_sha256: []const u8,
    registry_sha256: ?[]const u8,
    witness_sha256: []const u8,
    fixed_sha256: []const u8,
    relation_sha256: []const u8,
    proof_program_sha256: []const u8,
    variant: []const u8,
    allocated_bytes: u64,
    peak_live_bytes: u64,
};

const Selected = struct {
    pie: []const u8,
    first_block: u64,
    last_block: u64,
    input_sha256: []const u8,
    estimated_ingress_and_cairo_ms: ?u64,
    allocated_bytes: u64,
    peak_live_bytes: u64,
};

const Options = struct {
    manifest_path: ?[]const u8 = null,
    geometry_path: ?[]const u8 = null,
    registry_path: ?[]const u8 = null,
    device_bytes: ?u64 = null,
    reserve_bytes: u64 = 6_000_000_000,
    leaf_wrap_ms: ?u64 = null,
    fold_ms: ?u64 = null,
    objective: partition.Objective = .leaves,
};

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const args = try std.process.argsAlloc(allocator);
    const options = try parseOptions(args);
    const manifest_bytes = try std.fs.cwd().readFileAlloc(allocator, options.manifest_path.?, 64 << 20);
    const parsed_manifest = try std.json.parseFromSlice(Manifest, allocator, manifest_bytes, .{
        .ignore_unknown_fields = false,
    });
    const manifest = parsed_manifest.value;
    if (!std.mem.eql(u8, manifest.schema, "stwo.cairo-pie-candidates.v1"))
        return error.InvalidCandidateSchema;

    const registry_bytes = try std.fs.cwd().readFileAlloc(allocator, options.registry_path.?, 16 << 20);
    var registry_sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(registry_bytes, &registry_sha, .{});
    const registry_hex = std.fmt.bytesToHex(registry_sha, .lower);
    const geometry_bytes = try std.fs.cwd().readFileAlloc(allocator, options.geometry_path.?, 64 << 20);
    var manifest_sha: [32]u8 = undefined;
    var geometry_sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(manifest_bytes, &manifest_sha, .{});
    std.crypto.hash.sha2.Sha256.hash(geometry_bytes, &geometry_sha, .{});
    const manifest_hex = std.fmt.bytesToHex(manifest_sha, .lower);
    const geometry_hex = std.fmt.bytesToHex(geometry_sha, .lower);
    var reports: std.ArrayList(std.json.Parsed(GeometryReport)) = .empty;
    var by_pie = std.StringHashMap(usize).init(allocator);
    var lines = std.mem.splitScalar(u8, geometry_bytes, '\n');
    while (lines.next()) |line| {
        if (std.mem.trim(u8, line, " \r\t").len == 0) continue;
        const parsed = try std.json.parseFromSlice(GeometryReport, allocator, line, .{
            .ignore_unknown_fields = true,
        });
        const report = parsed.value;
        if (!std.mem.eql(u8, report.schema, "stwo.cairo-trace-geometry.v1"))
            return error.InvalidGeometrySchema;
        if (report.registry_sha256 == null or
            !std.ascii.eqlIgnoreCase(report.registry_sha256.?, &registry_hex))
            return error.GeometryRegistryMismatch;
        try validHash(report.input_sha256);
        try validHash(report.witness_sha256);
        try validHash(report.fixed_sha256);
        try validHash(report.relation_sha256);
        try validHash(report.proof_program_sha256);
        if (report.allocated_bytes == 0 or report.peak_live_bytes == 0)
            return error.InvalidGeometryReceipt;
        if (reports.items.len != 0) {
            const first = reports.items[0].value;
            if (!std.ascii.eqlIgnoreCase(report.witness_sha256, first.witness_sha256) or
                !std.ascii.eqlIgnoreCase(report.fixed_sha256, first.fixed_sha256) or
                !std.ascii.eqlIgnoreCase(report.relation_sha256, first.relation_sha256))
                return error.MixedGeometryAssets;
        }
        if (by_pie.contains(report.pie)) return error.DuplicateGeometryReceipt;
        try by_pie.put(report.pie, reports.items.len);
        try reports.append(allocator, parsed);
    }
    if (reports.items.len == 0) return error.MissingGeometryReceipt;

    const candidates = try allocator.alloc(partition.Candidate, manifest.candidates.len);
    var seen_pies = std.StringHashMap(void).init(allocator);
    for (manifest.candidates, candidates) |source, *candidate| {
        if (source.pie.len == 0 or !std.mem.eql(u8, std.fs.path.basename(source.pie), source.pie))
            return error.InvalidCandidateName;
        if (seen_pies.contains(source.pie)) return error.DuplicateCandidate;
        try seen_pies.put(source.pie, {});
        try validHash(source.input_sha256);
        const report_index = by_pie.get(source.pie) orelse return error.MissingGeometryReceipt;
        const geometry = reports.items[report_index].value;
        if (!std.ascii.eqlIgnoreCase(source.input_sha256, geometry.input_sha256))
            return error.GeometryInputMismatch;
        candidate.* = .{
            .pie = source.pie,
            .first_block = source.first_block,
            .last_block = source.last_block,
            .initial_root = source.initial_root,
            .final_root = source.final_root,
            .input_sha256 = source.input_sha256,
            .allocated_bytes = geometry.allocated_bytes,
            .estimated_ingress_and_cairo_ms = source.estimated_ingress_and_cairo_ms,
        };
    }
    const device_bytes = options.device_bytes.?;
    if (options.reserve_bytes >= device_bytes) return error.InvalidDeviceReserve;
    const limit = device_bytes - options.reserve_bytes;
    var selected = try partition.choose(allocator, manifest.blocks, candidates, .{
        .admission_limit_bytes = limit,
        .leaf_wrap_ms = options.leaf_wrap_ms orelse 0,
        .fold_ms = options.fold_ms orelse 0,
        .objective = options.objective,
    });
    defer selected.deinit(allocator);
    const chosen = try allocator.alloc(Selected, selected.indices.len);
    for (selected.indices, chosen) |index, *item| {
        const candidate = candidates[index];
        const geometry = reports.items[by_pie.get(candidate.pie).?].value;
        item.* = .{
            .pie = candidate.pie,
            .first_block = candidate.first_block,
            .last_block = candidate.last_block,
            .input_sha256 = candidate.input_sha256,
            .estimated_ingress_and_cairo_ms = candidate.estimated_ingress_and_cairo_ms,
            .allocated_bytes = candidate.allocated_bytes,
            .peak_live_bytes = geometry.peak_live_bytes,
        };
    }
    const result = .{
        .schema = "stwo.cairo-pie-construction-plan.v1",
        .objective = @tagName(options.objective),
        .proof_qualified = false,
        .registry_sha256 = &registry_hex,
        .candidate_manifest_sha256 = &manifest_hex,
        .geometry_receipts_sha256 = &geometry_hex,
        .device_bytes = device_bytes,
        .reserve_bytes = options.reserve_bytes,
        .admission_limit_bytes = limit,
        .block_count = manifest.blocks.len,
        .candidate_count = manifest.candidates.len,
        .oversized_candidate_count = selected.oversized_candidates,
        .selected_count = chosen.len,
        .modeled_total_ms = selected.estimated_total_ms,
        .max_selected_allocated_bytes = selected.max_allocated_bytes,
        .selected = chosen,
    };
    const encoded = try std.json.Stringify.valueAlloc(allocator, result, .{});
    try std.fs.File.stdout().writeAll(encoded);
    try std.fs.File.stdout().writeAll("\n");
}

fn validHash(hash: []const u8) !void {
    if (hash.len != 64) return error.InvalidSha256;
    for (hash) |character| {
        if (!std.ascii.isHex(character)) return error.InvalidSha256;
    }
}

fn parseOptions(args: []const []const u8) !Options {
    var options: Options = .{};
    var index: usize = 1;
    while (index < args.len) : (index += 2) {
        const flag = args[index];
        if (std.mem.eql(u8, flag, "--help")) {
            std.debug.print("usage: cairo-pie-construction-plan --candidates manifest.json --geometry geometry.jsonl --circuit-registry registry.json --device-bytes N [--reserve-bytes N] [--objective leaves|estimated-time] [--leaf-wrap-ms N] [--fold-ms N]\n", .{});
            std.process.exit(0);
        }
        if (index + 1 >= args.len) return error.InvalidArgument;
        const value = args[index + 1];
        if (std.mem.eql(u8, flag, "--candidates")) options.manifest_path = value else if (std.mem.eql(u8, flag, "--geometry")) options.geometry_path = value else if (std.mem.eql(u8, flag, "--circuit-registry")) options.registry_path = value else if (std.mem.eql(u8, flag, "--device-bytes")) options.device_bytes = try std.fmt.parseUnsigned(u64, value, 10) else if (std.mem.eql(u8, flag, "--reserve-bytes")) options.reserve_bytes = try std.fmt.parseUnsigned(u64, value, 10) else if (std.mem.eql(u8, flag, "--leaf-wrap-ms")) options.leaf_wrap_ms = try std.fmt.parseUnsigned(u64, value, 10) else if (std.mem.eql(u8, flag, "--fold-ms")) options.fold_ms = try std.fmt.parseUnsigned(u64, value, 10) else if (std.mem.eql(u8, flag, "--objective")) options.objective =
            if (std.mem.eql(u8, value, "leaves")) .leaves else if (std.mem.eql(u8, value, "estimated-time")) .estimated_time else return error.InvalidObjective else return error.InvalidArgument;
    }
    if (options.manifest_path == null or options.geometry_path == null or
        options.registry_path == null or options.device_bytes == null or options.device_bytes.? == 0)
        return error.MissingArgument;
    if (options.objective == .estimated_time and
        (options.leaf_wrap_ms == null or options.fold_ms == null))
        return error.MissingCostModel;
    return options;
}
