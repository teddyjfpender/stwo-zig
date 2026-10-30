//! Saved ORIGINALS -> direct circuit windows -> one homogeneous circuit root.
//! No guest execution, original proving, NativeParent generation or reading of
//! saved node-i.proof occurs. Output node-i.proof files are NEW circuit proofs.
const std = @import("std");
const core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const Existing = @import("../../../frontends/riscv/prover/block_v8_full_block_pipeline_v1.zig");
const Full = @import("../../../frontends/riscv/prover/block_v8_full_boundary_policy_v1.zig");
const Upper = @import("../../../frontends/riscv/recursion/block_v8_window_root_receiver_v1.zig");
const OldWire = @import("../../../frontends/riscv/recursion/block_v8_window_root_wire_v1.zig");
const Capture = @import("../../../frontends/riscv/prover/block_v7_real_window_capture_v1.zig");
const Span = @import("../../../frontends/riscv/recursion/block_v8_window_root_statement_v1.zig").WindowSpan;
const Admission = @import("admission.zig");
const Saved = @import("saved_metadata.zig");
const Window = @import("window_registry.zig");
const Registry = @import("../riscv_recursion/registry_v1.zig");
const Fold = @import("../riscv_recursion/circuit_fold_v1.zig");
const Wire = @import("../riscv_recursion/fold_wire_v1.zig");
pub const production_active = false;
pub const Input = Existing.Input;
pub const Options = struct {
    registry: Registry.Options = .{},
    max_jobs: u32 = 2048,
    max_artifact_bytes: usize = 128 << 20,
    max_original_bytes_per_window: usize = 512 << 20,
    max_metadata_live_bytes: usize = 512 << 20,
    /// Required for FINAL independently loaded backend authority; producer
    /// key pointers or successful verification tokens are never serialized.
    canonical_circuit_air: []const u8,
    canonical_circuit_projection: []const u8,
};
pub const Summary = struct {
    schema: []const u8 = "stwo-riscv-direct-originals-block-v1",
    timing_scope: []const u8 = "saved_originals_to_single_circuit_root; excludes prior execution, capture and original proving",
    proof_verified: bool = false,
    prior_execution_included: bool = false,
    prior_original_proving_included: bool = false,
    native_parent_proofs_generated: u32 = 0,
    legacy_recursive_proofs_read: u32 = 0,
    legacy_parent_public_metadata_read: u32 = 0,
    cycles: u64,
    windows: u32,
    folds: u32 = 0,
    original_bundles_reused: u32 = 0,
    original_proofs_read: u64 = 0,
    original_bytes_read: u64 = 0,
    original_codec_reads_for_metadata: u64 = 0,
    original_bytes_for_metadata: u64 = 0,
    original_body_reads_for_proving: u64 = 0,
    original_bytes_for_proving: u64 = 0,
    elf_sha256: [32]u8,
    private_input_sha256: [32]u8,
    expected_output_sha256: [32]u8,
    initial_policy_id: [32]u8,
    terminal_policy_id: [32]u8,
    preflight_ns: u64 = 0,
    window_production_ns: u64 = 0,
    window_fresh_verification_ns: u64 = 0,
    fold_production_and_fresh_verification_ns: u64 = 0,
    final_fresh_verification_ns: u64 = 0,
    whole_ns: u64 = 0,
    root_index: u32 = 0,
    root_bytes: usize = 0,
    root_sha256: [64]u8 = @splat(0),
    charged_allocator_peak_bytes: usize = 0,
    /// Final receiving uses PUBLIC metadata in the NEW output plus externally
    /// pinned checkpoints/ELF. No original body/old parent metadata is needed.
    public_metadata_published_in_output: bool = true,
    external_checkpoint_pins_required_for_receiving: bool = true,
};
const Timing = struct {
    index: u32,
    role: u32,
    source_window: ?u32 = null,
    children: []const u32 = &.{},
    read_ns: u64 = 0,
    produce_ns: u64 = 0,
    fresh_verify_ns: u64 = 0,
    whole_ns: u64 = 0,
    proof_bytes: usize,
    proof_sha256: [64]u8,
    original_phases: ?Window.Times = null,
    /// Fold.produce performs fresh verification internally; do not label its
    /// total as raw proving time. Window phase fields retain their real bounds.
    produce_scope: []const u8,
};
const Metadata = struct {
    backing: std.mem.Allocator,
    budget: *Engine.host_budget_allocator.SharedHostBudget,
    arena: *std.heap.ArenaAllocator,
    root: Fold.Metadata = undefined,
    sources: []Wire.SourceMetadata = &.{},
    fn init(a: std.mem.Allocator, maximum: usize) !Metadata {
        if (maximum == 0) return error.InvalidOriginalBlockMetadataBudget;
        const budget = try Engine.host_budget_allocator.SharedHostBudget.createRetainingParent(a, maximum);
        errdefer budget.destroy();
        const storage_allocator = budget.allocator();
        const arena = try storage_allocator.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(storage_allocator);
        return .{ .backing = a, .budget = budget, .arena = arena };
    }
    fn allocator(self: *Metadata) std.mem.Allocator {
        return self.arena.allocator();
    }
    fn deinit(self: *Metadata) void {
        self.arena.deinit();
        self.budget.allocator().destroy(self.arena);
        self.budget.destroy();
        self.* = undefined;
    }
};
fn name(buffer: []u8, index: usize, extension: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "node-{d}.{s}", .{ index, extension });
}
fn sha(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}
fn writeAtomic(directory: std.fs.Dir, path: []const u8, bytes: []const u8) !void {
    var buffer: [128]u8 = undefined;
    const temporary = try std.fmt.bufPrint(&buffer, "{s}.partial", .{path});
    var file = try directory.createFile(temporary, .{ .exclusive = true });
    var open = true;
    defer if (open) file.close();
    errdefer directory.deleteFile(temporary) catch {};
    try file.writeAll(bytes);
    try file.sync();
    file.close();
    open = false;
    try directory.rename(temporary, path);
}
fn writeJson(a: std.mem.Allocator, directory: std.fs.Dir, path: []const u8, value: anytype) !void {
    const bytes = try std.json.Stringify.valueAlloc(a, value, .{ .whitespace = .indent_2 });
    defer a.free(bytes);
    try writeAtomic(directory, path, bytes);
}
fn external(job: Existing.Job, boundary: *const Full.Owned) !Upper.External {
    const r = job.request;
    return .{ .elf = r.elf, .incoming = r.incoming, .outgoing = r.outgoing, .trusted = r.trusted_window, .config = r.config, .boundary = try boundary.windowOptions(r.trusted_window.window.skip_cycles, r.trusted_window.window.cycles) };
}
fn expectedSpan(job: Existing.Job, boundary: *const Full.Owned) !Span {
    const r = job.request;
    const options = try boundary.windowOptions(r.trusted_window.window.skip_cycles, r.trusted_window.window.cycles);
    return .{ .elf_sha256 = r.elf_sha256, .config = r.config, .first_cycle = try std.math.add(u64, r.trusted_window.window.skip_cycles, 1), .cycles = r.trusted_window.window.cycles, .incoming_snapshot_id = r.trusted_window.incoming_sha256, .outgoing_snapshot_id = r.trusted_window.outgoing_sha256, .initial_cpu = r.incoming.cpu, .final_cpu = r.outgoing.cpu, .initial_policy_id = if (options.initial) |first| first.policy_id else null, .terminal_policy_id = if (options.terminal) |last| last.policy_id else null };
}
fn validateInput(input: Input, options: Options) !void {
    if (input.jobs.len == 0 or input.jobs.len > @min(options.max_jobs, 2048) or options.max_artifact_bytes == 0 or options.max_artifact_bytes > 128 << 20 or options.max_original_bytes_per_window == 0 or options.max_metadata_live_bytes == 0 or options.canonical_circuit_air.len == 0 or options.canonical_circuit_projection.len == 0) return error.InvalidOriginalBlockInput;
    if (!std.meta.eql(options.registry.fri, @as(Registry.Options, .{}).fri)) return error.UnsupportedRiscFoldSecurity;
    if (!std.meta.eql(Capture.sha(input.elf), input.trusted.elf_sha256)) return error.UntrustedOriginalBlockElf;
    var cursor: u64 = 0;
    var previous_outgoing: ?[32]u8 = null;
    for (input.jobs, 0..) |job, i| {
        const r = job.request;
        const window = r.trusted_window.window;
        if (window.cycles == 0 or window.cycles > 1 << 24 or window.skip_cycles != cursor or !std.meta.eql(r.config, input.trusted.config) or !std.meta.eql(r.elf_sha256, input.trusted.elf_sha256) or !std.meta.eql(r.trusted_window.elf_sha256, input.trusted.elf_sha256) or !std.mem.eql(u8, r.elf, input.elf)) return error.InvalidOriginalBlockCoverage;
        const incoming = if (i != 0 and r.incoming.words.ptr == input.jobs[i - 1].request.outgoing.words.ptr and r.incoming.words.len == input.jobs[i - 1].request.outgoing.words.len and std.meta.eql(r.incoming.cpu, input.jobs[i - 1].request.outgoing.cpu)) previous_outgoing.? else r.incoming.identity();
        const outgoing = r.outgoing.identity();
        if (!std.meta.eql(incoming, r.trusted_window.incoming_sha256) or !std.meta.eql(outgoing, r.trusted_window.outgoing_sha256)) return error.UntrustedOriginalBlockCheckpoint;
        if (i != 0 and (!std.meta.eql(previous_outgoing.?, incoming) or !std.meta.eql(input.jobs[i - 1].request.outgoing.cpu, r.incoming.cpu))) return error.NonAdjacentOriginalBlockWindows;
        previous_outgoing = outgoing;
        cursor = try std.math.add(u64, cursor, window.cycles);
    }
    if (cursor != input.trusted.total_cycles) return error.IncompleteOriginalBlockCoverage;
}
fn loadSource(t: std.mem.Allocator, saved: std.fs.Dir, index: usize, job: Existing.Job, boundary: *const Full.Owned, options: Options) !Wire.SourceMetadata {
    var buffer: [96]u8 = undefined;
    const raw = try saved.readFileAlloc(t, try name(&buffer, index, "public"), options.max_artifact_bytes);
    const ext = try external(job, boundary);
    if (job.kind == .native) {
        const leaf = try OldWire.decodeNativeLeafLeaky(t, raw, .{ .max_bytes = options.max_artifact_bytes });
        // Legacy leaf.main_root is ignored by OriginalAdmission, not trusted.
        return .{ .originals = .{ .native = .{ .external = ext, .input = leaf } } };
    }
    const leaf = try OldWire.decodeMixedLeafLeaky(t, raw, .{ .max_bytes = options.max_artifact_bytes });
    if (leaf.input.root.len != 0) return error.UnexpectedLegacyRecursiveProof;
    return .{ .originals = .{ .mixed = .{ .external = ext, .input = leaf.input } } };
}
fn originalCount(source: Wire.SourceMetadata) usize {
    return switch (source.originals) {
        .native => |v| v.input.local_metadata.len + 2,
        .mixed => 3,
    };
}
fn originalName(buffer: []u8, i: usize, count: usize) ![]const u8 {
    if (count < 3 or count > 64 or i >= count) return error.InvalidOriginalBlockSourceCount;
    return if (i + 2 < count) std.fmt.bufPrint(buffer, "local-{d}.proof", .{i}) else if (i + 2 == count) "bridge-0.proof" else "global-memory.proof";
}
fn inspectOriginals(saved: std.fs.Dir, index: usize, count: usize, options: Options) !u64 {
    var buffer: [96]u8 = undefined;
    var directory = try saved.openDir(try std.fmt.bufPrint(&buffer, "window-{d}", .{index}), .{});
    defer directory.close();
    var total: u64 = 0;
    for (0..count) |i| {
        const stat = try directory.statFile(try originalName(&buffer, i, count));
        if (stat.kind != .file or stat.size == 0 or stat.size > options.max_artifact_bytes) return error.InvalidOriginalBlockProofFile;
        total = try std.math.add(u64, total, stat.size);
        if (total > options.max_original_bytes_per_window) return error.OriginalBlockProofBudgetExceeded;
    }
    return total;
}
fn loadSubtree(t: std.mem.Allocator, saved: std.fs.Dir, records: []const Wire.Record, index: u32, input: Input, boundary: *const Full.Owned, options: Options, depth: usize) anyerror!Fold.Metadata {
    if (depth > 16 or index >= records.len) return error.InvalidOriginalBlockCatalog;
    const record = records[index];
    return switch (record.kind) {
        3 => blk: {
            if (record.a >= input.jobs.len or record.b != 0) return error.InvalidOriginalBlockCatalog;
            const source = try loadSource(t, saved, record.a, input.jobs[record.a], boundary, options);
            break :blk .{ .originals = source.originals };
        },
        2 => blk: {
            if (record.a >= index or record.b >= index or record.a == record.b) return error.InvalidOriginalBlockCatalog;
            const pair = try t.create([2]Fold.Metadata);
            pair.* = .{ try loadSubtree(t, saved, records, record.a, input, boundary, options, depth + 1), try loadSubtree(t, saved, records, record.b, input, boundary, options, depth + 1) };
            break :blk .{ .pair = pair };
        },
        else => error.InvalidOriginalBlockCatalog,
    };
}
fn writeArtifact(a: std.mem.Allocator, output: std.fs.Dir, index: u32, bytes: []const u8, certificate: @import("../riscv_recursion/fold_statement_v1.zig").Certificate, timing: Timing) !void {
    var buffer: [96]u8 = undefined;
    try writeAtomic(output, try name(&buffer, index, "proof"), bytes);
    try writeJson(a, output, try name(&buffer, index, "statement.json"), certificate);
    try writeJson(a, output, try name(&buffer, index, "timing.json"), timing);
}

/// One parent producer key/value witness at a time. A window necessarily
/// consumes its original bodies; a binary fold necessarily consumes two child
/// CIRCUIT bodies. Neither all campaign proofs nor wide witnesses are retained.
pub fn run(a: std.mem.Allocator, input: Input, saved: std.fs.Dir, output: std.fs.Dir, backend: *const Registry.BackendAuthority, options: Options) !Summary {
    var whole = try std.time.Timer.start();
    try validateInput(input, options);
    var iterator = output.iterate();
    if (try iterator.next() != null) return error.NonEmptyOriginalBlockOutput;
    // Claim the attempt before expensive work. Two drivers that both observed
    // an empty directory cannot later overwrite each other's proof outputs.
    // Retain the marker on failure: retries require a NEW empty attempt dir.
    {
        var lock = try output.createFile("run.lock", .{ .exclusive = true });
        defer lock.close();
        try lock.writeAll("exclusive saved-originals-to-circuit-root attempt\n");
        try lock.sync();
    }
    {
        // Validate final receiving authorities before spending any proving
        // time. Final receiving loads them independently again, after all keys.
        const canonical = try Registry.BackendAuthority.load(a, options.canonical_circuit_air, options.canonical_circuit_projection);
        defer canonical.deinit();
        if (!std.mem.eql(u8, canonical.air_bytes, backend.air_bytes) or !std.mem.eql(u8, canonical.projection_bytes, backend.projection_bytes)) return error.UntrustedOriginalBlockBackend;
    }
    const max_nodes = try std.math.sub(usize, try std.math.mul(usize, input.jobs.len, 2), 1);
    if (max_nodes > 4095) return error.InvalidOriginalBlockInput;
    const records = try a.alloc(Wire.Record, max_nodes);
    defer a.free(records);
    const frontier = try a.alloc(u32, input.jobs.len);
    defer a.free(frontier);
    var summary: Summary = undefined;
    var used: usize = input.jobs.len;
    var root_index: u32 = 0;
    {
        var boundary = try Full.Owned.derive(a, input.elf, input.private_input, input.trusted, .{});
        defer boundary.deinit();
        try boundary.requireInitial(input.jobs[0].request.incoming, 1);
        summary = .{ .cycles = input.trusted.total_cycles, .windows = @intCast(input.jobs.len), .elf_sha256 = input.trusted.elf_sha256, .private_input_sha256 = Capture.sha(input.private_input), .expected_output_sha256 = Capture.sha(&input.trusted.expected_output), .initial_policy_id = boundary.initial_policy.policy_id, .terminal_policy_id = boundary.terminal_policy.policy_id };
        var phase = try std.time.Timer.start();
        // Derive ALL canonical public metadata from ORIGINAL directory files,
        // never old node-i.public or node-i.proof. Codec extraction nominates
        // claims, not verification success. Each fresh profile dies here.
        for (input.jobs, 0..) |job, i| {
            var metadata = try Metadata.init(a, options.max_metadata_live_bytes);
            defer metadata.deinit();
            var path: [96]u8 = undefined;
            var originals = try saved.openDir(try std.fmt.bufPrint(&path, "window-{d}", .{i}), .{});
            defer originals.close();
            const kind: Saved.Kind = if (job.kind == .native) .native else .mixed;
            var canonical = try Saved.Owned.fromDirectory(metadata.allocator(), kind, originals, try external(job, &boundary));
            defer canonical.deinit();
            var admitted = try Admission.Owned.derive(a, canonical.metadata);
            defer admitted.deinit();
            if (!std.meta.eql(admitted.span, try expectedSpan(job, &boundary))) return error.UntrustedOriginalBlockWindowSpan;
            const source: Wire.SourceMetadata = .{ .originals = canonical.metadata };
            const count = originalCount(source);
            const parsed_bytes = try inspectOriginals(saved, i, count, options);
            if (canonical.public_bytes.len > options.max_artifact_bytes) return error.OriginalBlockMetadataBudgetExceeded;
            try writeAtomic(output, try name(&path, i, "public"), canonical.public_bytes);
            summary.original_codec_reads_for_metadata += count;
            summary.original_bytes_for_metadata += parsed_bytes;
            summary.original_proofs_read += count;
            summary.original_bytes_read += parsed_bytes;
            records[i] = .{ .kind = 3, .a = @intCast(i) };
            frontier[i] = @intCast(i);
        }
        summary.preflight_ns = phase.lap();
        for (input.jobs, 0..) |job, i| {
            var timer = try std.time.Timer.start();
            var metadata = try Metadata.init(a, options.max_metadata_live_bytes);
            defer metadata.deinit();
            const t = metadata.allocator();
            const source = try loadSource(t, output, i, job, &boundary, options);
            const count = originalCount(source);
            _ = try inspectOriginals(saved, i, count, options);
            var path: [96]u8 = undefined;
            var original_directory = try saved.openDir(try std.fmt.bufPrint(&path, "window-{d}", .{i}), .{});
            defer original_directory.close();
            const originals = try a.alloc([]const u8, count);
            defer a.free(originals);
            var loaded: usize = 0;
            defer for (originals[0..loaded]) |bytes| a.free(bytes);
            var original_bytes: u64 = 0;
            for (originals, 0..) |*bytes, j| {
                bytes.* = try original_directory.readFileAlloc(a, try originalName(&path, j, count), options.max_artifact_bytes);
                loaded += 1;
                original_bytes = try std.math.add(u64, original_bytes, bytes.len);
                if (original_bytes > options.max_original_bytes_per_window) return error.OriginalBlockProofBudgetExceeded;
            }
            const read_ns = timer.lap();
            var recorder = Engine.stage_profile.Recorder.initWithOptions(a, "circuit_cpu", "direct_original_window", .{ .capture_tasks = false });
            defer recorder.deinit();
            var registry_options = options.registry;
            registry_options.prover.recorder = &recorder;
            var artifact = try Window.produce(a, source.originals, originals, backend, registry_options);
            defer artifact.deinit();
            const produce_ns = timer.lap();
            try Window.verifyBytes(a, source.originals, artifact.bytes, backend, options.registry);
            const verify_ns = timer.lap();
            const timing: Timing = .{ .index = @intCast(i), .role = 3, .source_window = @intCast(i), .read_ns = read_ns, .produce_ns = produce_ns, .fresh_verify_ns = verify_ns, .whole_ns = read_ns + produce_ns + verify_ns, .proof_bytes = artifact.bytes.len, .proof_sha256 = sha(artifact.bytes), .original_phases = artifact.times, .produce_scope = "direct original circuit window; all setup/witness/proving/serialization; separate fresh verification" };
            try writeArtifact(a, output, @intCast(i), artifact.bytes, .{ .originals = artifact.statement }, timing);
            var stages = try recorder.snapshot(a);
            defer stages.deinit(a);
            try writeJson(a, output, try name(&path, i, "stages.json"), stages);
            summary.window_production_ns += produce_ns;
            summary.window_fresh_verification_ns += verify_ns;
            summary.original_bundles_reused += 1;
            summary.original_proofs_read += count;
            summary.original_bytes_read += original_bytes;
            summary.original_body_reads_for_proving += count;
            summary.original_bytes_for_proving += original_bytes;
        }
        var length = input.jobs.len;
        while (length > 1) {
            var next: usize = 0;
            var at: usize = 0;
            while (at + 1 < length) : (at += 2) {
                const index: u32 = @intCast(used);
                if (used >= records.len) return error.InvalidOriginalBlockCatalog;
                records[used] = .{ .kind = 2, .a = frontier[at], .b = frontier[at + 1] };
                var timer = try std.time.Timer.start();
                var metadata = try Metadata.init(a, options.max_metadata_live_bytes);
                defer metadata.deinit();
                metadata.root = try loadSubtree(metadata.allocator(), output, records[0 .. used + 1], index, input, &boundary, options, 0);
                var buffer: [96]u8 = undefined;
                const left = try output.readFileAlloc(a, try name(&buffer, records[used].a, "proof"), options.max_artifact_bytes);
                defer a.free(left);
                const right = try output.readFileAlloc(a, try name(&buffer, records[used].b, "proof"), options.max_artifact_bytes);
                defer a.free(right);
                const read_ns = timer.lap();
                var recorder = Engine.stage_profile.Recorder.initWithOptions(a, "circuit_cpu", "direct_original_binary_fold", .{ .capture_tasks = false });
                defer recorder.deinit();
                var registry_options = options.registry;
                registry_options.prover.recorder = &recorder;
                var artifact = try Fold.produce(a, metadata.root, .{ left, right }, backend, registry_options);
                defer artifact.deinit();
                const produce_ns = timer.lap();
                const children = [_]u32{ records[used].a, records[used].b };
                try writeArtifact(a, output, index, artifact.bytes, artifact.certificate, .{ .index = index, .role = 2, .children = &children, .read_ns = read_ns, .produce_ns = produce_ns, .whole_ns = read_ns + produce_ns, .proof_bytes = artifact.bytes.len, .proof_sha256 = sha(artifact.bytes), .produce_scope = "binary circuit fold including its internal fresh verification" });
                var stages = try recorder.snapshot(a);
                defer stages.deinit(a);
                try writeJson(a, output, try name(&buffer, index, "stages.json"), stages);
                summary.fold_production_and_fresh_verification_ns += produce_ns;
                summary.folds += 1;
                frontier[next] = index;
                next += 1;
                used += 1;
            }
            if (at < length) {
                frontier[next] = frontier[at];
                next += 1;
            } // exact odd carry, no invented sibling.
            length = next;
        }
        if (used != records.len or summary.folds + 1 != input.jobs.len) return error.InvalidOriginalBlockCatalog;
        root_index = frontier[0];
        const catalog = Wire.Catalog{ .records = records, .root = root_index, .sources = @intCast(input.jobs.len) };
        try Wire.validate(catalog, input.jobs.len);
        const public_bytes = try Wire.encode(a, catalog);
        defer a.free(public_bytes);
        try writeAtomic(output, "catalog.public", public_bytes);
        try writeJson(a, output, "catalog.json", catalog);
        var buffer: [96]u8 = undefined;
        const root = try output.readFileAlloc(a, try name(&buffer, root_index, "proof"), options.max_artifact_bytes);
        defer a.free(root);
        try writeAtomic(output, "root.proof", root);
        summary.root_index = root_index;
        summary.root_bytes = root.len;
        summary.root_sha256 = sha(root);
    } // Every producer key/material, parsed original and original Full owner is gone.
    var verification = try std.time.Timer.start();
    var receiving_boundary = try Full.Owned.derive(a, input.elf, input.private_input, input.trusted, .{});
    defer receiving_boundary.deinit();
    var metadata = try Metadata.init(a, options.max_metadata_live_bytes);
    defer metadata.deinit();
    metadata.sources = try metadata.allocator().alloc(Wire.SourceMetadata, input.jobs.len);
    for (metadata.sources, input.jobs, 0..) |*source, job, i| source.* = try loadSource(metadata.allocator(), output, i, job, &receiving_boundary, options);
    const catalog = try output.readFileAlloc(a, "catalog.public", 24 + 16 * 4095);
    defer a.free(catalog);
    const root = try output.readFileAlloc(a, "root.proof", options.max_artifact_bytes);
    defer a.free(root);
    try Wire.verifyFullSourceBytes(a, catalog, root, .{ .sources = metadata.sources, .elf = input.elf, .private_input = input.private_input, .trusted = input.trusted, .canonical_circuit_air = options.canonical_circuit_air, .canonical_circuit_projection = options.canonical_circuit_projection }, options.registry);
    summary.final_fresh_verification_ns = verification.read();
    summary.proof_verified = true;
    summary.whole_ns = whole.read();
    if (Engine.host_budget_allocator.SharedHostBudget.fromAllocator(a)) |budget| summary.charged_allocator_peak_bytes = budget.snapshot().peak_live_bytes;
    try writeJson(a, output, "report.json", summary);
    return summary;
}
