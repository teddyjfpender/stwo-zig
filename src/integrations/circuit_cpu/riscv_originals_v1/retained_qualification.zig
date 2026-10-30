//! Geometry/admission census for one actual retained Ethereum window.
//! Census mode reads no original bodies and performs no proving. The separate
//! proof opt-in consumes ORIGINALS and produces one conditional window circuit
//! proof, never a NativeParent or full-block/initial/terminal certificate.
const std = @import("std");
const E = @import("stwo_prover_engine");
const C = @import("../../../frontends/riscv/prover/block_v7_real_window_capture_v1.zig");
const Upper = @import("../../../frontends/riscv/recursion/block_v8_window_root_receiver_v1.zig");
const Wire = @import("../../../frontends/riscv/recursion/block_v8_window_root_wire_v1.zig");
const Metadata = @import("../../../frontends/riscv/prover/block_v8_endpoint_mixed_statement_wire_v1.zig");
const Join = @import("window_join.zig");
const Saved = @import("saved_metadata.zig");
const Admission = @import("admission.zig");
const WindowRegistry = @import("window_registry.zig");
const Registry = @import("../riscv_recursion/registry_v1.zig");

const source = "vectors/reports/block-v7-real-window-corpus-20261029/source/";
const assembly = "vectors/reports/riscv-cpu-architecture-20261029/full-block-assembly-v1/";
const attempt = assembly ++ "retained-139m-native4m-workers16-v1/";
fn digest(text: []const u8) ![32]u8 {
    var out: [32]u8 = undefined;
    if (text.len != 64) return error.InvalidRetainedOriginalFixturePin;
    _ = try std.fmt.hexToBytes(&out, text);
    return out;
}
fn pinned(a: std.mem.Allocator, path: []const u8, pin: []const u8, maximum: usize) ![]u8 {
    const bytes = try std.fs.cwd().readFileAlloc(a, path, maximum);
    errdefer a.free(bytes);
    if (!std.meta.eql(C.sha(bytes), try digest(pin))) return error.UntrustedRetainedOriginalFixtureBytes;
    return bytes;
}

test "RISC direct original retained window4 census or optional window proof q70" {
    const prove = std.process.hasEnvVarConstant("STWO_RISCV_ORIGINALS_RETAINED_WINDOW_PROVE_Q70");
    if (!prove and !std.process.hasEnvVarConstant("STWO_RISCV_ORIGINALS_RETAINED_CENSUS")) return error.SkipZigTest;
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, if (prove) 60 << 30 else 48 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: E.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = if (prove) 16 else 1, .backing_allocator = a });
    defer pool.deinit();
    var binding = try E.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();

    // Pin the historical schedule as provenance, not as a validity receipt.
    const plan = try pinned(a, attempt ++ "selected-plan.json", "aca2d95f1bf0d39072f6ba53c06852b2f9d2d8616a253bd13c7ac75d344322a6", 16 << 20);
    defer a.free(plan);
    const elf = try pinned(a, source ++ "guest.elf", "ef68fdca9e627a4969e64aa97119f52f2d9c9d6b6e8d5cbbeb541fb93dab0688", 32 << 20);
    defer a.free(elf);
    const incoming_bytes = try pinned(a, assembly ++ "execution/checkpoints/state-24641536.b7win", "0e04ab9d1d5a640550febe122a9720503004e2adefb5138890dbe9e5dc1e3cd0", 256 << 20);
    defer a.free(incoming_bytes);
    const outgoing_bytes = try pinned(a, assembly ++ "execution/checkpoints/state-25690112.b7win", "e6d2b38785e219e98e5b75020a5b0c5dd023c6b9b1ff062014104962851e90ea", 256 << 20);
    defer a.free(outgoing_bytes);
    const incoming_id = try digest("c5451c86f85cc67fd88ee516aa66e976dac7db97453ac17b577545ad617abeab");
    const outgoing_id = try digest("daa921b1f758dfd6adea30e2a542dd5f278926c5d78bec3528df1609a441c4d7");
    var incoming = try C.Snapshot.decode(a, incoming_bytes, incoming_id, .{});
    defer incoming.deinit(a);
    var outgoing = try C.Snapshot.decode(a, outgoing_bytes, outgoing_id, .{});
    defer outgoing.deinit(a);
    const config = @import("../../../frontends/riscv/recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    const external = Upper.External{
        .elf = elf,
        .incoming = incoming,
        .outgoing = outgoing,
        .trusted = .{ .elf_sha256 = C.sha(elf), .incoming_sha256 = incoming_id, .outgoing_sha256 = outgoing_id, .window = .{ .skip_cycles = 24641536, .cycles = 1048576 } },
        .config = config,
    };
    // Proof mode never depends on historical node-4.public. Canonical thin
    // metadata is freshly derived from the original directory instead.
    if (prove) return proveRetainedWindow(budget, external);
    const metadata_bytes = try pinned(a, attempt ++ "proof/node-4.public", "a20cd8a65b11e898caf46c7ca93f8f12fb59adf7e74b1f4be7f953c99f2116f5", 16 << 20);
    defer a.free(metadata_bytes);
    var leaf = try Wire.decodeMixedLeafOwned(a, metadata_bytes, .{});
    defer leaf.deinit();
    try std.testing.expect(leaf.value.global_g_repartition and leaf.value.input.global_g_repartition);
    try std.testing.expectEqual(@as(usize, 0), leaf.value.input.root.len);
    const decoded = try Metadata.decode(a, leaf.value.input.mixed_metadata, .{ .elf = elf, .elf_sha256 = C.sha(elf), .profile = .rv32im_zkvm_ethereum_sha_v1, .config = config, .cohort_count = 1 }, .{});
    defer decoded.deinit();
    try std.testing.expectEqual(@as(u32, 507), decoded.input.caller_statement.ethereum.counts.keccak_calls);
    try std.testing.expectEqual(@as(u32, 66), decoded.input.caller_statement.ethereum.counts.signer_calls);
    try std.testing.expectEqual(@as(u32, 0), decoded.input.caller_statement.sha.call_count);

    try printCensus(a, .{ .mixed = .{ .external = external, .input = leaf.value.input } });
    std.debug.print("RISC_RETAINED_ORIGINAL_SCOPE window=4 first_cycle=24641537 cycles=1048576 keccak=507 recovery=66 queries=70 pow_bits=26 admission_only=true execution_count=0 original_proofs_read=0 original_verifications=0 native_parent_derivations=0 circuit_witnesses=0 proofs_generated=0 full_block=false\n", .{});
}

fn printCensus(a: std.mem.Allocator, metadata: Admission.Metadata) !void {
    var authority = try Join.Authority.derive(a, metadata);
    defer authority.deinit();
    try authority.validate();
    try std.testing.expectEqual(@as(usize, 3), authority.sources.len);
    try std.testing.expectEqual(@as(u64, 24641537), authority.statement.span.first_cycle);
    try std.testing.expectEqual(@as(u64, 1048576), authority.statement.span.cycles);
    try std.testing.expect(authority.statement.span.initial_policy_id == null and authority.statement.span.terminal_policy_id == null);
    for (authority.sources, 0..) |*original, index| {
        const census = try original.quotientCensus(a);
        var columns: usize = 0;
        for (original.geometry.trees, 0..) |tree, tree_index| {
            columns += tree.columns.len;
            var samples: usize = 0;
            var min_log: u32 = 30;
            var max_log: u32 = 0;
            for (tree.columns) |column| {
                samples += column.masks.len;
                min_log = @min(min_log, column.log_size);
                max_log = @max(max_log, column.log_size);
            }
            std.debug.print("RISC_RETAINED_ORIGINAL_TREE source={d} family={s} tree={d} columns={d} samples={d} min_degree_log={d} max_degree_log={d} commitment_height={d}\n", .{ index, @tagName(std.meta.activeTag(original.source)), tree_index, tree.columns.len, samples, if (tree.columns.len == 0) 0 else min_log, max_log, original.geometry.treeHeight(tree) });
        }
        const fri = try original.geometry.friGeometry();
        std.debug.print("RISC_RETAINED_ORIGINAL_CENSUS source={d} family={s} trees={d} columns={d} samples={d} fri_start_log={d} responses={d} groups={d} current_divisions={d} grouped_divisions={d}\n", .{ index, @tagName(std.meta.activeTag(original.source)), original.geometry.trees.len, columns, original.geometry.sampleCount(), fri.startLog(), census.responses, census.groups, census.current_divisions, census.grouped_divisions });
    }
}

fn writeJson(a: std.mem.Allocator, directory: std.fs.Dir, name: []const u8, value: anytype) !void {
    const bytes = try std.json.Stringify.valueAlloc(a, value, .{ .whitespace = .indent_2 });
    defer a.free(bytes);
    try directory.writeFile(.{ .sub_path = name, .data = bytes });
}

fn proveRetainedWindow(budget: *E.host_budget_allocator.SharedHostBudget, external: Upper.External) !void {
    const a = budget.allocator();
    var whole = try std.time.Timer.start();
    const output_path = std.posix.getenv("STWO_RISCV_ORIGINALS_RETAINED_WINDOW_OUTPUT") orelse "campaign/qualification/new-direct-original-retained-window4-q70-v1";
    try std.fs.cwd().makePath(output_path);
    var output = try std.fs.cwd().openDir(output_path, .{ .iterate = true });
    defer output.close();
    var iterator = output.iterate();
    if (try iterator.next() != null) return error.NonEmptyRetainedOriginalWindowOutput;
    // Exclusive claim and retained partial evidence; retries use a new output.
    {
        var lock = try output.createFile("run.lock", .{ .exclusive = true });
        defer lock.close();
        try lock.writeAll("conditional retained window original-to-circuit proof\n");
    }
    var originals = try std.fs.cwd().openDir(attempt ++ "proof/window-4", .{});
    defer originals.close();
    var preparation = try std.time.Timer.start();
    var saved = try Saved.Owned.fromDirectory(a, .mixed, originals, external);
    defer saved.deinit();
    const metadata_ns = preparation.lap();
    {
        const decoded = try Metadata.decode(a, saved.metadata.mixed.input.mixed_metadata, .{ .elf = external.elf, .elf_sha256 = external.trusted.elf_sha256, .profile = .rv32im_zkvm_ethereum_sha_v1, .config = external.config, .cohort_count = 1 }, .{});
        defer decoded.deinit();
        try std.testing.expectEqual(@as(u32, 507), decoded.input.caller_statement.ethereum.counts.keccak_calls);
        try std.testing.expectEqual(@as(u32, 66), decoded.input.caller_statement.ethereum.counts.signer_calls);
        try std.testing.expectEqual(@as(u32, 0), decoded.input.caller_statement.sha.call_count);
    }
    try printCensus(a, saved.metadata);
    const census_ns = preparation.lap();
    try output.writeFile(.{ .sub_path = "source.public", .data = saved.public_bytes });
    const air = try std.fs.cwd().readFileAlloc(a, "vectors/circuit/official/circuit_air.air_programs_v1.bin", 1 << 20);
    defer a.free(air);
    const projection = try std.fs.cwd().readFileAlloc(a, "vectors/circuit/official/compiled_air_constraints_v1.bin", 1 << 20);
    defer a.free(projection);
    var recorder = E.stage_profile.Recorder.initWithOptions(a, "circuit_cpu", "direct_original_retained_window", .{ .capture_tasks = false });
    defer recorder.deinit();
    var options: Registry.Options = .{};
    options.prover.recorder = &recorder;
    var original_bytes: u64 = 0;
    var read_ns: u64 = 0;
    var produce_ns: u64 = 0;
    var artifact = blk: {
        var timer = try std.time.Timer.start();
        var raw: [3][]const u8 = undefined;
        var initialized: usize = 0;
        defer for (raw[0..initialized]) |bytes| a.free(bytes);
        for (&raw, [_][]const u8{ "local-0.proof", "bridge-0.proof", "global-memory.proof" }) |*bytes, name| {
            bytes.* = try originals.readFileAlloc(a, name, 128 << 20);
            initialized += 1;
            original_bytes = try std.math.add(u64, original_bytes, bytes.len);
        }
        const backend = try Registry.BackendAuthority.load(a, air, projection);
        defer backend.deinit();
        read_ns = timer.lap();
        const produced = try WindowRegistry.produce(a, saved.metadata, &raw, backend, options);
        produce_ns = timer.lap();
        break :blk produced;
    }; // All raw originals, decoded materials and producer keys are gone.
    defer artifact.deinit();
    try output.writeFile(.{ .sub_path = "root.proof", .data = artifact.bytes });
    try writeJson(a, output, "statement.json", artifact.statement);
    try writeJson(a, output, "producer-times.json", artifact.times);
    var stages = try recorder.snapshot(a);
    defer stages.deinit(a);
    try writeJson(a, output, "stages.json", stages);
    var verification = try std.time.Timer.start();
    const fresh_backend = try Registry.BackendAuthority.load(a, air, projection);
    defer fresh_backend.deinit();
    try WindowRegistry.verifyBytes(a, saved.metadata, artifact.bytes, fresh_backend, .{});
    const fresh_verify_ns = verification.read();
    var proof_sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(artifact.bytes, &proof_sha, .{});
    try writeJson(a, output, "report.json", .{
        .schema = "stwo-riscv-direct-original-retained-window-v1",
        .scope = "SourceScopeConditional; interior window only; checkpoint-dependent admission",
        .full_block = false,
        .initial_boundary = false,
        .terminal_boundary = false,
        .proof_verified = true,
        .window_index = 4,
        .skip_cycles = @as(u64, 24641536),
        .cycles = @as(u32, 1048576),
        .keccak_calls = @as(u32, 507),
        .recovery_calls = @as(u32, 66),
        .queries = @as(u32, 70),
        .pow_bits = @as(u32, 26),
        .workers = @as(u32, 16),
        .host_budget_bytes = @as(u64, 60) << 30,
        .execution_count = @as(u32, 0),
        .original_proofs_generated = @as(u32, 0),
        .native_parent_proofs_generated = @as(u32, 0),
        .legacy_recursive_proofs_read = @as(u32, 0),
        .legacy_parent_public_metadata_read = @as(u32, 0),
        .original_body_reads_for_metadata = @as(u32, 3),
        .original_body_reads_for_proving = @as(u32, 3),
        .original_bytes_per_pass = original_bytes,
        .metadata_ns = metadata_ns,
        .census_ns = census_ns,
        .read_and_backend_ns = read_ns,
        .produce_ns = produce_ns,
        .producer_times = artifact.times,
        .fresh_verify_ns = fresh_verify_ns,
        .whole_ns = whole.read(),
        .charged_allocator_peak_bytes = budget.snapshot().peak_live_bytes,
        .proof_bytes = artifact.bytes.len,
        .proof_sha256 = std.fmt.bytesToHex(proof_sha, .lower),
        .elf_sha256 = std.fmt.bytesToHex(external.trusted.elf_sha256, .lower),
        .incoming_snapshot_id = std.fmt.bytesToHex(external.trusted.incoming_sha256, .lower),
        .outgoing_snapshot_id = std.fmt.bytesToHex(external.trusted.outgoing_sha256, .lower),
        .timing_scope = "saved originals to conditional circuit window; excludes previous execution/original proving; includes census; stage parents and children are inclusive and must not be summed",
    });
    std.debug.print("RISC_RETAINED_ORIGINAL_WINDOW_PROVED proof_bytes={d} proof_sha256={s} produce_ns={d} fresh_verify_ns={d} peak_bytes={d} scope=SourceScopeConditional full_block=false output={s}\n", .{ artifact.bytes.len, std.fmt.bytesToHex(proof_sha, .lower), produce_ns, fresh_verify_ns, budget.snapshot().peak_live_bytes, output_path });
}
