//! Receiver CLI (stream rootverify): `derive-vk-tables` and the root-only
//! `verify-root-candidate`. Dispatched from the CPU-only receiver binary
//! before the legacy modes; no CUDA module is imported.
//!
//!   [--security-profile P] derive-vk-tables CONFIG OUT TABLE_OUT FIXED_SETUP_BYTES [RECEIVER_BYTES] [--merge TABLE] [--source-commit SHA]
//!   [--security-profile P] verify-root-candidate CONFIG OUT TABLE FIXED_SETUP_BYTES [RECEIVER_BYTES] [--audit] [--table-root HEX]
//!
//! --table-root pins the table: the receiver records the root printed by its
//! own derive in a place the producer cannot write and passes it here. Without
//! the pin the table's header and root are self-declared (anyone who can write
//! the file can relabel and reseal it), and stdout says `table_root_pinned: false`.
//!
//! derive-vk-tables (one-time, reported separately): runs today's full
//! independent receiver (native verify + every recursion proof, fresh
//! authorities from source, no producer store or setup cache) and records each
//! receiver-built authority as a compact verifier key, keyed by class. With
//! --merge it extends a table this same binary derived earlier.
//!
//! verify-root-candidate: per block. Native setup + receiver admission
//! (statement, inventory, manifest, frames, RAM/KIO/Wire closure: today's
//! receiver-side checks, which M5 moves in-circuit), leaf digests from the
//! admitted metadata, fold digests from table VKs, then ONE proof verified:
//! recursion-om31/root.proof. No native proof and no child recursion proof is
//! verified or read. --audit additionally runs the full-tree receiver and
//! requires it to agree on the root digest and authority.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Om31 = @import("stwo_circuit_cpu_integration").om31;
const RV = @import("root_verify.zig");
const Derive = @import("root_derive.zig");
const Bridge = @import("om31_outer.zig");
const ExecWrap = @import("om31_native/execution_wrap.zig");
const Root = @import("om31_native/services_root.zig");
const CpuLeaf = @import("om31_native/cpu_leaf.zig");
const TruthLeaf = @import("om31_native/truth_leaf.zig");
const KeccakLeaf = @import("om31_native/keccak_leaf.zig");
const Request = @import("../rv64_ethereum_request.zig");
const Image = @import("../word16_execution/expected_image.zig");
const Program = @import("../word16_execution/program.zig").Program;
const Keys = @import("../word16_global_execution/ethereum/keys.zig").Owner;
const SetupCache = @import("../word16_global_execution/ethereum/setup_cache.zig");
const Admission = @import("../word16_global_execution/ethereum/receiver.zig");
const NativeReceiver = @import("../word16_global_execution/ethereum/gkr_receiver.zig");
const Terminal = @import("../word16_global_execution/ethereum/terminal.zig");
const ReceiverBudget = @import("../word16_global_execution/ethereum/receiver_budget.zig");
const W = @import("../word16_global_execution/services/gkr_local/bundle_wire.zig");
const Execution = @import("../word16_global_execution/services/gkr_local/execution.zig");
const MW = @import("../word16_global_execution/services/gkr_local/manifest_wire.zig");
const FixedAuthority = @import("../word16_global_execution/services/gkr_local/fixed_authority.zig");
const FixedSet = @import("../word16_global_execution/services/gkr_local/fixed_authority_set.zig").Set;
const Suite = @import("../word16_execution/pcs_suite.zig").Suite;
const NativeCache = @import("../word16_execution/fixed_native_cache.zig");
const MetadataCache = @import("../word16_execution/program_metadata.zig");
const Candidate = @import("../word16_execution/om31_security_candidate.zig");
const Recycler = @import("../rv64_large_block_recycler.zig").LargeBlockRecycler;
const O = @import("stwo_core").fields.om31.OM31;

const SETUP_CACHE_ENV = "STWO_ZIG_RV64_SETUP_CACHE";
const PcsConfig = @typeInfo(@TypeOf(Candidate.configFor)).@"fn".return_type.?;
const DERIVE = "derive-vk-tables";
const VERIFY = "verify-root-candidate";
const DEFAULT_RECEIVER_BYTES: usize = 32 << 30;

/// True when argv selects one of this module's modes.
pub fn wants(args: []const [:0]u8) bool {
    const at: usize = if (args.len >= 3 and std.mem.eql(u8, args[1], "--security-profile")) 3 else 1;
    if (args.len <= at) return false;
    return std.mem.eql(u8, args[at], DERIVE) or std.mem.eql(u8, args[at], VERIFY);
}
fn nativeLabel(profile: Candidate.Profile) []const u8 {
    return switch (profile) {
        .proven_beta2_q256_p0_fold4 => "experimental-om31-local-gkr-beta2-q256-p0-fold4-engineering",
        .conjectured128_b2_q108_p20_fold4 => "experimental-om31-local-gkr-conjectured128-b2-q108-p20-fold4-engineering",
    };
}
fn since(start: std.time.Instant) u64 {
    const now = std.time.Instant.now() catch return 0;
    return now.since(start);
}
fn hex(a: std.mem.Allocator, bytes: []const u8) ![]u8 {
    return RV.hexAlloc(a, bytes);
}
fn emit(a: std.mem.Allocator, value: anytype) !void {
    const bytes = try std.json.Stringify.valueAlloc(a, value, .{ .whitespace = .indent_1 });
    defer a.free(bytes);
    try std.fs.File.stdout().writeAll(bytes);
    try std.fs.File.stdout().writeAll("\n");
}

pub fn main() !void {
    const process_start = try std.time.Instant.now();
    // Receiver policy env (outer profile, shape, arity) is validated before
    // anything resolves it: an unknown value is a clean error exit, never the
    // panic in protocol.active() (corpus P03; M5 integrate: this entry is
    // dispatched before gkr_main.runArguments, which does the same check).
    try ExecWrap.checkPolicyEnv();
    var recycler = Recycler.init(std.heap.smp_allocator, ReceiverBudget.RECYCLER_CACHE_BYTES);
    defer recycler.deinit();
    const base = recycler.allocator();
    const all = try std.process.argsAlloc(base);
    defer std.process.argsFree(base, all);
    var profile = Candidate.DEFAULT_PROFILE;
    var args: []const [:0]u8 = all;
    if (all.len >= 3 and std.mem.eql(u8, all[1], "--security-profile")) {
        profile = try Candidate.Profile.parse(all[2]);
        args = all[2..];
    }
    const derive = std.mem.eql(u8, args[1], DERIVE);
    if (args.len < 6) return error.ExpectedModeConfigOutTableAndFixedBytes;
    // Positional: mode CONFIG OUT TABLE FIXED [RECEIVER]; then flags.
    var positional: usize = 5;
    var receiver_bytes = DEFAULT_RECEIVER_BYTES;
    if (args.len > 6 and args[6].len > 0 and args[6][0] != '-') {
        receiver_bytes = try std.fmt.parseUnsigned(usize, args[6], 10);
        positional = 6;
    }
    var audit = false;
    var merge: ?[]const u8 = null;
    var table_root_pin: ?[]const u8 = null;
    var source_commit: []const u8 = "unrecorded";
    var i: usize = positional + 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--audit") and !derive) {
            audit = true;
        } else if (std.mem.eql(u8, args[i], "--table-root") and !derive and i + 1 < args.len) {
            table_root_pin = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--merge") and derive and i + 1 < args.len) {
            merge = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--source-commit") and derive and i + 1 < args.len) {
            source_commit = args[i + 1];
            i += 1;
        } else return error.InvalidRootVerifyArgument;
    }
    // Fresh receivers never read persisted producer setup.
    if (std.process.hasEnvVarConstant(SETUP_CACHE_ENV)) return error.PersistedSetupCacheForbiddenForReceiver;
    const fixed_setup_bytes = try std.fmt.parseUnsigned(usize, args[5], 10);
    if (fixed_setup_bytes == 0) return error.MissingCandidateFixedSetupAdmission;
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(base, receiver_bytes);
    defer budget.destroy();
    const a = budget.allocator();
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Receiver identity first: a table is admitted only by the binary that derived it.
    // sha256(/proc/self/exe) runs on a helper thread (joined before the
    // table header is checked); nothing below depends on it until then.
    const ShaJob = struct {
        a: std.mem.Allocator,
        out: [64]u8 = undefined,
        err: ?anyerror = null,
        ns: u64 = 0,
        fn run(job: *@This()) void {
            const start = std.time.Instant.now() catch null;
            job.out = RV.selfSha256(job.a) catch |err| blk: {
                job.err = err;
                break :blk undefined;
            };
            if (start) |s0| job.ns = since(s0);
        }
    };
    var sha_job = ShaJob{ .a = a };
    const sha_thread = try std.Thread.spawn(.{ .stack_size = 16 << 20 }, ShaJob.run, .{&sha_job});
    var sha_joined = false;
    defer if (!sha_joined) sha_thread.join();
    const proof_real = try std.fs.cwd().realpathAlloc(arena, args[3]);
    const pcs = Candidate.configFor(profile);

    var table_load_ns: u64 = 0;
    var loaded_table: ?RV.Table = null;
    defer if (loaded_table) |*t| t.deinit();
    const table_input: ?[]const u8 = if (derive) merge else args[4];
    if (table_input) |path| {
        const start = try std.time.Instant.now();
        const real = try std.fs.cwd().realpathAlloc(arena, path);
        try RV.requireReceiverLocal(real, proof_real);
        const bytes = try std.fs.cwd().readFileAlloc(a, path, 64 << 20);
        defer a.free(bytes);
        loaded_table = try RV.Table.fromJson(a, bytes);
        if (table_root_pin) |pin| try RV.requirePinnedRoot(&loaded_table.?, pin);
        table_load_ns = since(start);
    }
    if (derive) {
        // The output must not land in (or be read back from) the producer's tree.
        const out_parent = std.fs.path.dirname(args[4]) orelse ".";
        const parent_real = try std.fs.cwd().realpathAlloc(arena, out_parent);
        try RV.requireReceiverLocal(try std.fs.path.join(arena, &.{ parent_real, std.fs.path.basename(args[4]) }), proof_real);
    }

    const raw = try std.fs.cwd().readFileAlloc(a, args[2], 16384);
    defer a.free(raw);
    const request = try std.json.parseFromSlice(Request.Config, a, raw, .{});
    defer request.deinit();
    try @import("../word16_global_execution/services/gkr_local/service_scope.zig").profile(request.value.execution_profile);
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = try Request.effectiveWorkers(request.value), .stack_size = ReceiverBudget.WORKER_STACK_BYTES, .backing_allocator = a });
    defer pool.deinit();
    var pool_binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer pool_binding.deinit();

    var timer = try std.time.Timer.start();
    // M6: the bundle (metadata + stage-one bytes; no proof body is parsed
    // here) loads on a helper thread while the image and program authority
    // are rebuilt; both are pure inputs of the admission below.
    var dir = try std.fs.cwd().openDir(args[3], .{});
    defer dir.close();
    const BundleJob = struct {
        a: std.mem.Allocator,
        dir: std.fs.Dir,
        max_steps: @FieldType(Request.Config, "max_steps"),
        result: ?W.Loaded = null,
        err: ?anyerror = null,
        ns: u64 = 0,
        fn run(job: *@This()) void {
            const start = std.time.Instant.now() catch null;
            job.result = W.read(job.a, job.dir, .{ .max_total_steps = job.max_steps }) catch |err| blk: {
                job.err = err;
                break :blk null;
            };
            if (start) |s0| job.ns = since(s0);
        }
    };
    var bundle_job = BundleJob{ .a = a, .dir = dir, .max_steps = request.value.max_steps };
    const bundle_thread = try std.Thread.spawn(.{ .stack_size = 64 << 20 }, BundleJob.run, .{&bundle_job});
    var bundle_joined = false;
    defer if (!bundle_joined) {
        bundle_thread.join();
        if (bundle_job.result) |*value| value.deinit(a);
    };
    var image = try Image.Owner.init(a, request.value);
    defer image.deinit();
    var local_native = try NativeCache.Cache.init(a, 256 << 20);
    defer local_native.deinit();
    var local_metadata = try MetadataCache.Cache.init(a, 64 << 20);
    defer local_metadata.deinit();
    const caches = @import("../word16_execution/setup.zig").ImmutableCaches{ .native = &local_native, .program = &local_metadata };
    const image_owner_ns = timer.read();
    var program = try Program.initWithAuthorityAndMetadataCache(a, &image.authority, caches.program.?);
    defer program.deinit();
    const image_ns = timer.lap();
    sha_thread.join();
    sha_joined = true;
    if (sha_job.err) |err| return err;
    const self_sha = sha_job.out;
    const self_sha_ns = sha_job.ns;
    const expected_header = RV.Header{
        .profile = RV.Profile.m4_fold_v2_compat.id(),
        .native_profile = nativeLabel(profile),
        .outer_domain = Om31.protocol.domainName(),
        .fold_version = Bridge.version,
        .source_commit = if (loaded_table) |*t| t.header.source_commit else source_commit,
        .receiver_sha256 = &self_sha,
        .image = try hex(arena, &program.identity),
    };
    if (loaded_table) |*t| try RV.requireHeader(t, expected_header);

    bundle_thread.join();
    bundle_joined = true;
    if (bundle_job.err) |err| return err;
    var loaded = bundle_job.result.?;
    defer loaded.deinit(a);
    // bundle_ns: the helper thread's load time (overlapped with image_ns);
    // bundle_wait_ns: what the main thread still waited for it.
    const bundle_wait_ns = timer.lap();
    const bundle_ns = bundle_job.ns;
    const statement = try Admission.expectedFromRequests(&image, program.identity, loaded.bundle.requests, request.value.max_steps, request.value.batch_steps, true);
    // Native VK table (M6 fold-v3). Native keys + FIXED bindings come from a
    // receiver-owned setup cache in a private directory of this process:
    // derive builds every component from source (parallel, `.prover` mode,
    // nothing restored) and records each one's VK-only artifact in the table;
    // verify-root-candidate writes the table's (root-bound, pinnable)
    // artifacts there and restores keys in `.verifier` mode, so no native
    // commitment is recomputed. A component absent from the table is built
    // from source (counted in native_table.misses), never taken from elsewhere.
    const native_dir = try privateDir(arena);
    defer std.fs.cwd().deleteTree(native_dir) catch {};
    var native_written: usize = 0;
    if (!derive) if (loaded_table) |*t| {
        for (t.native.items) |entry| {
            const name = try std.fmt.allocPrint(arena, "{s}/{s}.rv64-setup", .{ native_dir, std.fmt.bytesToHex(entry.key, .lower) });
            try std.fs.cwd().writeFile(.{ .sub_path = name, .data = entry.artifact });
            native_written += 1;
        }
    };
    var setup = try SetupCache.Cache.init(a, .{ .log_blowup = pcs.fri_config.log_blowup_factor }, .{ .mode = if (derive) .prover else .verifier, .directory = native_dir, .fixed_setup_bytes = fixed_setup_bytes, .identity_only_cpu = false, .max_build_threads = NATIVE_BUILD_THREADS, .store_bulk = false });
    defer setup.deinit();
    try setup.bindRequest(request.value);
    var keys = try Keys.initResident(a, &image, loaded.cpu_declarations, loaded.truth_declarations, true, Suite.experimentalFold4(), caches, &setup);
    defer keys.deinit();
    const native_keys_ns = timer.lap();
    var fixed_set = if (derive) try fixedSetParallel(a, &setup.fixed, keys.cpus, keys.truths, pcs) else try FixedSet.init(a, &setup.fixed, keys.cpus, keys.truths, pcs);
    defer fixed_set.deinit();
    const fixed_authority_ns = timer.lap();
    const native_stats = setup.stats;

    // Receiver-side admission (today's homes of binding note §9.2) + leaf digests.
    var manifest_digest: [32]u8 = undefined;
    var admission = AdmissionNs{};
    const leaves = try admitAndDigest(a, arena, &keys, &loaded, statement, pcs, &fixed_set, &manifest_digest, &admission);
    const admission_ns = timer.lap();
    const last = loaded.bundle.requests[loaded.bundle.requests.len - 1].base;
    const output = try Terminal.require(&image, last.cpu, last.memory.terminal);
    var recursive_dir = try dir.openDir("recursion-om31", .{});
    defer recursive_dir.close();

    if (derive) {
        var table = if (loaded_table) |t| t else try RV.Table.init(a, expected_header);
        loaded_table = null;
        defer table.deinit();
        var sink = RV.Sink{ .allocator = a };
        defer sink.deinit();
        RV.active_sink = &sink;
        defer RV.active_sink = null;
        // Full independent receiver (the checks of --audit). Every authority is
        // built from source by this process; every proof is freshly verified.
        // M6: native verification runs on its own thread while the recursion
        // tree is verified by the parallel schedule (root_derive.zig).
        const NativeJob = struct {
            a: std.mem.Allocator,
            image: *const Image.Owner,
            keys: *const Keys,
            bundle: *const @FieldType(W.Loaded, "bundle"),
            max_steps: @FieldType(Request.Config, "max_steps"),
            batch_steps: @FieldType(Request.Config, "batch_steps"),
            pcs: PcsConfig,
            fixed: *const FixedSet,
            pool: ?*engine.work_pool.WorkPool,
            err: ?anyerror = null,
            ns: u64 = 0,
            fn run(job: *@This()) void {
                var binding: ?engine.work_pool.ScopedPoolBinding = if (job.pool) |p| (engine.work_pool.ScopedPoolBinding.initIfNeeded(p) catch null) else null;
                defer if (binding) |*b| b.deinit();
                const start = std.time.Instant.now() catch null;
                _ = NativeReceiver.verifyWithAuthority(job.a, job.image, job.keys, job.bundle, job.max_steps, job.batch_steps, true, job.pcs, job.fixed) catch |err| {
                    job.err = err;
                };
                if (start) |s0| job.ns = since(s0);
            }
        };
        var native_job = NativeJob{ .a = a, .image = &image, .keys = &keys, .bundle = &loaded.bundle, .max_steps = request.value.max_steps, .batch_steps = request.value.batch_steps, .pcs = pcs, .fixed = &fixed_set, .pool = engine.work_pool.currentScopedPool() };
        const native_thread = try std.Thread.spawn(.{ .stack_size = 256 << 20 }, NativeJob.run, .{&native_job});
        const tree = Derive.verifyTree(a, keys.cpus, keys.truths, &loaded.bundle, statement, pcs, &fixed_set, recursive_dir, deriveLanes(), &sink);
        native_thread.join();
        if (native_job.err) |err| return err;
        const recursion = try tree;
        const native_verify_ns = native_job.ns;
        if (sink.failure) |err| return err;
        if (sink.leaves.items.len != leaves.len) return error.VkDeriveLeafCoverage;
        var new_leaves: usize = 0;
        var new_folds: usize = 0;
        for (sink.leaves.items) |leaf| {
            if (leaf.ordinal >= leaves.len) return error.VkDeriveLeafCoverage;
            // The circuit's own leaf digest must equal the admission-side one.
            if (!std.mem.eql(u8, &leaf.digest, &leaves[leaf.ordinal].input.digest)) return error.VkLeafDigestReimplementationDrift;
            new_leaves += @intFromBool(try table.put(.leaf, leaves[leaf.ordinal].input.key, leaf.vk, leaves[leaf.ordinal].label));
        }
        for (sink.folds.items) |fold| new_folds += @intFromBool(try table.put(.fold, fold.class, fold.vk, "fold-v2-class"));
        const new_native = try recordNative(a, &setup, native_dir, &table);
        const block_label = try std.fmt.allocPrint(arena, "{s}", .{std.fs.path.basename(args[2])});
        try table.derived_from.append(a, try table.strings.allocator().dupe(u8, block_label));
        const derive_ns = since(process_start);
        table.derive_ns += derive_ns;
        // Self-check: the table just derived verifies this root, root-only.
        const root_bytes = try recursive_dir.readFileAlloc(a, "root.proof", Om31.wire.MAX_BYTES);
        defer a.free(root_bytes);
        const inputs = try arena.alloc(RV.LeafInput, leaves.len);
        for (inputs, leaves) |*out, leaf| out.* = leaf.input;
        const report = try RV.verifyRoot(a, &table, inputs, root_bytes);
        if (!std.mem.eql(u8, &report.root_digest, &recursion.root_digest) or !std.mem.eql(u8, &report.root_identity, &recursion.root_authority)) return error.RootOnlyAuditDisagreement;
        const json = try table.toJson(a);
        defer a.free(json);
        try std.fs.cwd().writeFile(.{ .sub_path = args[4], .data = json });
        const table_root = table.root();
        return emit(a, .{
            .schema = "rv64-rootverify-derive/v0",
            .mode = DERIVE,
            .table = args[4],
            .table_profile = table.header.profile,
            .table_root = try hex(arena, &table_root),
            .entries = table.entries.items.len,
            .new_leaf_classes = new_leaves,
            .new_fold_classes = new_folds,
            .native_entries = table.native.items.len,
            .new_native_classes = new_native,
            .block_leaves = leaves.len,
            .block_folds = recursion.fold_proofs,
            .fold_reimplementation_cross_checks = sink.cross_checked_folds,
            .audit_accepted = true,
            .root_only_self_check = true,
            .root_digest = try hex(arena, &report.root_digest),
            .root_identity = try hex(arena, &report.root_identity),
            .derive_once_ns = derive_ns,
            .table_cumulative_derive_ns = table.derive_ns,
            .breakdown = .{ .self_sha_ns = self_sha_ns, .table_load_ns = table_load_ns, .image_ns = image_ns, .bundle_ns = bundle_ns, .native_keys_ns = native_keys_ns, .fixed_authority_ns = fixed_authority_ns, .admission_ns = admission_ns, .native_verify_ns = native_verify_ns, .recursion_ns = recursion.total_ns, .recursion_leaves_ns = recursion.leaves_ns, .recursion_folds_ns = recursion.folds_ns },
            .recursion_schedule = .{ .lanes = recursion.lanes, .fold_class_builds = recursion.fold_class_builds, .fold_class_restores = recursion.fold_class_restores, .native_verify_overlapped = true },
            .native_build = .{ .components = native_stats.misses + native_stats.disk_hits, .max_build_ns = native_stats.max_build_ns, .max_build_kind = native_stats.max_build_kind, .threads = NATIVE_BUILD_THREADS },
            .receiver_sha256 = &self_sha,
            .source_commit = table.header.source_commit,
            .scope = "One-time derivation: today's full independent receiver (native + every recursion proof) with each receiver-built authority recorded as a compact class-keyed verifier key. Never reads producer stores or setup caches.",
        });
    }

    const table: *const RV.Table = if (loaded_table) |*t| t else return error.MissingVkTable;
    const table_root = table.root();
    const root_start = timer.read();
    const root_bytes = try recursive_dir.readFileAlloc(a, "root.proof", Om31.wire.MAX_BYTES);
    defer a.free(root_bytes);
    const inputs = try arena.alloc(RV.LeafInput, leaves.len);
    for (inputs, leaves) |*out, leaf| out.* = leaf.input;
    const report = try RV.verifyRoot(a, table, inputs, root_bytes);
    const root_ns = timer.read() - root_start;
    const verify_ns = since(process_start);
    var audit_report: ?struct { accepted: bool, agrees: bool, native_verify_ns: u64, recursion_ns: u64, root_digest: []const u8, root_authority: []const u8 } = null;
    if (audit) {
        const audit_start = timer.read();
        _ = try NativeReceiver.verifyWithAuthority(a, &image, &keys, &loaded.bundle, request.value.max_steps, request.value.batch_steps, true, pcs, &fixed_set);
        const native_verify_ns = timer.read() - audit_start;
        const recursion = try ExecWrap.verifyExisting(a, keys.cpus, keys.truths, &loaded.bundle, statement, pcs, &fixed_set, recursive_dir);
        const agrees = std.mem.eql(u8, &report.root_digest, &recursion.root_digest) and std.mem.eql(u8, &report.root_identity, &recursion.root_authority);
        if (!agrees) return error.RootOnlyAuditDisagreement;
        audit_report = .{ .accepted = true, .agrees = agrees, .native_verify_ns = native_verify_ns, .recursion_ns = recursion.total_ns, .root_digest = try hex(arena, &recursion.root_digest), .root_authority = try hex(arena, &recursion.root_authority) };
    }
    try emit(a, .{
        .schema = "rv64-rootverify-verify/v0",
        .mode = VERIFY,
        .accepted = true,
        .completed_ethereum_block = true,
        .output = output,
        .native_profile = nativeLabel(profile),
        .outer_profile = Om31.protocol.domainName(),
        .table_profile = table.header.profile,
        .table_root = try hex(arena, &table_root),
        .table_root_pinned = table_root_pin != null,
        .security_qualified = false,
        .acceptance_scope = "root-only: one OM31 proof verified (root.proof) under a receiver-derived table VK; leaves/folds bound by recomputed digests; native proofs and child recursion proofs neither verified nor read. Receiver-side admission (statement, inventory, manifest, frames, closure) as today. The table VK is the trust root of this mode: it is authenticated only by the --table-root pin (table_root_pinned); without it the table header and root are self-declared. Profile rv64-m4-fold-v2-compat/v0 rests on the leaf-class premise (root_verify.zig leafKey); --audit is the acceptance path for this profile until M5 canonical leaves.",
        .proofs_verified = 1,
        .leaves = report.leaves,
        .folds = report.folds,
        .root_digest = try hex(arena, &report.root_digest),
        .root_identity = try hex(arena, &report.root_identity),
        // Same keys and encoding as the full-tree receiver, so statements compare across modes.
        .recursive = .{ .root_digest = report.root_digest, .root_authority = report.root_identity, .manifest = manifest_digest, .proofs_verified = 1 },
        .verify_per_block_ns = verify_ns,
        // Native keys/FIXED restored from the table's receiver-derived VK
        // section (hits) or rebuilt from source (misses: not in the table).
        .native_table = .{ .entries = table.native.items.len, .written = native_written, .hits = native_stats.disk_hits, .misses = native_stats.misses, .max_build_ns = native_stats.max_build_ns, .max_build_kind = native_stats.max_build_kind },
        .breakdown = .{ .self_sha_ns = self_sha_ns, .table_load_ns = table_load_ns, .image_ns = image_ns, .bundle_ns = bundle_ns, .native_keys_ns = native_keys_ns, .fixed_authority_ns = fixed_authority_ns, .admission_ns = admission_ns, .root_ns = root_ns, .root_tree_ns = report.tree_ns, .root_authority_ns = report.authority_ns, .root_decode_ns = report.decode_ns, .root_verify_ns = report.verify_ns, .bundle_wait_ns = bundle_wait_ns, .image_owner_ns = image_owner_ns, .admission = admission },
        .audit = audit_report,
        .receiver_sha256 = &self_sha,
    });
    // Accepted and reported: exit without tearing down process-lifetime
    // state (keys, caches, pools); only the private native dir is removed.
    std.fs.cwd().deleteTree(native_dir) catch {};
    std.process.exit(0);
}

const NATIVE_BUILD_THREADS: usize = 16;
/// Parallel derive lanes (leaf/fold authorities in flight). Each CPU leaf
/// lane holds one trace-only leaf graph; 8 lanes fit the default budget.
fn deriveLanes() usize {
    const text = std.posix.getenv("STWO_RV64_DERIVE_LANES") orelse return 8;
    const value = std.fmt.parseUnsigned(usize, text, 10) catch return 8;
    return std.math.clamp(value, 1, 32);
}
/// `FixedSet.init` with the distinct source keys' candidate FIXED keys
/// acquired concurrently (`Fixed.Cache` serializes its entry table; the
/// coefficient identity hashing runs in parallel). Same bindings, same order,
/// same dedupe (one acquire per distinct source key, retained elsewhere).
fn fixedSetParallel(a: std.mem.Allocator, cache: *const FixedAuthority.Fixed.Cache, setups: []const *const @import("../word16_global_execution/services/roster.zig").CpuSetup, truths: []const @import("../word16_global_execution/services/roster.zig").Truth, config: PcsConfig) !FixedSet {
    const Source = @import("../word16_global_execution/keccak/shared/key.zig").Key;
    const count = try std.math.add(usize, setups.len, truths.len);
    if (setups.len == 0 or count > 256) return error.WideBeta2FixedInventoryMismatch;
    const sources = try a.alloc(*const Source, count);
    defer a.free(sources);
    for (setups, 0..) |setup, i| sources[i] = &setup.key;
    for (truths, 0..) |truth, i| sources[setups.len + i] = truth.key();
    // first[i] = index of the first slot holding the same source key.
    const first = try a.alloc(usize, count);
    defer a.free(first);
    var unique: std.ArrayList(usize) = .empty;
    defer unique.deinit(a);
    for (sources, 0..) |source, i| {
        first[i] = for (sources[0..i], 0..) |earlier, j| {
            if (earlier == source) break first[j];
        } else blk: {
            try unique.append(a, i);
            break :blk i;
        };
    }
    const acquired = try a.alloc(?FixedAuthority.Binding, count);
    defer a.free(acquired);
    @memset(acquired, null);
    errdefer for (acquired) |*b| if (b.*) |*binding| binding.deinit();
    const Job = struct {
        cache: *const FixedAuthority.Fixed.Cache,
        sources: []const *const Source,
        unique: []const usize,
        acquired: []?FixedAuthority.Binding,
        config: PcsConfig,
        fn run(job: *const @This(), k: usize) anyerror!void {
            const i = job.unique[k];
            job.acquired[i] = try FixedAuthority.Binding.acquire(job.cache, job.sources[i], job.config);
        }
    };
    const job = Job{ .cache = cache, .sources = sources, .unique = unique.items, .acquired = acquired, .config = config };
    try SetupCache.Cache.parallel(unique.items.len, NATIVE_BUILD_THREADS, &job, Job.run);
    const bindings = try a.alloc(FixedAuthority.Binding, count);
    errdefer a.free(bindings);
    var cells: usize = 0;
    for (bindings, 0..) |*out, i| {
        if (first[i] == i) {
            out.* = acquired[i].?;
            acquired[i] = null;
            cells = try std.math.add(usize, cells, out.source_coefficient_cells);
        } else out.* = bindings[first[i]].retain();
    }
    return .{ .allocator = a, .config = config, .cpu_count = setups.len, .bindings = bindings, .source_validations = unique.items.len, .source_coefficient_cells = cells };
}
/// Fresh private directory (this process only) for the native setup artifacts.
fn privateDir(arena: std.mem.Allocator) ![]const u8 {
    const base = std.posix.getenv("TMPDIR") orelse "/tmp";
    var suffix: [12]u8 = undefined;
    std.crypto.random.bytes(&suffix);
    const path = try std.fmt.allocPrint(arena, "{s}/rv64-rootverify-native-{s}", .{ base, std.fmt.bytesToHex(suffix, .lower) });
    try std.fs.cwd().makeDir(path);
    return path;
}
/// derive: persist the VK-only artifact of every native component this
/// process built from source and record it in the table (byte-identical on a
/// repeated key, `VkNativeClassMismatch` otherwise). Every component of the
/// block must be present afterwards (`VkDeriveNativeCoverage`).
fn recordNative(a: std.mem.Allocator, setup: *SetupCache.Cache, dir_path: []const u8, table: *RV.Table) !usize {
    try setup.persist();
    var dir = try std.fs.cwd().openDir(dir_path, .{ .iterate = true });
    defer dir.close();
    var added: usize = 0;
    var seen: usize = 0;
    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .file) return error.VkDeriveNativeArtifact;
        const suffix = ".rv64-setup";
        if (!std.mem.endsWith(u8, entry.name, suffix) or entry.name.len != 64 + suffix.len) return error.VkDeriveNativeArtifact;
        var key: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&key, entry.name[0..64]);
        const bytes = try dir.readFileAlloc(a, entry.name, RV.MAX_NATIVE_ARTIFACT_BYTES);
        defer a.free(bytes);
        added += @intFromBool(try table.putNative(key, bytes));
        seen += 1;
    }
    if (seen != setup.resident.count()) return error.VkDeriveNativeCoverage;
    return added;
}

const LeafRow = struct { input: RV.LeafInput, label: []const u8 };
/// Today's receiver-side admission (exactly `execution_wrap.runImpl`'s frame
/// construction + `services_root.check`) and the ordered leaf (key, digest)s.
const AdmissionNs = struct { inventory_ns: u64 = 0, decode_ns: u64 = 0, seal_ns: u64 = 0, words_ns: u64 = 0, check_ns: u64 = 0, keys_ns: u64 = 0 };
fn admitAndDigest(a: std.mem.Allocator, arena: std.mem.Allocator, keys: *const Keys, loaded: *const W.Loaded, statement: anytype, pcs: anytype, fixed: *const FixedSet, manifest_out: *[32]u8, ns: *AdmissionNs) ![]LeafRow {
    const bundle = &loaded.bundle;
    const setups = keys.cpus;
    const truths = keys.truths;
    var clock = try std.time.Timer.start();
    var inventory = try Execution.Inventory.initWithAuthority(a, setups, truths, bundle.requests, statement, pcs, fixed);
    defer inventory.deinit();
    ns.inventory_ns = clock.lap();
    var stages = try MW.decode(a, inventory.execution_identity, inventory.workers, bundle.stage_one_bytes);
    defer stages.deinit();
    ns.decode_ns = clock.lap();
    var manifest = try stages.verifyAndSeal(a, inventory.execution_identity, inventory.workers);
    defer manifest.deinit(a);
    ns.seal_ns = clock.lap();
    const n = inventory.workers.len;
    if (n == 0 or n > 256 or bundle.cpus.len != setups.len or bundle.truths.len != truths.len) return error.ServicesRootRoster;
    const words = try arena.alloc([]const u32, n);
    const cpus = try arena.alloc(Root.CpuFrame, setups.len);
    for (setups, 0..) |setup, i| {
        const local = manifest.entries[i].local orelse return error.WideCpuLocalRequired;
        words[i] = try CpuLeaf.expectedWords(arena, setup, bundle.requests[i], inventory.first_ids[i], inventory.workers[i], manifest.digest, stages.stages[i].main, local.digest, bundle.cpus[i].claims);
        cpus[i] = .{ .words = words[i], .physical_claims = bundle.cpus[i].claims, .terminal_marginals = local.artifact.claims_to_verify_by_instance };
    }
    for (truths, 0..) |truth, i| {
        const ordinal = setups.len + i;
        const worker = inventory.workers[ordinal];
        const claims = bundle.truths[i].claims;
        if (truth == .keccak) {
            if (claims.len != 5) return error.InvalidWideTruthClaims;
            const public = KeccakLeaf.Public{ .ordinal = worker.ordinal, .statement = worker.statement, .manifest = manifest.digest, .claims = claims[0..5].* };
            words[ordinal] = try arena.dupe(u32, &KeccakLeaf.statementWords(truth, public, stages.stages[ordinal].main));
        } else {
            if (claims.len != 1) return error.InvalidWideTruthClaims;
            const public = TruthLeaf.Public{ .ordinal = worker.ordinal, .statement = worker.statement, .manifest = manifest.digest, .claim = claims[0] };
            words[ordinal] = try arena.dupe(u32, &TruthLeaf.statementWords(truth, public, stages.stages[ordinal].main));
        }
    }
    ns.words_ns = clock.lap();
    // services_root.check with the Inventory/stage decode built above (same
    // arguments as check builds them), CPU frames checked concurrently.
    const metadata = try Root.checkPrepared(a, setups, truths, bundle.requests, &inventory, stages.stages, .{ .cpus = cpus, .truths = words[setups.len..] }, .{}, NATIVE_BUILD_THREADS);
    manifest_out.* = metadata.manifest.digest;
    ns.check_ns = clock.lap();
    const config_json = try std.json.Stringify.valueAlloc(arena, pcs, .{});
    const rows = try arena.alloc(LeafRow, n);
    for (rows, 0..) |*row, ordinal| {
        const binding = fixed.at(ordinal);
        const is_cpu = ordinal < setups.len;
        const kind: []const u8 = if (is_cpu) "cpu" else @tagName(std.meta.activeTag(truths[ordinal - setups.len]));
        const declaration = if (is_cpu) try std.json.Stringify.valueAlloc(arena, loaded.cpu_declarations[ordinal], .{}) else try std.json.Stringify.valueAlloc(arena, loaded.truth_declarations[ordinal - setups.len], .{});
        const native_profile = if (binding.profile) |p| p.name() else "legacy-beta2";
        row.* = .{ .input = .{ .key = RV.leafKey(kind, declaration, binding.source_root, binding.fixed_identity, binding.fixed_root, native_profile, config_json), .digest = RV.leafDigest(words[ordinal]) }, .label = try std.fmt.allocPrint(arena, "{s}-{d}", .{ kind, ordinal }) };
    }
    ns.keys_ns = clock.lap();
    return rows;
}

test {
    _ = RV;
}
