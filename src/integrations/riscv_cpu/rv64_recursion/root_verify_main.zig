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
    const self_start = try std.time.Instant.now();
    const self_sha = try RV.selfSha256(a);
    const self_sha_ns = since(self_start);
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
    var image = try Image.Owner.init(a, request.value);
    defer image.deinit();
    var local_native = try NativeCache.Cache.init(a, 256 << 20);
    defer local_native.deinit();
    var local_metadata = try MetadataCache.Cache.init(a, 64 << 20);
    defer local_metadata.deinit();
    const caches = @import("../word16_execution/setup.zig").ImmutableCaches{ .native = &local_native, .program = &local_metadata };
    var program = try Program.initWithAuthorityAndMetadataCache(a, &image.authority, caches.program.?);
    defer program.deinit();
    const image_ns = timer.lap();
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

    var dir = try std.fs.cwd().openDir(args[3], .{});
    defer dir.close();
    var loaded = try W.read(a, dir, .{ .max_total_steps = request.value.max_steps });
    defer loaded.deinit(a);
    const bundle_ns = timer.lap();
    const statement = try Admission.expectedFromRequests(&image, program.identity, loaded.bundle.requests, request.value.max_steps, request.value.batch_steps, true);
    var keys = try Keys.initWithSuiteAndCaches(a, &image, loaded.cpu_declarations, loaded.truth_declarations, true, Suite.experimentalFold4(), caches);
    defer keys.deinit();
    const native_keys_ns = timer.lap();
    var fixed_cache = try FixedAuthority.Fixed.Cache.init(a, fixed_setup_bytes);
    defer fixed_cache.deinit();
    var fixed_set = try FixedSet.init(a, &fixed_cache, keys.cpus, keys.truths, pcs);
    defer fixed_set.deinit();
    const fixed_authority_ns = timer.lap();

    // Receiver-side admission (today's homes of binding note §9.2) + leaf digests.
    var manifest_digest: [32]u8 = undefined;
    const leaves = try admitAndDigest(a, arena, &keys, &loaded, statement, pcs, &fixed_set, &manifest_digest);
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
        const derive_start = timer.read();
        // Full independent receiver = today's --audit. Every authority is built
        // from source by this process; every proof is freshly verified.
        _ = try NativeReceiver.verifyWithAuthority(a, &image, &keys, &loaded.bundle, request.value.max_steps, request.value.batch_steps, true, pcs, &fixed_set);
        const native_verify_ns = timer.read() - derive_start;
        const recursion = try ExecWrap.verifyExisting(a, keys.cpus, keys.truths, &loaded.bundle, statement, pcs, &fixed_set, recursive_dir);
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
            .block_leaves = leaves.len,
            .block_folds = recursion.fold_proofs,
            .fold_reimplementation_cross_checks = sink.cross_checked_folds,
            .audit_accepted = true,
            .root_only_self_check = true,
            .root_digest = try hex(arena, &report.root_digest),
            .root_identity = try hex(arena, &report.root_identity),
            .derive_once_ns = derive_ns,
            .table_cumulative_derive_ns = table.derive_ns,
            .breakdown = .{ .self_sha_ns = self_sha_ns, .table_load_ns = table_load_ns, .image_ns = image_ns, .bundle_ns = bundle_ns, .native_keys_ns = native_keys_ns, .fixed_authority_ns = fixed_authority_ns, .admission_ns = admission_ns, .native_verify_ns = native_verify_ns, .recursion_ns = recursion.total_ns },
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
    return emit(a, .{
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
        .breakdown = .{ .self_sha_ns = self_sha_ns, .table_load_ns = table_load_ns, .image_ns = image_ns, .bundle_ns = bundle_ns, .native_keys_ns = native_keys_ns, .fixed_authority_ns = fixed_authority_ns, .admission_ns = admission_ns, .root_ns = root_ns, .root_tree_ns = report.tree_ns, .root_authority_ns = report.authority_ns, .root_decode_ns = report.decode_ns, .root_verify_ns = report.verify_ns },
        .audit = audit_report,
        .receiver_sha256 = &self_sha,
    });
}

const LeafRow = struct { input: RV.LeafInput, label: []const u8 };
/// Today's receiver-side admission (exactly `execution_wrap.runImpl`'s frame
/// construction + `services_root.check`) and the ordered leaf (key, digest)s.
fn admitAndDigest(a: std.mem.Allocator, arena: std.mem.Allocator, keys: *const Keys, loaded: *const W.Loaded, statement: anytype, pcs: anytype, fixed: *const FixedSet, manifest_out: *[32]u8) ![]LeafRow {
    const bundle = &loaded.bundle;
    const setups = keys.cpus;
    const truths = keys.truths;
    var inventory = try Execution.Inventory.initWithAuthority(a, setups, truths, bundle.requests, statement, pcs, fixed);
    defer inventory.deinit();
    var stages = try MW.decode(a, inventory.execution_identity, inventory.workers, bundle.stage_one_bytes);
    defer stages.deinit();
    var manifest = try stages.verifyAndSeal(a, inventory.execution_identity, inventory.workers);
    defer manifest.deinit(a);
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
    const metadata = try Root.check(a, setups, truths, bundle.requests, statement, pcs, fixed, bundle.stage_one_bytes, .{ .cpus = cpus, .truths = words[setups.len..] }, .{});
    manifest_out.* = metadata.manifest.digest;
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
    return rows;
}

test {
    _ = RV;
}
