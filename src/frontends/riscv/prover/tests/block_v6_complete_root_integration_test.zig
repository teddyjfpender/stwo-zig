//! Genuine mixed execution -> one complete root integration gate.
//! Receiver setup is rebuilt from original policies and public claims, without
//! consuming producer rows, proof captures or a proposed verification key.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Engine = @import("stwo_prover_engine");
const Driver = @import("../block_v5_cpu_driver_common_v1.zig").ForCapacity(false);
const Collect = @import("../block_v5_cpu_collect_v1.zig");
const Assembly = @import("../block_v5_cpu_assembly_v1.zig").ForCapacity(false);
const Store = @import("../block_v5_cpu_bundle_store_v1.zig");
const Source = @import("../block_v4_cpu_runner_source.zig");
const Guest = @import("block_v6_mixed_guest_test_support.zig");
const Sources = @import("../block_v6_recursive_sources_v1.zig");
const NativeCollection = @import("../block_v6_native_recursive_collection_v1.zig");
const Providers = @import("../block_v6_provider_recursive_collection_v1.zig");
const SourcePages = @import("../block_v5_cpu_source_pages_v1.zig");
const PageJob = @import("../block_v5_memory_source_page_job_v1.zig");
const PageAdmissions = @import("../block_v6_source_recursive_admissions_v1.zig");
const PageCollection = @import("../block_v6_source_recursive_collection_v1.zig");
const Mixed = @import("../../recursion/block_v6_mixed_direct_public_v1.zig");
const Prepare = @import("../../recursion/block_v6_mixed_direct_prepare_v1.zig");
const Claims = @import("../../recursion/block_v6_mixed_claim_codec_v1.zig");
const Reconstruct = @import("../../recursion/block_v6_mixed_claim_reconstruct_v1.zig");
const Public = @import("../block_v6_complete_public_inputs_v1.zig");
const Root = @import("../block_v6_complete_root_receiver_v1.zig");
const Parent = @import("../../recursion/blake3_execution_parent_proof.zig");
const Protocol = @import("../../recursion/block_v6_mixed_direct_protocol_v1.zig");
const Observation = struct {
    fn raw(_: *anyopaque, _: *const PageJob.RawPage.VerifiedPage, _: PageJob.ArtifactPin) !void {}
    fn fold(_: *anyopaque, _: *const PageJob.FoldPage.VerifiedPage, _: PageJob.ArtifactPin) !void {}
};
fn stage(name: []const u8, timer: *std.time.Timer, budget: *Engine.host_budget_allocator.SharedHostBudget) void {
    const usage = budget.snapshot();
    // Diagnostic only: this gate includes independent setup and hostile replay.
    std.debug.print("COMPLETE_MIXED stage={s} elapsed_ns={d} live_bytes={d} charged_peak_bytes={d}\n", .{ name, timer.read(), usage.live_bytes, usage.peak_live_bytes });
}
fn limitMiB(a: std.mem.Allocator, name: []const u8, default_mib: usize, max_mib: usize) !usize {
    const text = std.process.getEnvVarOwned(a, name) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return std.math.mul(usize, default_mib, 1 << 20),
        else => return err,
    };
    defer a.free(text);
    const mib = std.fmt.parseInt(usize, text, 10) catch return error.InvalidCompleteFixtureLimit;
    if (mib == 0 or mib > max_mib) return error.InvalidCompleteFixtureLimit;
    return std.math.mul(usize, mib, 1 << 20);
}
fn securityProfile(a: std.mem.Allocator) !@import("../../recursion/blake3_execution_parent_protocol.zig").Profile {
    const text = std.process.getEnvVarOwned(a, "STWO_BLOCK_V6_CANONICAL") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return .diagnostic_q8_pow0,
        else => return err,
    };
    defer a.free(text);
    if (std.mem.eql(u8, text, "0")) return .diagnostic_q8_pow0;
    if (std.mem.eql(u8, text, "1")) return .csp_q70_pow26;
    return error.InvalidCompleteFixtureProfile;
}
fn providersFirst(a: std.mem.Allocator) !bool {
    const text = std.process.getEnvVarOwned(a, "STWO_BLOCK_V6_PROVIDERS_FIRST") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return false,
        else => return err,
    };
    defer a.free(text);
    if (std.mem.eql(u8, text, "0")) return false;
    if (std.mem.eql(u8, text, "1")) return true;
    return error.InvalidCompleteFixtureOrder;
}
fn preparePages(a: std.mem.Allocator, dir: std.fs.Dir, job: *SourcePages.Job, job_live: *bool, admitted: *const PageAdmissions.Owner, max_bytes: usize, timer: *std.time.Timer, budget: *Engine.host_budget_allocator.SharedHostBudget) !PageCollection.Owner {
    stage("source-publication", timer, budget);
    var observation: u8 = 0;
    try job.publishAll(.{ .context = &observation, .raw = Observation.raw, .fold = Observation.fold });
    try job.requirePublished();
    stage("source-preparation", timer, budget);
    var pages = try PageCollection.collect(a, dir, admitted, .{ .max_heap_bytes = max_bytes });
    errdefer pages.deinit();
    try @import("block_v6_page_scratch_allocator_test_support.zig").check(.fold, a, &admitted.fold[0], pages.records[admitted.raw.len].claim.source_fold);
    job.deinit() catch @panic("complete PAGE publication lifetime");
    job_live.* = false;
    return pages;
}
const QualificationScope = enum { complete_root, provider_preparation, canonical_geometry };

test "complete mixed root authenticates all real families after deleting intermediate files" {
    try qualify(.complete_root);
}

test "real mixed provider preparation matches independently compiled caller and provider circuits" {
    try qualify(.provider_preparation);
}

test "canonical mixed verifier geometry census without proving" {
    try qualify(.canonical_geometry);
}

fn qualify(comptime scope: QualificationScope) !void {
    var timer = try std.time.Timer.start();
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 56 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    const selected = try securityProfile(a);
    if (scope == .canonical_geometry and selected != .csp_q70_pow26) return error.CanonicalGeometryCensusRequiresCanonicalAdmissions;
    const providers_first = if (scope == .provider_preparation) true else try providersFirst(a);
    if (scope == .provider_preparation and !try @import("../block_v6_fixed_parity_v1.zig").enabled(a))
        return error.ProviderQualificationRequiresIndependentFixedParity;
    const page_capture_bytes = try limitMiB(a, "STWO_BLOCK_V6_PAGE_CAPTURE_MIB", 512, 8192);
    const page_prepare_bytes = try limitMiB(a, "STWO_BLOCK_V6_PAGE_PREPARE_MIB", 4096, 16384);
    const page_collection_bytes = try limitMiB(a, "STWO_BLOCK_V6_PAGE_COLLECTION_MIB", 8192, 32768);
    std.debug.print("COMPLETE_MIXED profile={s} page_capture_limit={d} page_prepare_limit={d} page_collection_limit={d}\n", .{ @tagName(selected), page_capture_bytes, page_prepare_bytes, page_collection_bytes });
    const instructions = try Guest.instructions(4096);
    const elf = @import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(instructions.len, &instructions, 256, Guest.profile);
    const oracle = [_]u8{1};
    // This tiny release ELF declares an empty input region. Nonempty digest
    // mutation is covered by the shared transition-admission regression.
    const public_input = [_]u8{};
    const planned = try @import("../blake3_execution_preflight.zig").runEthereumForProfile(Guest.profile, a, &elf, &public_input, &oracle, 3 * 4096);
    const cycle_limit: u32 = @intCast(try std.math.divCeil(u64, planned.last.cycle, 2));
    const schedule = try @import("../../runner/balanced_schedule.zig").Schedule.initExactWithTerminalSuffix(planned.last.cycle, cycle_limit, planned.required_terminal_cycles);
    try std.testing.expectEqual(@as(u32, 2), schedule.segments);
    const job = try @import("../../recursion/blake3_block_execution_span_v3.zig").initJobFromEndpoints(selected.config(), planned.first, planned.last, 2, planned.first.machine.rw_memory);
    const pins = Source.Pins{ .elf_sha256 = Source.sha256(&elf), .input_sha256 = Source.sha256(&public_input), .oracle_sha256 = Source.sha256(&oracle), .initial_rw_root = planned.first.machine.rw_memory, .program_root = planned.first.program, .expected_job = job };
    var source = try Source.Source.initFromPlan(a, &elf, &public_input, &oracle, cycle_limit, selected.config(), pins, planned);
    defer source.deinit();
    var temporary = std.testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    var options = @import("../block_v5_cpu_product_options_v1.zig").options(selected, 2, 8);
    options.collection.native_commitments = .{ .max_total_file_bytes = 1 << 30 };
    options.collection.access_commitments = .{ .max_total_file_bytes = 1 << 30 };
    options.collection.globals.program_commitments = .{ .max_total_file_bytes = 1 << 30 };
    options.collection.globals.ram_commitments = .{ .storage = .{ .max_total_file_bytes = 1 << 30 } };
    options.collection.groups.commitments = .{ .max_total_file_bytes = 1 << 30 };
    options.collection.caller_commitments = .{ .max_total_file_bytes = 1 << 30 };
    options.collection.external_commitments = .{ .max_total_file_bytes = 1 << 30 };
    const policy = @import("../block_v5_cpu_driver_admission_v1.zig").InputPolicy{ .runner_pins = pins, .job_id = @splat(114), .expected_final_rw_root = planned.last.machine.rw_memory.bytes };
    var pool: Engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 8, .backing_allocator = a });
    defer pool.deinit();
    var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const collected = try Collect.collect(a, temporary.dir, &source, policy, selected.config(), options.collection);
    defer collected.deinit();
    const assembly = try Assembly.assemblePartitioned(a, collected, policy, options.max_roster_entries);
    defer assembly.deinit();
    var page_options = SourcePages.Options{};
    // One independently sized PAGE per source class for this small real job.
    page_options.job.proof.raw.first.page_row_log = 7;
    page_options.job.proof.protocol.raw = page_options.job.proof.raw;
    page_options.job.proof.protocol.page_row_log = 7;
    page_options.job.proof.fold.protocol = page_options.job.proof.protocol;
    page_options.policy.pages = page_options.job.proof;
    page_options.join.pages = page_options.job.proof;
    const page_limits = PageAdmissions.Limits{ .page = .{ .page = page_options.job.proof, .max_capture_bytes = page_capture_bytes, .max_preparation_bytes = page_prepare_bytes } };
    const source_admissions = try Sources.Owner.create(a, collected, assembly, .{});
    var source_admissions_live = true;
    defer if (source_admissions_live) source_admissions.deinit();
    stage("source-collection", &timer, budget);
    const page_job = try SourcePages.collect(a, temporary.dir, &collected.globals.sources, assembly.seal_pins, assembly.entries, assembly.sealed, source.input, selected.config(), page_options);
    var page_job_live = true;
    defer if (page_job_live) page_job.deinit() catch @panic("complete PAGE lifetime");
    const page_admissions = try PageAdmissions.Owner.createFromJob(a, page_job, &page_job.context.?, page_limits);
    var page_admissions_live = true;
    defer if (page_admissions_live) page_admissions.deinit();
    if (scope == .canonical_geometry) {
        try @import("block_v6_canonical_geometry_census.zig").run(a, source_admissions, page_admissions, page_job);
        return;
    }
    const child_count = source_admissions.executions.len + source_admissions.ranges.len + source_admissions.lanes.len + 1 + source_admissions.lookups.len + 2 * source_admissions.callers.?.entries.len + page_admissions.expected.len;
    if (child_count > Mixed.MAX_CHILDREN) return error.CompleteFixtureExceedsDirectRoster;
    std.debug.print("COMPLETE_MIXED children={d} raw={d} fold={d}\n", .{ child_count, page_admissions.raw.len, page_admissions.fold.len });
    const provider_policies = try @import("../block_v5_cpu_bundle_policy_v1.zig").ForCapacity(false).buildProvidersForPartitioned(a, assembly.global_pins, options.store);
    defer a.free(provider_policies);
    var claim_bytes: []u8 = undefined;
    var prepared = prepare: {
        // Both independent families are always proved. Changing order only
        // shortens diagnosis when the remaining failure belongs to a provider.
        var pages: ?PageCollection.Owner = null;
        defer if (pages) |*owner| owner.deinit();
        if (!providers_first) pages = try preparePages(a, temporary.dir, page_job, &page_job_live, page_admissions, page_collection_bytes, &timer, budget);
        const native = try NativeCollection.Owner.create(a, a, source_admissions, .{});
        defer native.deinit();
        var writer = try Store.Store.initWriter(a, temporary.dir, provider_policies, selected.config(), options.store);
        defer writer.deinit();
        stage("base-publication", &timer, budget);
        _ = try Driver.publishPartitionedBase(a, temporary.dir, collected, assembly, &writer, &pool, options, native.sink());
        try native.requireFinished();
        stage("provider-preparation", &timer, budget);
        const files = try writer.filePins(a);
        defer a.free(files);
        // Exact source-derived census rejects omission before reading files.
        try std.testing.expectError(error.InvalidProviderCollectionRoster, Providers.collect(a, temporary.dir, source_admissions, provider_policies[0 .. provider_policies.len - 1], files[0 .. files.len - 1], .{ .store = options.store }));
        var providers = try Providers.collect(a, temporary.dir, source_admissions, provider_policies, files, .{ .store = options.store });
        defer providers.deinit();
        if (scope == .provider_preparation) {
            // A separately named regression for real original proofs and their
            // recursive preparations. This is never a complete-root success.
            try std.testing.expectEqual(@as(usize, 2), native.pieces.len);
            try std.testing.expectEqual(@as(usize, 4), providers.provider_count);
            try std.testing.expectEqual(@as(usize, 2), providers.auxiliary_count);
            stage("provider-preparation-qualified", &timer, budget);
            std.debug.print("PROVIDER_PREPARATION verified_originals=true native=2 providers=4 callers=2 independent_fixed_parity=true complete_root=false\n", .{});
            return;
        }
        if (pages == null) pages = try preparePages(a, temporary.dir, page_job, &page_job_live, page_admissions, page_collection_bytes, &timer, budget);
        const inputs = try a.alloc(Prepare.Input, child_count);
        defer a.free(inputs);
        const expected = try a.alloc(Mixed.Expected, child_count);
        defer a.free(expected);
        const records = try a.alloc(Claims.Record, child_count);
        defer a.free(records);
        var at: usize = 0;
        for (native.pieces, native.expected, native.records, 0..) |*piece, pin, record, i| {
            inputs[at] = .{ .native = .{ .index = @intCast(i), .prepared = piece } };
            expected[at] = pin;
            records[at] = record;
            at += 1;
        }
        const provider_inputs = try providers.mixedInputs(a);
        defer a.free(provider_inputs);
        for (provider_inputs, providers.expected, providers.records) |input, pin, record| {
            inputs[at] = input;
            expected[at] = pin;
            records[at] = record;
            at += 1;
        }
        for (pages.?.pieces, page_admissions.expected, pages.?.records) |*piece, pin, record| {
            inputs[at] = .{ .auxiliary = piece };
            expected[at] = pin;
            records[at] = record;
            at += 1;
        }
        try std.testing.expectEqual(child_count, at);
        claim_bytes = try Claims.encode(a, records, expected, .{});
        errdefer a.free(claim_bytes);
        stage("join", &timer, budget);
        break :prepare try Prepare.prepareDrainingWithLimits(a, inputs, expected, .{ .max_join_bytes = 24 << 30 });
    };
    var prepared_live = true;
    defer if (prepared_live) prepared.deinit();
    defer a.free(claim_bytes);
    // Destroy all producer proof/capture owners and remove every intermediate
    // file, including original operands/checkpoints. Only metadata remains.
    var entries_to_remove: std.ArrayList([]u8) = .empty;
    defer {
        for (entries_to_remove.items) |name| a.free(name);
        entries_to_remove.deinit(a);
    }
    var iterator = temporary.dir.iterate();
    while (try iterator.next()) |entry| try entries_to_remove.append(a, try a.dupe(u8, entry.name));
    for (entries_to_remove.items) |name| try temporary.dir.deleteTree(name);
    var empty = temporary.dir.iterate();
    try std.testing.expect((try empty.next()) == null);
    const fresh_sources = try Sources.Owner.create(a, collected, assembly, .{});
    defer fresh_sources.deinit();
    source_admissions.deinit();
    source_admissions_live = false;
    const row_views = try a.alloc([]const @import("../block_v5_memory_source_page_semantic_columns_v1.zig").FoldRow, page_admissions.inventories.len);
    defer a.free(row_views);
    for (row_views, page_admissions.inventories) |*view, inventory| view.* = inventory.rows;
    const fresh_pages = try PageAdmissions.Owner.create(a, &page_admissions.context, row_views, page_limits);
    defer fresh_pages.deinit();
    page_admissions.deinit();
    page_admissions_live = false;
    const reconstruct_inputs = try a.alloc(Reconstruct.Input, child_count);
    defer a.free(reconstruct_inputs);
    var at: usize = 0;
    for (fresh_sources.executions) |*value| {
        reconstruct_inputs[at] = .{ .native = value };
        at += 1;
    }
    for (fresh_sources.ranges) |*value| {
        reconstruct_inputs[at] = .{ .range16 = value };
        at += 1;
    }
    for (fresh_sources.lanes) |*value| {
        reconstruct_inputs[at] = .{ .ram_lanes = value };
        at += 1;
    }
    reconstruct_inputs[at] = .{ .program_table = &fresh_sources.program.? };
    at += 1;
    for (fresh_sources.lookups) |*value| {
        reconstruct_inputs[at] = .{ .native_lookup = value };
        at += 1;
    }
    for (fresh_sources.callers.?.entries) |entry| {
        reconstruct_inputs[at] = .{ .caller_arithmetic = &entry.admissions.arithmetic };
        at += 1;
    }
    for (fresh_sources.callers.?.entries) |entry| {
        reconstruct_inputs[at] = .{ .caller_fused = &entry.admissions.fused };
        at += 1;
    }
    for (fresh_pages.inputs) |value| {
        reconstruct_inputs[at] = value;
        at += 1;
    }
    try std.testing.expectEqual(child_count, at);
    var decoded = try Claims.decode(a, claim_bytes, prepared.expected, .{});
    defer decoded.deinit();
    var reconstructed = try Reconstruct.reconstruct(a, decoded.records, prepared.expected, reconstruct_inputs);
    defer reconstructed.deinit();
    const public = try Public.Owner.create(a, fresh_sources, .{ .context = &fresh_pages.context, .raw = fresh_pages.raw, .fold = fresh_pages.fold }, decoded.records, reconstructed.children, .{});
    defer public.deinit();
    // Check complete algebra before expensive parent proving. This is an early
    // rejection only; the final receiver authenticates these exact operands.
    _ = try @import("../block_v6_global_public_closure_v1.zig").close(a, assembly.global_pins, &fresh_pages.context, public.input(), .{ .source = page_options.join });
    stage("independent-setup", &timer, budget);
    // Compile original constraints from independently reconstructed admissions.
    // Public claims are proposals, bound by the final proof; no successful
    // child capture or live MAIN witness is an input to this setup factory.
    const setup = derive: {
        var cold = try @import("../../recursion/block_v6_mixed_direct_fixed_v1.zig").Owned.derive(a, decoded.records, prepared.expected, reconstruct_inputs, 2, selected, .{});
        defer cold.deinit();
        try cold.validateLive(&prepared);
        const geometry = try Parent.ForBackend(Cpu).deriveKeyFromFixed(a, cold.fixed, cold.context, selected);
        const key = try Protocol.Key.fromGeometry(geometry, cold.wires, cold.expected);
        const wires = try a.dupe(Mixed.Wire, cold.wires);
        errdefer a.free(wires);
        const roster = try a.dupe(Mixed.Expected, cold.expected);
        break :derive .{ .key = key, .wires = wires, .roster = roster };
    };
    defer a.free(setup.wires);
    defer a.free(setup.roster);
    stage("parent", &timer, budget);
    const key = setup.key;
    const key_id = try key.identity();
    const admission = try Protocol.Admission.init(key, key_id, setup.wires, prepared.values(), setup.roster);
    const bytes = produce: {
        const Plan = @import("../../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Cpu, Protocol);
        const plan = try Plan.init(a, &prepared.recursive.rows, admission);
        defer plan.deinit();
        var proof = try plan.prove(a, &prepared.recursive.rows);
        defer proof.deinit();
        break :produce try Parent.codec.encode(a, &proof, &admission);
    };
    defer a.free(bytes);
    prepared.deinit();
    prepared_live = false;
    stage("receiver", &timer, budget);
    const root_policy = Root.Policy{ .key = key, .expected_key = key_id, .wires = setup.wires, .roster = setup.roster, .globals = assembly.global_pins, .source = &fresh_pages.context, .expected_public_input = source.input };
    const limits = Root.Limits{ .closure = .{ .source = page_options.join } };
    const verified = try Root.verify(a, bytes, root_policy, public.input(), limits);
    try std.testing.expectEqual(@as(u32, 2), verified.algebra.execution_count);
    try std.testing.expectEqualDeep(planned.last.machine.rw_memory.bytes, verified.algebra.final_root);
    var wrong_input = root_policy;
    wrong_input.expected_public_input = &.{ 0xa5, 0x5b };
    try std.testing.expectError(error.UntrustedV5PublicInput, Root.verify(a, bytes, wrong_input, public.input(), limits));
    var wrong_policy = root_policy;
    wrong_policy.expected_key[0] ^= 1;
    try std.testing.expectError(error.UntrustedCompleteRootKey, Root.verify(a, bytes, wrong_policy, public.input(), limits));
    var wrong_security = root_policy;
    wrong_security.key.config.pow_bits += 1;
    try std.testing.expectError(error.CompleteRootSecurityMismatch, Root.verify(a, bytes, wrong_security, public.input(), limits));
    var missing_fold = public.input();
    missing_fold.source.fold = missing_fold.source.fold[0 .. missing_fold.source.fold.len - 1];
    try std.testing.expectError(error.UntrustedMixedDirectRoster, Root.verify(a, bytes, root_policy, missing_fold, limits));
    // Same roster and valid scalar representation, but a different original
    // ROM claim. The old root must not authenticate the changed public input.
    var altered_claim = public.input();
    altered_claim.program.claim = altered_claim.program.claim.add(@import("stwo_core").fields.qm31.QM31.one());
    if (Root.verify(a, bytes, root_policy, altered_claim, limits)) |_| {
        return error.TestExpectedChangedPublicClaimRejection;
    } else |err| {
        std.debug.print("COMPLETE_MIXED changed_claim_rejected={s}\n", .{@errorName(err)});
    }
    stage("complete", &timer, budget);
    std.debug.print("COMPLETE_MIXED verified=true segments=2 children={d} proof_bytes={d} claim_bytes={d} intermediate_files=0 setup_authority=independent_original_policy fixed_setup_parity=true security={s}\n", .{ child_count, bytes.len, claim_bytes.len, @tagName(selected) });
}
