//! Standalone source reconstruction: base proof files freshly derive every
//! original recursive template. Received inventory keys are proposals only.
//! One exact setup then derives/freshly receives all bounded scoped nodes.
const std = @import("std");
const Publication = @import("block_v5_cpu_recursive_publication_v1.zig");
const OriginalSources = @import("block_v5_cpu_recursive_sources_v1.zig");
const Sources = @import("block_v5_cpu_scoped_job_sources_v1.zig");
const Fold = @import("block_v5_cpu_scoped_job_fold_v1.zig");
const Job = @import("block_v5_cpu_scoped_job_v1.zig");
const Assembly = @import("block_v5_cpu_assembly_v1.zig").ForCapacity(true);
const Forest = @import("block_v5_capacity_open_forest_stage_v1.zig");
const Base = @import("block_v5_cpu_bundle_store_v1.zig").ForCapacity(true);
const Providers = @import("block_v5_recursive_provider_store_v1.zig");
const Executions = @import("block_v5_recursive_execution_leaf_store_v1.zig");
const Derive = @import("block_v5_cpu_recursive_template_derivation_v1.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub const Expected = struct { leaves_manifest: [32]u8, scoped_manifest: [32]u8 };
pub const Received = struct {
    transport: *Transport,
    sources: *Sources.Owner,
    folded: Fold.Result,
    pub const complete_block_authority = false;
    pub fn deinit(self: *Received) void {
        self.folded.deinit();
        self.sources.deinit();
        self.transport.deinit();
        self.* = undefined;
    }
};
const Transport = struct {
    budget: *Budget,
    arena: std.heap.ArenaAllocator,
    session: *Publication.Session,
    native: []Forest.LeafFile,
    fn deinit(self: *Transport) void {
        self.session.deinit();
        self.arena.deinit();
        const budget = self.budget;
        budget.allocator().destroy(self);
        budget.destroy();
    }
};
/// Original sources/Assembly/base Reader must have been independently rebuilt
/// from source policy in this process and outlive Received. Native file hashes
/// are bounded transport pins only; their received keys/claims are rederived
/// through genuine original native capture/rows below before use.
pub fn verify(a: std.mem.Allocator, dir: std.fs.Dir, assembly: *const Assembly.Assembly, independent: *OriginalSources.Owner, original: *Base.Store, native_proposals: []const Forest.LeafFile, expected: Expected, profile: @import("../recursion/blake3_execution_parent_protocol.zig").Profile, publication: Publication.Options, options: Job.Options) !Received {
    try options.validate();
    // Reject bounded transport corruption before touching independently owned
    // source admissions or consuming any original base proof. This grants no
    // authority to proposed job identities, keys or proof-file hashes.
    const raw = try readScopedManifest(a, dir, expected.scoped_manifest, options);
    defer a.free(raw);
    const transport = try reconstruct(a, dir, independent, original, native_proposals, expected.leaves_manifest, profile, publication, options.source.max_owned_bytes);
    errdefer transport.deinit();
    const sources = try Sources.create(a, assembly, transport.session, transport.native, options.source);
    errdefer sources.deinit();
    if (!std.mem.eql(u8, raw[12..44], &sources.publication.sources.roster.pins.job_id) or
        !std.mem.eql(u8, raw[44..76], &sources.coverage.pinned_digest) or
        !std.mem.eql(u8, raw[76..108], &sources.coverage.meta.seal_digest)) return error.UntrustedCpuScopedNodeManifest;
    const count = std.mem.readInt(u32, raw[8..12], .little);
    const pins = try a.alloc(Fold.Pin, count);
    defer a.free(pins);
    for (pins, 0..) |*pin, index| {
        const row = raw[204 + index * 76 ..][0..76];
        pin.* = .{ .byte_len = std.mem.readInt(u64, row[4..12], .little), .sha256 = row[12..44].* };
    }
    var folded = try Fold.ForBackend(@import("stwo_cpu_backend").CpuBackend).run(a, dir, sources, profile, options.fold, .{ .reconstruct = pins });
    errdefer folded.deinit();
    var at: usize = 12;
    inline for (.{ folded.owner.pins.job, folded.owner.pins.coverage, folded.owner.pins.source, folded.owner.pins.scoped, folded.owner.pins.routing, folded.owner.pinned_identity }) |digest| {
        if (!std.mem.eql(u8, raw[at..][0..32], &digest)) return error.UntrustedCpuScopedNodeManifest;
        at += 32;
    }
    for (folded.owner.pins.node_ids, 0..) |id, index| if (!std.mem.eql(u8, raw[204 + index * 76 + 44 ..][0..32], &id)) return error.UntrustedCpuScopedNodeManifest;
    return .{ .transport = transport, .sources = sources, .folded = folded };
}
pub fn readScopedManifest(a: std.mem.Allocator, dir: std.fs.Dir, digest: [32]u8, options: Job.Options) ![]u8 {
    var file = try dir.openFile("block-v5-cpu-scoped-nodes.pins", .{});
    defer file.close();
    const length = (try file.stat()).size;
    if (length < 204 or length > options.max_manifest_bytes) return error.CpuScopedManifestResourceLimit;
    const raw = try Files.readPinned(a, dir, "block-v5-cpu-scoped-nodes.pins", length, digest, options.max_manifest_bytes);
    errdefer a.free(raw);
    if (!std.mem.eql(u8, raw[0..8], "B5SCJOB1")) return error.UntrustedCpuScopedNodeManifest;
    const count = std.mem.readInt(u32, raw[8..12], .little);
    if (count > options.fold.setup.cohorts.max_nodes or raw.len != try std.math.add(usize, 204, try std.math.mul(usize, count, 76))) return error.CpuScopedManifestResourceLimit;
    var total: u64 = 0;
    for (0..count) |index| {
        const row = raw[204 + index * 76 ..][0..76];
        if (std.mem.readInt(u32, row[0..4], .little) != index) return error.UntrustedCpuScopedNodeManifest;
        const byte_len = std.mem.readInt(u64, row[4..12], .little);
        if (byte_len == 0 or byte_len > options.fold.max_parent_bytes) return error.CpuScopedFoldResourceLimit;
        total = try std.math.add(u64, total, byte_len);
        if (total > options.fold.max_total_parent_bytes) return error.CpuScopedFoldResourceLimit;
    }
    return raw;
}
const LeafRecord = struct { file: @import("block_v5_recursive_leaf_store_core_v1.zig").FilePin, key: [32]u8 };
fn record(raw: []const u8, ordinal: usize, family: u32, index: u32) !LeafRecord {
    const at = try std.math.add(usize, 76, try std.math.mul(usize, ordinal, 80));
    if (at > raw.len or raw.len - at < 80) return error.IncompleteCpuRecursiveOpenManifest;
    const row = raw[at..][0..80];
    if (std.mem.readInt(u32, row[0..4], .little) != family or std.mem.readInt(u32, row[4..8], .little) != index) return error.UntrustedCpuRecursiveOpenManifest;
    return .{ .file = .{ .index = index, .byte_len = std.mem.readInt(u64, row[8..16], .little), .sha256 = row[16..48].* }, .key = row[48..80].* };
}
fn reconstruct(a: std.mem.Allocator, dir: std.fs.Dir, source: *OriginalSources.Owner, original: *Base.Store, native: []const Forest.LeafFile, manifest: [32]u8, profile: @import("../recursion/blake3_execution_parent_protocol.zig").Profile, options: Publication.Options, maximum: usize) !*Transport {
    try options.validate();
    try source.require();
    if (maximum == 0 or native.len != source.selection.?.natives.len or !std.meta.eql(profile.config(), source.roster.pins.config)) return error.UntrustedCpuScopedReceiveSources;
    const budget = try Budget.create(a, maximum);
    errdefer budget.destroy();
    const self = try budget.allocator().create(Transport);
    errdefer budget.allocator().destroy(self);
    self.budget = budget;
    self.arena = std.heap.ArenaAllocator.init(budget.allocator());
    errdefer self.arena.deinit();
    const meta = self.arena.allocator();
    const scratch = budget.allocator();
    self.session = try meta.create(Publication.Session);
    self.session.* = .{ .a = meta, .sources = source, .base = original, .profile = profile, .options = options };
    errdefer self.session.deinit();
    self.native = try meta.alloc(Forest.LeafFile, native.len);
    for (native, self.native, 0..) |proposed, *admitted, index| {
        const prepared = source.selection.?.natives[index];
        if (proposed.policy.native != prepared) return error.UntrustedCpuScopedNativeSource;
        var proof = try original.take(.native, @intCast(index));
        defer proof.deinit(original.a);
        const Stage = @import("block_v5_native_capacity_recursive_stage_v1.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend);
        var capture = try Stage.captureNative(scratch, &proof, prepared, .{ .profile = profile, .transcript_capacity = options.transcript_capacity });
        defer capture.deinit();
        var rows = try @import("../recursion/block_v5_capacity_recursive_public_bus_v1.zig").prepare(scratch, prepared, &capture, options.transcript_capacity);
        defer rows.deinit();
        const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
        const geometry = try Parent.ForBackend(@import("stwo_cpu_backend").CpuBackend).deriveKeyWithProfile(scratch, &rows.recursive, profile);
        const key = try @import("../recursion/block_v5_reusable_capacity_parent_protocol_v1.zig").Key.fromGeometry(geometry, rows.wires);
        if (!std.meta.eql(key, proposed.policy.recursive_key) or !std.meta.eql(try key.identity(), proposed.policy.recursive_key_id) or !std.meta.eql(capture.receipt, proposed.policy.exported)) return error.UntrustedCpuScopedExpectedNativeKey;
        const schedule = try meta.dupe(@import("../recursion/block_v5_capacity_recursive_public_bus_v1.zig").Wire, rows.wires);
        if (!same(schedule, proposed.policy.recursive_schedule)) return error.UntrustedCpuScopedExpectedNativeKey;
        admitted.* = .{ .policy = .{ .native = prepared, .exported = capture.receipt, .recursive_key = key, .recursive_key_id = try key.identity(), .recursive_schedule = schedule }, .file = proposed.file };
    }
    const count = source.ranges.len + source.lanes.len + 1 + source.lookups.len + 2 * source.callers.?.entries.len + source.fused.len;
    const length = try std.math.add(usize, 76, try std.math.mul(usize, count, 80));
    const raw = try Files.readPinned(scratch, dir, "block-v5-recursive-open-leaves.pins", length, manifest, options.max_manifest_bytes);
    defer scratch.free(raw);
    if (!std.mem.eql(u8, raw[0..8], "B5RLOP01") or std.mem.readInt(u32, raw[8..12], .little) != count or !std.mem.eql(u8, raw[12..44], &source.roster.pins.job_id) or !std.mem.eql(u8, raw[44..76], &source.roster.sealed.digest)) return error.UntrustedCpuRecursiveOpenManifest;
    var cursor: usize = 0;
    inline for ([_]Providers.Family{ .range16, .ram_lanes, .program_table, .native_lookup }, 1..) |family, tag| {
        const D = @import("block_v5_recursive_provider_definition_v1.zig").ForFamily(family);
        const field = switch (family) {
            .range16 => "ranges",
            .ram_lanes => "lanes",
            .program_table => "program",
            .native_lookup => "lookups",
        };
        const base_family: Base.Family = switch (family) {
            .range16 => .range16,
            .ram_lanes => .ram_lanes,
            .program_table => .rom,
            .native_lookup => .native_provider,
        };
        const M = Providers.ForFamily(family);
        const prepared: []const D.Prepared = if (family == .program_table) (&source.program.?)[0..1] else @field(source, field);
        const policies = try meta.alloc(M.Policy, prepared.len);
        const pins = try meta.alloc(Providers.FilePin, prepared.len);
        for (prepared, policies, pins) |*admitted, *policy, *pin| {
            const received = try record(raw, cursor, tag, D.index(admitted));
            var proof = try original.take(base_family, D.index(admitted));
            defer proof.deinit(original.a);
            var template = try Derive.provider(family, scratch, &proof, admitted, profile, options.transcript_capacity);
            defer template.deinit();
            if (!std.meta.eql(template.template.key_id, received.key)) return error.UntrustedCpuScopedExpectedProviderKey;
            const owned = try meta.create(M.TemplatePolicy);
            owned.* = template.template;
            owned.schedule = try meta.dupe(D.Bus.Wire, template.template.schedule);
            policy.* = .{ .prepared = admitted, .template = owned };
            pin.* = received.file;
            cursor += 1;
        }
        @field(self.session, field) = .{ .store = try M.Store.initReader(meta, dir, source.roster, policies, pins, options.providers), .binding = undefined };
    }
    const callers = source.callers.?.entries;
    const Arithmetic = Executions.ForFamily(.caller_arithmetic);
    const CallerFused = Executions.ForFamily(.caller_fused);
    const arithmetic_policies = try meta.alloc(Arithmetic.Policy, callers.len);
    const fused_policies = try meta.alloc(CallerFused.Policy, callers.len);
    const arithmetic_pins = try meta.alloc(Executions.FilePin, callers.len);
    const fused_pins = try meta.alloc(Executions.FilePin, callers.len);
    // Both original caller proofs live together, exactly one base Store.take
    // per family/index; the Store deliberately rejects repeated consumption.
    for (callers, 0..) |entry, i| {
        var proof = try original.take(.caller, entry.index);
        defer proof.deinit(original.a);
        var fused = try original.take(.caller_fused, entry.index);
        defer fused.deinit(original.a);
        const ar = try record(raw, cursor + i, 5, entry.index);
        const fr = try record(raw, cursor + callers.len + i, 6, entry.index);
        var at = try Derive.arithmetic(scratch, &proof, &entry.admissions.arithmetic, profile, options.transcript_capacity);
        defer at.deinit();
        var ft = try Derive.callerFused(scratch, &proof, &fused, entry.admissions, profile, options.transcript_capacity);
        defer ft.deinit();
        if (!std.meta.eql(at.template.key_id, ar.key) or !std.meta.eql(ft.template.key_id, fr.key)) return error.UntrustedCpuScopedExpectedExecutionKey;
        const arithmetic_template = try meta.create(Arithmetic.TemplatePolicy);
        arithmetic_template.* = at.template;
        arithmetic_template.schedule = try meta.dupe(@import("block_v5_recursive_execution_leaf_files_v1.zig").ForFamily(.caller_arithmetic).Bus.Wire, at.template.schedule);
        const fused_template = try meta.create(CallerFused.TemplatePolicy);
        fused_template.* = ft.template;
        fused_template.schedule = try meta.dupe(@import("block_v5_recursive_execution_leaf_files_v1.zig").ForFamily(.caller_fused).Bus.Wire, ft.template.schedule);
        arithmetic_policies[i] = .{ .prepared = &entry.admissions.arithmetic, .template = arithmetic_template };
        fused_policies[i] = .{ .prepared = &entry.admissions.fused, .template = fused_template };
        arithmetic_pins[i] = ar.file;
        fused_pins[i] = fr.file;
    }
    self.session.caller_arithmetic = .{ .store = try Arithmetic.Store.initReader(meta, dir, source.roster, arithmetic_policies, arithmetic_pins, options.executions), .binding = undefined };
    self.session.caller_fused = .{ .store = try CallerFused.Store.initReader(meta, dir, source.roster, fused_policies, fused_pins, options.executions), .binding = undefined };
    cursor = try std.math.add(usize, cursor, try std.math.mul(usize, callers.len, 2));
    const NativeFused = Executions.ForFamily(.native_capacity_fused);
    const native_policies = try meta.alloc(NativeFused.Policy, source.fused.len);
    const native_pins = try meta.alloc(Executions.FilePin, source.fused.len);
    for (source.fused, native_policies, native_pins, 0..) |*prepared, *policy, *pin, i| {
        const index = prepared.native.index;
        const received = try record(raw, cursor + i, 7, index);
        var proof = try original.take(.native_fused, index);
        defer proof.deinit(original.a);
        var template = try Derive.nativeFused(scratch, &proof, prepared, profile, options.transcript_capacity);
        defer template.deinit();
        if (!std.meta.eql(template.template.key_id, received.key)) return error.UntrustedCpuScopedExpectedExecutionKey;
        const owned = try meta.create(NativeFused.TemplatePolicy);
        owned.* = template.template;
        owned.schedule = try meta.dupe(@import("block_v5_recursive_execution_leaf_files_v1.zig").ForFamily(.native_capacity_fused).Bus.Wire, template.template.schedule);
        policy.* = .{ .prepared = prepared, .template = owned };
        pin.* = received.file;
    }
    self.session.native_fused = .{ .store = try NativeFused.Store.initReaderWithSelection(meta, dir, source.roster, native_policies, native_pins, &source.selection.?, options.executions), .binding = undefined };
    return self;
}
fn same(a: anytype, b: anytype) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| if (!std.meta.eql(left, right)) return false;
    return true;
}
