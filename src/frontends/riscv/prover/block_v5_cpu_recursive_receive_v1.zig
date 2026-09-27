//! Fresh seven-family loading with independent original-proof setup derivation.
//! Returns a count only: leaves are individually genuine open equations, not
//! complete source/global/hierarchy cryptographic closure.
const std = @import("std");
const Files = @import("block_v5_artifact_files_v1.zig");
const Sources = @import("block_v5_cpu_recursive_sources_v1.zig");
const Publication = @import("block_v5_cpu_recursive_publication_v1.zig");
const Derive = @import("block_v5_cpu_recursive_template_derivation_v1.zig");
const WordCache = @import("block_v5_word_expected_setup_cache_v1.zig");
const Providers = @import("block_v5_recursive_provider_store_v1.zig");
const Definitions = @import("block_v5_recursive_provider_definition_v1.zig");
const Executions = @import("block_v5_recursive_execution_leaf_files_v1.zig");
const Base = @import("block_v5_cpu_bundle_store_v1.zig").ForCapacity(true);
const Shared = @import("block_v5_recursive_leaf_store_core_v1.zig");
const Profile = @import("../recursion/blake3_execution_parent_protocol.zig").Profile;
const HEADER: usize = 76;
const ROW: usize = 80;
const Record = struct { family: u32, file: Shared.FilePin, key_id: [32]u8 };

/// `source` must be reconstructed from independent source/policy authority in
/// each process; received metadata cannot construct it. `original` is a fresh
/// base reader over existing files, not a copied producer receipt.
pub fn verify(a: std.mem.Allocator, dir: std.fs.Dir, source: *const Sources.Owner, original: *Base.Store, expected_manifest: [32]u8, profile: Profile, options: Publication.Options) !usize {
    try options.validate();
    try source.require();
    if (!std.meta.eql(profile.config(), source.roster.pins.config)) return error.UntrustedCpuRecursiveReceiveSecurity;
    const count = try expectedCount(source);
    const size = try std.math.add(usize, HEADER, try std.math.mul(usize, count, ROW));
    const raw = try Files.readPinned(a, dir, "block-v5-recursive-open-leaves.pins", size, expected_manifest, options.max_manifest_bytes);
    defer a.free(raw);
    if (!std.mem.eql(u8, raw[0..8], "B5RLOP01") or std.mem.readInt(u32, raw[8..12], .little) != count or
        !std.mem.eql(u8, raw[12..44], &source.roster.pins.job_id) or !std.mem.eql(u8, raw[44..76], &source.roster.sealed.digest))
        return error.UntrustedCpuRecursiveOpenManifest;
    var ordinal: usize = 0;
    const Route = struct { provider: Providers.Family, base: Base.Family, field: []const u8, tag: u32 };
    inline for ([_]Route{
        .{ .provider = .range16, .base = .range16, .field = "ranges", .tag = 1 },
        .{ .provider = .ram_lanes, .base = .ram_lanes, .field = "lanes", .tag = 2 },
        .{ .provider = .program_table, .base = .rom, .field = "program", .tag = 3 },
        .{ .provider = .native_lookup, .base = .native_provider, .field = "lookups", .tag = 4 },
    }) |route| {
        const provider_family: Providers.Family = route.provider;
        const original_family: Base.Family = route.base;
        const D = Definitions.ForFamily(provider_family);
        const policies: []const D.Prepared = if (provider_family == .program_table) (&source.program.?)[0..1] else @field(source, route.field);
        const word_family = provider_family == .ram_lanes or provider_family == .range16;
        var expected_cache: if (word_family) WordCache.ForFamily(provider_family, @import("stwo_cpu_backend").CpuBackend) else void = if (word_family) try WordCache.ForFamily(provider_family, @import("stwo_cpu_backend").CpuBackend).init(a, options.max_word_template_metadata_bytes) else {};
        defer if (word_family) expected_cache.deinit();
        var total: u64 = 0;
        for (policies) |*admitted| {
            const record = try recordAt(raw, ordinal, route.tag, D.index(admitted));
            total = try std.math.add(u64, total, record.file.byte_len);
            if (total > options.providers.max_total_bytes) return error.RecursiveProviderTotalResourceLimit;
            if (word_family) {
                const expected = try expected_cache.get(a, admitted, profile, options.transcript_capacity);
                // Each original proof is still freshly verified. The bounded
                // cache contains independently derived setup, never this proof
                // capture, its claim values or its private witness rows.
                {
                    var base = try original.take(original_family, D.index(admitted));
                    defer base.deinit(a);
                    const Capture = if (provider_family == .ram_lanes) @import("block_v5_ram_lanes_recursive_capture_v1.zig") else @import("block_v5_range16_recursive_capture_v1.zig");
                    var checked = try Capture.ForBackend(@import("stwo_cpu_backend").CpuBackend).verifyBorrowed(a, &base, admitted);
                    defer checked.deinit();
                }
                try verifyProvider(provider_family, a, dir, admitted, expected, record, options.providers);
            } else {
                var base = try original.take(original_family, D.index(admitted));
                defer base.deinit(a);
                var expected = try Derive.provider(provider_family, a, &base, admitted, profile, options.transcript_capacity);
                defer expected.deinit();
                try verifyProvider(provider_family, a, dir, admitted, &expected.template, record, options.providers);
            }
            ordinal += 1;
        }
    }
    // Manifest is grouped by family, while each caller's two original proofs
    // stay live together. Index arithmetic preserves sparse execution indices.
    const callers = source.callers.?.entries;
    const fused_start = try std.math.add(usize, ordinal, callers.len);
    var arithmetic_bytes: u64 = 0;
    var fused_bytes: u64 = 0;
    for (callers, 0..) |entry, i| {
        var arithmetic = try original.take(.caller, entry.index);
        defer arithmetic.deinit(a);
        var fused = try original.take(.caller_fused, entry.index);
        defer fused.deinit(a);
        const ar = try recordAt(raw, ordinal + i, 5, entry.index);
        const fr = try recordAt(raw, fused_start + i, 6, entry.index);
        arithmetic_bytes = try std.math.add(u64, arithmetic_bytes, ar.file.byte_len);
        fused_bytes = try std.math.add(u64, fused_bytes, fr.file.byte_len);
        if (arithmetic_bytes > options.executions.max_total_bytes or fused_bytes > options.executions.max_total_bytes)
            return error.RecursiveExecutionTotalResourceLimit;
        var at = try Derive.arithmetic(a, &arithmetic, &entry.admissions.arithmetic, profile, options.transcript_capacity);
        defer at.deinit();
        try verifyExecution(.caller_arithmetic, a, dir, &entry.admissions.arithmetic, &at.template, ar, options.executions);
        var ft = try Derive.callerFused(a, &arithmetic, &fused, entry.admissions, profile, options.transcript_capacity);
        defer ft.deinit();
        try verifyExecution(.caller_fused, a, dir, &entry.admissions.fused, &ft.template, fr, options.executions);
    }
    ordinal = try std.math.add(usize, fused_start, callers.len);
    var native_bytes: u64 = 0;
    for (source.fused) |*admitted| {
        const index = admitted.native.index;
        const record = try recordAt(raw, ordinal, 7, index);
        native_bytes = try std.math.add(u64, native_bytes, record.file.byte_len);
        if (native_bytes > options.executions.max_total_bytes) return error.RecursiveExecutionTotalResourceLimit;
        var proof = try original.take(.native_fused, index);
        defer proof.deinit(a);
        var expected = try Derive.nativeFused(a, &proof, admitted, profile, options.transcript_capacity);
        defer expected.deinit();
        try verifyExecution(.native_capacity_fused, a, dir, admitted, &expected.template, record, options.executions);
        ordinal += 1;
    }
    if (ordinal != count) return error.IncompleteCpuRecursiveOpenManifest;
    return count;
}
fn expectedCount(source: *const Sources.Owner) !usize {
    var count: usize = 1;
    for ([_]usize{ source.ranges.len, source.lanes.len, source.lookups.len, source.callers.?.entries.len, source.callers.?.entries.len, source.fused.len }) |part|
        count = try std.math.add(usize, count, part);
    return count;
}
fn recordAt(raw: []const u8, ordinal: usize, family: u32, index: u32) !Record {
    const start = try std.math.add(usize, HEADER, try std.math.mul(usize, ordinal, ROW));
    if (start > raw.len or raw.len - start < ROW) return error.IncompleteCpuRecursiveOpenManifest;
    const row = raw[start..][0..ROW];
    if (std.mem.readInt(u32, row[0..4], .little) != family or std.mem.readInt(u32, row[4..8], .little) != index)
        return error.UntrustedCpuRecursiveOpenManifest;
    return .{ .family = family, .file = .{ .index = index, .byte_len = std.mem.readInt(u64, row[8..16], .little), .sha256 = row[16..48].* }, .key_id = row[48..80].* };
}
fn verifyProvider(comptime family: Providers.Family, a: std.mem.Allocator, dir: std.fs.Dir, admitted: *const Definitions.ForFamily(family).Prepared, template: *const Providers.ForFamily(family).TemplatePolicy, record: Record, limits: Providers.Limits) !void {
    const D = Definitions.ForFamily(family);
    const M = Providers.ForFamily(family);
    if (!std.meta.eql(record.key_id, template.key_id)) return error.UntrustedCpuRecursiveExpectedKey;
    var name: [128]u8 = undefined;
    const raw = try Files.readPinned(a, dir, try M.fileName(&name, record.file.index), record.file.byte_len, record.file.sha256, limits.codec.max_file_bytes);
    defer a.free(raw);
    const policy = M.Policy{ .prepared = admitted, .template = template };
    var view = try M.Codec.decodeMetadata(a, raw, policy, limits.codec);
    defer view.deinit();
    var fresh = try D.Receiver.verify(a, view.proof, template.key, template.key_id, template.schedule, admitted, view.open);
    defer fresh.deinit();
    if (!std.meta.eql(fresh.public_values, view.values)) return error.UntrustedRecursiveProviderPublicInputs;
}
fn verifyExecution(comptime family: Executions.Family, a: std.mem.Allocator, dir: std.fs.Dir, admitted: *const Executions.ForFamily(family).Admission.Prepared, template: *const Executions.ForFamily(family).Template, record: Record, limits: @import("block_v5_recursive_execution_leaf_store_v1.zig").Limits) !void {
    const D = Executions.ForFamily(family);
    if (!std.meta.eql(record.key_id, template.key_id)) return error.UntrustedCpuRecursiveExpectedKey;
    var name: [128]u8 = undefined;
    const raw = try Files.readPinned(a, dir, try D.fileName(&name, record.file.index), record.file.byte_len, record.file.sha256, limits.codec.codec.max_file_bytes);
    defer a.free(raw);
    const policy = D.Policy{ .prepared = admitted, .template = template };
    var view = try D.decodeMetadata(a, raw, policy, limits.codec);
    defer view.deinit();
    var fresh = try view.verify(a, policy);
    defer fresh.deinit();
}

test "cpu recursive publication: fixed transport records preserve sparse original indices and reject changed family order truncation and overflow" {
    var raw: [HEADER + ROW]u8 = @splat(0);
    const row = raw[HEADER..][0..ROW];
    std.mem.writeInt(u32, row[0..4], 5, .little);
    std.mem.writeInt(u32, row[4..8], 2, .little);
    std.mem.writeInt(u64, row[8..16], 99, .little);
    const record = try recordAt(&raw, 0, 5, 2);
    try std.testing.expectEqual(@as(u32, 2), record.file.index);
    try std.testing.expectEqual(@as(u64, 99), record.file.byte_len);
    try std.testing.expectError(error.UntrustedCpuRecursiveOpenManifest, recordAt(&raw, 0, 6, 2));
    try std.testing.expectError(error.UntrustedCpuRecursiveOpenManifest, recordAt(&raw, 0, 5, 0));
    try std.testing.expectError(error.IncompleteCpuRecursiveOpenManifest, recordAt(raw[0 .. raw.len - 1], 0, 5, 2));
    try std.testing.expectError(error.Overflow, recordAt(&raw, std.math.maxInt(usize), 5, 2));
}
