//! Out-of-band authenticated, bounded secure-kernel manifest. Admits an exact
//! offline product, not proof claims. NativeSession still authenticates cubins
//! from stwo_aot_lookup and matches every launch receipt to these independent pins.
const std = @import("std");
const codegen = @import("../secure_polynomial_resident_codegen_v1.zig");
const schema = @import("../abi/schema.zig");
pub const MAX_ENTRIES = codegen.dag.MAX_ENTRIES + codegen.helper_count;
pub const Limits = struct { max_manifest_bytes: usize = 64 * 1024, max_cubin_bytes: u64 = 128 * 1024 * 1024 };
pub const Entry = struct {
    name: []const u8,
    source_identity: [32]u8,
    cache_key: u64,
    abi_schema: schema.KernelSchema,
    argument_count: u32,
    cubin_sha256: [32]u8,
    cubin_bytes: u64,
};
pub const Wire = struct { version: u32, sm_major: u32, sm_minor: u32, entries: []const Entry };
pub const Catalog = struct {
    a: std.mem.Allocator,
    parsed: std.json.Parsed(Wire),
    sm_major: u32,
    sm_minor: u32,
    pub fn deinit(self: *Catalog) void {
        self.parsed.deinit();
        self.* = undefined;
    }
    pub fn read(a: std.mem.Allocator, bytes: []const u8, sha: [32]u8, programs: []const *const codegen.dag.ir.Program, sm_major: u32, sm_minor: u32, limits: Limits) !Catalog {
        if (bytes.len == 0 or bytes.len > limits.max_manifest_bytes or programs.len == 0 or programs.len > codegen.dag.MAX_ENTRIES or sm_major == 0 or std.mem.allEqual(u8, &sha, 0)) return error.InvalidSecureAotCatalog;
        var observed: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &observed, .{});
        if (!std.mem.eql(u8, &sha, &observed)) return error.SecureAotManifestHashMismatch;
        var parsed = try std.json.parseFromSlice(Wire, a, bytes, .{ .allocate = .alloc_always, .max_value_len = limits.max_manifest_bytes });
        errdefer parsed.deinit();
        const wire = parsed.value;
        if (wire.version != 1 or wire.sm_major != sm_major or wire.sm_minor != sm_minor or wire.entries.len > MAX_ENTRIES) return error.InvalidSecureAotCatalog;
        var unique: [codegen.dag.MAX_ENTRIES][32]u8 = undefined;
        var count: usize = 0;
        for (programs) |program| {
            const id = try codegen.dag.identity(program);
            var duplicate = false;
            for (unique[0..count]) |prior| if (std.mem.eql(u8, &id, &prior)) {
                duplicate = true;
                break;
            };
            if (duplicate) continue;
            unique[count] = id;
            count += 1;
            const n = try codegen.dag.kernelName(a, program);
            defer a.free(n);
            try requireEntry(wire.entries, id, n, if (codegen.dag.ir.isFraction(program.kind)) .secure_polynomial_fractions_v1 else .secure_polynomial_equations_v1, 12, limits);
        }
        inline for (std.meta.tags(codegen.Helper)) |helper| try requireEntry(wire.entries, codegen.helperIdentity(helper), codegen.name(helper), helperSchema(helper), helperArguments(helper), limits);
        if (wire.entries.len != count + codegen.helper_count) return error.InvalidSecureAotCatalog;
        for (wire.entries, 0..) |candidate, i| for (wire.entries[i + 1 ..]) |other| {
            if (candidate.cache_key == other.cache_key or std.mem.eql(u8, candidate.name, other.name)) return error.DuplicateSecureAotEntry;
        };
        return .{ .a = a, .parsed = parsed, .sm_major = sm_major, .sm_minor = sm_minor };
    }
    pub fn entry(self: *const Catalog, id: [32]u8) !Entry {
        for (self.parsed.value.entries) |value| if (std.mem.eql(u8, &id, &value.source_identity)) return value;
        return error.SecureAotEntryMissing;
    }
};
fn requireEntry(entries: []const Entry, id: [32]u8, name: []const u8, abi: schema.KernelSchema, argc: u32, limits: Limits) !void {
    var found: usize = 0;
    for (entries) |entry| if (std.mem.eql(u8, &id, &entry.source_identity)) {
        if (!std.mem.eql(u8, entry.name, name) or entry.cache_key != codegen.cacheKey(id) or entry.abi_schema != abi or entry.argument_count != argc or entry.cubin_bytes == 0 or entry.cubin_bytes > limits.max_cubin_bytes or std.mem.allEqual(u8, &entry.cubin_sha256, 0)) return error.InvalidSecureAotCatalog;
        found += 1;
    };
    if (found != 1) return error.SecureAotEntryMissing;
}
pub const helperSchema = codegen.helperSchema;
pub const helperArguments = codegen.helperArguments;
