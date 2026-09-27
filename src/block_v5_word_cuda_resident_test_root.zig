//! CPU-only admission/dispatch/status contract tests. No CUDA library, device,
//! STARK proof, source compiler or benchmark is launched by this test root.
const std = @import("std");
const Q = @import("stwo_core").fields.qm31.QM31;
const runtime = @import("backends/cuda/runtime/secure_polynomial_v1.zig");
const source = @import("backends/cuda/secure_polynomial_resident_codegen_v1.zig");
const registry = runtime.registry;
const common = @import("backends/cuda/runtime/stages/common.zig");
const Stage = @import("backends/cuda/runtime/telemetry.zig").Stage;
const Kernel = @import("backends/cuda/runtime/kernel.zig").Kernel;
const ir = runtime.ir;
fn program(a: std.mem.Allocator, kind: ir.Kind) !ir.Program {
    var b = ir.Builder.init(a);
    defer b.deinit();
    const value = b.input(.{ .tree = 0, .column = 0 });
    const weight = b.input(.{ .tree = 1, .column = 0 });
    const expression = if (ir.isFraction(kind)) ir.Expr.rangeFraction(weight, value, b.parameter(Q.fromU32Unchecked(7, 1, 0, 0))) else value.mul(b.parameter(Q.one()));
    var roots: [63]ir.Expr = undefined;
    const count = ir.layout(kind).roots;
    @memset(roots[0..count], expression);
    return b.finish(kind, [_]u8{5} ** 32, roots[0..count]);
}
fn manifest(a: std.mem.Allocator, p: *const ir.Program) ![]u8 {
    var entries: [1 + source.helper_count]registry.Entry = undefined;
    const id = try source.dag.identity(p);
    const name = try source.dag.kernelName(a, p);
    defer a.free(name);
    entries[0] = .{ .name = name, .source_identity = id, .cache_key = source.cacheKey(id), .abi_schema = if (ir.isFraction(p.kind)) .secure_polynomial_fractions_v1 else .secure_polynomial_equations_v1, .argument_count = 12, .cubin_sha256 = [_]u8{17} ** 32, .cubin_bytes = 8192 };
    inline for (std.meta.tags(source.Helper), 0..) |helper, i| {
        const helper_id = source.helperIdentity(helper);
        entries[i + 1] = .{ .name = source.name(helper), .source_identity = helper_id, .cache_key = source.cacheKey(helper_id), .abi_schema = registry.helperSchema(helper), .argument_count = registry.helperArguments(helper), .cubin_sha256 = [_]u8{17} ** 32, .cubin_bytes = 8192 };
    }
    return std.json.Stringify.valueAlloc(a, registry.Wire{ .version = 1, .sm_major = 9, .sm_minor = 0, .entries = &entries }, .{});
}
fn sha(bytes: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &out, .{});
    return out;
}
fn slice(comptime F: type, values: []F) @import("backends/cuda/runtime/column.zig").DeviceSlice(F) {
    return .{ .address = @intFromPtr(values.ptr), .len = values.len, .owner = 123, .generation = 1 };
}
const HostDispatch = struct {
    context: HostContext = .{},
    device: struct { sm_major: u32 = 9, sm_minor: u32 = 0 } = .{},
    launches: usize = 0,
    pub fn launchKernel(self: *HostDispatch, descriptor: Kernel, args: []const ?*anyopaque) !void {
        try descriptor.validate();
        try self.context.requireStage(descriptor.stage);
        try std.testing.expectEqual(@as(usize, descriptor.argument_count), args.len);
        try std.testing.expect(descriptor.expected_cubin_bytes.? == 8192);
        try std.testing.expectEqualSlices(u8, &([_]u8{17} ** 32), &descriptor.expected_cubin_sha256.?);
        self.launches += 1;
    }
};
const HostContext = struct {
    stage: Stage = .ingress,
    reads: usize = 0,
    syncs: usize = 0,
    pub fn requireStage(self: *HostContext, expected: Stage) !void {
        if (self.stage != expected) return error.StageOrderViolation;
    }
    pub fn deviceSlicePointer(_: *HostContext, comptime F: type, resident: anytype, minimum: usize) ![*]F {
        if (resident.owner != 123 or resident.generation != 1 or resident.len < minimum or resident.address == 0) return error.InvalidDeviceAddress;
        return @ptrFromInt(resident.address);
    }
    pub fn zeroDeviceSlice(self: *HostContext, comptime F: type, resident: anytype) !void {
        const values = try self.deviceSlicePointer(F, resident, resident.len);
        @memset(values[0..resident.len], 0);
    }
    pub fn uploadSlice(self: *HostContext, comptime F: type, resident: anytype, values: []const F) !void {
        try self.requireStage(.ingress);
        if (resident.len != values.len) return error.SizeOverflow;
        const destination = try self.deviceSlicePointer(F, resident, values.len);
        @memcpy(destination[0..values.len], values);
    }
    pub fn readProofSlice(self: *HostContext, comptime F: type, out: []F, resident: anytype) !void {
        try self.requireStage(.proof_assembly);
        if (out.len != resident.len) return error.SizeOverflow;
        const values = try self.deviceSlicePointer(F, resident, out.len);
        @memcpy(out, values[0..out.len]);
        self.reads += 1;
    }
    pub fn sync(self: *HostContext) !void {
        self.syncs += 1;
    }
};
test "CUDA secure catalog authenticates exact AOT schemas and source helpers" {
    const a = std.testing.allocator;
    var p = try program(a, .word_fractions_v4);
    defer p.deinit();
    const wire = try manifest(a, &p);
    defer a.free(wire);
    var catalog = try registry.Catalog.read(a, wire, sha(wire), &.{&p}, 9, 0, .{});
    defer catalog.deinit();
    try std.testing.expectEqual(@as(usize, 8), catalog.parsed.value.entries.len);
    var changed = sha(wire);
    changed[0] ^= 1;
    try std.testing.expectError(error.SecureAotManifestHashMismatch, registry.Catalog.read(a, wire, changed, &.{&p}, 9, 0, .{}));
    try std.testing.expectError(error.InvalidSecureAotCatalog, registry.Catalog.read(a, wire, sha(wire), &.{&p}, 8, 0, .{}));
    try std.testing.expectError(error.InvalidSecureAotCatalog, registry.Catalog.read(a, wire, sha(wire), &.{&p}, 9, 0, .{ .max_manifest_bytes = wire.len - 1 }));
    const exported_helpers = source.helperEntries();
    inline for (std.meta.tags(source.Helper), 0..) |helper, i| {
        const admitted = try catalog.entry(source.helperIdentity(helper));
        try std.testing.expectEqual(admitted.cache_key, exported_helpers[i].cache_key);
        try std.testing.expectEqual(@intFromEnum(admitted.abi_schema), exported_helpers[i].abi_schema);
        try std.testing.expectEqualSlices(u8, admitted.name, exported_helpers[i].kernel);
    }
    const library = try source.generateLibrary(a, &.{&p});
    defer a.free(library);
    inline for (std.meta.tags(source.Helper)) |helper| try std.testing.expect(std.mem.indexOf(u8, library, source.name(helper)) != null);
    try std.testing.expect(std.mem.indexOf(u8, library, "__shared__ RiscvQm31 prefix[256]") != null);
    try std.testing.expect(std.mem.indexOf(u8, library, "[[buffer(") == null);
}
test "CUDA secure hierarchical scan admission charges all scratch and range inverse bytes" {
    const g = try runtime.Geometry.fractions(22, 17, .{});
    try std.testing.expectEqual(@as(u32, 4194304), g.rows);
    try std.testing.expectEqual(@as(usize, 3), g.levels);
    try std.testing.expectEqualSlices(u32, &.{ 16384, 64, 1 }, g.scan_rows[0..g.levels]);
    try std.testing.expect(g.charged_bytes > g.output_words * 4 + runtime.TABLE_WORDS * 4);
    try std.testing.expectError(error.SecureResidentCap, runtime.Geometry.fractions(22, 17, .{ .max_resident_bytes = g.charged_bytes - 1 }));
    try std.testing.expectError(error.InvalidSecureInvocation, runtime.Geometry.fractions(22, 3, .{}));
    try std.testing.expectError(error.InvalidSecureInvocation, runtime.Geometry.fractions(26, 17, .{}));
}
test "CUDA secure dispatch requires exact leases and active poles cannot complete zero output" {
    const a = std.testing.allocator;
    var p = try program(a, .word_fractions_v4);
    defer p.deinit();
    const wire = try manifest(a, &p);
    defer a.free(wire);
    var catalog = try registry.Catalog.read(a, wire, sha(wire), &.{&p}, 9, 0, .{});
    defer catalog.deinit();
    var plan = try runtime.Plan.init(a, &catalog, &p, 3, &.{}, .{});
    defer plan.deinit();
    var session: HostDispatch = .{};
    var status_word: [1]u32 = .{99};
    var status = try runtime.ProofStatus.begin(&session, slice(u32, &status_word));
    var offsets: [2]u64 = undefined;
    var parameters: [4]u32 = undefined;
    var powers: [1]u32 = undefined;
    var denominators: [8]u32 = undefined;
    const binding = try plan.upload(&session, .{ .offsets = slice(u64, &offsets), .parameters = slice(u32, &parameters), .powers = slice(u32, &powers), .denominators = slice(u32, &denominators) });
    var z_storage: [4]u32 = undefined;
    var table_plan = try runtime.RangeTablePlan.init(plan.range_z.?);
    try table_plan.upload(&session, slice(u32, &z_storage));
    const table_storage = try a.alloc(u32, runtime.TABLE_WORDS);
    defer a.free(table_storage);
    session.context.stage = .constraint_evaluation;
    const table = try table_plan.generate(&session, &catalog, slice(u32, table_storage), .{});
    try std.testing.expectError(error.SecureRangeTableAlreadyGenerated, table_plan.generate(&session, &catalog, slice(u32, table_storage), .{}));
    var fixed: [12 * 8]u32 = @splat(0);
    var main: [27 * 8]u32 = @splat(0);
    var columns: [68 * 8]u32 = @splat(0);
    const buffers: runtime.Buffers = .{ .trees = .{ .{ .storage = slice(u32, &fixed), .column_stride_words = 8 }, .{ .storage = slice(u32, &main), .column_stride_words = 8 }, null }, .output = slice(u32, &columns) };
    var changed = binding;
    changed.invocation[0] ^= 1;
    try std.testing.expectError(error.InvalidSecureInvocation, plan.launch(&session, &catalog, changed, buffers, table, &status));
    const pending = try plan.launch(&session, &catalog, binding, buffers, table, &status);
    var scratch: [68]u32 = undefined;
    var totals: [68]u32 = undefined;
    const scanned = try runtime.scanAndCenter(&session, &catalog, pending, 3, 17, .{ .levels = .{ slice(u32, &scratch), null, null, null }, .totals = slice(u32, &totals) }, &status, .{});
    try std.testing.expectEqual(@as(usize, 6), session.launches);
    try std.testing.expectError(error.StageOrderViolation, status.complete(&session, scanned));
    status_word[0] = 1; // active pole: even all-zero output is terminal failure.
    session.context.stage = .proof_assembly;
    try std.testing.expectError(error.ActiveSecurePole, status.complete(&session, scanned));
    try std.testing.expect(status.checked);
    try std.testing.expectEqual(@as(usize, 1), session.context.reads);
    try std.testing.expectEqual(@as(usize, 1), session.context.syncs);
    status_word[0] = 0;
    try std.testing.expectError(error.SecureStatusAlreadyCompleted, status.complete(&session, scanned));
}
test "CUDA secure completion binds status lifetime and canonical witness endpoints" {
    var session: HostDispatch = .{};
    var word: [1]u32 = .{0};
    var output: [4]u32 = @splat(0);
    var totals: [4]u32 = .{ 3, 5, 7, 11 };
    var claim_read: [1]@import("backends/cuda/abi/field.zig").SecureField = undefined;
    var status = try runtime.ProofStatus.begin(&session, slice(u32, &word));
    const pending: runtime.Pending = .{ .columns = slice(u32, &output), .totals = slice(u32, &totals), .status = status.word, .status_id = status.id, .invocation = [_]u8{7} ** 32 };
    session.context.stage = .proof_assembly;
    const completion = try status.check(&session);
    const checked = try completion.admit(&session, pending);
    try checked.readTotals(&session, &claim_read);
    try std.testing.expectEqual(@as(u32, 3), claim_read[0].a);
    session.context.stage = .ingress;
    status = try runtime.ProofStatus.begin(&session, slice(u32, &word));
    session.context.stage = .proof_assembly;
    try std.testing.expectError(error.SecureStatusBindingMismatch, completion.admit(&session, pending));
    try std.testing.expectError(error.SecureStatusBindingMismatch, checked.readTotals(&session, &claim_read));
    try std.testing.expectError(error.NonCanonicalSecureValue, runtime.checkStatus(4));
    try std.testing.expectError(error.InvalidSecureWitness, runtime.checkStatus(2));
    try std.testing.expectError(error.UnknownSecureDeviceFailure, runtime.checkStatus(8));
    var claim: runtime.WordClaim = .{ .words = @splat(0) };
    claim.words[2] = 9;
    claim.words[4] = 8;
    claim.words[5] = 3;
    try std.testing.expectEqual(@as(u32, 8), try claim.validate(.{}));
    claim.words[4] = 10;
    try std.testing.expectError(error.InvalidSecureWitness, claim.validate(.{}));
}

test "CUDA secure witness dispatch keeps independently admitted metadata separate from records" {
    const a = std.testing.allocator;
    var p = try program(a, .word_equations_v4);
    defer p.deinit();
    const wire = try manifest(a, &p);
    defer a.free(wire);
    var catalog = try registry.Catalog.read(a, wire, sha(wire), &.{&p}, 9, 0, .{});
    defer catalog.deinit();
    var session: HostDispatch = .{};
    var word: [1]u32 = .{0};
    var status = try runtime.ProofStatus.begin(&session, slice(u32, &word));
    var claim: runtime.WordClaim = .{ .words = @splat(0) };
    claim.words[2] = 8;
    claim.words[4] = 8;
    claim.words[5] = 3;
    var witness = try runtime.WitnessPlan.init(claim, .{});
    var metadata: [25]u32 = undefined;
    try witness.upload(&session, slice(u32, &metadata));
    var records: [48]u32 = @splat(0);
    var columns: [39 * 8]u32 = @splat(0);
    const multiplicities = try a.alloc(u32, 65536);
    defer a.free(multiplicities);
    const range_columns = try a.alloc(u32, 65536 * 2);
    defer a.free(range_columns);
    session.context.stage = .trace_generation;
    const first = try witness.generate(&session, &catalog, slice(u32, &records), slice(u32, &columns), &status, .{});
    const second = try runtime.rangeWitness(&session, &catalog, slice(u32, multiplicities), slice(u32, range_columns), &status, .{});
    try std.testing.expectEqual(@as(usize, 2), session.launches);
    session.context.stage = .proof_assembly;
    const completion = try status.check(&session);
    _ = try completion.admit(&session, first);
    _ = try completion.admit(&session, second);
    try std.testing.expectEqual(@as(usize, 1), session.context.reads);
}

test "CUDA secure cubin pins reject a verified receipt from a different product" {
    const abi = @import("backends/cuda/abi/types.zig");
    var stream_word: u8 = 0;
    const descriptor = Kernel{
        .stage = .constraint_evaluation,
        .abi_schema = .secure_polynomial_equations_v1,
        .cache_key = 7,
        .name = "test_secure_aot",
        .grid = .{ 1, 1, 1 },
        .block = .{ 256, 1, 1 },
        .argument_count = 12,
        .expected_cubin_sha256 = [_]u8{17} ** 32,
        .expected_cubin_bytes = 8192,
    };
    const device = abi.DeviceSnapshot{ .count = 1, .current = 0, .sm_major = 9, .sm_minor = 0 };
    var receipt = abi.NativeAotFunctionReceipt{
        .abi_version = @import("backends/cuda/runtime/kernel.zig").receipt_abi_version,
        .abi_schema = @intFromEnum(descriptor.abi_schema),
        .device_ordinal = 0,
        .sm_major = 9,
        .sm_minor = 0,
        .argument_count = 12,
        .grid = descriptor.grid,
        .block = descriptor.block,
        .dynamic_shared_bytes = 0,
        .registers_per_thread = 48,
        .max_threads_per_block = 1024,
        .binary_version = 90,
        .local_bytes = 0,
        .static_shared_bytes = 0,
        .cache_key = 7,
        .context_token = 1,
        .module_token = 2,
        .function_token = 3,
        .stream_token = @intFromPtr(&stream_word),
        .verification = .{ .abi_version = abi.aot_verification_abi_version, .verified = abi.aot_verification_verified, .cubin_bytes = 8192, .expected_sha256 = [_]u8{17} ** 32, .observed_sha256 = [_]u8{17} ** 32 },
    };
    try descriptor.validateReceipt(receipt, device, &stream_word);
    receipt.verification.expected_sha256 = [_]u8{19} ** 32;
    receipt.verification.observed_sha256 = [_]u8{19} ** 32;
    try std.testing.expect(receipt.verification.isVerified());
    try std.testing.expectError(error.AotReceiptMismatch, descriptor.validateReceipt(receipt, device, &stream_word));
    receipt.verification.expected_sha256 = [_]u8{17} ** 32;
    receipt.verification.observed_sha256 = [_]u8{17} ** 32;
    receipt.verification.cubin_bytes -= 1;
    try std.testing.expectError(error.AotReceiptMismatch, descriptor.validateReceipt(receipt, device, &stream_word));
}
