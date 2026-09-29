//! Current upstream Cairo witness product. Never derive identities from a proof.
const std = @import("std");
const model = @import("cairo_witness_model");
const writer = @import("writer.zig");

pub const codegen_version: u64 = 17;
const bundle_sha256 = "b2108615463b3c7003b07df20e800a42c4c7625344a681ed22e78e57238c90a6";
const cairo_revision = "82f21252a68ec006d73e299f5bf1ce6d4db0ee78";
const stwo_revision = "7b211edde786775016ef3eecb837a6240d8fe792";

pub fn generate(allocator: std.mem.Allocator, bundle_path: []const u8, support_path: []const u8, provenance_path: []const u8, output_path: []const u8) !void {
    var bundle = try model.Bundle.read(allocator, bundle_path);
    defer bundle.deinit();
    const digest = sha256(bundle.storage);
    if (!std.mem.eql(u8, &digest, bundle_sha256) or bundle.programs.len != 64)
        return error.UnauthenticatedCanonicalBundle;
    const provenance = try std.fs.cwd().readFileAlloc(allocator, provenance_path, 1 << 20);
    defer allocator.free(provenance);
    const Provenance = struct {
        source: struct { revision: []const u8, stwo_revision: []const u8 },
        artifact: struct { sha256: []const u8, component_count: usize },
    };
    const parsed = try std.json.parseFromSlice(Provenance, allocator, provenance, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const source = parsed.value.source;
    if (!std.mem.eql(u8, source.revision, cairo_revision) or
        !std.mem.eql(u8, source.stwo_revision, stwo_revision))
        return error.CanonicalSourcePinMismatch;
    const artifact = parsed.value.artifact;
    if (!std.mem.eql(u8, artifact.sha256, bundle_sha256) or
        artifact.component_count != bundle.programs.len)
        return error.CanonicalSourcePinMismatch;
    std.mem.sort(model.Program, bundle.programs, {}, struct {
        fn lessThan(_: void, a: model.Program, b: model.Program) bool {
            return std.mem.lessThan(u8, a.label, b.label);
        }
    }.lessThan);

    var support = try std.fs.cwd().openDir(support_path, .{});
    defer support.close();
    try std.fs.cwd().makePath(output_path);
    var output = try std.fs.cwd().openDir(output_path, .{});
    defer output.close();
    var manifest = std.Io.Writer.Allocating.init(allocator);
    defer manifest.deinit();
    const Entry = struct {
        abi_schema: []const u8 = "recorded_witness_v1",
        cache_key: []const u8,
        file: []const u8,
        identity_scheme: []const u8 = "sha256-source-and-blake3-program-v1",
        kernel_name: []const u8,
        kind: []const u8 = "witness",
        codegen_version: u64 = codegen_version,
        label: []const u8,
        module_globals: []const u8,
        program_identity: []const u8,
        semantic_hash: []const u8,
        source_sha256: []const u8,
    };
    try manifest.writer.writeAll("[\n");
    var selectors = [_]bool{false} ** @typeInfo(model.DeduceKind).@"enum".fields.len;
    for (bundle.programs, 0..) |program, index| {
        var generated = std.Io.Writer.Allocating.init(allocator);
        defer generated.deinit();
        try generated.writer.writeAll(
            \\#ifndef unlikely
            \\#define unlikely(condition) (condition)
            \\#endif
            \\#if defined(STWO_CUMETAL)
            \\__host__ __device__ constexpr unsigned stwo_funnel_r(unsigned low, unsigned high, unsigned shift) {
            \\    unsigned n = shift & 31u;
            \\    return n == 0u ? low : (low >> n) | (high << (32u - n));
            \\}
            \\__host__ __device__ constexpr unsigned stwo_funnel_rc(unsigned low, unsigned high, unsigned shift) {
            \\    return shift >= 32u ? high : stwo_funnel_r(low, high, shift);
            \\}
            \\#define __funnelshift_r stwo_funnel_r
            \\#define __funnelshift_rc stwo_funnel_rc
            \\#endif
            \\
        );
        try writer.emitCanonical(allocator, &generated.writer, program, support);
        // Clang checks device callees during its host pass as well. The imported
        // carry fallbacks are ordinary integer arithmetic, so mark them callable
        // in both passes. Preserve the historical writer's source identities.
        const carry_pass = try std.mem.replaceOwned(u8, allocator, generated.written(), "__host__ __forceinline__", "__host__ __device__ __forceinline__");
        defer allocator.free(carry_pass);
        const dual_pass = try std.mem.replaceOwned(u8, allocator, carry_pass,
            "static __host__ uint32_t", "static __host__ __device__ uint32_t");
        defer allocator.free(dual_pass);
        // CuMetal cannot import the multi-instruction PTX carry chain. Use the
        // source authority's exact integer carry implementation on Apple GPUs;
        // NVIDIA retains its original PTX path.
        const portable = try std.mem.replaceOwned(u8, allocator, dual_pass,
            "#ifdef __CUDA_ARCH__", "#if defined(__CUDA_ARCH__) && !defined(STWO_CUMETAL)");
        defer allocator.free(portable);
        // EC-op invokes this deduction 252 times. Share the device function
        // instead of expanding the complete field inversion at every call.
        // Its input/output ABI and arithmetic remain exactly the same.
        var uses_generic_ec = false;
        var uses_inverse = false;
        for (program.insts) |inst| {
            if (inst.op != .deduce_call) continue;
            const kind = try std.meta.intToEnum(model.DeduceKind, inst.imm);
            uses_generic_ec = uses_generic_ec or kind == .partial_ec_mul_generic;
            uses_inverse = uses_inverse or kind == .partial_ec_mul_generic or kind == .partial_ec_mul_w9 or kind == .partial_ec_mul_w18 or kind == .felt_div;
        }
        const bounded = if (uses_generic_ec)
            try std.mem.replaceOwned(u8, allocator, portable,
                "static __device__ __forceinline__ void stwo_wit_deduce_partial_ec_mul_generic(",
                "static __device__ __noinline__ void stwo_wit_deduce_partial_ec_mul_generic(")
        else
            try allocator.dupe(u8, portable);
        defer allocator.free(bounded);
        // Sharing inversion is particularly valuable when a deduction calls it
        // repeatedly. It preserves the imported arithmetic and avoids copying
        // the entire inverse implementation into every curve/addition site.
        const final_source = if (uses_inverse)
            try std.mem.replaceOwned(u8, allocator, bounded,
                "__device__ __forceinline__ felt252 felt_inverse(",
                "__device__ __noinline__ felt252 felt_inverse(")
        else try allocator.dupe(u8, bounded);
        defer allocator.free(final_source);
        const cache_key = witnessCacheKey(program.semantic_hash);
        const name = try std.fmt.allocPrint(allocator, "witness_{s}_{x:0>16}.cu", .{ program.label, cache_key });
        defer allocator.free(name);
        const kernel = try std.fmt.allocPrint(allocator, "stwo_jit_witness_{x:0>16}", .{program.semantic_hash});
        defer allocator.free(kernel);
        var file = try output.createFile(name, .{});
        defer file.close();
        try file.writeAll(final_source);
        var key_hex: [16]u8 = undefined;
        var semantic_hex: [16]u8 = undefined;
        const identity = std.fmt.bytesToHex(program.semanticIdentity(), .lower);
        const source_digest = sha256(final_source);
        if (index != 0) try manifest.writer.writeAll(",\n");
        try std.json.Stringify.value(Entry{
            .cache_key = try std.fmt.bufPrint(&key_hex, "{x:0>16}", .{cache_key}),
            .file = name,
            .kernel_name = kernel,
            .label = program.label,
            .module_globals = try globals(program),
            .program_identity = &identity,
            .semantic_hash = try std.fmt.bufPrint(&semantic_hex, "{x:0>16}", .{program.semantic_hash}),
            .source_sha256 = &source_digest,
        }, .{ .whitespace = .indent_2 }, &manifest.writer);
        for (program.insts) |inst| {
            if (inst.op == .deduce_call) selectors[inst.imm] = true;
        }
    }
    // A corpus omission must not silently remove a deduction implementation.
    if (!std.mem.allEqual(bool, &selectors, true)) return error.IncompleteCanonicalDeductionCorpus;
    try manifest.writer.writeAll("\n]\n");
    const manifest_file = try output.createFile("aot_manifest.json", .{});
    defer manifest_file.close();
    try manifest_file.writeAll(manifest.written());
    const receipt_file = try output.createFile("generation-receipt.json", .{});
    defer receipt_file.close();
    var receipt = std.Io.Writer.Allocating.init(allocator);
    defer receipt.deinit();
    const manifest_digest = sha256(manifest.written());
    try std.json.Stringify.value(.{
        .schema = "stwo_cairo_canonical_cuda_witness_generation_v1",
        .codegen_version = codegen_version,
        .bundle_sha256 = bundle_sha256,
        .cairo_revision = cairo_revision,
        .stwo_revision = stwo_revision,
        .program_count = bundle.programs.len,
        .deduction_count = selectors.len,
        .manifest_sha256 = @as([]const u8, &manifest_digest),
        .device_qualified = false,
        .full_proof_verified = false,
    }, .{ .whitespace = .indent_2 }, &receipt.writer);
    try receipt_file.writeAll(receipt.written());
    std.debug.print("Canonical CUDA witness generated: {} programs, {} deductions\n", .{ bundle.programs.len, selectors.len });
}

fn sha256(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn witnessCacheKey(semantic_hash: u64) u64 {
    var hash: u64 = 0xcbf29ce484222325;
    var values = [_]u64{ semantic_hash, codegen_version };
    for (std.mem.sliceAsBytes(&values)) |byte| {
        hash ^= byte;
        hash *%= 0x100000001b3;
    }
    return hash;
}

fn globals(program: model.Program) ![]const u8 {
    var w9 = false;
    var w18 = false;
    for (program.insts) |inst| {
        if (inst.op != .deduce_call) continue;
        const kind = try std.meta.intToEnum(model.DeduceKind, inst.imm);
        w9 = w9 or kind == .partial_ec_mul_w9 or kind == .pedersen_points_table_w9;
        w18 = w18 or kind == .partial_ec_mul_w18 or kind == .pedersen_points_table_w18;
    }
    if (w9 and w18) return error.MixedPedersenWindowModule;
    return if (w9) "pedersen_w9_columns_rows_v1" else if (w18) "pedersen_w18_columns_rows_v1" else "none";
}
