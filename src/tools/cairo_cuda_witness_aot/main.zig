//! Cache-resident Native CUDA AOT generation from authenticated witness IR.

const std = @import("std");
const model = @import("cairo_witness_model");
const cuda_writer = @import("writer.zig");

const recorded_schema = "recorded_witness_v1";
const codegen_version: u64 = 12;
const expected_entries: usize = 48;
const expected_recorded: usize = 33;
const expected_isolated: usize = 7;
const inline_mul =
    "static __device__ __forceinline__ void stwo_wit_deduce_felt_mul(\n";
const isolated_mul =
    "static __device__ __noinline__ void stwo_wit_deduce_felt_mul(\n";

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len != 6) return error.InvalidArguments;

    var bundle = try model.Bundle.read(allocator, args[1]);
    defer bundle.deinit();
    const pinned_root = try std.fs.cwd().openDir(args[2], .{});
    const support_root = try std.fs.cwd().openDir(args[3], .{});
    const native_root = try std.fs.cwd().openDir(args[4], .{ .iterate = true });
    const manifest_bytes = try pinned_root.readFileAlloc(
        allocator,
        "aot_manifest.json",
        2 << 20,
    );
    defer allocator.free(manifest_bytes);
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        allocator,
        manifest_bytes,
        .{},
    );
    defer parsed.deinit();
    if (parsed.value != .array or
        parsed.value.array.items.len != expected_entries)
        return error.InvalidManifest;
    try std.fs.cwd().makePath(args[5]);
    const product_root = try std.fs.cwd().openDir(args[5], .{});
    try product_root.makePath("aot/native");
    const output_root = try product_root.openDir("aot/native", .{});
    try copyTree(allocator, native_root, product_root, "native");

    var recorded_count: usize = 0;
    var isolated_count: usize = 0;
    for (parsed.value.array.items) |entry_value| {
        if (entry_value != .object) return error.InvalidManifest;
        const entry = entry_value.object;
        const file_name = try string(entry, "file");
        const schema = try string(entry, "abi_schema");
        if (!std.mem.eql(u8, schema, recorded_schema)) {
            try copyFile(allocator, pinned_root, output_root, file_name);
            continue;
        }
        recorded_count += 1;
        const label = try string(entry, "label");
        const program = findProgram(bundle.programs, label) orelse
            return error.MissingProgram;
        try validateIdentity(entry, program);

        var generated = std.Io.Writer.Allocating.init(allocator);
        defer generated.deinit();
        try cuda_writer.emit(
            allocator,
            &generated.writer,
            program,
            support_root,
        );
        const raw = generated.written();
        const occurrence_count = std.mem.count(u8, raw, inline_mul);
        if (occurrence_count > 1 or
            std.mem.indexOf(u8, raw, isolated_mul) != null)
            return error.InvalidFeltMulBoundary;
        const source = if (occurrence_count == 1) blk: {
            isolated_count += 1;
            var derived = std.Io.Writer.Allocating.init(allocator);
            errdefer derived.deinit();
            const index = std.mem.indexOf(u8, raw, inline_mul).?;
            try derived.writer.writeAll(raw[0..index]);
            try derived.writer.writeAll(isolated_mul);
            try derived.writer.writeAll(raw[index + inline_mul.len ..]);
            break :blk try derived.toOwnedSlice();
        } else try allocator.dupe(u8, raw);
        defer allocator.free(source);
        try writeFile(output_root, file_name, source);
        validateSource(entry, source) catch |err| {
            std.log.err("{s}: {s}", .{ file_name, @errorName(err) });
            return err;
        };
    }
    if (recorded_count != expected_recorded or
        isolated_count != expected_isolated or
        bundle.programs.len != expected_recorded)
        return error.InvalidProductCount;
    try writeFile(output_root, "aot_manifest.json", manifest_bytes);
    std.debug.print(
        "Native CUDA AOT generated: {} entries, {} witness programs\n",
        .{ expected_entries, recorded_count },
    );
}

fn validateIdentity(
    entry: std.json.ObjectMap,
    program: model.Program,
) !void {
    if (program.calculatedSemanticHash() != program.semantic_hash)
        return error.SemanticHashMismatch;
    const semantic_hash = try std.fmt.parseInt(
        u64,
        try string(entry, "semantic_hash"),
        16,
    );
    if (semantic_hash != program.semantic_hash)
        return error.SemanticHashMismatch;
    const cache_key = try std.fmt.parseInt(
        u64,
        try string(entry, "cache_key"),
        16,
    );
    if (cache_key != witnessCacheKey(program.semantic_hash))
        return error.CacheKeyMismatch;
    var expected_kernel: [64]u8 = undefined;
    const kernel = try std.fmt.bufPrint(
        &expected_kernel,
        "stwo_jit_witness_{x:0>16}",
        .{program.semantic_hash},
    );
    if (!std.mem.eql(u8, kernel, try string(entry, "kernel_name")))
        return error.KernelNameMismatch;
    var expected_file: [256]u8 = undefined;
    const file_name = try std.fmt.bufPrint(
        &expected_file,
        "witness_{s}_{x:0>16}.cu",
        .{ program.label, cache_key },
    );
    if (!std.mem.eql(u8, file_name, try string(entry, "file")))
        return error.FileNameMismatch;
    const identity = program.semanticIdentity();
    var identity_hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&identity_hex, "{x}", .{identity}) catch unreachable;
    if (!std.mem.eql(
        u8,
        &identity_hex,
        try string(entry, "program_identity"),
    )) return error.ProgramIdentityMismatch;
    if (!std.mem.eql(
        u8,
        try string(entry, "identity_scheme"),
        "sha256-source-and-blake3-program-v1",
    )) return error.IdentitySchemeMismatch;
    const expected_globals = if (needsPedersen(program))
        "pedersen_w18_columns_rows_v1"
    else
        "none";
    if (!std.mem.eql(
        u8,
        expected_globals,
        try string(entry, "module_globals"),
    )) return error.ModuleGlobalsMismatch;
}

fn validateSource(entry: std.json.ObjectMap, source: []const u8) !void {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source, &digest, .{});
    var digest_hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&digest_hex, "{x}", .{digest}) catch unreachable;
    if (!std.mem.eql(
        u8,
        &digest_hex,
        try string(entry, "source_sha256"),
    )) return error.SourceIdentityMismatch;
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

fn needsPedersen(program: model.Program) bool {
    for (program.insts) |inst| {
        if (inst.op != .deduce_call) continue;
        const kind = std.meta.intToEnum(
            model.DeduceKind,
            inst.imm,
        ) catch return false;
        if (kind.needsPedersenModule()) return true;
    }
    return false;
}

fn findProgram(
    programs: []const model.Program,
    label: []const u8,
) ?model.Program {
    for (programs) |program| {
        if (std.mem.eql(u8, program.label, label)) return program;
    }
    return null;
}

fn string(object: std.json.ObjectMap, name: []const u8) ![]const u8 {
    const value = object.get(name) orelse return error.InvalidManifest;
    if (value != .string) return error.InvalidManifest;
    return value.string;
}

fn copyFile(
    allocator: std.mem.Allocator,
    source: std.fs.Dir,
    destination: std.fs.Dir,
    name: []const u8,
) !void {
    const payload = try source.readFileAlloc(allocator, name, 4 << 20);
    defer allocator.free(payload);
    try writeFile(destination, name, payload);
}

fn copyTree(
    allocator: std.mem.Allocator,
    source: std.fs.Dir,
    destination: std.fs.Dir,
    prefix: []const u8,
) !void {
    try destination.makePath(prefix);
    var walker = try source.walk(allocator);
    defer walker.deinit();
    while (try walker.next()) |entry| {
        const output_name = try std.fs.path.join(
            allocator,
            &.{ prefix, entry.path },
        );
        defer allocator.free(output_name);
        switch (entry.kind) {
            .directory => try destination.makePath(output_name),
            .file => {
                const parent = std.fs.path.dirname(output_name) orelse prefix;
                try destination.makePath(parent);
                const payload = try source.readFileAlloc(
                    allocator,
                    entry.path,
                    16 << 20,
                );
                defer allocator.free(payload);
                try writeFile(destination, output_name, payload);
            },
            else => return error.UnsupportedNativeEntry,
        }
    }
}

fn writeFile(directory: std.fs.Dir, name: []const u8, payload: []const u8) !void {
    const file = try directory.createFile(name, .{ .truncate = true });
    defer file.close();
    try file.writeAll(payload);
}
