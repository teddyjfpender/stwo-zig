const std = @import("std");
const stwo = @import("stwo");
const witness_aot = stwo.integrations.cairo_metal.witness_aot;
const witness_codegen = stwo.integrations.cairo_metal.witness_codegen;
const bundle_mod = stwo.frontends.cairo.witness.bundle;
const program_mod = stwo.frontends.cairo.witness.program;

pub fn main() !void {
    var debug_allocator = std.heap.DebugAllocator(.{}).init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len == 4 and std.mem.eql(u8, args[1], "--compile-one"))
        return compileOne(allocator, args[2], args[3]);
    if (args.len == 3 and std.mem.eql(u8, args[1], "--list-deductions"))
        return listDeductions(allocator, args[2]);
    if (args.len != 3) return error.InvalidArguments;
    var bundle = try bundle_mod.Bundle.readFile(allocator, args[1]);
    defer bundle.deinit();
    var output = try std.fs.cwd().createFile(args[2], .{});
    defer output.close();
    var buffer: [64 * 1024]u8 = undefined;
    var file_writer = output.writer(&buffer);
    const writer = &file_writer.interface;
    const source = try witness_aot.generateSource(allocator, bundle);
    defer allocator.free(source);
    try writer.writeAll(source);
    try writer.flush();
    std.debug.print("emitted {} specialized canonical Metal witness kernels\n", .{bundle.entries.len * 2});
}

fn compileOne(
    allocator: std.mem.Allocator,
    bundle_path: []const u8,
    label: []const u8,
) !void {
    var bundle = try bundle_mod.Bundle.readFile(allocator, bundle_path);
    defer bundle.deinit();
    const entry = bundle.find(label) orelse return error.UnknownWitnessProgram;
    const source = try witness_codegen.generateStandaloneKernel(
        allocator,
        entry.program,
        .all,
    );
    defer allocator.free(source);
    var runtime = try stwo.backends.metal.runtime.Runtime.init();
    defer runtime.deinit();
    var library = try runtime.compileEvalLibrary(source);
    defer library.deinit();
    const name = try witness_codegen.kernelName(
        allocator,
        entry.program.semanticIdentity(),
    );
    defer allocator.free(name);
    var plan = try runtime.prepareWitnessFromLibrary(
        library,
        name,
        .{
            .input_offsets = 0,
            .table_offsets = 0,
            .table_strides = 0,
            .output_offsets = 0,
            .multiplicity_offsets = 0,
            .lookup_words = 0,
            .sub_words = 0,
            .row_count = 16,
            .pedersen_offsets = 0,
            .pedersen_rows = 1,
            .poseidon_keys = 0,
        },
    );
    defer plan.deinit();
    const identity = std.fmt.bytesToHex(
        entry.program.semanticIdentity(),
        .lower,
    );
    std.debug.print(
        "compiled Metal witness {s}: source_bytes={} identity={s}\n",
        .{
            label,
            source.len,
            identity[0..],
        },
    );
}

fn listDeductions(
    allocator: std.mem.Allocator,
    bundle_path: []const u8,
) !void {
    var bundle = try bundle_mod.Bundle.readFile(allocator, bundle_path);
    defer bundle.deinit();
    var stdout_buffer: [16 * 1024]u8 = undefined;
    var stdout = std.fs.File.stdout().writer(&stdout_buffer);
    for (bundle.entries) |entry| {
        var selectors = std.AutoHashMap(u32, void).init(allocator);
        defer selectors.deinit();
        for (entry.program.insts) |inst| {
            if (std.meta.intToEnum(program_mod.Op, inst.op) catch null ==
                .deduce_call)
                try selectors.put(inst.imm, {});
        }
        if (selectors.count() == 0) continue;
        try stdout.interface.print("{s}:", .{entry.label});
        var iterator = selectors.keyIterator();
        while (iterator.next()) |selector|
            try stdout.interface.print(" {}", .{selector.*});
        try stdout.interface.writeByte('\n');
    }
    try stdout.interface.flush();
}
