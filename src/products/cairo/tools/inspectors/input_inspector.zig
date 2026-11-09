//! CLI boundary for inspecting an adapted Cairo prover input.

const std = @import("std");
const stwo = @import("stwo");

const adapted_input = stwo.frontends.cairo.adapter.adapted_input;
const OpcodeTag = stwo.frontends.cairo.adapter.opcodes.OpcodeTag;
const witness_bundle = stwo.frontends.cairo.witness.bundle;
const feed_bundle = stwo.frontends.cairo.witness.feed_bundle;
const fixed_table_bundle = stwo.frontends.cairo.witness.fixed_table_bundle;
const receipt = stwo.frontends.cairo.conformance.receipt;
const direct_trace = stwo.frontends.cairo.conformance.direct_trace;
const memory_trace = stwo.frontends.cairo.conformance.memory_trace;
const fixed_trace = stwo.frontends.cairo.conformance.fixed_trace;
const base_trace_suite = stwo.frontends.cairo.conformance.base_trace_suite;

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len == 2) return inspect(allocator, args[1]);
    if (args.len == 5 and std.mem.eql(u8, args[1], "compare-direct")) {
        return compareDirect(allocator, args[2], args[3], args[4]);
    }
    if (args.len == 6 and std.mem.eql(u8, args[1], "compare-memory")) {
        return compareMemory(allocator, args[2], args[3], args[4], args[5]);
    }
    if (args.len == 7 and std.mem.eql(u8, args[1], "compare-fixed")) {
        return compareFixed(allocator, args[2], args[3], args[4], args[5], args[6]);
    }
    if (args.len == 7 and std.mem.eql(u8, args[1], "compare-base")) {
        return compareBase(allocator, args[2], args[3], args[4], args[5], args[6]);
    }
    std.debug.print(
        "usage:\n  cairo-input <adapted-input.stwzcpi>\n  cairo-input compare-direct <adapted-input.stwzcpi> <witness.bin> <rust-receipt.json>\n  cairo-input compare-memory <adapted-input.stwzcpi> <witness.bin> <feeds.bin> <rust-receipt.json>\n  cairo-input compare-fixed <adapted-input.stwzcpi> <witness.bin> <feeds.bin> <fixed.bin> <rust-receipt.json>\n  cairo-input compare-base <adapted-input.stwzcpi> <witness.bin> <feeds.bin> <fixed.bin> <rust-receipt.json>\n",
        .{},
    );
    return error.InvalidArgument;
}

fn compareBase(
    allocator: std.mem.Allocator,
    input_path: []const u8,
    witness_path: []const u8,
    feeds_path: []const u8,
    fixed_path: []const u8,
    receipt_path: []const u8,
) !void {
    const input_sha256 = try hashFile(input_path);
    var expected = try receipt.readFile(allocator, receipt_path, .{
        .input_sha256 = input_sha256,
        .authority = direct_trace.trace_oracle_authority,
    });
    defer expected.deinit();
    var input = try adapted_input.readFile(allocator, input_path);
    defer input.deinit(allocator);
    var witnesses = try witness_bundle.Bundle.readFile(allocator, witness_path);
    defer witnesses.deinit();
    var feeds = try feed_bundle.Bundle.readFile(allocator, feeds_path);
    defer feeds.deinit();
    var fixed = try fixed_table_bundle.Bundle.readFile(allocator, fixed_path);
    defer fixed.deinit();

    const outcome = try base_trace_suite.compare(
        allocator,
        &input,
        &witnesses,
        &feeds,
        &fixed,
        expected.components,
        expected.final_accumulator,
    );
    switch (outcome) {
        .success => |summary| {
            const accumulator = std.fmt.bytesToHex(summary.final_accumulator, .lower);
            std.debug.print(
                "base trace parity: {d}/{d} components, {d} columns, final_accumulator_sha256={s}\n",
                .{ summary.components, base_trace_suite.component_count, summary.columns, &accumulator },
            );
        },
        .direct_mismatch => |mismatch| {
            printDirectMismatch(mismatch);
            return error.CairoBaseTraceMismatch;
        },
        .memory_mismatch => |mismatch| {
            std.debug.print(
                "base trace mismatch lane=memory component={d} label={s} kind={s}",
                .{ mismatch.component_ordinal, mismatch.component_label, @tagName(mismatch.kind) },
            );
            if (mismatch.column_ordinal) |column| std.debug.print(" column={d}", .{column});
            std.debug.print(
                " expected_sha256={x} actual_sha256={x}\n",
                .{ mismatch.expected_digest, mismatch.actual_digest },
            );
            return error.CairoBaseTraceMismatch;
        },
        .fixed_mismatch => |mismatch| {
            std.debug.print(
                "base trace mismatch lane=fixed component={d} label={s} kind={s} column={d} expected_sha256={x} actual_sha256={x}\n",
                .{
                    mismatch.component_ordinal,
                    mismatch.component_label,
                    @tagName(mismatch.kind),
                    mismatch.column_ordinal,
                    mismatch.expected_digest,
                    mismatch.actual_digest,
                },
            );
            return error.CairoBaseTraceMismatch;
        },
    }
}

fn printDirectMismatch(mismatch: direct_trace.Mismatch) void {
    std.debug.print(
        "base trace mismatch lane=direct component={d} label={s} kind={s}",
        .{ mismatch.component_ordinal, mismatch.component_label, @tagName(mismatch.kind) },
    );
    if (mismatch.column_ordinal) |column| std.debug.print(" column={d}", .{column});
    if (mismatch.expected_count) |count| std.debug.print(" expected_count={d}", .{count});
    if (mismatch.actual_count) |count| std.debug.print(" actual_count={d}", .{count});
    if (mismatch.expected_digest) |digest| std.debug.print(" expected_sha256={x}", .{digest});
    if (mismatch.actual_digest) |digest| std.debug.print(" actual_sha256={x}", .{digest});
    std.debug.print("\n", .{});
}

fn compareFixed(
    allocator: std.mem.Allocator,
    input_path: []const u8,
    witness_path: []const u8,
    feeds_path: []const u8,
    fixed_path: []const u8,
    receipt_path: []const u8,
) !void {
    const input_sha256 = try hashFile(input_path);
    var expected = try receipt.readFile(allocator, receipt_path, .{
        .input_sha256 = input_sha256,
        .authority = direct_trace.trace_oracle_authority,
    });
    defer expected.deinit();
    var input = try adapted_input.readFile(allocator, input_path);
    defer input.deinit(allocator);
    var witnesses = try witness_bundle.Bundle.readFile(allocator, witness_path);
    defer witnesses.deinit();
    var feeds = try feed_bundle.Bundle.readFile(allocator, feeds_path);
    defer feeds.deinit();
    var fixed = try fixed_table_bundle.Bundle.readFile(allocator, fixed_path);
    defer fixed.deinit();

    var report = try fixed_trace.compare(
        allocator,
        &input,
        &witnesses,
        &feeds,
        &fixed,
        expected.components,
    );
    defer report.deinit();
    for (report.matches) |matched| std.debug.print(
        "match component={d} label={s} rows={d} columns={d}\n",
        .{ matched.ordinal, matched.label, matched.row_count, matched.column_count },
    );
    if (report.mismatch) |mismatch| {
        std.debug.print(
            "mismatch component={d} label={s} kind={s} column={d} expected_sha256={x} actual_sha256={x}\n",
            .{
                mismatch.component_ordinal,
                mismatch.component_label,
                @tagName(mismatch.kind),
                mismatch.column_ordinal,
                mismatch.expected_digest,
                mismatch.actual_digest,
            },
        );
        return error.CairoFixedTraceMismatch;
    }
    std.debug.print("fixed trace parity: {d} matched\n", .{report.matches.len});
}

fn compareMemory(
    allocator: std.mem.Allocator,
    input_path: []const u8,
    witness_path: []const u8,
    feeds_path: []const u8,
    receipt_path: []const u8,
) !void {
    const input_sha256 = try hashFile(input_path);
    var expected = try receipt.readFile(allocator, receipt_path, .{
        .input_sha256 = input_sha256,
        .authority = direct_trace.trace_oracle_authority,
    });
    defer expected.deinit();
    var input = try adapted_input.readFile(allocator, input_path);
    defer input.deinit(allocator);
    var witness = try witness_bundle.Bundle.readFile(allocator, witness_path);
    defer witness.deinit();
    var feeds = try feed_bundle.Bundle.readFile(allocator, feeds_path);
    defer feeds.deinit();

    const report = try memory_trace.compare(
        allocator,
        &input,
        &witness,
        &feeds,
        expected.components,
    );
    for (report.matches[0..report.match_count]) |matched| std.debug.print(
        "match component={d} label={s} rows={d} columns={d}\n",
        .{ matched.ordinal, matched.label, matched.row_count, matched.column_count },
    );
    if (report.mismatch) |mismatch| {
        std.debug.print(
            "mismatch component={d} label={s} kind={s}",
            .{ mismatch.component_ordinal, mismatch.component_label, @tagName(mismatch.kind) },
        );
        if (mismatch.column_ordinal) |column| std.debug.print(" column={d}", .{column});
        std.debug.print(
            " expected_sha256={x} actual_sha256={x}\n",
            .{ mismatch.expected_digest, mismatch.actual_digest },
        );
        return error.CairoMemoryTraceMismatch;
    }
    std.debug.print("memory trace parity: {d} matched\n", .{report.match_count});
}

fn inspect(allocator: std.mem.Allocator, input_path: []const u8) !void {
    var input = try adapted_input.readFile(allocator, input_path);
    defer input.deinit(allocator);

    const cycles = input.state_transitions.casm_states_by_opcode.totalCount();
    std.debug.print("Cairo adapted prover input\n", .{});
    std.debug.print("cycles: {d}\n", .{cycles});
    std.debug.print("pc_count: {d}\n", .{input.pc_count});
    std.debug.print("memory_address_to_id: {d}\n", .{input.memory.address_to_id.len});
    std.debug.print("memory_id_to_big: {d}\n", .{input.memory.f252_values.len});
    std.debug.print("memory_id_to_small: {d}\n", .{input.memory.small_values.len});
    std.debug.print("public_memory_addresses: {d}\n", .{input.public_memory_addresses.len});
    inline for (@typeInfo(OpcodeTag).@"enum".fields) |field| {
        const tag: OpcodeTag = @enumFromInt(field.value);
        const count = input.state_transitions.casm_states_by_opcode.getConst(tag).len;
        if (count != 0) std.debug.print("opcode {s}: {d}\n", .{ field.name, count });
    }
}

fn compareDirect(
    allocator: std.mem.Allocator,
    input_path: []const u8,
    witness_path: []const u8,
    receipt_path: []const u8,
) !void {
    const input_sha256 = try hashFile(input_path);
    var expected = try receipt.readFile(allocator, receipt_path, .{
        .input_sha256 = input_sha256,
        .authority = direct_trace.trace_oracle_authority,
    });
    defer expected.deinit();
    var input = try adapted_input.readFile(allocator, input_path);
    defer input.deinit(allocator);
    var bundle = try witness_bundle.Bundle.readFile(allocator, witness_path);
    defer bundle.deinit();

    var report = try direct_trace.compare(allocator, &input, &bundle, expected.components);
    defer report.deinit();
    for (report.matches) |matched| std.debug.print(
        "match component={d} label={s} rows={d} columns={d}\n",
        .{ matched.ordinal, matched.label, matched.row_count, matched.column_count },
    );
    if (report.mismatch) |mismatch| {
        std.debug.print(
            "mismatch component={d} label={s} kind={s}",
            .{ mismatch.component_ordinal, mismatch.component_label, @tagName(mismatch.kind) },
        );
        if (mismatch.column_ordinal) |column| std.debug.print(" column={d}", .{column});
        if (mismatch.expected_count) |count| std.debug.print(" expected_count={d}", .{count});
        if (mismatch.actual_count) |count| std.debug.print(" actual_count={d}", .{count});
        if (mismatch.expected_digest) |digest| std.debug.print(" expected_sha256={x}", .{digest});
        if (mismatch.actual_digest) |digest| std.debug.print(" actual_sha256={x}", .{digest});
        std.debug.print("\n", .{});
        return error.CairoBaseTraceMismatch;
    }
    std.debug.print(
        "direct trace parity: {d} matched, {d} non-direct components skipped\n",
        .{ report.matches.len, report.skipped_components },
    );
}

fn hashFile(path: []const u8) ![32]u8 {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [256 * 1024]u8 = undefined;
    while (true) {
        const count = try file.read(&buffer);
        if (count == 0) return hasher.finalResult();
        hasher.update(buffer[0..count]);
    }
}
