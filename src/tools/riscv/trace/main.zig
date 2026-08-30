//! RISC-V trace dumper CLI for cross-verification.
//!
//! Runs a RISC-V RV32IM ELF binary through the Zig execution engine and
//! writes a canonical retirement trace suitable for Sail/Spike differential
//! comparison.
//!
//! Usage:
//!   riscv-trace-dump --elf <path> [--output <trace.json>] [--max-steps N]
//!
//! When --output is omitted the JSON is written to stdout.

const std = @import("std");
const build_identity = @import("build_identity");
const runner = @import("stwo_riscv_frontend").runner;
const trace_dump = @import("stwo_riscv_frontend").runner.trace_dump;
const witness_layout = @import("stwo_riscv_frontend").witness_layout;
const opcode_manifest = @import("stwo_riscv_frontend").opcode_manifest;
const public_data = @import("stwo_riscv_frontend").air.public_data;
const relation_evidence = @import("stwo_riscv_frontend").air.relation_evidence;
const public_values_diagnostic = @import("stwo_riscv_frontend").diagnostics.public_values;
const segment_manifest = @import("stwo_riscv_frontend").diagnostics.segment_manifest;
const riscv_cpu = @import("stwo_riscv_cpu_integration");
const pcs = @import("stwo_core").pcs;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var elf_path: ?[]const u8 = null;
    var input_path: ?[]const u8 = null;
    var output_path: ?[]const u8 = null;
    var decode_file: ?[]const u8 = null;
    var program_tuples: ?[]const u8 = null;
    var poseidon2_file: ?[]const u8 = null;
    var transcript_prefix: ?[]const u8 = null;
    var witness_rows: ?[]const u8 = null;
    var ordered_accesses: ?[]const u8 = null;
    var relation_tuples: ?[]const u8 = null;
    var relation_sums: ?[]const u8 = null;
    var public_values: ?[]const u8 = null;
    var max_steps: usize = 1_000_000;
    var max_steps_set = false;
    var segment_steps: ?usize = null;
    var help = false;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--elf")) {
            try takeOptionValue(args, &i, &elf_path);
        } else if (std.mem.eql(u8, args[i], "--input")) {
            try takeOptionValue(args, &i, &input_path);
        } else if (std.mem.eql(u8, args[i], "--output")) {
            try takeOptionValue(args, &i, &output_path);
        } else if (std.mem.eql(u8, args[i], "--decode-file")) {
            try takeOptionValue(args, &i, &decode_file);
        } else if (std.mem.eql(u8, args[i], "--program-tuples")) {
            try takeOptionValue(args, &i, &program_tuples);
        } else if (std.mem.eql(u8, args[i], "--poseidon2-file")) {
            try takeOptionValue(args, &i, &poseidon2_file);
        } else if (std.mem.eql(u8, args[i], "--transcript-prefix")) {
            try takeOptionValue(args, &i, &transcript_prefix);
        } else if (std.mem.eql(u8, args[i], "--witness-rows")) {
            try takeOptionValue(args, &i, &witness_rows);
        } else if (std.mem.eql(u8, args[i], "--ordered-accesses")) {
            try takeOptionValue(args, &i, &ordered_accesses);
        } else if (std.mem.eql(u8, args[i], "--relation-tuples")) {
            try takeOptionValue(args, &i, &relation_tuples);
        } else if (std.mem.eql(u8, args[i], "--relation-sums")) {
            try takeOptionValue(args, &i, &relation_sums);
        } else if (std.mem.eql(u8, args[i], "--public-values")) {
            try takeOptionValue(args, &i, &public_values);
        } else if (std.mem.eql(u8, args[i], "--max-steps")) {
            if (max_steps_set) return error.DuplicateOption;
            const raw = try takeValue(args, &i);
            max_steps = try std.fmt.parseInt(usize, raw, 10);
            max_steps_set = true;
        } else if (std.mem.eql(u8, args[i], "--segment-steps")) {
            if (segment_steps != null) return error.DuplicateOption;
            segment_steps = try std.fmt.parseInt(usize, try takeValue(args, &i), 10);
            if (segment_steps.? == 0) return error.ZeroSegmentStepBudget;
        } else if (std.mem.eql(u8, args[i], "--help") or std.mem.eql(u8, args[i], "-h")) {
            if (help) return error.DuplicateOption;
            help = true;
        } else return error.UnknownOption;
    }

    const mode_count = countPresent(.{
        elf_path,
        decode_file,
        program_tuples,
        poseidon2_file,
        transcript_prefix,
        witness_rows,
        ordered_accesses,
        relation_tuples,
        relation_sums,
        public_values,
    });
    if (help) {
        if (mode_count != 0 or output_path != null or input_path != null or
            max_steps_set or segment_steps != null)
            return error.ConflictingOptions;
        printUsage();
        return;
    }
    if (mode_count != 1) return error.ConflictingOptions;
    if (segment_steps != null and (elf_path == null or output_path != null or max_steps_set))
        return error.ConflictingOptions;
    if (output_path != null and elf_path == null) return error.ConflictingOptions;
    if (input_path != null and elf_path == null and relation_tuples == null and
        relation_sums == null and public_values == null)
        return error.ConflictingOptions;

    const input = if (input_path) |path|
        try std.fs.cwd().readFileAlloc(allocator, path, 64 * 1024 * 1024)
    else
        try allocator.alloc(u8, 0);
    defer allocator.free(input);

    if (decode_file) |path| {
        try dumpDecodeMatrix(allocator, path);
        return;
    }

    if (program_tuples) |path| {
        try dumpProgramTuples(allocator, path);
        return;
    }

    if (poseidon2_file) |path| {
        try dumpPoseidon2(allocator, path);
        return;
    }

    if (transcript_prefix) |path| {
        try dumpTranscriptPrefix(allocator, path);
        return;
    }

    if (witness_rows) |path| {
        try dumpWitnessRows(allocator, path, max_steps);
        return;
    }

    if (ordered_accesses) |path| {
        try dumpOrderedAccesses(allocator, path, max_steps);
        return;
    }

    if (relation_tuples) |path| {
        try dumpRelationEvidence(allocator, path, input, max_steps, .tuples);
        return;
    }

    if (relation_sums) |path| {
        try dumpRelationEvidence(allocator, path, input, max_steps, .sums);
        return;
    }

    if (public_values) |path| {
        try dumpPublicValues(allocator, path, input, max_steps);
        return;
    }

    // Read ELF binary.
    const elf_bytes = std.fs.cwd().readFileAlloc(allocator, elf_path.?, 64 * 1024 * 1024) catch |err| {
        std.debug.print("error: cannot read ELF file '{s}': {}\n", .{ elf_path.?, err });
        std.process.exit(1);
    };
    defer allocator.free(elf_bytes);

    if (segment_steps) |budget| {
        var buffer: [4096]u8 = undefined;
        var stdout = std.fs.File.stdout().writer(&buffer);
        try segment_manifest.stream(
            allocator,
            elf_bytes,
            input,
            budget,
            true,
            &stdout.interface,
        );
        return;
    }

    // Execute.
    var result = runner.runWithInput(allocator, elf_bytes, input, max_steps) catch |err| {
        std.debug.print("error: execution failed: {}\n", .{err});
        std.process.exit(1);
    };
    defer result.deinit();

    // Serialize trace to an in-memory buffer, then write it out.
    var json_buf: std.ArrayList(u8) = .{};
    defer json_buf.deinit(allocator);
    try trace_dump.writeTraceJson(json_buf.writer(allocator), &result.execution_trace, result.cpu_final);

    if (output_path) |path| {
        const file = try std.fs.cwd().createFile(path, .{});
        defer file.close();
        try file.writeAll(json_buf.items);
    } else {
        // Write to stdout.
        try json_buf.append(allocator, '\n');
        const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };
        try stdout.writeAll(json_buf.items);
    }
}

fn takeValue(args: []const []const u8, index: *usize) ![]const u8 {
    if (index.* + 1 >= args.len or std.mem.startsWith(u8, args[index.* + 1], "-"))
        return error.MissingOptionValue;
    index.* += 1;
    return args[index.*];
}

fn takeOptionValue(
    args: []const []const u8,
    index: *usize,
    destination: *?[]const u8,
) !void {
    if (destination.* != null) return error.DuplicateOption;
    destination.* = try takeValue(args, index);
}

fn countPresent(values: anytype) usize {
    var count: usize = 0;
    inline for (values) |value| count += @intFromBool(value != null);
    return count;
}

const Family = witness_layout.Family;

fn familyRowCount(trace: *const runner.trace.Trace, family: Family) !usize {
    var count: usize = 0;
    for (trace.rows.items) |row| {
        if (try runner.trace.proofOpcodeFamily(row.opcode) == family) count += 1;
    }
    return count;
}

fn writeFamilyWitness(
    allocator: std.mem.Allocator,
    writer: anytype,
    trace: *const runner.trace.Trace,
    comptime family: Family,
) !void {
    const row_count = try familyRowCount(trace, family);
    const padded_count = @max(row_count, 1);
    const log_size: u32 = @intCast(std.math.log2_int_ceil(usize, padded_count));
    var columns = try trace.columnsForFamily(allocator, family, log_size);
    defer columns.deinit(allocator);
    const Layout = witness_layout.LayoutFor(family);
    const fields = @typeInfo(Layout).@"struct".fields;
    std.debug.assert(fields.len == columns.n_columns);

    try writer.print("family={s} rows={d} columns={d}\n", .{
        @tagName(family),
        columns.n_real_rows,
        columns.n_columns,
    });
    try writer.writeAll("names=");
    inline for (fields, 0..) |field, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.writeAll(field.name);
    }
    try writer.writeByte('\n');
    for (0..columns.n_real_rows) |row| {
        try writer.print("row={d}", .{row});
        for (columns.columns[0..columns.n_columns]) |column| {
            try writer.print(" {d}", .{column[row].v});
        }
        try writer.writeByte('\n');
    }
}

fn dumpWitnessRows(allocator: std.mem.Allocator, path: []const u8, max_steps: usize) !void {
    const elf_bytes = try std.fs.cwd().readFileAlloc(allocator, path, 64 * 1024 * 1024);
    defer allocator.free(elf_bytes);
    var result = try runner.run(allocator, elf_bytes, max_steps);
    defer result.deinit();

    var out: std.ArrayList(u8) = .{};
    defer out.deinit(allocator);
    const writer = out.writer(allocator);
    inline for (witness_layout.canonical_families) |family| {
        try writeFamilyWitness(allocator, writer, &result.execution_trace, family);
    }
    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };
    try stdout.writeAll(out.items);
}

const OrderedAccess = struct {
    clock: u32,
    kind: u8,
    ordinal: u8,
    family_index: usize,
    family: []const u8,
    role: []const u8,
    addr_space: u32,
    addr: u32,
    previous_clock: u32,
    previous: u32,
    next: u32,
};

fn canonicalFamilyIndex(family: Family) usize {
    inline for (witness_layout.canonical_families, 0..) |candidate, index| {
        if (family == candidate) return index;
    }
    unreachable;
}

fn columnIndex(comptime Layout: type, comptime name: []const u8) usize {
    inline for (@typeInfo(Layout).@"struct".fields, 0..) |field, index| {
        if (comptime std.mem.eql(u8, field.name, name)) return index;
    }
    @compileError("missing witness column " ++ name);
}

fn columnValue(
    columns: *const runner.trace.TraceColumns,
    comptime Layout: type,
    comptime name: []const u8,
    row: usize,
) u32 {
    return columns.columns[columnIndex(Layout, name)][row].v;
}

fn columnWord(
    columns: *const runner.trace.TraceColumns,
    comptime Layout: type,
    comptime role: []const u8,
    comptime phase: []const u8,
    row: usize,
) u32 {
    return columnValue(columns, Layout, role ++ "_" ++ phase ++ "_0", row) |
        (columnValue(columns, Layout, role ++ "_" ++ phase ++ "_1", row) << 8) |
        (columnValue(columns, Layout, role ++ "_" ++ phase ++ "_2", row) << 16) |
        (columnValue(columns, Layout, role ++ "_" ++ phase ++ "_3", row) << 24);
}

fn appendColumnAccess(
    allocator: std.mem.Allocator,
    accesses: *std.ArrayList(OrderedAccess),
    columns: *const runner.trace.TraceColumns,
    comptime family: Family,
    row: usize,
    ordinal: u8,
    comptime role: []const u8,
    addr_space: u32,
) !void {
    const Layout = witness_layout.LayoutFor(family);
    try accesses.append(allocator, .{
        .clock = columnValue(columns, Layout, "clock", row),
        .kind = 1,
        .ordinal = ordinal,
        .family_index = canonicalFamilyIndex(family),
        .family = @tagName(family),
        .role = role,
        .addr_space = addr_space,
        .addr = columnValue(columns, Layout, role ++ "_addr", row),
        .previous_clock = columnValue(columns, Layout, role ++ "_clock_prev", row),
        .previous = columnWord(columns, Layout, role, "prev", row),
        .next = columnWord(columns, Layout, role, "next", row),
    });
}

fn appendReadColumnAccess(
    allocator: std.mem.Allocator,
    accesses: *std.ArrayList(OrderedAccess),
    columns: *const runner.trace.TraceColumns,
    comptime family: Family,
    row: usize,
    ordinal: u8,
    comptime role: []const u8,
    addr_space: u32,
) !void {
    const Layout = witness_layout.LayoutFor(family);
    const value = columnWord(columns, Layout, role, "prev", row);
    try accesses.append(allocator, .{
        .clock = columnValue(columns, Layout, "clock", row),
        .kind = 1,
        .ordinal = ordinal,
        .family_index = canonicalFamilyIndex(family),
        .family = @tagName(family),
        .role = role,
        .addr_space = addr_space,
        .addr = columnValue(columns, Layout, role ++ "_addr", row),
        .previous_clock = columnValue(columns, Layout, role ++ "_clock_prev", row),
        .previous = value,
        .next = value,
    });
}

fn appendFamilyAccesses(
    allocator: std.mem.Allocator,
    accesses: *std.ArrayList(OrderedAccess),
    trace: *const runner.trace.Trace,
    comptime family: Family,
) !void {
    const row_count = try familyRowCount(trace, family);
    const log_size: u32 = @intCast(std.math.log2_int_ceil(usize, @max(row_count, 1)));
    var columns = try trace.columnsForFamily(allocator, family, log_size);
    defer columns.deinit(allocator);
    for (0..columns.n_real_rows) |row| switch (family) {
        .base_alu_reg => {
            try appendReadColumnAccess(allocator, accesses, &columns, family, row, 0, "rs1", 0);
            try appendReadColumnAccess(allocator, accesses, &columns, family, row, 1, "rs2", 0);
            try appendColumnAccess(allocator, accesses, &columns, family, row, 2, "rd", 0);
        },
        .shifts_reg, .lt_reg, .mul, .mulh, .div => {
            try appendColumnAccess(allocator, accesses, &columns, family, row, 0, "rs1", 0);
            try appendColumnAccess(allocator, accesses, &columns, family, row, 1, "rs2", 0);
            try appendColumnAccess(allocator, accesses, &columns, family, row, 2, "rd", 0);
        },
        .base_alu_imm, .shifts_imm, .lt_imm, .jalr => {
            try appendColumnAccess(allocator, accesses, &columns, family, row, 0, "rs1", 0);
            try appendColumnAccess(allocator, accesses, &columns, family, row, 1, "rd", 0);
        },
        .branch_eq, .branch_lt => {
            try appendColumnAccess(allocator, accesses, &columns, family, row, 0, "rs1", 0);
            try appendColumnAccess(allocator, accesses, &columns, family, row, 1, "rs2", 0);
        },
        .lui, .auipc, .jal => try appendColumnAccess(allocator, accesses, &columns, family, row, 0, "rd", 0),
        .load_store => {
            const Layout = witness_layout.LayoutFor(family);
            const is_store = columnValue(&columns, Layout, "opcode_sb_flag", row) +
                columnValue(&columns, Layout, "opcode_sh_flag", row) +
                columnValue(&columns, Layout, "opcode_sw_flag", row) != 0;
            try appendReadColumnAccess(allocator, accesses, &columns, family, row, 0, "rs1", 0);
            try appendReadColumnAccess(
                allocator,
                accesses,
                &columns,
                family,
                row,
                1,
                "src",
                if (is_store) 0 else 1,
            );
            try appendColumnAccess(
                allocator,
                accesses,
                &columns,
                family,
                row,
                2,
                "dst",
                if (is_store) 1 else 0,
            );
        },
        .fence => {},
    };
}

fn orderedAccessLessThan(_: void, lhs: OrderedAccess, rhs: OrderedAccess) bool {
    if (lhs.clock != rhs.clock) return lhs.clock < rhs.clock;
    if (lhs.kind != rhs.kind) return lhs.kind < rhs.kind;
    if (lhs.ordinal != rhs.ordinal) return lhs.ordinal < rhs.ordinal;
    if (lhs.addr_space != rhs.addr_space) return lhs.addr_space < rhs.addr_space;
    if (lhs.addr != rhs.addr) return lhs.addr < rhs.addr;
    return lhs.family_index < rhs.family_index;
}

fn dumpOrderedAccesses(allocator: std.mem.Allocator, path: []const u8, max_steps: usize) !void {
    const elf_bytes = try std.fs.cwd().readFileAlloc(allocator, path, 64 * 1024 * 1024);
    defer allocator.free(elf_bytes);
    var result = try runner.run(allocator, elf_bytes, max_steps);
    defer result.deinit();

    var accesses: std.ArrayList(OrderedAccess) = .{};
    defer accesses.deinit(allocator);
    inline for (witness_layout.canonical_families) |family| {
        try appendFamilyAccesses(allocator, &accesses, &result.execution_trace, family);
    }
    for (result.state_chain_tracker.clock_updates_reg.items) |gap| {
        const value = gap.value;
        try accesses.append(allocator, .{
            .clock = gap.clk,
            .kind = 0,
            .ordinal = 0,
            .family_index = std.math.maxInt(usize),
            .family = "clock_update",
            .role = "clock_update",
            .addr_space = gap.addr_space,
            .addr = gap.addr,
            .previous_clock = gap.clk_prev,
            .previous = value,
            .next = value,
        });
    }
    for (result.state_chain_tracker.clock_updates_mem.items) |gap| {
        const value = gap.value;
        try accesses.append(allocator, .{
            .clock = gap.clk,
            .kind = 0,
            .ordinal = 0,
            .family_index = std.math.maxInt(usize),
            .family = "clock_update",
            .role = "clock_update",
            .addr_space = gap.addr_space,
            .addr = gap.addr,
            .previous_clock = gap.clk_prev,
            .previous = value,
            .next = value,
        });
    }
    std.mem.sort(OrderedAccess, accesses.items, {}, orderedAccessLessThan);

    var out: std.ArrayList(u8) = .{};
    defer out.deinit(allocator);
    const writer = out.writer(allocator);
    for (accesses.items) |access| {
        try writer.print(
            "clock={d} ordinal={d} family={s} role={s} space={d} addr={d} previous_clock={d} previous={d} next={d}\n",
            .{
                access.clock,
                access.ordinal,
                access.family,
                access.role,
                access.addr_space,
                access.addr,
                access.previous_clock,
                access.previous,
                access.next,
            },
        );
    }
    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };
    try stdout.writeAll(out.items);
}

const RelationEvidenceMode = enum { tuples, sums };

fn dumpRelationEvidence(
    allocator: std.mem.Allocator,
    path: []const u8,
    input: []const u8,
    max_steps: usize,
    mode: RelationEvidenceMode,
) !void {
    const elf_bytes = try std.fs.cwd().readFileAlloc(allocator, path, 64 * 1024 * 1024);
    defer allocator.free(elf_bytes);
    var result = try runner.runWithInput(allocator, elf_bytes, input, max_steps);
    defer result.deinit();
    if (result.rw_memory.program_words.len == 0 or
        result.completion_reason != .halt_flag)
        return error.UnsupportedRelationEvidenceSource;

    var elf_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(elf_bytes, &elf_digest, .{});
    var input_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(result.input, &input_digest, .{});
    const binding = relation_evidence.Binding{
        .implementation_commit = build_identity.implementation_commit,
        .implementation_dirty = build_identity.implementation_dirty,
        .oracle_commit = opcode_manifest.legacy_layout_revision,
        .elf_sha256 = elf_digest,
        .input_sha256 = input_digest,
    };

    const input_words = try public_data.packInputWords(allocator, result.input);
    defer allocator.free(input_words);
    const output_words = try allocator.alloc(public_data.OutputWord, result.output_words.len);
    defer allocator.free(output_words);
    for (result.output_words, output_words) |source, *destination| {
        destination.* = .{
            .addr = source.addr,
            .value = source.value,
            .clock = source.clock,
        };
    }
    const config = pcs.PcsConfig{
        .pow_bits = 0,
        .fri_config = .{
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = 3,
        },
    };
    const diagnostic = try riscv_cpu.diagnoseRiscVRelations(
        allocator,
        config,
        &result.execution_trace,
        &result.state_chain_tracker,
        &result.rw_memory,
        .{
            .initial_pc = result.initial_pc,
            .final_pc = result.final_pc,
            .clock = @intCast(result.step_count),
            .initial_regs = result.initial_regs,
            .final_regs = result.final_regs,
            .reg_last_clock = result.state_chain_tracker.reg_last_clk,
            .program_root = null,
            .initial_rw_root = null,
            .final_rw_root = null,
            .completion = try public_data.completionFromRun(&result),
            .io_entries = .{
                .input_start = result.input_start,
                .input_len = @intCast(result.input.len),
                .input_words = input_words,
                .output_len = result.output_len,
                .output_len_addr = result.output_len_addr,
                .output_data_addr = result.output_data_addr,
                .output_words = output_words,
            },
        },
    );
    var out: std.ArrayList(u8) = .{};
    defer out.deinit(allocator);
    switch (mode) {
        .tuples => try relation_evidence.writeTuples(
            out.writer(allocator),
            &diagnostic.bundle,
            binding,
        ),
        .sums => try relation_evidence.writeSums(
            out.writer(allocator),
            &diagnostic.bundle,
            &diagnostic.relations,
            binding,
        ),
    }
    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };
    try stdout.writeAll(out.items);
}

fn dumpPublicValues(
    allocator: std.mem.Allocator,
    path: []const u8,
    input: []const u8,
    max_steps: usize,
) !void {
    const elf_bytes = try std.fs.cwd().readFileAlloc(allocator, path, 64 * 1024 * 1024);
    defer allocator.free(elf_bytes);
    var result = try runner.runWithInput(allocator, elf_bytes, input, max_steps);
    defer result.deinit();
    var owned = try public_values_diagnostic.derive(allocator, &result);
    defer owned.deinit(allocator);
    const encoded = try public_values_diagnostic.encode(
        allocator,
        owned.data,
        build_identity.implementation_commit,
        build_identity.implementation_dirty,
        elf_bytes,
        result.input,
    );
    defer allocator.free(encoded);
    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };
    try stdout.writeAll(encoded);
    try stdout.writeAll("\n");
}

fn printUsage() void {
    std.debug.print(
        \\Usage: riscv-trace-dump --elf <path> [--output <trace.json>] [--max-steps N]
        \\
        \\Options:
        \\  --elf <path>         Path to a RISC-V RV32IM ELF binary (required)
        \\  --output <path>      Write JSON trace to file (default: stdout)
        \\  --input <path>       Load bytes into the ELF's declared input region
        \\  --max-steps <N>      Maximum execution steps (default: 1000000)
        \\  --segment-steps <N>  Stream strict, bounded execution NDJSON to stdout
        \\  --relation-tuples <path>  Dump bound default-challenge tuple evidence
        \\  --relation-sums <path>    Dump bound default-challenge sum evidence
        \\  --public-values <path>    Dump proof-independent public statement JSON
        \\  --help, -h           Show this message
        \\
    , .{});
}

/// Decode-matrix mode for formal-model parity: canonical one-line-per-word
/// output compared against the pinned Sail decoder over the same corpus.
fn dumpDecodeMatrix(allocator: std.mem.Allocator, path: []const u8) !void {
    const raw = try std.fs.cwd().readFileAlloc(allocator, path, 64 * 1024 * 1024);
    defer allocator.free(raw);
    var out: std.ArrayList(u8) = .{};
    defer out.deinit(allocator);
    const writer = out.writer(allocator);
    var offset: usize = 0;
    while (offset + 4 <= raw.len) : (offset += 4) {
        const word = std.mem.readInt(u32, raw[offset..][0..4], .little);
        if (runner.DecodedInst.decode(word)) |inst| {
            try writer.print("{x:0>8} {s} {d} {d} {d} {d}\n", .{
                word,
                @tagName(inst.opcode),
                inst.rd,
                inst.rs1,
                inst.rs2,
                inst.imm,
            });
        } else |_| {
            try writer.print("{x:0>8} -\n", .{word});
        }
    }
    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };
    try stdout.writeAll(out.items);
}

/// Program-tuple mode for oracle parity: decode_program rows over the
/// declared region, canonical line format, byte-compared with the oracle.
fn dumpProgramTuples(allocator: std.mem.Allocator, path: []const u8) !void {
    const program_decode = @import("stwo_riscv_frontend").air.program.decode;
    const memory_mod = @import("stwo_riscv_frontend").runner.memory;
    const elf_loader = @import("stwo_riscv_frontend").runner.elf_loader;

    const elf_bytes = try std.fs.cwd().readFileAlloc(allocator, path, 64 * 1024 * 1024);
    defer allocator.free(elf_bytes);
    var mem = memory_mod.Memory.init(allocator);
    defer mem.deinit();
    const elf_info = try elf_loader.loadElf(elf_bytes, &mem);
    const layout = elf_info.memory_layout;

    var out: std.ArrayList(u8) = .{};
    defer out.deinit(allocator);
    const writer = out.writer(allocator);
    var addr: u32 = layout.program_base;
    while (addr < layout.program_end) : (addr += 4) {
        const word = mem.readU32(addr);
        const values = program_decode.decodeProgramWord(word) catch |err| {
            std.debug.print(
                "invalid declared program word: address=0x{x:0>8} word=0x{x:0>8}\n",
                .{ addr, word },
            );
            return err;
        };
        try writer.print("{x:0>8} {d} {d} {d} {d}\n", .{
            addr, values[0], values[1], values[2], values[3],
        });
    }
    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };
    try stdout.writeAll(out.items);
}

/// Poseidon2 permutation parity mode: 16-word LE states in, permuted states
/// out, byte-compared with the pinned oracle over the same corpus.
fn dumpPoseidon2(allocator: std.mem.Allocator, path: []const u8) !void {
    const poseidon2 = @import("stwo_riscv_frontend").air.memory_commitment.poseidon2;
    const M31 = @import("stwo_core").fields.m31.M31;

    const raw = try std.fs.cwd().readFileAlloc(allocator, path, 64 * 1024 * 1024);
    defer allocator.free(raw);
    var out: std.ArrayList(u8) = .{};
    defer out.deinit(allocator);
    const writer = out.writer(allocator);
    var offset: usize = 0;
    while (offset + 64 <= raw.len) : (offset += 64) {
        var state: poseidon2.State = undefined;
        for (0..16) |i| {
            const word = std.mem.readInt(u32, raw[offset + i * 4 ..][0..4], .little);
            state[i] = M31.fromU64(word);
        }
        poseidon2.permute(&state);
        for (state, 0..) |value, i| {
            if (i > 0) try writer.writeByte(' ');
            try writer.print("{d}", .{value.v});
        }
        try writer.writeByte('\n');
    }
    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };
    try stdout.writeAll(out.items);
}

/// Blake2s channel wrapper that records `mix_u32s len=N digest=<hex>` lines
/// after every mix step. `PublicData.mixInto` drives the sequence — this is
/// pure instrumentation, mirroring the oracle adapter's RecordingChannel.
/// The channel mix contract is infallible, so recording failures abort
/// rather than silently truncating the transcript.
const DigestRecorder = struct {
    channel: @import("stwo_core").channel.blake2s.Blake2sChannel = .{},
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),

    pub fn mixU32s(self: *DigestRecorder, values: []const u32) void {
        self.channel.mixU32s(values);
        const writer = self.out.writer(self.allocator);
        writer.print("mix_u32s len={d} ", .{values.len}) catch
            @panic("transcript prefix recording failed");
        self.appendDigest();
    }

    fn appendDigest(self: *DigestRecorder) void {
        const writer = self.out.writer(self.allocator);
        writer.print("digest=", .{}) catch
            @panic("transcript prefix recording failed");
        for (self.channel.digestBytes()) |byte| {
            writer.print("{x:0>2}", .{byte}) catch
                @panic("transcript prefix recording failed");
        }
        writer.print("\n", .{}) catch
            @panic("transcript prefix recording failed");
    }
};

/// Shared-transcript-prefix mode: run the ELF, build the prover-shaped
/// public data (with sparse-tree roots, exactly like the staged prover),
/// then replay the pinned Stark-V pre-commitment Fiat-Shamir prefix — a
/// default Blake2s channel seeded by `PublicData.mixInto` — printing the
/// channel digest after every mix step for byte comparison with the oracle.
fn dumpTranscriptPrefix(allocator: std.mem.Allocator, path: []const u8) !void {
    const elf_bytes = try std.fs.cwd().readFileAlloc(allocator, path, 64 * 1024 * 1024);
    defer allocator.free(elf_bytes);
    var run_result = try runner.run(allocator, elf_bytes, 10_000_000);
    defer run_result.deinit();
    var owned = try public_values_diagnostic.derive(allocator, &run_result);
    defer owned.deinit(allocator);

    var out: std.ArrayList(u8) = .{};
    defer out.deinit(allocator);
    var recorder = DigestRecorder{ .allocator = allocator, .out = &out };
    {
        const writer = out.writer(allocator);
        try writer.print("init ", .{});
    }
    recorder.appendDigest();
    owned.data.mixInto(&recorder);

    const stdout = std.fs.File{ .handle = std.posix.STDOUT_FILENO };
    try stdout.writeAll(out.items);
}
