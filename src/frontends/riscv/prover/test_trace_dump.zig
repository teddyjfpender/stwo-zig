//! Test-only export of a proving run's complete committed main trace and its
//! LogUp inputs, for the independent Python checker
//! (`scripts/air_satisfaction.py`).
//!
//! ## Why this lives on the proving path
//!
//! Three of the four things the Python checker needs cannot be reconstructed
//! outside a real proving run:
//!
//!   * the relation challenges `(z, alpha)` are drawn from the Fiat-Shamir
//!     channel after Tree 0 and Tree 1 are committed, so nothing outside the
//!     transcript can produce them;
//!   * the interaction claims are the prover's own accumulated LogUp sums;
//!   * the witness may carry a `test_witness_hook` forgery, which is applied
//!     inside the run and must be visible to the checker exactly as the
//!     commitment saw it.
//!
//! ## What "committed" means here, precisely
//!
//! `recordMain` serialises the exact complete `ColumnEvaluation` array after
//! every test mutation and immediately before that array is handed to
//! `Engine.commit`. Nothing is regenerated: opcode, program, RW-memory,
//! Merkle, Poseidon2, clock-update, and lookup-multiplicity values all come
//! from the same Tree-1 buffers. This is a code-level identity, not a
//! cryptographic one: the export does not recompute the Merkle root, so a
//! consumer knows which buffers the prover committed but not that they are the
//! values the proof opens.
//!
//! Rows are exported in COMMITTED (bit-reversed) order, deliberately. Undoing
//! that permutation is the reader's job, so a bit-reversal placement bug cannot
//! be cancelled by the same bug on both sides.
//!
//! The six lookup multiplicity columns have domains as large as 2^20 and are
//! overwhelmingly zero, so they use an exact sparse committed-index encoding.
//! Every other column is dense. The reader undoes the placement in both cases.
//!
//! Ownership: both record methods borrow everything and own only JSON buffers.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const prover_pcs = @import("stwo_prover_engine").pcs;

const public_data_mod = @import("../air/public_data.zig");
const relation_challenges = @import("../air/relation_challenges.zig");
const statement_mod = @import("../air/statement.zig");
const transcript_claims = @import("../air/transcript/claims.zig");

const MODULUS: u32 = (1 << 31) - 1;

/// Bumped whenever a field changes meaning. `air_satisfaction_lib.dump` refuses
/// any other value rather than guessing at a layout it was not written for.
pub const SCHEMA: []const u8 = "riscv-committed-trace/2";

pub const Capture = struct {
    allocator: std.mem.Allocator,
    json: std.ArrayList(u8) = .{},
    main_json: std.ArrayList(u8) = .{},
    opcode_component_count: usize = 0,
    infra_component_count: usize = 0,
    main_recorded: bool = false,
    recorded: bool = false,

    pub fn init(allocator: std.mem.Allocator) Capture {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Capture) void {
        self.json.deinit(self.allocator);
        self.main_json.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn bytes(self: *const Capture) []const u8 {
        return self.json.items;
    }

    pub fn nOpcodeComponents(self: *const Capture) usize {
        return self.opcode_component_count;
    }

    pub fn nInfraComponents(self: *const Capture) usize {
        return self.infra_component_count;
    }

    pub fn nMainComponents(self: *const Capture) usize {
        return self.opcode_component_count + self.infra_component_count;
    }

    pub fn writeTo(self: *const Capture, dir_path: []const u8, name: []const u8) !void {
        if (!self.recorded) return error.NothingRecorded;
        std.fs.cwd().makePath(dir_path) catch {};
        var dir = try std.fs.cwd().openDir(dir_path, .{});
        defer dir.close();
        try dir.writeFile(.{ .sub_path = name, .data = self.json.items });
    }

    /// Serialises the exact Tree-1 buffers at the commitment boundary.
    pub fn recordMain(
        self: *Capture,
        statement: *const statement_mod.RiscVStatement,
        columns: []const prover_pcs.ColumnEvaluation,
    ) !void {
        if (self.main_recorded) return error.AlreadyRecorded;
        if (columns.len != @as(usize, statement.nMainColumns()))
            return error.InvalidTraceShape;

        const w = self.main_json.writer(self.allocator);
        try w.writeAll("  \"components\": [\n");
        var offset: usize = 0;
        var component_number: usize = 0;
        const component_count: usize =
            @as(usize, statement.n_components) + @as(usize, statement.n_infra);
        for (0..statement.n_components) |index| {
            const desc = statement.component_descs[index];
            const n_columns: usize = @intCast(desc.n_columns);
            try writeComponent(
                w,
                "opcode",
                @tagName(desc.family),
                index,
                desc.log_size,
                desc.n_rows,
                desc.n_columns,
                columns[offset..][0..n_columns],
                false,
                component_number + 1 == component_count,
            );
            offset += n_columns;
            component_number += 1;
        }
        for (0..statement.n_infra) |index| {
            const desc = statement.infra_descs[index];
            const n_columns: usize = @intCast(desc.n_columns);
            try writeComponent(
                w,
                "infra",
                @tagName(desc.kind),
                index,
                desc.log_size,
                desc.n_rows,
                desc.n_columns,
                columns[offset..][0..n_columns],
                statement_mod.tableKind(desc.kind) != null,
                component_number + 1 == component_count,
            );
            offset += n_columns;
            component_number += 1;
        }
        if (offset != columns.len or component_number != component_count)
            return error.InvalidTraceShape;
        try w.writeAll("  ]\n");
        self.opcode_component_count = statement.n_components;
        self.infra_component_count = statement.n_infra;
        self.main_recorded = true;
    }

    /// Serialises one proving run. Called once, from `orchestration.proveStages`,
    /// after the interaction claim exists and before the proof is assembled.
    pub fn record(
        self: *Capture,
        statement: *const statement_mod.RiscVStatement,
        relations: *const relation_challenges.Relations,
        claim: *const statement_mod.RiscVInteractionClaim,
    ) !void {
        // A second record would silently describe a different run under the
        // same handle, and the caller could not tell which one it read.
        if (self.recorded) return error.AlreadyRecorded;
        if (!self.main_recorded) return error.MainTraceNotRecorded;
        const w = self.json.writer(self.allocator);
        try w.print(
            "{{\n  \"schema\": \"{s}\",\n  \"modulus\": {d},\n",
            .{ SCHEMA, MODULUS },
        );
        try writePublicData(w, &statement.public_data);
        try writeRelations(w, relations);
        try writeClaims(w, statement, claim);
        try w.writeAll(self.main_json.items);
        try w.writeAll("}\n");
        self.recorded = true;
    }
};

fn writeSecure(w: anytype, value: QM31) !void {
    const parts = value.toM31Array();
    try w.print("[{d}, {d}, {d}, {d}]", .{
        parts[0].toU32(), parts[1].toU32(), parts[2].toU32(), parts[3].toU32(),
    });
}

fn writeOptionalU32(w: anytype, value: ?u32) !void {
    if (value) |present| try w.print("{d}", .{present}) else try w.writeAll("null");
}

fn writeU32Array(w: anytype, values: []const u32) !void {
    try w.writeAll("[");
    for (values, 0..) |value, index| {
        try w.print("{d}{s}", .{ value, if (index + 1 == values.len) "" else ", " });
    }
    try w.writeAll("]");
}

fn writePublicData(w: anytype, data: *const public_data_mod.PublicData) !void {
    try w.print(
        "  \"public_data\": {{\n    \"initial_pc\": {d},\n    \"final_pc\": {d},\n    \"clock\": {d},\n",
        .{ data.initial_pc, data.final_pc, data.clock },
    );
    try w.writeAll("    \"initial_regs\": ");
    try writeU32Array(w, &data.initial_regs);
    try w.writeAll(",\n    \"final_regs\": ");
    try writeU32Array(w, &data.final_regs);
    try w.writeAll(",\n    \"reg_last_clock\": ");
    try writeU32Array(w, &data.reg_last_clock);
    try w.writeAll(",\n    \"program_root\": ");
    try writeOptionalU32(w, data.program_root);
    try w.writeAll(",\n    \"initial_rw_root\": ");
    try writeOptionalU32(w, data.initial_rw_root);
    try w.writeAll(",\n    \"final_rw_root\": ");
    try writeOptionalU32(w, data.final_rw_root);
    try w.writeAll(",\n    \"completion\": ");
    if (data.completion) |completion| {
        try w.print(
            "{{\"kind\": \"{s}\", \"address\": {d}, \"value\": {d}, \"clock\": {d}}}",
            .{ @tagName(completion.kind), completion.address, completion.value, completion.clock },
        );
    } else try w.writeAll("null");
    try writeIoEntries(w, data.io_entries);
    try w.writeAll("\n  },\n");
}

fn writeIoEntries(w: anytype, io: public_data_mod.IoEntries) !void {
    try w.print(
        ",\n    \"io_entries\": {{\n      \"input_start\": {d},\n      \"input_len\": {d},\n      \"input_words\": ",
        .{ io.input_start, io.input_len },
    );
    try writeU32Array(w, io.input_words);
    try w.print(
        ",\n      \"output_len\": {d},\n      \"output_len_addr\": {d},\n      \"output_data_addr\": {d},\n      \"output_words\": [",
        .{ io.output_len, io.output_len_addr, io.output_data_addr },
    );
    for (io.output_words, 0..) |word, index| {
        try w.print("{{\"addr\": {d}, \"value\": {d}, \"clock\": {d}}}{s}", .{
            word.addr,                                          word.value, word.clock,
            if (index + 1 == io.output_words.len) "" else ", ",
        });
    }
    try w.writeAll("]\n    }");
}

/// Relation names are the `entry.Domain` tags, which are also the domain names
/// the extracted IR uses for its lookup requests. One spelling, both files.
fn writeRelations(w: anytype, relations: *const relation_challenges.Relations) !void {
    try w.writeAll("  \"relations\": {\n");
    const fields = @typeInfo(relation_challenges.Relations).@"struct".fields;
    inline for (fields, 0..) |field, index| {
        const elements = @field(relations, field.name);
        try w.print("    \"{s}\": {{\"z\": ", .{field.name});
        try writeSecure(w, elements.z);
        try w.writeAll(", \"alpha\": ");
        try writeSecure(w, elements.alpha);
        try w.print("}}{s}\n", .{if (index + 1 == fields.len) "" else ","});
    }
    try w.writeAll("  },\n");
}

/// Per-component claimed sums, never their total: the reader adds them up, so
/// the closure it reports is its own arithmetic and not a copy of the prover's.
fn writeClaims(
    w: anytype,
    statement: *const statement_mod.RiscVStatement,
    claim: *const statement_mod.RiscVInteractionClaim,
) !void {
    try w.writeAll("  \"claims\": {\n    \"opcode\": [\n");
    for (0..statement.n_components) |index| {
        const desc = statement.component_descs[index];
        try w.print("      {{\"family\": \"{s}\", \"index\": {d}, \"total\": ", .{
            @tagName(desc.family), index,
        });
        try writeSecure(w, try claim.opcodeClaimTotal(desc.family, index));
        try w.print("}}{s}\n", .{if (index + 1 == statement.n_components) "" else ","});
    }
    try w.writeAll("    ],\n    \"infra\": [\n");
    for (0..statement.n_infra) |index| {
        const desc = statement.infra_descs[index];
        try w.print("      {{\"kind\": \"{s}\", \"index\": {d}, \"total\": ", .{
            @tagName(desc.kind), index,
        });
        try writeSecure(w, try claim.infraClaimTotal(desc.kind, index));
        try w.print("}}{s}\n", .{if (index + 1 == statement.n_infra) "" else ","});
    }
    try w.writeAll("    ],\n    \"transcript\": [\n");
    const canonical = try claim.canonical(statement);
    const components = @typeInfo(transcript_claims.Component).@"enum".fields;
    inline for (components, 0..) |component, index| {
        try w.print("      {{\"component\": \"{s}\", \"index\": {d}, \"total\": ", .{
            component.name, index,
        });
        try writeSecure(w, canonical.claimed_sums[index]);
        try w.print("}}{s}\n", .{if (index + 1 == components.len) "" else ","});
    }
    try w.writeAll("    ]\n  },\n");
}

fn writeComponent(
    w: anytype,
    class: []const u8,
    label: []const u8,
    index: usize,
    log_size: u32,
    n_rows: u32,
    n_columns: u32,
    columns: []const prover_pcs.ColumnEvaluation,
    sparse: bool,
    last: bool,
) !void {
    const domain_size = @as(usize, 1) << @intCast(log_size);
    if (columns.len != n_columns) return error.InvalidTraceShape;
    for (columns) |column| {
        if (column.log_size != log_size or column.values.len != domain_size)
            return error.InvalidTraceShape;
    }
    try w.print(
        "    {{\"class\": \"{s}\", \"label\": \"{s}\", \"index\": {d}, \"log_size\": {d}, \"n_rows\": {d}, \"n_columns\": {d},\n     \"encoding\": \"{s}\", \"columns\": [\n",
        .{
            class,
            label,
            index,
            log_size,
            n_rows,
            n_columns,
            if (sparse) "sparse_committed" else "dense_committed",
        },
    );
    for (columns, 0..) |column, column_index| {
        if (sparse)
            try writeSparseColumn(w, column.values, column_index + 1 == columns.len)
        else
            try writeDenseColumn(w, column.values, column_index + 1 == columns.len);
    }
    try w.print("     ]}}{s}\n", .{if (last) "" else ","});
}

fn writeDenseColumn(w: anytype, values: []const M31, last: bool) !void {
    try w.writeAll("      [");
    for (values, 0..) |value, row| {
        try w.print("{d}{s}", .{ value.toU32(), if (row + 1 == values.len) "" else "," });
    }
    try w.print("]{s}\n", .{if (last) "" else ","});
}

fn writeSparseColumn(w: anytype, values: []const M31, last: bool) !void {
    try w.writeAll("      [");
    var written: usize = 0;
    for (values, 0..) |value, committed_row| {
        if (value.isZero()) continue;
        if (written != 0) try w.writeAll(",");
        try w.print("[{d},{d}]", .{ committed_row, value.toU32() });
        written += 1;
    }
    try w.print("]{s}\n", .{if (last) "" else ","});
}
