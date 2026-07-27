//! Test-only export of a proving run's committed opcode trace and its LogUp
//! inputs, for the independent Python row checker (`scripts/air_satisfaction.py`).
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
//!   * the opcode witness may carry a `test_witness_hook` forgery, which is
//!     applied inside the run and must be visible to the checker exactly as the
//!     commitment saw it.
//!
//! ## What "committed" means here, precisely
//!
//! `record` reads `workspace.opcode_columns`, the buffers `main_trace`'s
//! `copyOpcodeColumns` duplicated verbatim (`allocator.dupe`) into the Tree-1
//! column array that was handed to `Engine.commit`. Nothing writes them after
//! that copy, so the exported values are bit-identical to the committed opcode
//! prefix of Tree 1. That is a code-level identity, not a cryptographic one:
//! this export does not recompute the Merkle root, so a consumer of the JSON
//! knows the values came from the prover's committed buffers and not that they
//! are the values the *proof* opens.
//!
//! Rows are exported in COMMITTED (bit-reversed) order, deliberately. Undoing
//! that permutation is the reader's job, so a bit-reversal placement bug cannot
//! be cancelled by the same bug on both sides.
//!
//! Ownership: `record` borrows everything and owns only its JSON buffer.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

const opcode_trace = @import("opcode_trace.zig");
const public_data_mod = @import("../air/public_data.zig");
const relation_challenges = @import("../air/relation_challenges.zig");
const statement_mod = @import("../air/statement.zig");

const MODULUS: u32 = (1 << 31) - 1;

/// Bumped whenever a field changes meaning. `air_satisfaction_lib.dump` refuses
/// any other value rather than guessing at a layout it was not written for.
pub const SCHEMA: []const u8 = "riscv-committed-trace/1";

pub const Capture = struct {
    allocator: std.mem.Allocator,
    json: std.ArrayList(u8) = .{},
    recorded: bool = false,

    pub fn init(allocator: std.mem.Allocator) Capture {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Capture) void {
        self.json.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn bytes(self: *const Capture) []const u8 {
        return self.json.items;
    }

    pub fn writeTo(self: *const Capture, dir_path: []const u8, name: []const u8) !void {
        if (!self.recorded) return error.NothingRecorded;
        std.fs.cwd().makePath(dir_path) catch {};
        var dir = try std.fs.cwd().openDir(dir_path, .{});
        defer dir.close();
        try dir.writeFile(.{ .sub_path = name, .data = self.json.items });
    }

    /// Serialises one proving run. Called once, from `orchestration.proveStages`,
    /// after the interaction claim exists and before the proof is assembled.
    pub fn record(
        self: *Capture,
        statement: *const statement_mod.RiscVStatement,
        columns: *const opcode_trace.Columns,
        relations: *const relation_challenges.Relations,
        claim: *const statement_mod.RiscVInteractionClaim,
    ) !void {
        // A second record would silently describe a different run under the
        // same handle, and the caller could not tell which one it read.
        if (self.recorded) return error.AlreadyRecorded;
        const w = self.json.writer(self.allocator);
        try w.print(
            "{{\n  \"schema\": \"{s}\",\n  \"modulus\": {d},\n",
            .{ SCHEMA, MODULUS },
        );
        try writePublicData(w, &statement.public_data);
        try writeRelations(w, relations);
        try writeClaims(w, statement, claim);
        try writeComponents(w, statement, columns);
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
    try w.writeAll("    ]\n  },\n");
}

fn writeComponents(
    w: anytype,
    statement: *const statement_mod.RiscVStatement,
    columns: *const opcode_trace.Columns,
) !void {
    try w.writeAll("  \"components\": [\n");
    for (0..statement.n_components) |index| {
        const desc = statement.component_descs[index];
        const component = &columns.components[index];
        if (component.n_columns != desc.n_columns) return error.InvalidTraceShape;
        try w.print(
            "    {{\"family\": \"{s}\", \"index\": {d}, \"log_size\": {d}, \"n_rows\": {d}, \"n_columns\": {d},\n     \"columns\": [\n",
            .{ @tagName(desc.family), index, desc.log_size, desc.n_rows, desc.n_columns },
        );
        for (component.columns[0..component.n_columns], 0..) |values, column| {
            try writeColumn(w, values, column + 1 == component.n_columns);
        }
        try w.print("     ]}}{s}\n", .{if (index + 1 == statement.n_components) "" else ","});
    }
    try w.writeAll("  ]\n");
}

fn writeColumn(w: anytype, values: []const M31, last: bool) !void {
    try w.writeAll("      [");
    for (values, 0..) |value, row| {
        try w.print("{d}{s}", .{ value.toU32(), if (row + 1 == values.len) "" else "," });
    }
    try w.print("]{s}\n", .{if (last) "" else ","});
}
