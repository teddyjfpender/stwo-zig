//! CPU differential runner for source-derived Cairo base-trace components.

const std = @import("std");
const adapter = @import("../adapter/mod.zig");
const claim_registry = @import("../air/official_claim_registry.zig");
const witness_bundle = @import("../witness/bundle.zig");
const direct_inputs = @import("../witness/direct_inputs.zig");
const component_executor = @import("../witness/component_executor.zig");
const verify_instruction_inputs = @import("../witness/verify_instruction_inputs.zig");
const program = @import("../witness/program.zig");
const checkpoint = @import("checkpoint.zig");
const receipt = @import("receipt.zig");

/// The compilable Rust base-trace oracle is distinct from the final verifier
/// Stwo revision carried by `claim_registry.source_revision.stwo`.
pub const trace_oracle_stwo_revision = "3fe684648ff31e55b71525ad689fab7dfbd88880";
pub const trace_oracle_authority = receipt.Authority{
    .stwo_cairo_revision = claim_registry.source_revision.stwo_cairo,
    .stwo_revision = trace_oracle_stwo_revision,
};

pub const Match = struct {
    ordinal: u32,
    label: []const u8,
    row_count: u64,
    column_count: u32,
};

pub const MismatchKind = component_executor.MismatchKind;
pub const Mismatch = component_executor.Mismatch;

pub const Report = struct {
    allocator: std.mem.Allocator,
    matches: []Match,
    skipped_components: usize,
    mismatch: ?Mismatch,

    pub fn deinit(self: *Report) void {
        self.allocator.free(self.matches);
        self.* = undefined;
    }
};

pub const Error = error{
    MissingWitnessProgram,
    WitnessInputCountMismatch,
    InvalidReceiptGeometry,
    AllocationSizeOverflow,
};

/// Compares directly seeded components and the compacted `verify_instruction`
/// consumer. Receipt order is authoritative; bundle order is never observed
/// except to locate a program by label.
pub fn compare(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    bundle: *const witness_bundle.Bundle,
    expected_components: []const checkpoint.Component,
) !Report {
    var matches = std.ArrayList(Match).empty;
    errdefer matches.deinit(allocator);
    var skipped_components: usize = 0;

    for (expected_components) |expected| {
        if (std.mem.eql(u8, expected.label, "verify_instruction")) {
            var compact = try verify_instruction_inputs.gather(allocator, input);
            defer compact.deinit();
            if (try compareComponent(allocator, input, try entryProgram(bundle, expected.label), compact, expected)) |mismatch| {
                return .{
                    .allocator = allocator,
                    .matches = try matches.toOwnedSlice(allocator),
                    .skipped_components = skipped_components,
                    .mismatch = mismatch,
                };
            }
            try appendMatch(allocator, &matches, expected);
            continue;
        }
        const direct = try direct_inputs.resolve(input, expected.label) orelse {
            skipped_components += 1;
            continue;
        };
        if (try compareComponent(allocator, input, try entryProgram(bundle, expected.label), direct, expected)) |mismatch| {
            return .{
                .allocator = allocator,
                .matches = try matches.toOwnedSlice(allocator),
                .skipped_components = skipped_components,
                .mismatch = mismatch,
            };
        }
        try appendMatch(allocator, &matches, expected);
    }

    return .{
        .allocator = allocator,
        .matches = try matches.toOwnedSlice(allocator),
        .skipped_components = skipped_components,
        .mismatch = null,
    };
}

fn entryProgram(bundle: *const witness_bundle.Bundle, label: []const u8) Error!program.Program {
    const entry = bundle.find(label) orelse return Error.MissingWitnessProgram;
    return entry.program;
}

fn appendMatch(allocator: std.mem.Allocator, matches: *std.ArrayList(Match), expected: checkpoint.Component) !void {
    try matches.append(allocator, .{
        .ordinal = expected.ordinal,
        .label = expected.label,
        .row_count = expected.columns[0].row_count,
        .column_count = @intCast(expected.columns.len),
    });
}

fn compareComponent(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    witness_program: program.Program,
    source: anytype,
    expected: checkpoint.Component,
) !?Mismatch {
    if (expected.columns.len != witness_program.n_cols) return .{
        .kind = .column_count,
        .component_ordinal = expected.ordinal,
        .component_label = expected.label,
        .expected_count = expected.columns.len,
        .actual_count = witness_program.n_cols,
    };
    var execution = try component_executor.execute(
        allocator,
        input,
        witness_program,
        source,
        expected,
    );
    defer execution.deinit();
    return execution.compare(expected);
}

fn testInput(
    grouped: @import("../adapter/opcodes.zig").CasmStatesByOpcode,
    addresses: []@import("../common/memory.zig").EncodedMemoryValueId,
) adapter.ProverInput {
    return .{
        .state_transitions = .{
            .initial_state = undefined,
            .final_state = undefined,
            .casm_states_by_opcode = grouped,
        },
        .memory = .{
            .config = .{},
            .address_to_id = addresses,
            .f252_values = &.{},
            .small_values = &.{ 0, 0, 0, 0 },
        },
        .pc_count = 0,
        .public_memory_addresses = &.{},
        .builtin_segments = .{},
        .public_segment_context = [_]bool{false} ** adapter.N_PUBLIC_SEGMENTS,
    };
}

test "Cairo direct trace: receipt ordinal drives CPU column hashing" {
    const M31 = @import("stwo_core").fields.m31.M31;
    const opcodes = @import("../adapter/opcodes.zig");
    var grouped = opcodes.CasmStatesByOpcode.init(std.testing.allocator);
    defer grouped.deinit(std.testing.allocator);
    try grouped.get(.ret_opcode).append(std.testing.allocator, .{
        .pc = M31.fromCanonical(11),
        .ap = M31.fromCanonical(12),
        .fp = M31.fromCanonical(13),
    });
    const memory_mod = @import("../common/memory.zig");
    var addresses = [_]memory_mod.EncodedMemoryValueId{memory_mod.EncodedMemoryValueId.EMPTY} ** 12;
    addresses[11] = memory_mod.EncodedMemoryValueId.small(3);
    var input = testInput(grouped, &addresses);

    const insts = [_]program.Inst{
        .{ .op = @intFromEnum(program.Op.input), .dst = 0, .a = 0, .b = 0, .imm = 0 },
        .{ .op = @intFromEnum(program.Op.table_limb), .dst = 1, .a = 0, .b = 0, .imm = 0 },
        .{ .op = @intFromEnum(program.Op.col_write), .dst = 0, .a = 1, .b = 0, .imm = 0 },
    };
    var entries = [_]witness_bundle.Entry{.{
        .label = @constCast("ret_opcode"),
        .semantic_hash = 0,
        .program = .{
            .insts = &insts,
            .n_regs = 2,
            .n_inputs = 4,
            .n_cols = 1,
            .n_mult_tables = 0,
            .n_lookup_words = 0,
            .n_sub_words = 0,
        },
    }};
    const bundle = witness_bundle.Bundle{ .allocator = std.testing.allocator, .entries = &entries };
    const unsupported_columns = [_]checkpoint.Column{.{
        .ordinal = 0,
        .row_count = 16,
        .sha256 = [_]u8{0} ** 32,
    }};
    const values = [_]u32{3} ** 16;
    const ret_columns = [_]checkpoint.Column{.{
        .ordinal = 0,
        .row_count = 16,
        .sha256 = try checkpoint.digestColumn(1, "ret_opcode", 0, &values),
    }};
    const components = [_]checkpoint.Component{
        .{ .ordinal = 0, .label = "range_check_6", .columns = &unsupported_columns, .accumulator = undefined },
        .{ .ordinal = 1, .label = "ret_opcode", .columns = &ret_columns, .accumulator = undefined },
    };

    var report = try compare(std.testing.allocator, &input, &bundle, &components);
    defer report.deinit();
    try std.testing.expect(report.mismatch == null);
    try std.testing.expectEqual(@as(usize, 1), report.skipped_components);
    try std.testing.expectEqual(@as(usize, 1), report.matches.len);
    try std.testing.expectEqual(@as(u32, 1), report.matches[0].ordinal);
}

test "Cairo direct trace: comparison stops at the first digest mismatch" {
    const M31 = @import("stwo_core").fields.m31.M31;
    const opcodes = @import("../adapter/opcodes.zig");
    var grouped = opcodes.CasmStatesByOpcode.init(std.testing.allocator);
    defer grouped.deinit(std.testing.allocator);
    try grouped.get(.ret_opcode).append(std.testing.allocator, .{
        .pc = M31.fromCanonical(11),
        .ap = M31.fromCanonical(12),
        .fp = M31.fromCanonical(13),
    });
    const memory_mod = @import("../common/memory.zig");
    var addresses = [_]memory_mod.EncodedMemoryValueId{memory_mod.EncodedMemoryValueId.EMPTY} ** 12;
    var input = testInput(grouped, &addresses);
    const insts = [_]program.Inst{
        .{ .op = @intFromEnum(program.Op.input), .dst = 0, .a = 0, .b = 0, .imm = 0 },
        .{ .op = @intFromEnum(program.Op.col_write), .dst = 0, .a = 0, .b = 0, .imm = 0 },
    };
    var entries = [_]witness_bundle.Entry{.{
        .label = @constCast("ret_opcode"),
        .semantic_hash = 0,
        .program = .{ .insts = &insts, .n_regs = 1, .n_inputs = 4, .n_cols = 1, .n_mult_tables = 0, .n_lookup_words = 0, .n_sub_words = 0 },
    }};
    const bundle = witness_bundle.Bundle{ .allocator = std.testing.allocator, .entries = &entries };
    const columns = [_]checkpoint.Column{.{ .ordinal = 0, .row_count = 16, .sha256 = [_]u8{0} ** 32 }};
    const components = [_]checkpoint.Component{.{
        .ordinal = 0,
        .label = "ret_opcode",
        .columns = &columns,
        .accumulator = undefined,
    }};

    var report = try compare(std.testing.allocator, &input, &bundle, &components);
    defer report.deinit();
    try std.testing.expectEqual(@as(usize, 0), report.matches.len);
    const mismatch = report.mismatch orelse return error.ExpectedMismatch;
    try std.testing.expectEqual(MismatchKind.column_digest, mismatch.kind);
    try std.testing.expectEqual(@as(u32, 0), mismatch.component_ordinal);
    try std.testing.expectEqual(@as(?u32, 0), mismatch.column_ordinal);
}
