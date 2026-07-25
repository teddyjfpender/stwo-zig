//! Explicit development admission map from Cairo proof nodes to CUDA work.

const std = @import("std");
const backend = @import("stwo_backend_contracts");

const ir = backend.proof_program;

pub const Authority = enum {
    zig_owned,
    copied_reference,
    proof_derived,
};

pub const Admission = enum {
    admitted_development,
    reusable_ready,
    blocked,
};

pub const Entry = struct {
    kind: ir.OperationKind,
    stage: ir.Stage,
    label: []const u8,
    symbol: ?[]const u8,
    source: []const u8,
    metal_reference: []const u8,
    authority: Authority,
    admission: Admission,
    blocker: ?[]const u8,
};

pub const entries = [_]Entry{
    .{
        .kind = .trace_generation,
        .stage = .trace_generation,
        .label = "canonical CASM state scatter",
        .symbol = "stwo_witness_casm_input_scatter_on",
        .source = "src/backends/cuda/native/cairo/casm_input.cu",
        .metal_reference = "src/integrations/cairo_metal/resident/witness/inputs.zig",
        .authority = .zig_owned,
        .admission = .admitted_development,
        .blocker = null,
    },
    .{
        .kind = .trace_generation,
        .stage = .trace_generation,
        .label = "Cairo component witness writers",
        .symbol = null,
        .source = "src/backends/cuda/vendor/upstream/generated",
        .metal_reference = "src/integrations/cairo_metal/resident/witness/execute.zig",
        .authority = .copied_reference,
        .admission = .blocked,
        .blocker = "authenticated source AIR writers and fixed-table binding",
    },
    .{
        .kind = .commitment,
        .stage = .trace_commit,
        .label = "resident circle transform and Merkle commitment",
        .symbol = null,
        .source = "src/backends/cuda/native/transform + commitment",
        .metal_reference = "src/integrations/cairo_metal/resident/trace/interpolation.zig",
        .authority = .zig_owned,
        .admission = .reusable_ready,
        .blocker = "Cairo trace-column residency binding",
    },
    .{
        .kind = .constraint_evaluation,
        .stage = .constraint_evaluation,
        .label = "Cairo AIR component constraints and interactions",
        .symbol = null,
        .source = "src/backends/cuda/vendor/upstream/generated",
        .metal_reference = "src/integrations/cairo_metal/resident/interaction/execute.zig",
        .authority = .copied_reference,
        .admission = .blocked,
        .blocker = "authenticated source AIR and interaction lowering",
    },
    .{
        .kind = .oods,
        .stage = .oods,
        .label = "compact mixed-source OODS schedule",
        .symbol = null,
        .source = "src/backends/cuda/runtime/stages/oods_batches.zig",
        .metal_reference = "src/integrations/cairo_metal/oods.zig",
        .authority = .zig_owned,
        .admission = .reusable_ready,
        .blocker = "Cairo sampled-value topology binding",
    },
    .{
        .kind = .quotient,
        .stage = .quotient,
        .label = "compact mixed-height quotient sources",
        .symbol = "stwo_accumulate_quotient_numerator_compact_on",
        .source = "src/backends/cuda/native/quotient/numerator.cu",
        .metal_reference = "src/integrations/cairo_metal/quotient_inputs.zig",
        .authority = .zig_owned,
        .admission = .reusable_ready,
        .blocker = "Cairo composition-term lowering",
    },
    .{
        .kind = .fri_commit,
        .stage = .fri_commit,
        .label = "resident FRI fold and commitment",
        .symbol = null,
        .source = "src/backends/cuda/native/fri + commitment",
        .metal_reference = "src/integrations/cairo_metal/arena_binding.zig",
        .authority = .zig_owned,
        .admission = .reusable_ready,
        .blocker = "authenticated Cairo proof prefix",
    },
    .{
        .kind = .pow,
        .stage = .pow,
        .label = "resident Blake2s proof of work",
        .symbol = "stwo_blake2s_pow_persistent_on",
        .source = "src/backends/cuda/native/pow/search.cu",
        .metal_reference = "src/integrations/cairo_metal/resident/transcript/operations.zig",
        .authority = .zig_owned,
        .admission = .reusable_ready,
        .blocker = "authenticated Cairo transcript prefix",
    },
    .{
        .kind = .decommit,
        .stage = .decommit,
        .label = "resident query planning and decommitment",
        .symbol = null,
        .source = "src/backends/cuda/native/decommit",
        .metal_reference = "src/integrations/cairo_metal/runtime_decommit_geometry.zig",
        .authority = .zig_owned,
        .admission = .reusable_ready,
        .blocker = "authenticated Cairo commitment and query bindings",
    },
};

pub fn firstExecutable() *const Entry {
    for (&entries) |*entry| {
        if (entry.admission == .admitted_development) return entry;
    }
    unreachable;
}

pub fn productionReadyCount() usize {
    return 0;
}

test "lowering map is complete and fails closed" {
    inline for (@typeInfo(ir.OperationKind).@"enum".fields) |field| {
        const kind: ir.OperationKind = @enumFromInt(field.value);
        var found = false;
        for (entries) |entry| {
            if (entry.kind == kind) found = true;
        }
        try std.testing.expect(found);
    }
    try std.testing.expectEqualStrings(
        "stwo_witness_casm_input_scatter_on",
        firstExecutable().symbol.?,
    );
    try std.testing.expectEqual(@as(usize, 0), productionReadyCount());
    var admitted: usize = 0;
    for (entries) |entry| {
        if (entry.admission == .admitted_development) admitted += 1;
        if (entry.authority == .copied_reference)
            try std.testing.expect(entry.admission == .blocked);
    }
    try std.testing.expectEqual(@as(usize, 1), admitted);
}
