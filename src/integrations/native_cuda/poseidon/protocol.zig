//! Protocol-stage contract and completed Native CUDA binding ledger.

const std = @import("std");
const telemetry = @import("../../../backends/cuda/runtime/telemetry.zig");

pub const Stage = telemetry.Stage;

pub const BindingKind = enum {
    protocol_derivation,
    resident_layout,
    proof_encoding,
    oracle_gate,
};

pub const State = enum {
    /// The resident driver owns and executes this boundary.
    resident,
    /// This is checked outside the CUDA-labelled product after its final read.
    external_gate,
};

pub const Binding = struct {
    id: []const u8,
    stage: Stage,
    kind: BindingKind,
    state: State,
    requirement: []const u8,
};

/// Complete v1 integration surface. Every resident entry is exercised by the
/// end-to-end CUDA proof; external gates consume only the final proof artifact.
pub const bindings = [_]Binding{
    .{
        .id = "pcs_config_transcript",
        .stage = .ingress,
        .kind = .protocol_derivation,
        .state = .resident,
        .requirement = "encode and mix the pinned PcsConfig words on device",
    },
    .{
        .id = "circle_twiddle_pack",
        .stage = .ingress,
        .kind = .resident_layout,
        .state = .resident,
        .requirement = "materialize forward and inverse twiddles once in the proof arena",
    },
    .{
        .id = "empty_preprocessed_commitment",
        .stage = .trace_commit,
        .kind = .protocol_derivation,
        .state = .resident,
        .requirement = "mix the canonical empty-tree root without a fake decommit tree",
    },
    .{
        .id = "main_retained_tree",
        .stage = .trace_commit,
        .kind = .resident_layout,
        .state = .resident,
        .requirement = "retain coefficients, LDE values, Merkle layers, and root by lifetime",
    },
    .{
        .id = "main_root_transcript",
        .stage = .trace_commit,
        .kind = .protocol_derivation,
        .state = .resident,
        .requirement = "mix the main root and the Native Poseidon statement in Rust order",
    },
    .{
        .id = "composition_challenge",
        .stage = .constraint_evaluation,
        .kind = .protocol_derivation,
        .state = .resident,
        .requirement = "draw the random coefficient into resident secure-field storage",
    },
    .{
        .id = "composition_split_commit",
        .stage = .constraint_evaluation,
        .kind = .resident_layout,
        .state = .resident,
        .requirement = "interpolate, split, commit, and retain eight composition columns",
    },
    .{
        .id = "composition_root_transcript",
        .stage = .constraint_evaluation,
        .kind = .protocol_derivation,
        .state = .resident,
        .requirement = "mix the composition root before drawing the OODS point",
    },
    .{
        .id = "oods_mask_topology",
        .stage = .oods,
        .kind = .protocol_derivation,
        .state = .resident,
        .requirement = "derive one point per main and split-composition column",
    },
    .{
        .id = "oods_values_transcript",
        .stage = .oods,
        .kind = .protocol_derivation,
        .state = .resident,
        .requirement = "mix sampled values in canonical tree/column/point order",
    },
    .{
        .id = "quotient_topology",
        .stage = .quotient,
        .kind = .resident_layout,
        .state = .resident,
        .requirement = "seal sample, term, group, source, and combine descriptors at ingress",
    },
    .{
        .id = "quotient_challenge",
        .stage = .quotient,
        .kind = .protocol_derivation,
        .state = .resident,
        .requirement = "draw and bind the quotient random coefficient",
    },
    .{
        .id = "fri_first_circle_layer",
        .stage = .fri_commit,
        .kind = .resident_layout,
        .state = .resident,
        .requirement = "commit the quotient coordinates and perform circle-to-line fold",
    },
    .{
        .id = "fri_line_layers",
        .stage = .fri_commit,
        .kind = .resident_layout,
        .state = .resident,
        .requirement = "commit and fold every line layer while retaining opening data",
    },
    .{
        .id = "fri_last_layer",
        .stage = .fri_commit,
        .kind = .protocol_derivation,
        .state = .resident,
        .requirement = "interpolate, degree-check, truncate, and mix the final polynomial",
    },
    .{
        .id = "pow_nonce_transcript",
        .stage = .pow,
        .kind = .protocol_derivation,
        .state = .resident,
        .requirement = "grind a bounded nonce and absorb it in the same transcript step",
    },
    .{
        .id = "query_draw",
        .stage = .decommit,
        .kind = .protocol_derivation,
        .state = .resident,
        .requirement = "draw raw queries only after PoW and retain raw ordering",
    },
    .{
        .id = "trace_openings",
        .stage = .decommit,
        .kind = .resident_layout,
        .state = .resident,
        .requirement = "open main and composition trees into the compact bundle",
    },
    .{
        .id = "fri_openings",
        .stage = .decommit,
        .kind = .resident_layout,
        .state = .resident,
        .requirement = "open every FRI tree with cumulative-fold topology",
    },
    .{
        .id = "canonical_stark_proof_encoding",
        .stage = .proof_assembly,
        .kind = .proof_encoding,
        .state = .resident,
        .requirement = "decode the one D2H bundle into canonical Zig proof bytes",
    },
    .{
        .id = "zig_cpu_byte_parity",
        .stage = .proof_assembly,
        .kind = .oracle_gate,
        .state = .external_gate,
        .requirement = "require byte-identical Native CPU and CUDA proofs",
    },
    .{
        .id = "pinned_rust_verifier",
        .stage = .proof_assembly,
        .kind = .oracle_gate,
        .state = .external_gate,
        .requirement = "require acceptance by the pinned Rust Stwo oracle",
    },
};

pub const execution_stages = [_]Stage{
    .trace_generation,
    .trace_commit,
    .constraint_evaluation,
    .oods,
    .quotient,
    .fri_commit,
    .pow,
    .decommit,
};

pub fn assertLedger() void {
    for (bindings, 0..) |binding, index| {
        std.debug.assert(binding.id.len != 0);
        for (bindings[0..index]) |previous| {
            std.debug.assert(!std.mem.eql(u8, previous.id, binding.id));
        }
        if (index != 0) {
            std.debug.assert(
                bindings[index - 1].stage.index() <= binding.stage.index(),
            );
        }
    }
    for (execution_stages, 0..) |stage, index| {
        std.debug.assert(stage.requiresKernel());
        if (index != 0) {
            std.debug.assert(
                execution_stages[index - 1].index() + 1 == stage.index(),
            );
        }
    }
}

test "binding ledger is unique and follows transcript order" {
    assertLedger();
    try std.testing.expectEqual(@as(usize, 22), bindings.len);
    try std.testing.expectEqual(
        Stage.trace_generation,
        execution_stages[0],
    );
    try std.testing.expectEqual(Stage.decommit, execution_stages[7]);
}
