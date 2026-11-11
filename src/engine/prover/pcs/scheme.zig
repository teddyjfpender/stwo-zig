//! Stateful PCS commitment, opening, and proof orchestration.

const std = @import("std");
const builtin = @import("builtin");
const backend_merkle = @import("stwo_backend_contracts").merkle_ops;
const circle = @import("stwo_core").circle;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const core_fri = @import("stwo_core").fri;
const pcs_core = @import("stwo_core").pcs;
const verifier_types = @import("stwo_core").verifier_types;
const vcs_verifier = @import("stwo_core").vcs_lifted.verifier;
const canonic = @import("stwo_core").poly.circle.canonic;
const prover_circle = @import("../poly/circle/mod.zig");
const twiddle_source_mod = @import("../poly/twiddle_source.zig");
const work_pool = @import("../work_pool.zig");
const prover_api = @import("stwo_prover_api");
const stage_profile = prover_api.stage_profile;
const work_profile = prover_api.work_profile;
const prover_fri = @import("../fri.zig");
const commitment_tree = @import("commitment_tree.zig");
const commit_polys = @import("commit_polys.zig");
const column_preparation = @import("columns/preparation.zig");
const deferred_commit = @import("deferred_commit.zig");
const column_storage = @import("columns/storage.zig");
const pow_search = @import("proof_of_work.zig");
const sampled_value_transcript = @import("sampled_value_transcript.zig");
const sampled_value_evaluation = @import("sampled_values.zig");
const tree_builders = @import("tree_builders.zig");
const commit_dispatch = @import("commit_dispatch.zig");
const backed_columns = @import("backed_columns.zig");
const scheme_decommit = @import("scheme_decommit.zig");
const scheme_views = @import("scheme_views.zig");
const shell_work_profile = @import("shell_work_profile.zig");
pub const revision_lifting = @import("revision_lifting.zig");

pub const quotient_ops = @import("quotient_ops.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CirclePointQM31 = circle.CirclePointQM31;
const PcsConfig = pcs_core.PcsConfig;
const Revision = @import("stwo_core").protocol_revision.Revision;
const TreeVec = pcs_core.TreeVec;
const PREPROCESSED_TRACE_IDX = verifier_types.PREPROCESSED_TRACE_IDX;
const TwiddleSource = twiddle_source_mod.TwiddleSource;
const M31TwiddleTower = @import("../poly/twiddle_tower.zig").M31TwiddleTower;

pub const ForField = @import("scheme_family.zig").ForField;
const Default = ForField(QM31);
pub const CommitmentSchemeError = Default.CommitmentSchemeError;
pub const ColumnEvaluation = Default.ColumnEvaluation;
pub const CommitmentTreeProver = Default.CommitmentTreeProver;
pub const TreeDecommitmentResult = Default.TreeDecommitmentResult;
pub const CommitmentSchemeProver = Default.CommitmentSchemeProver;
pub const TreeBuilder = Default.TreeBuilder;
pub const StreamingTreeBuilder = Default.StreamingTreeBuilder;
