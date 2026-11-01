//! Complete prover transaction contract shared by native and device backends.

const std = @import("std");
const api = @import("stwo_prover_api");
const pcs_core = @import("stwo_core").pcs;
const proof = @import("stwo_core").proof;
const component = @import("air/component_prover.zig");
const pcs = @import("pcs/mod.zig");
const prove_mod = @import("prove.zig");
const session_mod = @import("session.zig");
const stage_profile = api.stage_profile;

pub const ProveOptions = api.ProveOptions;
pub const CpuCompositionContentionPolicy = api.CpuCompositionContentionPolicy;
pub const CpuCompositionExecutionRequest = api.CpuCompositionExecutionRequest;
pub const ProveDiagnostic = api.ProveDiagnostic;
pub const CompositionSubphase = api.CompositionSubphase;
pub const EvaluationDiagnostic = api.EvaluationDiagnostic;
pub const EvaluationStage = api.EvaluationStage;
pub const assertProverEngine = api.assertProverEngine;

/// Builds a complete proving engine from a PCS backend and protocol types.
///
/// `commit` consumes its column slice and `prove` consumes the scheme. This
/// keeps ownership identical for host and resident-device implementations.
pub const ForField = @import("engine_family.zig").ForField;
const Default = ForField(@import("stwo_core").fields.qm31.QM31);
pub const ProverEngine = Default.ProverEngine;
