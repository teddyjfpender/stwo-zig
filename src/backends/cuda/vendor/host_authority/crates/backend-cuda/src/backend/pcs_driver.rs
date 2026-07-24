//! CUDA-owned PCS/FRI orchestration.
//!
//! Protocol computations remain in stwo's typed proof stages, but this module
//! owns their order and records the architecture path.  Explicit arena hooks
//! are caller-provided: there is no default or thread-local CUDA context.

use stwo::core::channel::MerkleChannel;
use stwo::core::circle::CirclePoint;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::quotients::ExtendedCommitmentSchemeProof;
use stwo::core::pcs::TreeVec;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::core::ColumnVec;
use stwo::prover::backend::BackendForChannel;
use stwo::prover::pcs::proof_driver::{PcsProofStage, PcsProofStageObserver};
use stwo::prover::pcs::CommitmentSchemeProver;

use super::backend::CudaBackend;
use super::exec_context::{CudaExecTelemetry, DeviceArena};

/// Runtime architecture selected for this driver invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CudaPcsRuntimeMode {
    /// Compatibility entry through [`BackendForChannel`]. CUDA kernels are used,
    /// but graph/arena segments have not been bound by the caller.
    DetachedEager,
    /// A proof-owned arena and its isolated execution context are explicit.
    ArenaGraph,
}

#[derive(Clone, Copy)]
enum RuntimeBinding<'a> {
    DetachedEager,
    ArenaGraph(&'a DeviceArena),
}

/// Rejection from a caller-owned graph-segment hook.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CudaPcsGraphHookError {
    message: String,
}

impl CudaPcsGraphHookError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl core::fmt::Display for CudaPcsGraphHookError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CudaPcsGraphHookError {}

/// Explicit graph-segment boundary hook.
///
/// The arena owns the matching [`super::exec_context::CudaExecContext`], so a
/// hook cannot accidentally enqueue on a process-wide default stream. Returning
/// an error makes the configured driver fail closed (the proof is not returned).
pub trait CudaPcsGraphHooks {
    fn stage_started(
        &mut self,
        stage: PcsProofStage,
        arena: &DeviceArena,
    ) -> Result<(), CudaPcsGraphHookError>;

    fn stage_finished(
        &mut self,
        stage: PcsProofStage,
        arena: &DeviceArena,
    ) -> Result<(), CudaPcsGraphHookError>;
}

/// Explicit CUDA PCS driver configuration.
///
/// `arena_graph` requires both the arena and its hooks. There is no `Option`al
/// context and no silent fallback to a default stream. The trait override uses
/// `detached_eager` until its stwo-cairo call site is changed to call the
/// configured API and supply the per-proof workspace.
pub struct CudaPcsDriverConfig<'a> {
    runtime: RuntimeBinding<'a>,
    hooks: Option<&'a mut dyn CudaPcsGraphHooks>,
}

impl CudaPcsDriverConfig<'_> {
    pub const fn detached_eager() -> Self {
        Self {
            runtime: RuntimeBinding::DetachedEager,
            hooks: None,
        }
    }

    pub fn runtime_mode(&self) -> CudaPcsRuntimeMode {
        match self.runtime {
            RuntimeBinding::DetachedEager => CudaPcsRuntimeMode::DetachedEager,
            RuntimeBinding::ArenaGraph(_) => CudaPcsRuntimeMode::ArenaGraph,
        }
    }
}

impl<'a> CudaPcsDriverConfig<'a> {
    pub fn arena_graph(arena: &'a DeviceArena, hooks: &'a mut dyn CudaPcsGraphHooks) -> Self {
        Self {
            runtime: RuntimeBinding::ArenaGraph(arena),
            hooks: Some(hooks),
        }
    }
}

/// Per-invocation proof-driver architecture telemetry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CudaPcsDriverTelemetry {
    pub architecture: &'static str,
    pub runtime_mode: CudaPcsRuntimeMode,
    pub stage_started: [u32; PcsProofStage::ALL.len()],
    pub stage_finished: [u32; PcsProofStage::ALL.len()],
    /// The trace-tree stage routes through stwo's backend-batched sparse gather.
    pub batched_tree_decommit: bool,
    /// Resident-context counters. Detached migration runs deliberately report
    /// `None`; strict ArenaGraph admission requires this evidence.
    pub exec: Option<CudaExecTelemetry>,
    /// Exact captured topology accepted before the ArenaGraph proof returned.
    /// Detached migration runs do not have a resident replay topology.
    pub expected_graph_launches: Option<u64>,
    pub expected_kernel_launches: Option<u64>,
}

impl CudaPcsDriverTelemetry {
    fn new(runtime_mode: CudaPcsRuntimeMode) -> Self {
        Self {
            architecture: "cuda-typed-pcs-driver-v1",
            runtime_mode,
            stage_started: [0; PcsProofStage::ALL.len()],
            stage_finished: [0; PcsProofStage::ALL.len()],
            batched_tree_decommit: false,
            exec: None,
            expected_graph_launches: None,
            expected_kernel_launches: None,
        }
    }

    pub fn completed_arena_graph(
        exec: CudaExecTelemetry,
        expected_graph_launches: u64,
        expected_kernel_launches: u64,
    ) -> Self {
        assert_eq!(
            exec.graph_launches, expected_graph_launches,
            "ArenaGraph telemetry graph count was not budget-accepted"
        );
        assert_eq!(
            exec.kernel_launches, expected_kernel_launches,
            "ArenaGraph telemetry kernel count was not budget-accepted"
        );
        Self {
            architecture: "cuda-typed-pcs-driver-v1",
            runtime_mode: CudaPcsRuntimeMode::ArenaGraph,
            stage_started: [1; PcsProofStage::ALL.len()],
            stage_finished: [1; PcsProofStage::ALL.len()],
            batched_tree_decommit: true,
            exec: Some(exec),
            expected_graph_launches: Some(expected_graph_launches),
            expected_kernel_launches: Some(expected_kernel_launches),
        }
    }

    pub fn completed(&self, stage: PcsProofStage) -> u32 {
        self.stage_finished[stage.index()]
    }

    pub fn is_complete(&self) -> bool {
        self.stage_started.iter().all(|&count| count == 1)
            && self.stage_finished.iter().all(|&count| count == 1)
            && self.batched_tree_decommit
    }
}

#[derive(Debug)]
pub enum CudaPcsDriverError {
    GraphHook {
        stage: PcsProofStage,
        boundary: &'static str,
        source: CudaPcsGraphHookError,
    },
    IncompleteTelemetry(CudaPcsDriverTelemetry),
}

impl core::fmt::Display for CudaPcsDriverError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::GraphHook {
                stage,
                boundary,
                source,
            } => write!(
                f,
                "CUDA PCS graph hook rejected {stage:?} {boundary}: {source}"
            ),
            Self::IncompleteTelemetry(_) => {
                f.write_str("CUDA PCS driver did not complete each typed stage exactly once")
            }
        }
    }
}

impl std::error::Error for CudaPcsDriverError {}

pub struct CudaPcsDriverOutput<H: MerkleHasherLifted> {
    pub proof: ExtendedCommitmentSchemeProof<H>,
    pub telemetry: CudaPcsDriverTelemetry,
}

struct TelemetryObserver<'config, 'runtime> {
    config: &'config mut CudaPcsDriverConfig<'runtime>,
    telemetry: CudaPcsDriverTelemetry,
    hook_error: Option<CudaPcsDriverError>,
}

impl TelemetryObserver<'_, '_> {
    fn call_hook(&mut self, stage: PcsProofStage, boundary: &'static str) {
        if self.hook_error.is_some() {
            return;
        }
        let RuntimeBinding::ArenaGraph(arena) = self.config.runtime else {
            return;
        };
        let hooks = self
            .config
            .hooks
            .as_deref_mut()
            .expect("ArenaGraph configuration always carries hooks");
        let result = if boundary == "start" {
            hooks.stage_started(stage, arena)
        } else {
            hooks.stage_finished(stage, arena)
        };
        if let Err(source) = result {
            self.hook_error = Some(CudaPcsDriverError::GraphHook {
                stage,
                boundary,
                source,
            });
        }
    }
}

impl PcsProofStageObserver for TelemetryObserver<'_, '_> {
    fn stage_started(&mut self, stage: PcsProofStage) {
        self.telemetry.stage_started[stage.index()] += 1;
        self.call_hook(stage, "start");
    }

    fn stage_finished(&mut self, stage: PcsProofStage) {
        self.call_hook(stage, "finish");
        self.telemetry.stage_finished[stage.index()] += 1;
        if stage == PcsProofStage::TreeDecommit {
            self.telemetry.batched_tree_decommit = true;
        }
    }
}

pub fn prove_values_with_config<'a, MC: MerkleChannel>(
    commitment_scheme: CommitmentSchemeProver<'a, CudaBackend, MC>,
    sampled_points: TreeVec<ColumnVec<Vec<CirclePoint<SecureField>>>>,
    channel: &mut MC::C,
    config: &mut CudaPcsDriverConfig<'_>,
) -> Result<CudaPcsDriverOutput<MC::H>, CudaPcsDriverError>
where
    CudaBackend: BackendForChannel<MC>,
{
    let mut observer = TelemetryObserver {
        telemetry: CudaPcsDriverTelemetry::new(config.runtime_mode()),
        config,
        hook_error: None,
    };

    // CUDA owns the protocol orchestration. Each consuming transition is the
    // shared stwo implementation, so this order cannot drift from the reference.
    let proof = commitment_scheme
        .begin_proof_driver(sampled_points)
        .evaluate_oods(channel, &mut observer)
        .compute_quotient_and_compact(channel, &mut observer)
        .with_fri_commit(channel, &mut observer, |committed, channel, observer| {
            committed
                .prove_work_and_draw_queries(channel, observer)
                .decommit_trees(observer)
                .assemble(observer)
        });

    if let Some(error) = observer.hook_error {
        return Err(error);
    }
    if !observer.telemetry.is_complete() {
        return Err(CudaPcsDriverError::IncompleteTelemetry(observer.telemetry));
    }
    Ok(CudaPcsDriverOutput {
        proof,
        telemetry: observer.telemetry,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detached_configuration_is_explicit() {
        let config = CudaPcsDriverConfig::detached_eager();
        assert_eq!(config.runtime_mode(), CudaPcsRuntimeMode::DetachedEager);
    }

    #[test]
    fn telemetry_requires_every_stage_and_batched_tree_decommit() {
        let mut telemetry = CudaPcsDriverTelemetry::new(CudaPcsRuntimeMode::DetachedEager);
        assert!(!telemetry.is_complete());
        for stage in PcsProofStage::ALL {
            telemetry.stage_started[stage.index()] = 1;
            telemetry.stage_finished[stage.index()] = 1;
        }
        assert!(!telemetry.is_complete());
        telemetry.batched_tree_decommit = true;
        assert!(telemetry.is_complete());
    }

    #[test]
    fn arena_graph_telemetry_preserves_accepted_topology() {
        let exec = CudaExecTelemetry {
            graph_launches: 14,
            kernel_launches: 2_530,
            ..CudaExecTelemetry::default()
        };
        let telemetry = CudaPcsDriverTelemetry::completed_arena_graph(exec, 14, 2_530);
        assert_eq!(telemetry.exec, Some(exec));
        assert_eq!(telemetry.expected_graph_launches, Some(14));
        assert_eq!(telemetry.expected_kernel_launches, Some(2_530));
    }

    #[test]
    #[should_panic(expected = "ArenaGraph telemetry graph count was not budget-accepted")]
    fn arena_graph_telemetry_rejects_unaccepted_topology() {
        let exec = CudaExecTelemetry {
            graph_launches: 13,
            kernel_launches: 2_530,
            ..CudaExecTelemetry::default()
        };
        let _ = CudaPcsDriverTelemetry::completed_arena_graph(exec, 14, 2_530);
    }
}
