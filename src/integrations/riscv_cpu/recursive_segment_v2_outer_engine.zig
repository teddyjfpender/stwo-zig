//! CPU backend and diagnostic bindings for the shared publication transaction.
const recursion = @import("stwo_riscv_frontend").recursion;
const diagnostics_source = @import("recursive_fri_outer.zig");
const Diagnostics = struct {
    pub const COMPOSITION_DIAGNOSTIC_ENV = diagnostics_source.COMPOSITION_DIAGNOSTIC_ENV;
    pub const validateCompositionDiagnosticRoster = diagnostics_source.validateCompositionDiagnosticRoster;
    pub const diagnoseCompositionComponents = diagnostics_source.diagnoseCompositionComponents;
};
const implementation = recursion.segment_outer_transaction_v2.ForBackend(@import("stwo_cpu_backend").CpuBackend, Diagnostics);

pub const Engine = implementation.Engine;
pub const OuterProofCapture = implementation.OuterProofCapture;
pub const VerifiedSegmentV2PublicationV1 = implementation.VerifiedSegmentV2PublicationV1;
pub const RecursiveWitnessV1 = implementation.RecursiveWitnessV1;
pub const ProducerAllocator = implementation.ProducerAllocator;
pub const FORMAT_VERSION = implementation.FORMAT_VERSION;
pub const COMPLETE_ROW_COUNT = implementation.COMPLETE_ROW_COUNT;
pub const ENGINE_AVAILABLE = implementation.ENGINE_AVAILABLE;
pub const CANONICAL_PROOF_SERIALIZATION_PASSES = implementation.CANONICAL_PROOF_SERIALIZATION_PASSES;
pub const Error = implementation.Error;
pub const ExecutionOptions = implementation.ExecutionOptions;
pub const Receipt = implementation.Receipt;
pub const EngineKernel = implementation.EngineKernel;
pub const OUTER_CONFIG = implementation.OUTER_CONFIG;

test "segment V2 verified-publication engine pins the 39-row three-tree protocol" {
    try implementation.testProtocolContract();
}
