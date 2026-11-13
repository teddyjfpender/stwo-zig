//! Product extension binding of the one shared graph support implementation.
const Bound = @import("stwo_riscv_recursion").vm_composition_graph_support.ForExtension(@import("ethereum_composition_extension_geometry.zig"));
pub const Scalar = Bound.Scalar;
pub const Builder = Bound.Builder;
pub const TREE_COUNT = Bound.TREE_COUNT;
pub const EXTENSION_TREE_COUNT = Bound.EXTENSION_TREE_COUNT;
pub const Error = Bound.Error;
pub const SampleLayoutV2 = Bound.SampleLayoutV2;
pub const secureInput = Bound.secureInput;
pub const challengeInput = Bound.challengeInput;
pub const scalarInput = Bound.scalarInput;
pub const pointFromSeed = Bound.pointFromSeed;
pub const compositionDiagnosticsEnabled = Bound.compositionDiagnosticsEnabled;
pub const diagnosticCheckpoint = Bound.diagnosticCheckpoint;
pub const quotientDenominator = Bound.quotientDenominator;
pub const accumulate = Bound.accumulate;
pub const reconstructComposition = Bound.reconstructComposition;
pub const fromPartialEvals = Bound.fromPartialEvals;
