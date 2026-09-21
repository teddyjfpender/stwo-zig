//! Compatibility exports for shared verifier parameter construction.
const owner = @import("stwo_riscv_frontend").recursion.air.verifier_component_parameters;
pub const vmInputParameters = owner.vmInputParameters;
pub const merkleRootParameters = owner.merkleRootParameters;
pub const traceMerkleParameters = owner.traceMerkleParameters;
pub const friLeafParameters = owner.friLeafParameters;
pub const friAnchorParameters = owner.friAnchorParameters;
pub const queryBitsParameters = owner.queryBitsParameters;
pub const queryMappingParameters = owner.queryMappingParameters;
pub const controlParameters = owner.controlParameters;
pub const inputParameters = owner.inputParameters;
pub const pcsParameters = owner.pcsParameters;
