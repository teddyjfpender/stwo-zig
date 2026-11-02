const std = @import("std");
const circle = @import("stwo_core").circle;
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const pcs = @import("stwo_core").pcs;
const accumulation = @import("accumulation.zig");
const composition_work = @import("composition_work.zig");
const oods_work = @import("oods_work.zig");
const composition_execution = @import("composition_execution.zig");
const component_parallel = @import("component_parallel.zig");
const component_trace = @import("component_trace.zig");
const device_composition = @import("device_composition.zig");
const prepared_domain = @import("prepared_domain.zig");
const prover_twiddles = @import("../poly/twiddles.zig");
const secure_column = @import("../secure_column.zig");
const work_pool_mod = @import("../work_pool.zig");
const prover_api = @import("stwo_prover_api");
const stage_profile = prover_api.stage_profile;

const CirclePointQM31 = circle.CirclePointQM31;
const M31 = m31.M31;
const QM31 = qm31.QM31;
const TreeVec = pcs.TreeVec;
const SecureColumnByCoords = secure_column.SecureColumnByCoords;
const M31TwiddleTree = prover_twiddles.TwiddleTree([]const M31);

pub const ComponentProverError = component_trace.Error;
pub const Poly = component_trace.Poly;
pub const Trace = component_trace.Trace;

/// Backend-neutral base-field polynomial program exported by a frontend from
/// the same typed builder used by its reference AIR evaluator. Node order is
/// topological: every operand names an earlier node. `column` values address
/// the capability's ordered input columns.
const component_programs = @import("component_programs.zig");
pub const BasePolynomialOp = component_programs.BasePolynomialOp;
pub const BasePolynomialNode = component_programs.BasePolynomialNode;
pub const OwnedBasePolynomialProgram = component_programs.OwnedBasePolynomialProgram;
pub const TypedPolynomialColumnV1 = component_programs.TypedPolynomialColumnV1;
pub const TypedPolynomialInputV1 = component_programs.TypedPolynomialInputV1;
pub const FRAMEWORK_LOOKUP_MAX_ARITY_V1 = component_programs.FRAMEWORK_LOOKUP_MAX_ARITY_V1;
pub const FrameworkLookupEntryV1 = component_programs.FrameworkLookupEntryV1;
pub const FrameworkLookupBatchV1 = component_programs.FrameworkLookupBatchV1;
pub const FrameworkLookupLayoutV1 = component_programs.FrameworkLookupLayoutV1;
pub const OwnedFrameworkPolynomialProgramV1 = component_programs.OwnedFrameworkPolynomialProgramV1;
pub const FrameworkPolynomialParametersV1 = component_programs.FrameworkPolynomialParametersV1;
pub const OwnedFrameworkPolynomialParametersV1 = component_programs.OwnedFrameworkPolynomialParametersV1;
pub const FrameworkPolynomialCapabilityV1 = component_programs.FrameworkPolynomialCapabilityV1;
pub const BasePolynomialCapabilityV1 = component_programs.BasePolynomialCapabilityV1;
pub const MAX_LOOKUP_POLYNOMIAL_ARITY = component_programs.MAX_LOOKUP_POLYNOMIAL_ARITY;
pub const LookupPolynomialEntry = component_programs.LookupPolynomialEntry;
pub const OwnedLookupPolynomialProgram = component_programs.OwnedLookupPolynomialProgram;
pub const LOOKUP_POLYNOMIAL_LAYOUT_V2_FORMAT_VERSION = component_programs.LOOKUP_POLYNOMIAL_LAYOUT_V2_FORMAT_VERSION;
pub const LOOKUP_POLYNOMIAL_LAYOUT_V2_MAXIMUM_BATCH_SIZE = component_programs.LOOKUP_POLYNOMIAL_LAYOUT_V2_MAXIMUM_BATCH_SIZE;
pub const LOOKUP_POLYNOMIAL_LAYOUT_V2_INTERACTION_COORDINATES = component_programs.LOOKUP_POLYNOMIAL_LAYOUT_V2_INTERACTION_COORDINATES;
pub const LOOKUP_POLYNOMIAL_LAYOUT_V2_MAXIMUM_DEGREE = component_programs.LOOKUP_POLYNOMIAL_LAYOUT_V2_MAXIMUM_DEGREE;
pub const LOOKUP_POLYNOMIAL_LAYOUT_V2_IDENTITY_DOMAIN = component_programs.LOOKUP_POLYNOMIAL_LAYOUT_V2_IDENTITY_DOMAIN;
pub const LOOKUP_POLYNOMIAL_PROGRAM_V2_IDENTITY_DOMAIN = component_programs.LOOKUP_POLYNOMIAL_PROGRAM_V2_IDENTITY_DOMAIN;
pub const LookupPolynomialIdentity = component_programs.LookupPolynomialIdentity;
pub const LookupPolynomialProgramV2Error = component_programs.LookupPolynomialProgramV2Error;
pub const LookupPolynomialEventDegreeV2 = component_programs.LookupPolynomialEventDegreeV2;
pub const LookupPolynomialBatchV2 = component_programs.LookupPolynomialBatchV2;
pub const LookupPolynomialLayoutV2 = component_programs.LookupPolynomialLayoutV2;
pub const LookupPolynomialAuthorityV2 = component_programs.LookupPolynomialAuthorityV2;
pub const OwnedLookupPolynomialProgramV2 = component_programs.OwnedLookupPolynomialProgramV2;
pub const LookupPolynomialCapabilityV1 = component_programs.LookupPolynomialCapabilityV1;
pub const LookupPolynomialCapabilityV2 = component_programs.LookupPolynomialCapabilityV2;
pub const ComponentConstraintRangeV1 = component_programs.ComponentConstraintRangeV1;
pub const BasePolynomialPartitionV1 = component_programs.BasePolynomialPartitionV1;
pub const MAX_BASE_POLYNOMIAL_PARTITIONS_V1 =
    component_programs.MAX_BASE_POLYNOMIAL_PARTITIONS_V1;
pub const BaseLookupPolynomialCapabilitiesV1 = component_programs.BaseLookupPolynomialCapabilitiesV1;
pub const BaseLookupPolynomialCapabilityV1 = component_programs.BaseLookupPolynomialCapabilityV1;
pub const BackendCompositionCapability = component_programs.BackendCompositionCapability;
pub const ComponentProfileIdentity = @import("component_profile_identity.zig").ComponentProfileIdentity;
pub const CompositionGeometryOverrideV1 =
    core_air_components.CompositionGeometryOverrideV1;

pub const ForField = @import("component_prover_family.zig").ForField;
const Default = ForField(QM31);
pub const ComponentProverVTable = Default.ComponentProverVTable;
pub const ComponentProver = Default.ComponentProver;
pub const ComponentProvers = Default.ComponentProvers;
