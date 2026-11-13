const base = @import("stwo_riscv_rv32").prover.main_trace_plan;
const Statement = @import("stwo_riscv_rv32").air.statement.RiscVStatement;
const CircuitProfile = @import("stwo_riscv_air_lang").physical_profile.CircuitProfileV1;
pub const Error = base.Error;
pub const BuildOptions = base.BuildOptions;
pub const ColumnRange = base.ColumnRange;
pub const RowRange = base.RowRange;
pub const Resources = base.Resources;
pub const TaskCounts = base.TaskCounts;
pub const Plan = base.Plan;
pub const StageRank = base.StageRank;
pub const MAIN_TRACE_EPOCH = base.MAIN_TRACE_EPOCH;
pub const MAX_DESCRIPTORS = base.MAX_DESCRIPTORS;
pub const MAX_PLAN_SIZE_BYTES = base.MAX_PLAN_SIZE_BYTES;
pub const OPCODE_ROWS_PER_CHUNK = base.OPCODE_ROWS_PER_CHUNK;
pub const POSEIDON_ROWS_PER_CHUNK = base.POSEIDON_ROWS_PER_CHUNK;
pub const LOOKUP_COUNTER_SET_CELLS = base.LOOKUP_COUNTER_SET_CELLS;
pub const LOOKUP_COUNTER_SET_PAYLOAD_BYTES = base.LOOKUP_COUNTER_SET_PAYLOAD_BYTES;
pub const LOOKUP_COUNTER_SET_DESCRIPTOR_BYTES = base.LOOKUP_COUNTER_SET_DESCRIPTOR_BYTES;
pub const prepareTaskKey = base.prepareTaskKey;
pub const opcodeFillTaskKey = base.opcodeFillTaskKey;
pub const infrastructureFillTaskKey = base.infrastructureFillTaskKey;
pub const opcodeReduceTaskKey = base.opcodeReduceTaskKey;
pub const opcodeAuditTaskKey = base.opcodeAuditTaskKey;
pub const lookupSeedTaskKey = base.lookupSeedTaskKey;
pub const opcodeFinalizeTaskKey = base.opcodeFinalizeTaskKey;
pub const infrastructureFinalizeTaskKey = base.infrastructureFinalizeTaskKey;
pub const sealTaskKey = base.sealTaskKey;
pub const checkedBytesForCells = base.checkedBytesForCells;
pub const counterSetReservationBytes = base.counterSetReservationBytes;
pub const Poseidon2ExecutionCounts = base.Poseidon2ExecutionCounts;
pub const build = base.build;
pub const buildPoseidon2 = base.buildPoseidon2;
pub const buildWithCircuitLayout = base.buildWithCircuitLayout;
pub const validateWithCircuitLayout = base.validateWithCircuitLayout;
pub const validate = base.validate;
pub const validatePoseidon2 = base.validatePoseidon2;
pub fn buildWithCircuitProfileV1(statement: *const Statement, options: BuildOptions, circuit_profile: CircuitProfile) Error!Plan {
    return base.buildWithCircuitLayout(statement, options, circuit_profile.layout());
}
pub fn validateWithCircuitProfileV1(plan: *const Plan, statement: *const Statement, circuit_profile: CircuitProfile) Error!void {
    return base.validateWithCircuitLayout(plan, statement, circuit_profile.layout());
}
