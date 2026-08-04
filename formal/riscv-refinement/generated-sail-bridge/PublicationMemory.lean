import ExecutionClosure
import DecodeMemoryState
import ExecutionMemory
import ExecutionMemoryVmem
import ExecutionMemoryStore
import RiscvRefinement.Publication.TeamB.LoadStore

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 100_000
set_option linter.unusedVariables false

open Sail

namespace LeanRV32IM.Publication

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Generated
open RiscvRefinement.Opcodes
open RiscvRefinement.Sail.Reviewed

namespace Memory

abbrev Kind :=
  RiscvRefinement.Publication.TeamB.LoadStore.Kind

abbrev Row := RiscvRefinement.Air.Family.LoadStoreRow

def selector : Kind → GeneratedOpcodeSelector
  | .lb => .lb
  | .lh => .lh
  | .lw => .lw
  | .lbu => .lbu
  | .lhu => .lhu
  | .sb => .sb
  | .sh => .sh
  | .sw => .sw

def funct3 : Kind → BitVec 3
  | .lb => LoadStoreDecode.funct3Lb
  | .lh => LoadStoreDecode.funct3Lh
  | .lw => LoadStoreDecode.funct3Lw
  | .lbu => LoadStoreDecode.funct3Lbu
  | .lhu => LoadStoreDecode.funct3Lhu
  | .sb => LoadStoreDecode.funct3Sb
  | .sh => LoadStoreDecode.funct3Sh
  | .sw => LoadStoreDecode.funct3Sw

def width : Kind → Nat
  | .lb | .lbu | .sb => 1
  | .lh | .lhu | .sh => 2
  | .lw | .sw => 4

def unsigned : Kind → Bool
  | .lbu | .lhu => true
  | _ => false

def isLoad : Kind → Bool
  | .lb | .lh | .lw | .lbu | .lhu => true
  | .sb | .sh | .sw => false

def expectedWord
    (kind : Kind)
    (row : Row)
    (environment : LoadStoreEnvironment row) : BitVec 32 :=
  match kind with
  | .lb | .lh | .lw | .lbu | .lhu =>
      LoadStoreDecode.encodeLoad
        environment.imm row.rs1Addr row.r2Idx (funct3 kind)
  | .sb | .sh | .sw =>
      LoadStoreDecode.encodeStore
        environment.imm row.r2Idx row.rs1Addr (funct3 kind)

def decoded
    (kind : Kind)
    (row : Row)
    (environment : LoadStoreEnvironment row) : instruction :=
  match kind with
  | .lb => Functions.decodedLbMemory
      environment.imm row.rs1Addr row.r2Idx
  | .lh => Functions.decodedLhMemory
      environment.imm row.rs1Addr row.r2Idx
  | .lw => Functions.decodedLwMemory
      environment.imm row.rs1Addr row.r2Idx
  | .lbu => Functions.decodedLbuMemory
      environment.imm row.rs1Addr row.r2Idx
  | .lhu => Functions.decodedLhuMemory
      environment.imm row.rs1Addr row.r2Idx
  | .sb => Functions.decodedSbMemory
      environment.imm row.r2Idx row.rs1Addr
  | .sh => Functions.decodedShMemory
      environment.imm row.r2Idx row.rs1Addr
  | .sw => Functions.decodedSwMemory
      environment.imm row.r2Idx row.rs1Addr

def ExactExecuteClause
    (kind : Kind)
    (row : Row)
    (environment : LoadStoreEnvironment row) : Prop :=
  match kind with
  | .lb | .lh | .lw | .lbu | .lhu =>
      Functions.execute (decoded kind row environment) =
        Functions.execute_LOAD environment.imm
          (.Regidx row.rs1Addr) (.Regidx row.r2Idx)
          (unsigned kind) (width kind)
  | .sb | .sh | .sw =>
      Functions.execute (decoded kind row environment) =
        Functions.execute_STORE environment.imm
          (.Regidx row.r2Idx) (.Regidx row.rs1Addr)
          (width kind)

def NormalizedRetirement
    (kind : Kind)
    (row : Row)
    (environment : LoadStoreEnvironment row) : Prop :=
  match kind with
  | .lb | .lh | .lw | .lbu | .lhu =>
      Functions.completeBaseExecution environment.pre.pc
          (Functions.execute_LOAD environment.imm
            (.Regidx row.rs1Addr) (.Regidx row.r2Idx)
            (unsigned kind) (width kind)) =
        Functions.eraseObservation
          (Functions.normalizedLoadCompletion
            environment.pre.pc environment.imm
            row.rs1Addr row.r2Idx (unsigned kind) (width kind))
  | .sb | .sh | .sw =>
      Functions.completeBaseExecution environment.pre.pc
          (Functions.execute_STORE environment.imm
            (.Regidx row.r2Idx) (.Regidx row.rs1Addr)
            (width kind)) =
        Functions.eraseObservation
          (Functions.normalizedStoreCompletion
            environment.pre.pc environment.imm
            row.r2Idx row.rs1Addr (width kind))

noncomputable def observedProgram
    (kind : Kind)
    (row : Row)
    (environment : LoadStoreEnvironment row) :=
  match kind with
  | .lb | .lh | .lw | .lbu | .lhu =>
      Functions.normalizedLoadCompletion
        environment.pre.pc environment.imm
        row.rs1Addr row.r2Idx (unsigned kind) (width kind)
  | .sb | .sh | .sw =>
      Functions.normalizedStoreCompletion
        environment.pre.pc environment.imm
        row.r2Idx row.rs1Addr (width kind)

def airRetirement
    (kind : Kind)
    (row : Row)
    (environment : LoadStoreEnvironment row) : Retirement :=
  match kind with
  | .lb => executeLb environment.pre.pc environment.baseValue
      environment.imm row.r2Idx environment.memoryWord
  | .lh => executeLh environment.pre.pc environment.baseValue
      environment.imm row.r2Idx environment.memoryWord
  | .lw => executeLw environment.pre.pc environment.baseValue
      environment.imm row.r2Idx environment.memoryWord
  | .lbu => executeLbu environment.pre.pc environment.baseValue
      environment.imm row.r2Idx environment.memoryWord
  | .lhu => executeLhu environment.pre.pc environment.baseValue
      environment.imm row.r2Idx environment.memoryWord
  | .sb => executeSb environment.pre.pc environment.baseValue
      environment.imm environment.operandValue environment.memoryWord
  | .sh => executeSh environment.pre.pc environment.baseValue
      environment.imm environment.operandValue environment.memoryWord
  | .sw => executeSw environment.pre.pc environment.baseValue
      environment.imm environment.operandValue environment.memoryWord

def ConstructiveExecution
    (kind : Kind)
    (row : Row)
    (environment : LoadStoreEnvironment row)
    (initial : Functions.GeneratedState)
    (stepNo : Nat) : Prop :=
  Functions.ConstructiveGeneratedExecution
    stepNo environment.word (decoded kind row environment)
    (Functions.completeBaseExecution environment.pre.pc
      (Functions.execute (decoded kind row environment)))
    (observedProgram kind row environment) initial
    (airRetirement kind row environment)

def RegisterBindings
    (kind : Kind)
    (row : Row)
    (environment : LoadStoreEnvironment row)
    (initial : Functions.GeneratedState) : Prop :=
  match kind with
  | .lb | .lh | .lw | .lbu | .lhu =>
      GeneratedUnaryRegisterStateBindings initial
        row.rs1Addr row.r2Idx environment.baseValue
        (environment.pre.registers row.r2Idx)
  | .sb | .sh | .sw =>
      GeneratedReadPairStateBindings initial
        row.rs1Addr row.r2Idx environment.baseValue
        environment.operandValue

def physicalAddress
    (environment : LoadStoreEnvironment row) : physaddr :=
  .Physaddr (_root_.zero_extend (m := 34) environment.effectiveAddress)

/--
Componentwise generated-memory profile for the exact load/store execution.
This deliberately exposes the CSR and PMA facts from which `vmem_read` and
`vmem_write` are reduced; it does not accept either generated memory operation
or its final state as a premise.
-/
structure OrdinaryRamBindings
    (kind : Kind)
    (row : Row)
    (environment : LoadStoreEnvironment row)
    (initial : Functions.GeneratedState) : Prop where
  mstatus :
    ∃ value : BitVec 64,
      initial.regs.get? Register.mstatus = some value ∧
      Functions._get_Mstatus_MPRV value = 0#1
  pmaRegion :
    ∃ (regions : List PMA_Region) (region : PMA_Region),
      initial.regs.get? Register.pma_regions = some regions ∧
      Functions.matching_pma_region regions
          (physicalAddress environment) (width kind) = some region ∧
      region.attributes.mem_type = .MainMemory ∧
      region.attributes.readable = true ∧
      region.attributes.writable = true
  virtualAligned :
    Functions.is_aligned_vaddr
      (.Virtaddr environment.effectiveAddress) (width kind) = true
  physicalAligned :
    Functions.is_aligned_paddr
      (physicalAddress environment) (width kind) = true
  pageBound :
    environment.effectiveAddress.toNat % 4096 + width kind ≤ 4096
  samePage :
    ExecutionMemory.SamePage environment.effectiveAddress (width kind)
  accessBytes :
    ∀ offset : Fin (width kind),
      initial.mem.get?
          (environment.effectiveAddress.toNat + offset.val) =
        some (BitVec.extractLsb'
          (8 * (environment.effectiveAddress.toNat % 4 + offset.val))
          8 environment.memoryWord.word)

def StateBindings
    (kind : Kind)
    (row : Row)
    (environment : LoadStoreEnvironment row)
    (initial : Functions.GeneratedState) : Prop :=
  GeneratedInstructionStateBindings
      environment.pre.pc environment.word initial ∧
    RegisterBindings kind row environment initial ∧
    GeneratedMemoryWordBinding initial
      environment.busAddress environment.memoryWord.word ∧
    OrdinaryRamBindings kind row environment initial

theorem StateBindings.instruction
    (bindings : StateBindings kind row environment initial) :
    GeneratedInstructionStateBindings
      environment.pre.pc environment.word initial :=
  bindings.1

theorem StateBindings.registers
    (bindings : StateBindings kind row environment initial) :
    RegisterBindings kind row environment initial :=
  bindings.2.1

theorem StateBindings.memory
    (bindings : StateBindings kind row environment initial) :
    GeneratedMemoryWordBinding initial
      environment.busAddress environment.memoryWord.word :=
  bindings.2.2.1

theorem StateBindings.ordinaryRam
    (bindings : StateBindings kind row environment initial) :
    OrdinaryRamBindings kind row environment initial :=
  bindings.2.2.2

def AcceptedComposition
    (kind : Kind)
    (row : Row)
    (witness : RiscvRefinement.Publication.TeamB.LoadStore.Witness row)
    (relationHolds : EvaluatedLookup → Prop)
    (environment : LoadStoreEnvironment row)
    (initial : Functions.GeneratedState)
    (stepNo : Nat)
    (exitWait : Bool) : Prop :=
  AcceptedGeneratedOpcodeComposition
    (selector kind)
    (RiscvRefinement.Publication.TeamB.LoadStore.program kind)
    (RiscvRefinement.Publication.TeamB.LoadStore.program kind).source.contentDigest
    ((RiscvRefinement.Publication.TeamB.LoadStore.program kind).evalSymbolic
      (RiscvRefinement.Publication.TeamB.LoadStore.columns row witness))
    relationHolds
    environment.word
    (expectedWord kind row environment)
    (decoded kind row environment)
    initial
    (StateBindings kind row environment initial)
    (GeneratedInstructionProfileAdmission
      environment.pre.pc environment.word initial)
    (RiscvRefinement.Publication.TeamB.LoadStore.Admission row)
    (RiscvRefinement.Publication.TeamB.LoadStore.semanticClaim
      kind row environment)
    (RiscvRefinement.Publication.TeamB.LoadStore.ExactTupleProjection
      kind row witness)
    (ExactExecuteClause kind row environment)
    (NormalizedRetirement kind row environment)
    (ConstructiveExecution kind row environment initial stepNo)
    stepNo
    exitWait

/-- Exact public proposition for one load/store selector. -/
def RefinementTheorem (kind : Kind) : Prop :=
  ∀
    (row : Row)
    (witness : RiscvRefinement.Publication.TeamB.LoadStore.Witness row)
    (relationHolds : EvaluatedLookup → Prop)
    (environment : LoadStoreEnvironment row)
    (admission :
      RiscvRefinement.Publication.TeamB.LoadStore.Admission row)
    (bindings :
      RiscvRefinement.Publication.TeamB.LoadStore.Bindings
        kind row witness)
    (accepted :
      RiscvRefinement.Publication.AcceptedProductionEvaluation
        ((RiscvRefinement.Publication.TeamB.LoadStore.program kind).evalSymbolic
          (RiscvRefinement.Publication.TeamB.LoadStore.columns row witness))
        relationHolds)
    (initial : Functions.GeneratedState)
    (stateBindings : StateBindings kind row environment initial)
    (profileAdmission :
      GeneratedInstructionProfileAdmission
        environment.pre.pc environment.word initial)
    (stepNo : Nat)
    (exitWait : Bool),
    AcceptedComposition kind row witness relationHolds environment
      initial stepNo exitWait

theorem canonicalWord
    (kind : Kind)
    (row : Row)
    (witness : RiscvRefinement.Publication.TeamB.LoadStore.Witness row)
    (relationHolds : EvaluatedLookup → Prop)
    (environment : LoadStoreEnvironment row)
    (localCertificate :
      RiscvRefinement.Publication.TeamB.LoadStore.PublicationResult
        kind
        (RiscvRefinement.Publication.TeamB.LoadStore.program kind)
        (RiscvRefinement.Publication.TeamB.LoadStore.expectedProgramIdentity kind)
        row witness environment relationHolds
        (RiscvRefinement.Publication.TeamB.LoadStore.semanticClaim
          kind row environment)) :
    environment.word = expectedWord kind row environment := by
  cases kind
  · rw [environment.wordBinds]
    have selected : row.isLb = true := by
      simpa [RiscvRefinement.Publication.TeamB.LoadStore.selected]
        using localCertificate.selectedRow
    simp [
      expectedWord, funct3, LoadStoreDecode.encoding,
      selected,
    ]
  · obtain ⟨lb, _, _, _, _, _, _⟩ :=
      lh_flags row localCertificate.holds (by
        simpa [RiscvRefinement.Publication.TeamB.LoadStore.selected]
          using localCertificate.selectedRow)
    rw [environment.wordBinds]
    simp [expectedWord, funct3, LoadStoreDecode.encoding, lb,
      show row.isLh = true by
        simpa [RiscvRefinement.Publication.TeamB.LoadStore.selected]
          using localCertificate.selectedRow]
  · obtain ⟨lb, lh, _, _, _, _, _⟩ :=
      lw_flags row localCertificate.holds (by
        simpa [RiscvRefinement.Publication.TeamB.LoadStore.selected]
          using localCertificate.selectedRow)
    rw [environment.wordBinds]
    simp [expectedWord, funct3, LoadStoreDecode.encoding, lb, lh,
      show row.isLw = true by
        simpa [RiscvRefinement.Publication.TeamB.LoadStore.selected]
          using localCertificate.selectedRow]
  · obtain ⟨lb, lh, _, lw, _, _, _⟩ :=
      lbu_flags row localCertificate.holds (by
        simpa [RiscvRefinement.Publication.TeamB.LoadStore.selected]
          using localCertificate.selectedRow)
    rw [environment.wordBinds]
    simp [expectedWord, funct3, LoadStoreDecode.encoding, lb, lh, lw,
      show row.isLbu = true by
        simpa [RiscvRefinement.Publication.TeamB.LoadStore.selected]
          using localCertificate.selectedRow]
  · obtain ⟨lb, lh, lbu, lw, _, _, _⟩ :=
      lhu_flags row localCertificate.holds (by
        simpa [RiscvRefinement.Publication.TeamB.LoadStore.selected]
          using localCertificate.selectedRow)
    rw [environment.wordBinds]
    simp [expectedWord, funct3, LoadStoreDecode.encoding, lb, lh, lbu, lw,
      show row.isLhu = true by
        simpa [RiscvRefinement.Publication.TeamB.LoadStore.selected]
          using localCertificate.selectedRow]
  · obtain ⟨lb, lh, lbu, lhu, lw, _, _⟩ :=
      sb_flags row localCertificate.holds (by
        simpa [RiscvRefinement.Publication.TeamB.LoadStore.selected]
          using localCertificate.selectedRow)
    rw [environment.wordBinds]
    simp [expectedWord, funct3, LoadStoreDecode.encoding, lb, lh, lbu, lhu,
      lw, show row.isSb = true by
        simpa [RiscvRefinement.Publication.TeamB.LoadStore.selected]
          using localCertificate.selectedRow]
  · obtain ⟨lb, lh, lbu, lhu, lw, sb, _⟩ :=
      sh_flags row localCertificate.holds (by
        simpa [RiscvRefinement.Publication.TeamB.LoadStore.selected]
          using localCertificate.selectedRow)
    rw [environment.wordBinds]
    simp [expectedWord, funct3, LoadStoreDecode.encoding, lb, lh, lbu, lhu,
      lw, sb, show row.isSh = true by
        simpa [RiscvRefinement.Publication.TeamB.LoadStore.selected]
          using localCertificate.selectedRow]
  · obtain ⟨lb, lh, lbu, lhu, lw, sb, sh⟩ :=
      sw_flags row localCertificate.holds (by
        simpa [RiscvRefinement.Publication.TeamB.LoadStore.selected]
          using localCertificate.selectedRow)
    rw [environment.wordBinds]
    simp [expectedWord, funct3, LoadStoreDecode.encoding, lb, lh, lbu, lhu,
      lw, sb, sh]


end Memory

end LeanRV32IM.Publication
