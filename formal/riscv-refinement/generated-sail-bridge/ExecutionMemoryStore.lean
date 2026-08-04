import ExecutionMemoryVmem

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 2_000_000
set_option linter.unusedVariables false

open Sail

namespace LeanRV32IM.Publication.ExecutionMemory

open LeanRV32IM.Functions
open RiscvRefinement

/-! Constructive generated store execution over the ordinary-RAM profile. -/

theorem generatedWordBytes_word (memory : WordBytes) :
    generatedWordBytes memory.word = memory := by
  apply WordBytes.eq_of_limbs
  · rw [WordBytes.word_append]
    simp only [
      generatedWordBytes,
      BitVec.extractLsb,
      Nat.reduceSub,
      Nat.reduceAdd,
    ]
    change
      BitVec.extractLsb' 0 8
          (memory.limb3 +++
            (memory.limb2 +++
              (memory.limb1 +++ memory.limb0))) =
        memory.limb0
    rw [BitVec.extractLsb'_append_eq_of_add_le
      (start := 0) (len := 8) (by decide)]
    rw [BitVec.extractLsb'_append_eq_of_add_le
      (start := 0) (len := 8) (by decide)]
    exact BitVec.extractLsb'_append_eq_right
  · rw [WordBytes.word_append]
    simp only [
      generatedWordBytes,
      BitVec.extractLsb,
      Nat.reduceSub,
      Nat.reduceAdd,
    ]
    change
      BitVec.extractLsb' 8 8
          (memory.limb3 +++
            (memory.limb2 +++
              (memory.limb1 +++ memory.limb0))) =
        memory.limb1
    rw [BitVec.extractLsb'_append_eq_of_add_le
      (start := 8) (len := 8) (by decide)]
    rw [BitVec.extractLsb'_append_eq_of_add_le
      (start := 8) (len := 8) (by decide)]
    exact BitVec.extractLsb'_append_eq_left
  · rw [WordBytes.word_append]
    simp only [
      generatedWordBytes,
      BitVec.extractLsb,
      Nat.reduceSub,
      Nat.reduceAdd,
    ]
    change
      BitVec.extractLsb' 16 8
          (memory.limb3 +++
            (memory.limb2 +++
              (memory.limb1 +++ memory.limb0))) =
        memory.limb2
    rw [BitVec.extractLsb'_append_eq_of_add_le
      (start := 16) (len := 8) (by decide)]
    rw [BitVec.extractLsb'_append_eq_of_le
      (start := 16) (len := 8) (by decide)]
    exact BitVec.extractLsb'_eq_self
  · rw [WordBytes.word_append]
    simp only [
      generatedWordBytes,
      BitVec.extractLsb,
      Nat.reduceSub,
      Nat.reduceAdd,
    ]
    change
      BitVec.extractLsb' 24 8
          (memory.limb3 +++
            (memory.limb2 +++
              (memory.limb1 +++ memory.limb0))) =
        memory.limb3
    rw [BitVec.extractLsb'_append_eq_of_le
      (start := 24) (len := 8) (by decide)]
    exact BitVec.extractLsb'_eq_self

theorem vmem_write_addr_store_data_succeeds
    (state : GeneratedState)
    (address : BitVec 32)
    (width : Nat)
    (value : BitVec (8 * width))
    (mstatus : BitVec 64)
    (regions : List PMA_Region)
    (region : PMA_Region)
    (widthCases : width = 1 ∨ width = 2 ∨ width = 4)
    (mstatusBinding :
      state.regs.get? Register.mstatus = some mstatus)
    (mprvClear : _get_Mstatus_MPRV mstatus = 0#1)
    (privilegeBinding :
      state.regs.get? Register.cur_privilege = some .Machine)
    (regionsBinding :
      state.regs.get? Register.pma_regions = some regions)
    (matching : matching_pma_region regions
      (.Physaddr (zero_extend (m := 34) address)) width = some region)
    (mainMemory : region.attributes.mem_type = .MainMemory)
    (writable : region.attributes.writable = true)
    (virtualAligned : is_aligned_vaddr (.Virtaddr address) width = true)
    (physicalAligned : is_aligned_paddr
      (.Physaddr (zero_extend (m := 34) address)) width = true)
    (samePage : SamePage address width)
    (htifDisabled :
      state.regs.get? Register.htif_tohost_base = some none) :
    ∃ final : GeneratedState,
      vmem_write_addr (.Virtaddr address) width value (.Store .Data)
          false false false state =
        .ok (.Ok true) final ∧
      final.regs = state.regs := by
  have notShadow :
      is_shadow_stack_access (.Store .Data) = pure false := by
    rfl
  have privilegeOutcome := effectivePrivilege_machine_of_mprv_clear
    (.Store .Data) mstatus mprvClear
  have mstatusRead :
      ((PreSail.readReg Register.mstatus : SailM (BitVec 64)) state) =
        .ok mstatus state := by
    simp [
      PreSail.readReg, mstatusBinding,
      bind, EStateM.bind, pure, EStateM.pure,
      MonadState.get, getThe, MonadStateOf.get, EStateM.get,
    ]
  have privilegeRead :
      ((PreSail.readReg Register.cur_privilege : SailM Privilege) state) =
        .ok .Machine state := by
    simp [
      PreSail.readReg, privilegeBinding,
      bind, EStateM.bind, pure, EStateM.pure,
      MonadState.get, getThe, MonadStateOf.get, EStateM.get,
    ]
  have machineEq :
      ((Privilege.Machine == Privilege.Machine) : Bool) = true := by
    decide
  have bareEq : ((SATPMode.Bare == SATPMode.Bare) : Bool) = true := by
    decide
  have splitOutcome := split_on_page_boundary_succeeds
    state address width samePage
  have translateOutcome := translateAddr_machine_bare_succeeds
    state address (.Store .Data) mstatus mstatusBinding mprvClear
    privilegeBinding notShadow
  have eaOutcome := mem_write_ea_store_data_succeeds
    state (zero_extend (m := 34) address) width mstatus regions region
    mstatusBinding mprvClear privilegeBinding regionsBinding matching
    mainMemory writable physicalAligned
  rcases mem_write_value_store_data_succeeds
      state (zero_extend (m := 34) address) width value mstatus regions
      region widthCases mstatusBinding mprvClear privilegeBinding
      regionsBinding matching mainMemory writable physicalAligned
      htifDisabled with ⟨final, writeOutcome, regsPreserved⟩
  have valueNormalized :
      BitVec.setWidth (8 * width)
          (Sail.BitVec.extractLsb value
            ((8 *i width) -i 1) 0) = value := by
    rcases widthCases with rfl | rfl | rfl <;>
      simp [Sail.BitVec.extractLsb, BitVec.extractLsb]
  refine ⟨final, ?_, regsPreserved⟩
  simp [
    vmem_write_addr,
    Sail.SailME.run,
    PreSail.PreSailME.run,
    virtualAligned,
    splitOutcome,
    effectivePrivilege,
    privilegeOutcome,
    mstatusRead,
    privilegeRead,
    machineEq,
    bareEq,
    PreSail.assert,
    valueNormalized,
    mstatusBinding,
    privilegeBinding,
    mprvClear,
    translationMode,
    translateOutcome,
    eaOutcome,
    writeOutcome,
    notShadow,
    is_store_conditional,
    bne,
    Functions.not,
    bits_of_virtaddr,
    ExceptT.pure,
    ExceptT.bind,
    ExceptT.bindCont,
    ExceptT.lift,
    ExceptT.run,
    ExceptT.mk,
    liftM,
    monadLift,
    MonadLiftT.monadLift,
    MonadLift.monadLift,
    Functor.map,
    bind,
    EStateM.bind,
    EStateM.map,
    pure,
    EStateM.pure,
    MonadState.get,
    getThe,
    MonadStateOf.get,
    EStateM.get,
    Sail.BitVec.updateSubrange,
  ]

theorem vmem_write_store_data_succeeds
    (state : GeneratedState)
    (rs1 : BitVec 5)
    (baseValue effectiveAddress : BitVec 32)
    (offset : BitVec 32)
    (width : Nat)
    (value : BitVec (8 * width))
    (mstatus : BitVec 64)
    (regions : List PMA_Region)
    (region : PMA_Region)
    (widthCases : width = 1 ∨ width = 2 ∨ width = 4)
    (baseBinding :
      LeanRV32IM.Publication.generatedRegisterValue? state rs1 =
        some baseValue)
    (addressEq : baseValue + offset = effectiveAddress)
    (mstatusBinding :
      state.regs.get? Register.mstatus = some mstatus)
    (mprvClear : _get_Mstatus_MPRV mstatus = 0#1)
    (privilegeBinding :
      state.regs.get? Register.cur_privilege = some .Machine)
    (regionsBinding :
      state.regs.get? Register.pma_regions = some regions)
    (matching : matching_pma_region regions
      (.Physaddr (zero_extend (m := 34) effectiveAddress)) width =
        some region)
    (mainMemory : region.attributes.mem_type = .MainMemory)
    (writable : region.attributes.writable = true)
    (virtualAligned :
      is_aligned_vaddr (.Virtaddr effectiveAddress) width = true)
    (physicalAligned : is_aligned_paddr
      (.Physaddr (zero_extend (m := 34) effectiveAddress)) width = true)
    (samePage : SamePage effectiveAddress width)
    (htifDisabled :
      state.regs.get? Register.htif_tohost_base = some none) :
    ∃ final : GeneratedState,
      vmem_write (.Regidx rs1) offset width value (.Store .Data)
          false false false state =
        .ok (.Ok true) final ∧
      final.regs = state.regs := by
  have registerOutcome :=
    ExecutionClosure.generatedRegister_read_succeeds
      state rs1 baseValue baseBinding
  have transformOutcome := transform_effective_address_machine_succeeds
    state effectiveAddress (.Store .Data) mstatus mstatusBinding mprvClear
    privilegeBinding
  rcases vmem_write_addr_store_data_succeeds
      state effectiveAddress width value mstatus regions region widthCases
      mstatusBinding mprvClear privilegeBinding regionsBinding matching
      mainMemory writable virtualAligned physicalAligned samePage htifDisabled
      with ⟨final, addressOutcome, regsPreserved⟩
  refine ⟨final, ?_, regsPreserved⟩
  simp [
    vmem_write,
    get_transformed_data_addr,
    ext_data_get_addr,
    registerOutcome,
    addressEq,
    transformOutcome,
    addressOutcome,
    Sail.SailME.run,
    PreSail.PreSailME.run,
    ExceptT.pure,
    ExceptT.bind,
    ExceptT.bindCont,
    ExceptT.lift,
    ExceptT.run,
    ExceptT.mk,
    liftM,
    monadLift,
    MonadLiftT.monadLift,
    MonadLift.monadLift,
    Functor.map,
    bind,
    EStateM.bind,
    EStateM.map,
    pure,
    EStateM.pure,
  ]

theorem constructiveStoreExecution
    (stepNo : Nat)
    (word : BitVec 32)
    (decoded : instruction)
    (pc : BitVec 32)
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5)
    (width : Nat)
    (source baseValue effectiveAddress busAddress memoryWord : BitVec 32)
    (retirement : Retirement)
    (initial : GeneratedState)
    (mstatus : BitVec 64)
    (regions : List PMA_Region)
    (region : PMA_Region)
    (widthCases : width = 1 ∨ width = 2 ∨ width = 4)
    (pcBinding : initial.regs.get? Register.PC = some pc)
    (landingPadClear :
      initial.regs.get? Register.elp =
        some (landing_pad_bits_backwards .NO_LP_EXPECTED))
    (baseBinding :
      LeanRV32IM.Publication.generatedRegisterValue? initial rs1 =
        some baseValue)
    (sourceBinding :
      LeanRV32IM.Publication.generatedRegisterValue? initial rs2 =
        some source)
    (mstatusBinding :
      initial.regs.get? Register.mstatus = some mstatus)
    (mprvClear : _get_Mstatus_MPRV mstatus = 0#1)
    (privilegeBinding :
      initial.regs.get? Register.cur_privilege = some .Machine)
    (regionsBinding :
      initial.regs.get? Register.pma_regions = some regions)
    (matching : matching_pma_region regions
      (.Physaddr (zero_extend (m := 34) effectiveAddress)) width =
        some region)
    (mainMemory : region.attributes.mem_type = .MainMemory)
    (writable : region.attributes.writable = true)
    (virtualAligned :
      is_aligned_vaddr (.Virtaddr effectiveAddress) width = true)
    (physicalAligned : is_aligned_paddr
      (.Physaddr (zero_extend (m := 34) effectiveAddress)) width = true)
    (samePage : SamePage effectiveAddress width)
    (htifDisabled :
      initial.regs.get? Register.htif_tohost_base = some none)
    (memoryBinding :
      LeanRV32IM.Publication.GeneratedMemoryWordBinding
        initial busAddress memoryWord)
    (effectiveAddressEq :
      baseValue + sign_extend (m := 32) imm = effectiveAddress)
    (busAddressEq : Memory.busAddress effectiveAddress = busAddress)
    (executeClause : execute decoded =
      execute_STORE imm (.Regidx rs2) (.Regidx rs1) width)
    (normalizes :
      completeBaseExecution pc (execute decoded) =
        eraseObservation
          (normalizedStoreCompletion pc imm rs2 rs1 width))
    (retirementEq : retirement = {
      nextPc := RiscvRefinement.nextPc pc
      write := none
      read := none
      store := some {
        address := busAddress
        mask := storeMask width effectiveAddress
        value := (Memory.applyMask
          (generatedWordBytes memoryWord)
          (generatedStorePayload width source)
          (storeMask width effectiveAddress)).word
      }
    }) :
    ConstructiveGeneratedExecution stepNo word decoded
      (completeBaseExecution pc (execute decoded))
      (normalizedStoreCompletion pc imm rs2 rs1 width)
      initial retirement := by
  let afterNextPc : GeneratedState := {
    initial with
    regs := initial.regs.insert Register.nextPC
      (RiscvRefinement.nextPc pc)
  }
  have baseAfterNextPc :
      LeanRV32IM.Publication.generatedRegisterValue?
          afterNextPc rs1 = some baseValue := by
    rw [ExecutionClosure.generatedRegisterValue?_insert_nextPC]
    exact baseBinding
  have sourceAfterNextPc :
      LeanRV32IM.Publication.generatedRegisterValue?
          afterNextPc rs2 = some source := by
    rw [ExecutionClosure.generatedRegisterValue?_insert_nextPC]
    exact sourceBinding
  have mstatusAfterNextPc :
      afterNextPc.regs.get? Register.mstatus = some mstatus := by
    simp [afterNextPc, Std.ExtDHashMap.get?_insert, mstatusBinding]
  have privilegeAfterNextPc :
      afterNextPc.regs.get? Register.cur_privilege = some .Machine := by
    simp [afterNextPc, Std.ExtDHashMap.get?_insert, privilegeBinding]
  have regionsAfterNextPc :
      afterNextPc.regs.get? Register.pma_regions = some regions := by
    simp [afterNextPc, Std.ExtDHashMap.get?_insert, regionsBinding]
  have htifAfterNextPc :
      afterNextPc.regs.get? Register.htif_tohost_base = some none := by
    simp [afterNextPc, Std.ExtDHashMap.get?_insert, htifDisabled]
  have sourceOutcome := ExecutionClosure.generatedRegister_read_succeeds
    afterNextPc rs2 source sourceAfterNextPc
  have widthCheck :
      (width ≤b LeanRV32IM.Functions.xlen_bytes) = true := by
    rcases widthCases with rfl | rfl | rfl <;> decide
  let data : BitVec (8 * width) :=
    BitVec.extractLsb' 0 (8 * width) source
  have dataEq :
      Sail.BitVec.extractLsb source ((width *i 8) -i 1) 0 = data := by
    rcases widthCases with rfl | rfl | rfl <;>
      simp [data, Sail.BitVec.extractLsb, BitVec.extractLsb]
  have dataWidthNormalized :
      BitVec.setWidth (8 * width)
          (BitVec.setWidth
            (((width : Int) * 8 - 1).toNat + 1) data) = data := by
    rcases widthCases with rfl | rfl | rfl <;> simp
  rcases vmem_write_store_data_succeeds
      afterNextPc rs1 baseValue effectiveAddress
      (sign_extend (m := 32) imm) width data mstatus regions region
      widthCases baseAfterNextPc effectiveAddressEq mstatusAfterNextPc
      mprvClear privilegeAfterNextPc regionsAfterNextPc matching mainMemory
      writable virtualAligned physicalAligned samePage htifAfterNextPc with
    ⟨afterMemory, vmemOutcome, regsPreserved⟩
  have afterMemoryNextPc :
      afterMemory.regs.get? Register.nextPC =
        some (RiscvRefinement.nextPc pc) := by
    rw [regsPreserved]
    simp [afterNextPc, Std.ExtDHashMap.get?_insert]
  rcases ExecutionClosure.generated_tick_pc_succeeds
      afterMemory (RiscvRefinement.nextPc pc) afterMemoryNextPc with
    ⟨afterTick, tickOutcome⟩
  have bodyOutcome :
      execute decoded afterNextPc = .ok RETIRE_SUCCESS afterMemory := by
    rw [executeClause]
    simp [
      execute_STORE,
      widthCheck,
      PreSail.assert,
      sourceOutcome,
      dataEq,
      dataWidthNormalized,
      vmemOutcome,
      bind,
      EStateM.bind,
      pure,
      EStateM.pure,
    ]
  have runBase := ExecutionClosure.runBaseAfterDecode_succeeds_of_body
    stepNo word decoded pc initial pcBinding landingPadClear
    ⟨afterMemory, bodyOutcome⟩
  have baseProjection : generatedX? rs1 initial = some baseValue := by
    simpa [LeanRV32IM.Publication.generatedRegisterValue?] using baseBinding
  have sourceProjection : generatedX? rs2 initial = some source := by
    simpa [LeanRV32IM.Publication.generatedRegisterValue?] using sourceBinding
  have memoryProjection := generatedMemoryWord?_succeeds
    initial busAddress memoryWord memoryBinding
  have architecturalAddress :
      Memory.effectiveAddress baseValue imm = effectiveAddress := by
    simpa [
      Memory.effectiveAddress,
      Functions.sign_extend,
      Sail.BitVec.signExtend,
    ] using effectiveAddressEq
  have observedOutcome :
      normalizedStoreCompletion pc imm rs2 rs1 width initial =
        .ok {
          generatedResult := RETIRE_SUCCESS
          retirement := some retirement
        } afterTick := by
    rw [retirementEq]
    simp [
      normalizedStoreCompletion,
      completeStoreEffects,
      afterNextPc,
      widthCheck,
      PreSail.assert,
      sourceOutcome,
      dataEq,
      dataWidthNormalized,
      vmemOutcome,
      tickOutcome,
      baseProjection,
      sourceProjection,
      PreSail.writeReg,
      bind,
      EStateM.bind,
      pure,
      EStateM.pure,
      modify,
      modifyGet,
      MonadStateOf.modifyGet,
      EStateM.modifyGet,
      MonadState.get,
      getThe,
      MonadStateOf.get,
      EStateM.get,
    ]
    rw [architecturalAddress, busAddressEq, memoryProjection]
    rfl
  constructor
  · exact runBase
  · constructor
    · exact normalizes.symm
    · refine ⟨afterTick, observedOutcome, ?_⟩
      calc
        completeBaseExecution pc (execute decoded) initial =
            eraseObservation
              (normalizedStoreCompletion pc imm rs2 rs1 width) initial :=
          congrFun normalizes initial
        _ = .ok RETIRE_SUCCESS afterTick := by
          simp [eraseObservation, observedOutcome]

end LeanRV32IM.Publication.ExecutionMemory
