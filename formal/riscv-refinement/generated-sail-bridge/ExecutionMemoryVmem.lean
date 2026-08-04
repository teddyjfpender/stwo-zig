import ExecutionMemoryWrite
import ExecutionClosure

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 2_000_000
set_option linter.unusedVariables false

open Sail

namespace LeanRV32IM.Publication.ExecutionMemory

open LeanRV32IM.Functions
open RiscvRefinement

/-!
Composition of the checked ordinary-RAM primitives with the generated virtual
memory and RV32 load/store instruction bodies.  The lower-level component
reducers live in `ExecutionMemory.lean`; this module stays below the manual
file ceiling while exposing the final constructive execution interface.
-/

private theorem bitVec2_cases (index : BitVec 2) :
    index = 0#2 ∨ index = 1#2 ∨ index = 2#2 ∨ index = 3#2 := by
  simp only [← BitVec.toNat_inj]
  have bound := index.isLt
  simp at bound ⊢
  omega

private theorem halfSelector_of_byteOffset_eq
    (address : BitVec 32)
    (offset : BitVec 2)
    (offsetEq : Memory.byteOffset address = offset) :
    Memory.halfSelector address = BitVec.extractLsb' 1 1 offset := by
  have projected :=
    congrArg
      (fun value : BitVec 2 => BitVec.extractLsb' 1 1 value)
      offsetEq
  change
    BitVec.extractLsb' 1 1 (BitVec.extractLsb' 0 2 address) =
      BitVec.extractLsb' 1 1 offset at projected
  rw [BitVec.extractLsb'_extractLsb'_of_le
    (x := address)
    (start := 1)
    (len := 1)
    (len' := 2)
    (by decide)] at projected
  exact projected

private theorem lowBit_of_byteOffset_eq
    (address : BitVec 32)
    (offset : BitVec 2)
    (offsetEq : Memory.byteOffset address = offset) :
    BitVec.extractLsb' 0 1 address =
      BitVec.extractLsb' 0 1 offset := by
  have projected :=
    congrArg
      (fun value : BitVec 2 => BitVec.extractLsb' 0 1 value)
      offsetEq
  change
    BitVec.extractLsb' 0 1 (BitVec.extractLsb' 0 2 address) =
      BitVec.extractLsb' 0 1 offset at projected
  rw [BitVec.extractLsb'_extractLsb'_of_le
    (x := address)
    (start := 0)
    (len := 1)
    (len' := 2)
    (by decide)] at projected
  exact projected

theorem accessValue_one_eq_selectByte
    (address : BitVec 32)
    (memory : WordBytes) :
    accessValue address memory.word 1 =
      Memory.selectByte memory (Memory.byteOffset address) := by
  have modulus :=
    RiscvRefinement.Opcodes.byteOffset_toNat address
  rcases bitVec2_cases (Memory.byteOffset address) with h | h | h | h
  all_goals
    rw [h] at modulus ⊢
    simp at modulus
    simp only [accessValue]
    rw [WordBytes.word_append, ← modulus]
    simp [Memory.selectByte]
  · rw [BitVec.extractLsb'_append_eq_of_add_le
      (start := 0) (len := 8) (by decide)]
    rw [BitVec.extractLsb'_append_eq_of_add_le
      (start := 0) (len := 8) (by decide)]
    exact BitVec.extractLsb'_append_eq_right
  · rw [BitVec.extractLsb'_append_eq_of_add_le
      (start := 8) (len := 8) (by decide)]
    rw [BitVec.extractLsb'_append_eq_of_add_le
      (start := 8) (len := 8) (by decide)]
    exact BitVec.extractLsb'_append_eq_left
  · rw [BitVec.extractLsb'_append_eq_of_add_le
      (start := 16) (len := 8) (by decide)]
    rw [BitVec.extractLsb'_append_eq_of_le
      (start := 16) (len := 8) (by decide)]
    exact BitVec.extractLsb'_eq_self
  · rw [BitVec.extractLsb'_append_eq_of_le
      (start := 24) (len := 8) (by decide)]
    exact BitVec.extractLsb'_eq_self

theorem accessValue_two_eq_selectHalf
    (address : BitVec 32)
    (memory : WordBytes)
    (aligned : Memory.isHalfAligned address) :
    accessValue address memory.word 2 =
      Memory.selectHalf memory (Memory.halfSelector address) := by
  have modulus :=
    RiscvRefinement.Opcodes.byteOffset_toNat address
  rcases bitVec2_cases (Memory.byteOffset address) with h | h | h | h
  · have selector : Memory.halfSelector address = 0#1 := by
      simpa using halfSelector_of_byteOffset_eq address (0#2) h
    rw [h] at modulus
    simp at modulus
    simp only [accessValue]
    rw [WordBytes.word_halves, ← modulus]
    simp [
      Memory.selectHalf,
      selector,
    ]
    exact BitVec.extractLsb'_append_eq_right
  · exfalso
    have lowBit := lowBit_of_byteOffset_eq address (1#2) h
    change BitVec.extractLsb' 0 1 address = 0#1 at aligned
    have impossible :
        (0#1 : BitVec 1) = BitVec.extractLsb' 0 1 (1#2) :=
      aligned.symm.trans lowBit
    have mismatch :
        (0#1 : BitVec 1) ≠ BitVec.extractLsb' 0 1 (1#2) := by
      decide
    exact mismatch impossible
  · have selector : Memory.halfSelector address = 1#1 := by
      simpa using halfSelector_of_byteOffset_eq address (2#2) h
    rw [h] at modulus
    simp at modulus
    simp only [accessValue]
    rw [WordBytes.word_halves, ← modulus]
    simp [
      Memory.selectHalf,
      selector,
    ]
    exact BitVec.extractLsb'_append_eq_left
  · exfalso
    have lowBit := lowBit_of_byteOffset_eq address (3#2) h
    change BitVec.extractLsb' 0 1 address = 0#1 at aligned
    have impossible :
        (0#1 : BitVec 1) = BitVec.extractLsb' 0 1 (3#2) :=
      aligned.symm.trans lowBit
    have mismatch :
        (0#1 : BitVec 1) ≠ BitVec.extractLsb' 0 1 (3#2) := by
      decide
    exact mismatch impossible

theorem accessValue_four_eq_word
    (address : BitVec 32)
    (memory : WordBytes)
    (aligned : Memory.isWordAligned address) :
    accessValue address memory.word 4 = memory.word := by
  have offset : Memory.byteOffset address = 0#2 := aligned
  have modulus :=
    RiscvRefinement.Opcodes.byteOffset_toNat address
  rw [offset] at modulus
  simp at modulus
  simp only [accessValue]
  rw [← modulus]
  exact BitVec.extractLsb'_eq_self

theorem extend_accessValue_one_signed
    (address : BitVec 32)
    (memory : WordBytes) :
    extend_value false (accessValue address memory.word 1) =
      Memory.signExtendByte
        (Memory.selectByte memory (Memory.byteOffset address)) := by
  rw [accessValue_one_eq_selectByte]
  rfl

theorem extend_accessValue_one_unsigned
    (address : BitVec 32)
    (memory : WordBytes) :
    extend_value true (accessValue address memory.word 1) =
      Memory.zeroExtendByte
        (Memory.selectByte memory (Memory.byteOffset address)) := by
  rw [accessValue_one_eq_selectByte]
  rfl

theorem extend_accessValue_two_signed
    (address : BitVec 32)
    (memory : WordBytes)
    (aligned : Memory.isHalfAligned address) :
    extend_value false (accessValue address memory.word 2) =
      Memory.signExtendHalf
        (Memory.selectHalf memory (Memory.halfSelector address)) := by
  rw [accessValue_two_eq_selectHalf address memory aligned]
  rfl

theorem extend_accessValue_two_unsigned
    (address : BitVec 32)
    (memory : WordBytes)
    (aligned : Memory.isHalfAligned address) :
    extend_value true (accessValue address memory.word 2) =
      Memory.zeroExtendHalf
        (Memory.selectHalf memory (Memory.halfSelector address)) := by
  rw [accessValue_two_eq_selectHalf address memory aligned]
  rfl

theorem extend_accessValue_four
    (address : BitVec 32)
    (memory : WordBytes)
    (aligned : Memory.isWordAligned address) :
    extend_value false (accessValue address memory.word 4) = memory.word := by
  rw [accessValue_four_eq_word address memory aligned]
  simp [
    extend_value,
    Functions.sign_extend,
    Sail.BitVec.signExtend,
  ]

theorem mem_read_load_data_succeeds
    (state : GeneratedState)
    (address : BitVec 34)
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
    (matching :
      matching_pma_region regions (.Physaddr address) width = some region)
    (mainMemory : region.attributes.mem_type = .MainMemory)
    (readable : region.attributes.readable = true)
    (aligned : is_aligned_paddr (.Physaddr address) width = true)
    (htifDisabled :
      state.regs.get? Register.htif_tohost_base = some none)
    (bytes : RawByteBindings state address.toNat width value) :
    mem_read (.Load .Data) .PBMT_PMA (.Physaddr address) width
        false false false state =
      .ok (.Ok value) state := by
  have privilegeOutcome := effectivePrivilege_machine_of_mprv_clear
    (.Load .Data) mstatus mprvClear
  have mstatusRead :
      ((PreSail.readReg Register.mstatus : SailM (BitVec 64)) state) =
        .ok mstatus state := by
    simp [
      PreSail.readReg,
      mstatusBinding,
      bind,
      EStateM.bind,
      pure,
      EStateM.pure,
      MonadState.get,
      getThe,
      MonadStateOf.get,
      EStateM.get,
    ]
  have privilegeRead :
      ((PreSail.readReg Register.cur_privilege : SailM Privilege) state) =
        .ok .Machine state := by
    simp [
      PreSail.readReg,
      privilegeBinding,
      bind,
      EStateM.bind,
      pure,
      EStateM.pure,
      MonadState.get,
      getThe,
      MonadStateOf.get,
      EStateM.get,
    ]
  have checkedOutcome := checked_mem_read_load_data_succeeds
    state address width value regions region widthCases regionsBinding
    matching mainMemory readable aligned htifDisabled bytes
  simp [
    mem_read,
    mem_read_priv,
    mem_read_priv_meta,
    MemoryOpResult_drop_meta,
    effectivePrivilege,
    mstatusRead,
    privilegeRead,
    mstatusBinding,
    privilegeBinding,
    mprvClear,
    privilegeOutcome,
    checkedOutcome,
    mem_read_callback,
    PreSail.readReg,
    bind,
    EStateM.bind,
    pure,
    EStateM.pure,
    MonadState.get,
    getThe,
    MonadStateOf.get,
    EStateM.get,
  ]

theorem vmem_read_addr_load_data_succeeds
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
    (readable : region.attributes.readable = true)
    (virtualAligned : is_aligned_vaddr (.Virtaddr address) width = true)
    (physicalAligned : is_aligned_paddr
      (.Physaddr (zero_extend (m := 34) address)) width = true)
    (samePage : SamePage address width)
    (htifDisabled :
      state.regs.get? Register.htif_tohost_base = some none)
    (bytes : RawByteBindings state
      (zero_extend (m := 34) address).toNat width value) :
    vmem_read_addr (.Virtaddr address) width (.Load .Data)
        false false false state =
      .ok (.Ok value) state := by
  have notShadow :
      is_shadow_stack_access (.Load .Data) = pure false := by
    rfl
  have privilegeOutcome := effectivePrivilege_machine_of_mprv_clear
    (.Load .Data) mstatus mprvClear
  have mstatusRead :
      ((PreSail.readReg Register.mstatus : SailM (BitVec 64)) state) =
        .ok mstatus state := by
    simp [
      PreSail.readReg,
      mstatusBinding,
      bind,
      EStateM.bind,
      pure,
      EStateM.pure,
      MonadState.get,
      getThe,
      MonadStateOf.get,
      EStateM.get,
    ]
  have privilegeRead :
      ((PreSail.readReg Register.cur_privilege : SailM Privilege) state) =
        .ok .Machine state := by
    simp [
      PreSail.readReg,
      privilegeBinding,
      bind,
      EStateM.bind,
      pure,
      EStateM.pure,
      MonadState.get,
      getThe,
      MonadStateOf.get,
      EStateM.get,
    ]
  have machineEq :
      ((Privilege.Machine == Privilege.Machine) : Bool) = true := by
    decide
  have bareEq : ((SATPMode.Bare == SATPMode.Bare) : Bool) = true := by
    decide
  have splitOutcome := split_on_page_boundary_succeeds
    state address width samePage
  have translateOutcome := translateAddr_machine_bare_succeeds
    state address (.Load .Data) mstatus mstatusBinding mprvClear
    privilegeBinding notShadow
  have memoryOutcome := mem_read_load_data_succeeds
    state (zero_extend (m := 34) address) width value mstatus regions
    region widthCases mstatusBinding mprvClear privilegeBinding
    regionsBinding matching mainMemory readable physicalAligned htifDisabled
    bytes
  simp [
    vmem_read_addr,
    Sail.SailME.run,
    PreSail.PreSailME.run,
    virtualAligned,
    splitOutcome,
    effectivePrivilege,
    mstatusRead,
    privilegeRead,
    machineEq,
    bareEq,
    privilegeOutcome,
    mstatusBinding,
    privilegeBinding,
    mprvClear,
    translationMode,
    translateOutcome,
    memoryOutcome,
    notShadow,
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
  rcases widthCases with rfl | rfl | rfl <;>
    simp [Sail.BitVec.updateSubrange']

theorem vmem_read_load_data_succeeds
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
    (readable : region.attributes.readable = true)
    (virtualAligned :
      is_aligned_vaddr (.Virtaddr effectiveAddress) width = true)
    (physicalAligned : is_aligned_paddr
      (.Physaddr (zero_extend (m := 34) effectiveAddress)) width = true)
    (samePage : SamePage effectiveAddress width)
    (htifDisabled :
      state.regs.get? Register.htif_tohost_base = some none)
    (bytes : RawByteBindings state
      (zero_extend (m := 34) effectiveAddress).toNat width value) :
    vmem_read (.Regidx rs1) offset width (.Load .Data)
        false false false state =
      .ok (.Ok value) state := by
  have registerOutcome :=
    ExecutionClosure.generatedRegister_read_succeeds
      state rs1 baseValue baseBinding
  have transformOutcome := transform_effective_address_machine_succeeds
    state effectiveAddress (.Load .Data) mstatus mstatusBinding mprvClear
    privilegeBinding
  have addressOutcome := vmem_read_addr_load_data_succeeds
    state effectiveAddress width value mstatus regions region widthCases
    mstatusBinding mprvClear privilegeBinding regionsBinding matching
    mainMemory readable virtualAligned physicalAligned samePage htifDisabled
    bytes
  simp [
    vmem_read,
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

theorem constructiveLoadExecution
    (stepNo : Nat)
    (word : BitVec 32)
    (decoded : instruction)
    (pc : BitVec 32)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5)
    (isUnsigned : Bool)
    (width : Nat)
    (baseValue effectiveAddress busAddress memoryWord loadedValue : BitVec 32)
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
    (readable : region.attributes.readable = true)
    (virtualAligned :
      is_aligned_vaddr (.Virtaddr effectiveAddress) width = true)
    (physicalAligned : is_aligned_paddr
      (.Physaddr (zero_extend (m := 34) effectiveAddress)) width = true)
    (samePage : SamePage effectiveAddress width)
    (htifDisabled :
      initial.regs.get? Register.htif_tohost_base = some none)
    (bytes : RawByteBindings initial
      (zero_extend (m := 34) effectiveAddress).toNat width
      (accessValue effectiveAddress memoryWord width))
    (memoryBinding :
      LeanRV32IM.Publication.GeneratedMemoryWordBinding
        initial busAddress memoryWord)
    (effectiveAddressEq :
      baseValue + sign_extend (m := 32) imm = effectiveAddress)
    (busAddressEq : Memory.busAddress effectiveAddress = busAddress)
    (valueMatches :
      extend_value isUnsigned
          (accessValue effectiveAddress memoryWord width) =
        loadedValue)
    (executeClause : execute decoded =
      execute_LOAD imm (.Regidx rs1) (.Regidx rd) isUnsigned width)
    (normalizes :
      completeBaseExecution pc (execute decoded) =
        eraseObservation
          (normalizedLoadCompletion
            pc imm rs1 rd isUnsigned width))
    (retirementEq : retirement = {
      nextPc := RiscvRefinement.nextPc pc
      write := RiscvRefinement.architecturalWrite rd loadedValue
      read := some { address := busAddress, value := memoryWord }
      store := none
    }) :
    ConstructiveGeneratedExecution stepNo word decoded
      (completeBaseExecution pc (execute decoded))
      (normalizedLoadCompletion pc imm rs1 rd isUnsigned width)
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
  have bytesAfterNextPc : RawByteBindings afterNextPc
      (zero_extend (m := 34) effectiveAddress).toNat width
      (accessValue effectiveAddress memoryWord width) := by
    constructor
    intro offset
    simpa [afterNextPc] using bytes.byte offset
  have vmemOutcome := vmem_read_load_data_succeeds
    afterNextPc rs1 baseValue effectiveAddress
    (sign_extend (m := 32) imm) width
    (accessValue effectiveAddress memoryWord width)
    mstatus regions region widthCases baseAfterNextPc effectiveAddressEq
    mstatusAfterNextPc mprvClear privilegeAfterNextPc regionsAfterNextPc
    matching mainMemory readable virtualAligned physicalAligned samePage
    htifAfterNextPc bytesAfterNextPc
  have widthCheck :
      (width ≤b LeanRV32IM.Functions.xlen_bytes) = true := by
    rcases widthCases with rfl | rfl | rfl <;> decide
  rcases ExecutionClosure.generatedRegister_write_succeeds
      afterNextPc rd
      (extend_value isUnsigned
        (accessValue effectiveAddress memoryWord width)) with
    ⟨afterWrite, writeOutcome, nextPcPreserved⟩
  have nextPcBinding :
      afterNextPc.regs.get? Register.nextPC =
        some (RiscvRefinement.nextPc pc) := by
    simp [afterNextPc, Std.ExtDHashMap.get?_insert]
  have afterWriteNextPc :
      afterWrite.regs.get? Register.nextPC =
        some (RiscvRefinement.nextPc pc) := by
    rw [nextPcPreserved]
    exact nextPcBinding
  rcases ExecutionClosure.generated_tick_pc_succeeds
      afterWrite (RiscvRefinement.nextPc pc) afterWriteNextPc with
    ⟨afterTick, tickOutcome⟩
  have bodyOutcome :
      execute decoded afterNextPc = .ok RETIRE_SUCCESS afterWrite := by
    rw [executeClause]
    simp [
      execute_LOAD,
      widthCheck,
      PreSail.assert,
      vmemOutcome,
      writeOutcome,
      bind,
      EStateM.bind,
      pure,
      EStateM.pure,
    ]
  have runBase := ExecutionClosure.runBaseAfterDecode_succeeds_of_body
    stepNo word decoded pc initial pcBinding landingPadClear
    ⟨afterWrite, bodyOutcome⟩
  have baseProjection : generatedX? rs1 initial = some baseValue := by
    simpa [LeanRV32IM.Publication.generatedRegisterValue?] using baseBinding
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
      normalizedLoadCompletion pc imm rs1 rd isUnsigned width initial =
        .ok {
          generatedResult := RETIRE_SUCCESS
          retirement := some retirement
        } afterTick := by
    rw [retirementEq, ← valueMatches]
    simp [
      normalizedLoadCompletion,
      completeLoadEffects,
      afterNextPc,
      widthCheck,
      vmemOutcome,
      writeOutcome,
      tickOutcome,
      baseProjection,
      PreSail.writeReg,
      PreSail.assert,
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
              (normalizedLoadCompletion
                pc imm rs1 rd isUnsigned width) initial :=
          congrFun normalizes initial
        _ = .ok RETIRE_SUCCESS afterTick := by
          simp [eraseObservation, observedOutcome]

end LeanRV32IM.Publication.ExecutionMemory
