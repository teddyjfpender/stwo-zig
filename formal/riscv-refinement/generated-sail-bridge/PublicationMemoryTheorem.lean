import PublicationMemory

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 2_000_000
set_option linter.unusedVariables false

open Sail

namespace LeanRV32IM.Publication

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Family
open RiscvRefinement.Air.Generated
open RiscvRefinement.Opcodes
open RiscvRefinement.Sail.Reviewed

namespace Memory

theorem constructiveExecution
    (kind : Kind)
    (row : Row)
    (environment : LoadStoreEnvironment row)
    (initial : Functions.GeneratedState)
    (stepNo : Nat)
    (stateBindings : StateBindings kind row environment initial)
    (holds : LoadStoreHolds row)
    (selected :
      RiscvRefinement.Publication.TeamB.LoadStore.selected kind row = true) :
    ConstructiveExecution kind row environment initial stepNo := by
  unfold ConstructiveExecution
  rcases stateBindings.ordinaryRam.mstatus with
    ⟨mstatus, mstatusBinding, mprvClear⟩
  rcases stateBindings.ordinaryRam.pmaRegion with
    ⟨regions, region, regionsBinding, matching,
      mainMemory, readable, writable⟩
  have widthCases : width kind = 1 ∨ width kind = 2 ∨ width kind = 4 := by
    cases kind <;> simp [width]
  have rawAtEffective :
      ExecutionMemory.RawByteBindings initial
        environment.effectiveAddress.toNat (width kind)
        (ExecutionMemory.accessValue environment.effectiveAddress
          environment.memoryWord.word (width kind)) :=
    ExecutionMemory.rawByteBindings_of_access_bytes
      initial environment.effectiveAddress environment.memoryWord.word
      (width kind) stateBindings.ordinaryRam.accessBytes
  have raw :
      ExecutionMemory.RawByteBindings initial
        (_root_.zero_extend (m := 34) environment.effectiveAddress).toNat
        (width kind)
        (ExecutionMemory.accessValue environment.effectiveAddress
          environment.memoryWord.word (width kind)) := by
    have addressBound :
        environment.effectiveAddress.toNat < 17179869184 := by
      have widthBound := environment.effectiveAddress.isLt
      omega
    simpa [zero_extend, Sail.BitVec.zeroExtend, BitVec.zeroExtend,
      Nat.mod_eq_of_lt addressBound] using rawAtEffective
  have physicalMatching :
      Functions.matching_pma_region regions
          (.Physaddr (_root_.zero_extend (m := 34)
            environment.effectiveAddress))
          (width kind) = some region := by
    simpa [physicalAddress] using matching
  have effectiveAddressEq :
      environment.baseValue +
          Functions.sign_extend (m := 32) environment.imm =
        environment.effectiveAddress := by
    rfl
  have busAddressEq :
      RiscvRefinement.Memory.busAddress environment.effectiveAddress =
        environment.busAddress := by
    rfl
  have architecturalAddress :
      RiscvRefinement.Memory.effectiveAddress
          environment.baseValue environment.imm =
        environment.effectiveAddress := by
    simpa [
      RiscvRefinement.Memory.effectiveAddress,
      Functions.sign_extend,
      Sail.BitVec.signExtend,
    ] using effectiveAddressEq
  cases kind
  · exact ExecutionMemory.constructiveLoadExecution
      (stepNo := stepNo)
      (word := environment.word)
      (decoded := decoded .lb row environment)
      (pc := environment.pre.pc)
      (imm := environment.imm)
      (rs1 := row.rs1Addr)
      (rd := row.r2Idx)
      (isUnsigned := false)
      (width := 1)
      (baseValue := environment.baseValue)
      (effectiveAddress := environment.effectiveAddress)
      (busAddress := environment.busAddress)
      (memoryWord := environment.memoryWord.word)
      (loadedValue := loadByteSignedValue environment.baseValue
        environment.imm environment.memoryWord)
      (retirement := airRetirement .lb row environment)
      (initial := initial)
      (mstatus := mstatus)
      (regions := regions)
      (region := region)
      (widthCases := by simp)
      (pcBinding := stateBindings.instruction.programCounter)
      (landingPadClear := stateBindings.instruction.landingPadClear)
      (baseBinding := stateBindings.registers.source)
      (mstatusBinding := mstatusBinding)
      (mprvClear := mprvClear)
      (privilegeBinding := stateBindings.instruction.privilege)
      (regionsBinding := regionsBinding)
      (matching := by simpa [width] using physicalMatching)
      (mainMemory := mainMemory)
      (readable := readable)
      (virtualAligned := stateBindings.ordinaryRam.virtualAligned)
      (physicalAligned := stateBindings.ordinaryRam.physicalAligned)
      (samePage := stateBindings.ordinaryRam.samePage)
      (htifDisabled := stateBindings.instruction.htifDisabled)
      (bytes := by simpa [width] using raw)
      (memoryBinding := stateBindings.memory)
      (effectiveAddressEq := effectiveAddressEq)
      (busAddressEq := busAddressEq)
      (valueMatches :=
        ExecutionMemory.extend_accessValue_one_signed
          environment.effectiveAddress environment.memoryWord)
      (executeClause := by rfl)
      (normalizes := Functions.complete_LB_normalizes _ _ _ _)
      (retirementEq := by rfl)
  · have aligned :
        RiscvRefinement.Memory.isHalfAligned environment.effectiveAddress :=
      half_access_aligned row environment holds (by
        have isLh : row.isLh = true := by
          simpa [RiscvRefinement.Publication.TeamB.LoadStore.selected] using
            selected
        simp [LoadStoreRow.isHalf, isLh])
    exact ExecutionMemory.constructiveLoadExecution
      (stepNo := stepNo)
      (word := environment.word)
      (decoded := decoded .lh row environment)
      (pc := environment.pre.pc)
      (imm := environment.imm)
      (rs1 := row.rs1Addr)
      (rd := row.r2Idx)
      (isUnsigned := false)
      (width := 2)
      (baseValue := environment.baseValue)
      (effectiveAddress := environment.effectiveAddress)
      (busAddress := environment.busAddress)
      (memoryWord := environment.memoryWord.word)
      (loadedValue := loadHalfSignedValue environment.baseValue
        environment.imm environment.memoryWord)
      (retirement := airRetirement .lh row environment)
      (initial := initial)
      (mstatus := mstatus)
      (regions := regions)
      (region := region)
      (widthCases := by simp)
      (pcBinding := stateBindings.instruction.programCounter)
      (landingPadClear := stateBindings.instruction.landingPadClear)
      (baseBinding := stateBindings.registers.source)
      (mstatusBinding := mstatusBinding)
      (mprvClear := mprvClear)
      (privilegeBinding := stateBindings.instruction.privilege)
      (regionsBinding := regionsBinding)
      (matching := by simpa [width] using physicalMatching)
      (mainMemory := mainMemory)
      (readable := readable)
      (virtualAligned := stateBindings.ordinaryRam.virtualAligned)
      (physicalAligned := stateBindings.ordinaryRam.physicalAligned)
      (samePage := stateBindings.ordinaryRam.samePage)
      (htifDisabled := stateBindings.instruction.htifDisabled)
      (bytes := by simpa [width] using raw)
      (memoryBinding := stateBindings.memory)
      (effectiveAddressEq := effectiveAddressEq)
      (busAddressEq := busAddressEq)
      (valueMatches :=
        ExecutionMemory.extend_accessValue_two_signed
          environment.effectiveAddress environment.memoryWord aligned)
      (executeClause := by rfl)
      (normalizes := Functions.complete_LH_normalizes _ _ _ _)
      (retirementEq := by rfl)
  · have aligned :
        RiscvRefinement.Memory.isWordAligned environment.effectiveAddress :=
      word_access_aligned row environment holds (by
        have isLw : row.isLw = true := by
          simpa [RiscvRefinement.Publication.TeamB.LoadStore.selected] using
            selected
        simp [LoadStoreRow.isWord, isLw])
    exact ExecutionMemory.constructiveLoadExecution
      (stepNo := stepNo) (word := environment.word)
      (decoded := decoded .lw row environment)
      (pc := environment.pre.pc) (imm := environment.imm)
      (rs1 := row.rs1Addr) (rd := row.r2Idx)
      (isUnsigned := false) (width := 4)
      (baseValue := environment.baseValue)
      (effectiveAddress := environment.effectiveAddress)
      (busAddress := environment.busAddress)
      (memoryWord := environment.memoryWord.word)
      (loadedValue := loadWordValue environment.memoryWord)
      (retirement := airRetirement .lw row environment)
      (initial := initial) (mstatus := mstatus)
      (regions := regions) (region := region)
      (widthCases := by simp)
      (pcBinding := stateBindings.instruction.programCounter)
      (landingPadClear := stateBindings.instruction.landingPadClear)
      (baseBinding := stateBindings.registers.source)
      (mstatusBinding := mstatusBinding) (mprvClear := mprvClear)
      (privilegeBinding := stateBindings.instruction.privilege)
      (regionsBinding := regionsBinding)
      (matching := by simpa [width] using physicalMatching)
      (mainMemory := mainMemory) (readable := readable)
      (virtualAligned := stateBindings.ordinaryRam.virtualAligned)
      (physicalAligned := stateBindings.ordinaryRam.physicalAligned)
      (samePage := stateBindings.ordinaryRam.samePage)
      (htifDisabled := stateBindings.instruction.htifDisabled)
      (bytes := by simpa [width] using raw)
      (memoryBinding := stateBindings.memory)
      (effectiveAddressEq := effectiveAddressEq)
      (busAddressEq := busAddressEq)
      (valueMatches := ExecutionMemory.extend_accessValue_four
        environment.effectiveAddress environment.memoryWord aligned)
      (executeClause := by rfl)
      (normalizes := Functions.complete_LW_normalizes _ _ _ _)
      (retirementEq := by rfl)
  · exact ExecutionMemory.constructiveLoadExecution
      (stepNo := stepNo) (word := environment.word)
      (decoded := decoded .lbu row environment)
      (pc := environment.pre.pc) (imm := environment.imm)
      (rs1 := row.rs1Addr) (rd := row.r2Idx)
      (isUnsigned := true) (width := 1)
      (baseValue := environment.baseValue)
      (effectiveAddress := environment.effectiveAddress)
      (busAddress := environment.busAddress)
      (memoryWord := environment.memoryWord.word)
      (loadedValue := loadByteUnsignedValue environment.baseValue
        environment.imm environment.memoryWord)
      (retirement := airRetirement .lbu row environment)
      (initial := initial) (mstatus := mstatus)
      (regions := regions) (region := region)
      (widthCases := by simp)
      (pcBinding := stateBindings.instruction.programCounter)
      (landingPadClear := stateBindings.instruction.landingPadClear)
      (baseBinding := stateBindings.registers.source)
      (mstatusBinding := mstatusBinding) (mprvClear := mprvClear)
      (privilegeBinding := stateBindings.instruction.privilege)
      (regionsBinding := regionsBinding)
      (matching := by simpa [width] using physicalMatching)
      (mainMemory := mainMemory) (readable := readable)
      (virtualAligned := stateBindings.ordinaryRam.virtualAligned)
      (physicalAligned := stateBindings.ordinaryRam.physicalAligned)
      (samePage := stateBindings.ordinaryRam.samePage)
      (htifDisabled := stateBindings.instruction.htifDisabled)
      (bytes := by simpa [width] using raw)
      (memoryBinding := stateBindings.memory)
      (effectiveAddressEq := effectiveAddressEq)
      (busAddressEq := busAddressEq)
      (valueMatches :=
        ExecutionMemory.extend_accessValue_one_unsigned
          environment.effectiveAddress environment.memoryWord)
      (executeClause := by rfl)
      (normalizes := Functions.complete_LBU_normalizes _ _ _ _)
      (retirementEq := by rfl)
  · have aligned :
        RiscvRefinement.Memory.isHalfAligned environment.effectiveAddress :=
      half_access_aligned row environment holds (by
        have isLhu : row.isLhu = true := by
          simpa [RiscvRefinement.Publication.TeamB.LoadStore.selected] using
            selected
        simp [LoadStoreRow.isHalf, isLhu])
    exact ExecutionMemory.constructiveLoadExecution
      (stepNo := stepNo) (word := environment.word)
      (decoded := decoded .lhu row environment)
      (pc := environment.pre.pc) (imm := environment.imm)
      (rs1 := row.rs1Addr) (rd := row.r2Idx)
      (isUnsigned := true) (width := 2)
      (baseValue := environment.baseValue)
      (effectiveAddress := environment.effectiveAddress)
      (busAddress := environment.busAddress)
      (memoryWord := environment.memoryWord.word)
      (loadedValue := loadHalfUnsignedValue environment.baseValue
        environment.imm environment.memoryWord)
      (retirement := airRetirement .lhu row environment)
      (initial := initial) (mstatus := mstatus)
      (regions := regions) (region := region)
      (widthCases := by simp)
      (pcBinding := stateBindings.instruction.programCounter)
      (landingPadClear := stateBindings.instruction.landingPadClear)
      (baseBinding := stateBindings.registers.source)
      (mstatusBinding := mstatusBinding) (mprvClear := mprvClear)
      (privilegeBinding := stateBindings.instruction.privilege)
      (regionsBinding := regionsBinding)
      (matching := by simpa [width] using physicalMatching)
      (mainMemory := mainMemory) (readable := readable)
      (virtualAligned := stateBindings.ordinaryRam.virtualAligned)
      (physicalAligned := stateBindings.ordinaryRam.physicalAligned)
      (samePage := stateBindings.ordinaryRam.samePage)
      (htifDisabled := stateBindings.instruction.htifDisabled)
      (bytes := by simpa [width] using raw)
      (memoryBinding := stateBindings.memory)
      (effectiveAddressEq := effectiveAddressEq)
      (busAddressEq := busAddressEq)
      (valueMatches :=
        ExecutionMemory.extend_accessValue_two_unsigned
          environment.effectiveAddress environment.memoryWord aligned)
      (executeClause := by rfl)
      (normalizes := Functions.complete_LHU_normalizes _ _ _ _)
      (retirementEq := by rfl)
  · exact ExecutionMemory.constructiveStoreExecution
      (stepNo := stepNo) (word := environment.word)
      (decoded := decoded .sb row environment)
      (pc := environment.pre.pc) (imm := environment.imm)
      (rs2 := row.r2Idx) (rs1 := row.rs1Addr) (width := 1)
      (source := environment.operandValue)
      (baseValue := environment.baseValue)
      (effectiveAddress := environment.effectiveAddress)
      (busAddress := environment.busAddress)
      (memoryWord := environment.memoryWord.word)
      (retirement := airRetirement .sb row environment)
      (initial := initial) (mstatus := mstatus)
      (regions := regions) (region := region)
      (widthCases := by simp)
      (pcBinding := stateBindings.instruction.programCounter)
      (landingPadClear := stateBindings.instruction.landingPadClear)
      (baseBinding := stateBindings.registers.sourceOne)
      (sourceBinding := stateBindings.registers.sourceTwo)
      (mstatusBinding := mstatusBinding) (mprvClear := mprvClear)
      (privilegeBinding := stateBindings.instruction.privilege)
      (regionsBinding := regionsBinding)
      (matching := by simpa [width] using physicalMatching)
      (mainMemory := mainMemory) (writable := writable)
      (virtualAligned := stateBindings.ordinaryRam.virtualAligned)
      (physicalAligned := stateBindings.ordinaryRam.physicalAligned)
      (samePage := stateBindings.ordinaryRam.samePage)
      (htifDisabled := stateBindings.instruction.htifDisabled)
      (memoryBinding := stateBindings.memory)
      (effectiveAddressEq := effectiveAddressEq)
      (busAddressEq := busAddressEq)
      (executeClause := by rfl)
      (normalizes := Functions.complete_SB_normalizes _ _ _ _)
      (retirementEq := by
        simp [airRetirement, executeSb, executeStore,
          storeBytePayload,
          Functions.storeMask, Functions.generatedStorePayload,
          ExecutionMemory.generatedWordBytes_word,
          architecturalAddress, busAddressEq])
  · exact ExecutionMemory.constructiveStoreExecution
      (stepNo := stepNo) (word := environment.word)
      (decoded := decoded .sh row environment)
      (pc := environment.pre.pc) (imm := environment.imm)
      (rs2 := row.r2Idx) (rs1 := row.rs1Addr) (width := 2)
      (source := environment.operandValue)
      (baseValue := environment.baseValue)
      (effectiveAddress := environment.effectiveAddress)
      (busAddress := environment.busAddress)
      (memoryWord := environment.memoryWord.word)
      (retirement := airRetirement .sh row environment)
      (initial := initial) (mstatus := mstatus)
      (regions := regions) (region := region)
      (widthCases := by simp)
      (pcBinding := stateBindings.instruction.programCounter)
      (landingPadClear := stateBindings.instruction.landingPadClear)
      (baseBinding := stateBindings.registers.sourceOne)
      (sourceBinding := stateBindings.registers.sourceTwo)
      (mstatusBinding := mstatusBinding) (mprvClear := mprvClear)
      (privilegeBinding := stateBindings.instruction.privilege)
      (regionsBinding := regionsBinding)
      (matching := by simpa [width] using physicalMatching)
      (mainMemory := mainMemory) (writable := writable)
      (virtualAligned := stateBindings.ordinaryRam.virtualAligned)
      (physicalAligned := stateBindings.ordinaryRam.physicalAligned)
      (samePage := stateBindings.ordinaryRam.samePage)
      (htifDisabled := stateBindings.instruction.htifDisabled)
      (memoryBinding := stateBindings.memory)
      (effectiveAddressEq := effectiveAddressEq)
      (busAddressEq := busAddressEq)
      (executeClause := by rfl)
      (normalizes := Functions.complete_SH_normalizes _ _ _ _)
      (retirementEq := by
        simp [airRetirement, executeSh, executeStore,
          storeHalfPayload,
          Functions.storeMask, Functions.generatedStorePayload,
          ExecutionMemory.generatedWordBytes_word,
          architecturalAddress, busAddressEq])
  · exact ExecutionMemory.constructiveStoreExecution
      (stepNo := stepNo) (word := environment.word)
      (decoded := decoded .sw row environment)
      (pc := environment.pre.pc) (imm := environment.imm)
      (rs2 := row.r2Idx) (rs1 := row.rs1Addr) (width := 4)
      (source := environment.operandValue)
      (baseValue := environment.baseValue)
      (effectiveAddress := environment.effectiveAddress)
      (busAddress := environment.busAddress)
      (memoryWord := environment.memoryWord.word)
      (retirement := airRetirement .sw row environment)
      (initial := initial) (mstatus := mstatus)
      (regions := regions) (region := region)
      (widthCases := by simp)
      (pcBinding := stateBindings.instruction.programCounter)
      (landingPadClear := stateBindings.instruction.landingPadClear)
      (baseBinding := stateBindings.registers.sourceOne)
      (sourceBinding := stateBindings.registers.sourceTwo)
      (mstatusBinding := mstatusBinding) (mprvClear := mprvClear)
      (privilegeBinding := stateBindings.instruction.privilege)
      (regionsBinding := regionsBinding)
      (matching := by simpa [width] using physicalMatching)
      (mainMemory := mainMemory) (writable := writable)
      (virtualAligned := stateBindings.ordinaryRam.virtualAligned)
      (physicalAligned := stateBindings.ordinaryRam.physicalAligned)
      (samePage := stateBindings.ordinaryRam.samePage)
      (htifDisabled := stateBindings.instruction.htifDisabled)
      (memoryBinding := stateBindings.memory)
      (effectiveAddressEq := effectiveAddressEq)
      (busAddressEq := busAddressEq)
      (executeClause := by rfl)
      (normalizes := Functions.complete_SW_normalizes _ _ _ _)
      (retirementEq := by
        simp [airRetirement, executeSw, executeStore,
          Functions.storeMask, Functions.generatedStorePayload,
          architecturalAddress, busAddressEq]
        rw [ExecutionMemory.generatedWordBytes_word]
        rfl)

set_option maxRecDepth 100_000 in
theorem accepted_air_refines
    (kind : Kind)
    (row : Row)
    (witness : RiscvRefinement.Publication.TeamB.LoadStore.Witness row)
    (relationHolds : EvaluatedLookup → Prop)
    (environment : LoadStoreEnvironment row)
    (admission :
      RiscvRefinement.Publication.TeamB.LoadStore.Admission row)
    (bindings :
      RiscvRefinement.Publication.TeamB.LoadStore.Bindings kind row witness)
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
    (exitWait : Bool) :
    AcceptedComposition kind row witness relationHolds environment
      initial stepNo exitWait := by
  let localCertificate :=
    RiscvRefinement.Publication.TeamB.LoadStore.accepted_air_refines
      kind row witness relationHolds environment admission bindings accepted
  have wordEq :=
    canonicalWord kind row witness relationHolds environment localCertificate
  rcases stateBindings.instruction.decodeState.mseccfg with
    ⟨mseccfgValue, mseccfgBinding⟩
  have decoderCertificate :
      Functions.GeneratedDecodeCertificateAt
        environment.word (decoded kind row environment) initial := by
    rw [wordEq]
    cases kind
    · simpa [expectedWord, funct3, LoadStoreDecode.encodeLoad,
        RiscvRefinement.Decode.encodeLb,
        RiscvRefinement.Decode.encodeLoad,
        LoadStoreDecode.loadOpcode,
        RiscvRefinement.Decode.loadOpcode] using
        Functions.decode_lb_memory_certificate_at
          environment.imm row.rs1Addr row.r2Idx initial mseccfgValue
          profileAdmission.pauseDisabled
          profileAdmission.landingPadExtensionDisabled
          stateBindings.instruction.privilege mseccfgBinding
    · simpa [expectedWord, funct3, LoadStoreDecode.encodeLoad,
        RiscvRefinement.Decode.encodeLh,
        RiscvRefinement.Decode.encodeLoad,
        LoadStoreDecode.loadOpcode,
        RiscvRefinement.Decode.loadOpcode] using
        Functions.decode_lh_memory_certificate_at
          environment.imm row.rs1Addr row.r2Idx initial mseccfgValue
          profileAdmission.pauseDisabled
          profileAdmission.landingPadExtensionDisabled
          stateBindings.instruction.privilege mseccfgBinding
    · simpa [expectedWord, funct3, LoadStoreDecode.encodeLoad,
        RiscvRefinement.Decode.encodeLw,
        RiscvRefinement.Decode.encodeLoad,
        LoadStoreDecode.loadOpcode,
        RiscvRefinement.Decode.loadOpcode] using
        Functions.decode_lw_memory_certificate_at
          environment.imm row.rs1Addr row.r2Idx initial mseccfgValue
          profileAdmission.pauseDisabled
          profileAdmission.landingPadExtensionDisabled
          stateBindings.instruction.privilege mseccfgBinding
    · simpa [expectedWord, funct3, LoadStoreDecode.encodeLoad,
        RiscvRefinement.Decode.encodeLbu,
        RiscvRefinement.Decode.encodeLoad,
        LoadStoreDecode.loadOpcode,
        RiscvRefinement.Decode.loadOpcode] using
        Functions.decode_lbu_memory_certificate_at
          environment.imm row.rs1Addr row.r2Idx initial mseccfgValue
          profileAdmission.pauseDisabled
          profileAdmission.landingPadExtensionDisabled
          stateBindings.instruction.privilege mseccfgBinding
    · simpa [expectedWord, funct3, LoadStoreDecode.encodeLoad,
        RiscvRefinement.Decode.encodeLhu,
        RiscvRefinement.Decode.encodeLoad,
        LoadStoreDecode.loadOpcode,
        RiscvRefinement.Decode.loadOpcode] using
        Functions.decode_lhu_memory_certificate_at
          environment.imm row.rs1Addr row.r2Idx initial mseccfgValue
          profileAdmission.pauseDisabled
          profileAdmission.landingPadExtensionDisabled
          stateBindings.instruction.privilege mseccfgBinding
    · simpa [expectedWord, funct3, LoadStoreDecode.encodeStore,
        RiscvRefinement.Decode.encodeSb,
        RiscvRefinement.Decode.encodeStore,
        LoadStoreDecode.storeOpcode,
        RiscvRefinement.Decode.storeOpcode] using
        Functions.decode_sb_memory_certificate_at
          environment.imm row.r2Idx row.rs1Addr initial mseccfgValue
          profileAdmission.pauseDisabled
          profileAdmission.landingPadExtensionDisabled
          stateBindings.instruction.privilege mseccfgBinding
    · simpa [expectedWord, funct3, LoadStoreDecode.encodeStore,
        RiscvRefinement.Decode.encodeSh,
        RiscvRefinement.Decode.encodeStore,
        LoadStoreDecode.storeOpcode,
        RiscvRefinement.Decode.storeOpcode] using
        Functions.decode_sh_memory_certificate_at
          environment.imm row.r2Idx row.rs1Addr initial mseccfgValue
          profileAdmission.pauseDisabled
          profileAdmission.landingPadExtensionDisabled
          stateBindings.instruction.privilege mseccfgBinding
    · simpa [expectedWord, funct3, LoadStoreDecode.encodeStore,
        RiscvRefinement.Decode.encodeSw,
        RiscvRefinement.Decode.encodeStore,
        LoadStoreDecode.storeOpcode,
        RiscvRefinement.Decode.storeOpcode] using
        Functions.decode_sw_memory_certificate_at
          environment.imm row.r2Idx row.rs1Addr initial mseccfgValue
          profileAdmission.pauseDisabled
          profileAdmission.landingPadExtensionDisabled
          stateBindings.instruction.privilege mseccfgBinding
  exact {
    acceptedProduction := accepted
    inputBoundSelector := {
      schemaVersion := by cases kind <;> rfl
      manifestId := by cases kind <;> rfl
      mnemonic := by cases kind <;> rfl
      digest := rfl
      inputWord := wordEq
    }
    stateBindings := stateBindings
    profileAdmission := profileAdmission
    admission := admission
    admissionProofUnique := by
      intro first second
      exact Subsingleton.elim first second
    localRefinement := localCertificate.semantic
    exactTuple := localCertificate.exactOrderedTuples
    decoder := decoderCertificate
    generatedExecuteSuccess := by cases kind <;> rfl
    normalizedRetirement := by
      cases kind
      · exact Functions.complete_LB_normalizes _ _ _ _
      · exact Functions.complete_LH_normalizes _ _ _ _
      · exact Functions.complete_LW_normalizes _ _ _ _
      · exact Functions.complete_LBU_normalizes _ _ _ _
      · exact Functions.complete_LHU_normalizes _ _ _ _
      · exact Functions.complete_SB_normalizes _ _ _ _
      · exact Functions.complete_SH_normalizes _ _ _ _
      · exact Functions.complete_SW_normalizes _ _ _ _
    constructiveExecution := constructiveExecution kind row environment
      initial stepNo stateBindings localCertificate.holds
      localCertificate.selectedRow
    fullStepFraming :=
      Functions.generated_full_step_retirement_composition stepNo exitWait
  }

end Memory

theorem LB_accepted_air_refines : Memory.RefinementTheorem .lb :=
  Memory.accepted_air_refines .lb
theorem LH_accepted_air_refines : Memory.RefinementTheorem .lh :=
  Memory.accepted_air_refines .lh
theorem LW_accepted_air_refines : Memory.RefinementTheorem .lw :=
  Memory.accepted_air_refines .lw
theorem LBU_accepted_air_refines : Memory.RefinementTheorem .lbu :=
  Memory.accepted_air_refines .lbu
theorem LHU_accepted_air_refines : Memory.RefinementTheorem .lhu :=
  Memory.accepted_air_refines .lhu
theorem SB_accepted_air_refines : Memory.RefinementTheorem .sb :=
  Memory.accepted_air_refines .sb
theorem SH_accepted_air_refines : Memory.RefinementTheorem .sh :=
  Memory.accepted_air_refines .sh
theorem SW_accepted_air_refines : Memory.RefinementTheorem .sw :=
  Memory.accepted_air_refines .sw

end LeanRV32IM.Publication
