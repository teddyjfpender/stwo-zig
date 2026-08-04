import ExecutionMemory

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 2_000_000
set_option linter.unusedVariables false

open Sail

namespace LeanRV32IM.Publication.ExecutionMemory

open LeanRV32IM.Functions

/-!
Constructive ordinary-RAM write closure.  The resulting state is existential;
callers supply only PMA/alignment/MMIO component facts, never an outcome or a
post-state.
-/

private theorem write_ram_plain_one_succeeds
    (state : GeneratedState)
    (address : BitVec 34)
    (value : BitVec 8) :
    ∃ final : GeneratedState,
      write_ram .Write_plain (.Physaddr address) 1 value () state =
        .ok true final ∧
      final.regs = state.regs := by
  simp [
    write_ram,
    Sail.ConcurrencyInterfaceV1.sail_mem_write,
    PreSail.ConcurrencyInterfaceV1.sail_mem_write,
    PreSail.writeBytes,
    PreSail.writeByte,
    List.forM,
    bind,
    EStateM.bind,
    pure,
    EStateM.pure,
    modify,
    modifyGet,
    MonadStateOf.modifyGet,
    EStateM.modifyGet,
  ]

private theorem write_ram_plain_two_succeeds
    (state : GeneratedState)
    (address : BitVec 34)
    (value : BitVec 16) :
    ∃ final : GeneratedState,
      write_ram .Write_plain (.Physaddr address) 2 value () state =
        .ok true final ∧
      final.regs = state.regs := by
  simp [
    write_ram,
    Sail.ConcurrencyInterfaceV1.sail_mem_write,
    PreSail.ConcurrencyInterfaceV1.sail_mem_write,
    PreSail.writeBytes,
    PreSail.writeByte,
    List.forM,
    bind,
    EStateM.bind,
    pure,
    EStateM.pure,
    modify,
    modifyGet,
    MonadStateOf.modifyGet,
    EStateM.modifyGet,
  ]

private theorem write_ram_plain_four_succeeds
    (state : GeneratedState)
    (address : BitVec 34)
    (value : BitVec 32) :
    ∃ final : GeneratedState,
      write_ram .Write_plain (.Physaddr address) 4 value () state =
        .ok true final ∧
      final.regs = state.regs := by
  simp [
    write_ram,
    Sail.ConcurrencyInterfaceV1.sail_mem_write,
    PreSail.ConcurrencyInterfaceV1.sail_mem_write,
    PreSail.writeBytes,
    PreSail.writeByte,
    List.forM,
    bind,
    EStateM.bind,
    pure,
    EStateM.pure,
    modify,
    modifyGet,
    MonadStateOf.modifyGet,
    EStateM.modifyGet,
  ]

theorem write_ram_plain_succeeds
    (state : GeneratedState)
    (address : BitVec 34)
    (width : Nat)
    (value : BitVec (8 * width))
    (widthCases : width = 1 ∨ width = 2 ∨ width = 4) :
    ∃ final : GeneratedState,
      write_ram .Write_plain (.Physaddr address) width value () state =
        .ok true final ∧
      final.regs = state.regs := by
  rcases widthCases with rfl | rfl | rfl
  · exact write_ram_plain_one_succeeds state address value
  · exact write_ram_plain_two_succeeds state address value
  · exact write_ram_plain_four_succeeds state address value

theorem mem_write_ea_store_data_succeeds
    (state : GeneratedState)
    (address : BitVec 34)
    (width : Nat)
    (mstatus : BitVec 64)
    (regions : List PMA_Region)
    (region : PMA_Region)
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
    (writable : region.attributes.writable = true)
    (aligned : is_aligned_paddr (.Physaddr address) width = true) :
    mem_write_ea (.Physaddr address) width (.Store .Data) .PBMT_PMA
        false false false state =
      .ok (.Ok ()) state := by
  have pmaOutcome := check_pma_with_pmp_priority_store_succeeds
    state (.Physaddr address) width regions region regionsBinding matching
    mainMemory writable aligned
  have splitOutcome := split_misaligned_aligned_succeeds
    state (.Physaddr address) width
  have pmpOutcome := pmpCheck_disabled state (.Physaddr address) width
    (.Store .Data) .Machine
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
  have privilegeOutcome := effectivePrivilege_machine_of_mprv_clear
    (.Store .Data) mstatus mprvClear
  have addIntZero : Sail.BitVec.addInt address 0 = address := by
    exact BitVec.add_zero address
  simp [
    mem_write_ea,
    Sail.SailME.run,
    PreSail.PreSailME.run,
    mstatusRead,
    privilegeRead,
    privilegeOutcome,
    pmaOutcome,
    splitOutcome,
    pmpOutcome,
    write_kind_of_flags,
    misaligned_order,
    sys_misaligned_order_decreasing,
    untilFuelM,
    untilFuelM.go,
    PreSail.assert,
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
    bits_of_physaddr,
    addIntZero,
  ]

theorem checked_mem_write_store_data_succeeds
    (state : GeneratedState)
    (address : BitVec 34)
    (width : Nat)
    (value : BitVec (8 * width))
    (regions : List PMA_Region)
    (region : PMA_Region)
    (widthCases : width = 1 ∨ width = 2 ∨ width = 4)
    (regionsBinding :
      state.regs.get? Register.pma_regions = some regions)
    (matching :
      matching_pma_region regions (.Physaddr address) width = some region)
    (mainMemory : region.attributes.mem_type = .MainMemory)
    (writable : region.attributes.writable = true)
    (aligned : is_aligned_paddr (.Physaddr address) width = true)
    (htifDisabled :
      state.regs.get? Register.htif_tohost_base = some none) :
    ∃ final : GeneratedState,
      checked_mem_write (.Physaddr address) width value (.Store .Data)
          .PBMT_PMA .Machine () false false false state =
        .ok (.Ok true) final ∧
      final.regs = state.regs := by
  have pmaOutcome := check_pma_with_pmp_priority_store_succeeds
    state (.Physaddr address) width regions region regionsBinding matching
    mainMemory writable aligned
  have splitOutcome := split_misaligned_aligned_succeeds
    state (.Physaddr address) width
  have pmpOutcome := pmpCheck_disabled state (.Physaddr address) width
    (.Store .Data) .Machine
  have mmioOutcome := within_mmio_writable_false
    state (.Physaddr address) width htifDisabled
  rcases write_ram_plain_succeeds state address width value widthCases with
    ⟨final, ramOutcome, regsPreserved⟩
  have addIntZero : Sail.BitVec.addInt address 0 = address := by
    exact BitVec.add_zero address
  refine ⟨final, ?_, regsPreserved⟩
  simp [
      checked_mem_write,
      Sail.SailME.run,
      PreSail.PreSailME.run,
      pmaOutcome,
      splitOutcome,
      pmpOutcome,
      within_mmio_writable,
      within_clint,
      within_sig,
      within_htif_writable,
      get_config_rvfi,
      plat_have_clint,
      plat_have_sig,
      htifDisabled,
      Functions.not,
      PreSail.readReg,
      mmioOutcome,
      write_kind_of_flags,
      misaligned_order,
      sys_misaligned_order_decreasing,
      untilFuelM,
      untilFuelM.go,
      PreSail.assert,
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
      bits_of_physaddr,
      addIntZero,
      Sail.BitVec.updateSubrange,
    ]
  rcases widthCases with rfl | rfl | rfl <;>
    simp [
      addIntZero,
      Sail.BitVec.extractLsb,
      BitVec.extractLsb,
      BitVec.extractLsb'_eq_self,
      ramOutcome,
      ExceptT.pure,
      ExceptT.bind,
      ExceptT.bindCont,
      bind,
      EStateM.bind,
      pure,
      EStateM.pure,
      Sail.BitVec.updateSubrange',
    ]

theorem mem_write_value_store_data_succeeds
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
    (writable : region.attributes.writable = true)
    (aligned : is_aligned_paddr (.Physaddr address) width = true)
    (htifDisabled :
      state.regs.get? Register.htif_tohost_base = some none) :
    ∃ final : GeneratedState,
      mem_write_value (.Physaddr address) width value (.Store .Data)
          .PBMT_PMA false false false state =
        .ok (.Ok true) final ∧
      final.regs = state.regs := by
  rcases checked_mem_write_store_data_succeeds state address width value
      regions region widthCases regionsBinding matching mainMemory writable
      aligned htifDisabled with ⟨final, checkedOutcome, regsPreserved⟩
  refine ⟨final, ?_, regsPreserved⟩
  simp [
    mem_write_value,
    mem_write_value_meta,
    mem_write_value_priv_meta,
    effectivePrivilege,
    mstatusBinding,
    privilegeBinding,
    mprvClear,
    checkedOutcome,
    mem_write_callback,
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

end LeanRV32IM.Publication.ExecutionMemory
