import DecodeMemoryState

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 2_000_000
set_option linter.unusedVariables false

open Sail

namespace LeanRV32IM.Publication.ExecutionMemory

open LeanRV32IM.Functions

/-!
Constructive ordinary-RAM closure for the generated RV32 load/store path.
Every hypothesis below is a component of the initial state or address profile;
no `vmem_read`, `vmem_write`, `mem_read`, or `mem_write_value` outcome is
accepted as a premise.
-/

/-- Machine data accesses with `MPRV = 0` retain Machine privilege. -/
theorem effectivePrivilege_machine_of_mprv_clear
    (access : MemoryAccessType mem_payload)
    (mstatus : BitVec 64)
    (mprvClear : _get_Mstatus_MPRV mstatus = 0#1) :
    effectivePrivilege access mstatus .Machine = pure .Machine := by
  simp [effectivePrivilege, mprvClear, bne, Functions.not]

/-- The pinned RV32 model applies no pointer mask to a Machine data address. -/
theorem transform_effective_address_machine_succeeds
    (state : GeneratedState)
    (address : BitVec 32)
    (access : MemoryAccessType mem_payload)
    (mstatus : BitVec 64)
    (mstatusBinding :
      state.regs.get? Register.mstatus = some mstatus)
    (mprvClear : _get_Mstatus_MPRV mstatus = 0#1)
    (privilegeBinding :
      state.regs.get? Register.cur_privilege = some .Machine) :
    transform_effective_address (.Virtaddr address) access state =
      .ok (.Virtaddr address) state := by
  have machineEq :
      ((Privilege.Machine == Privilege.Machine) : Bool) = true := by
    decide
  have bareEq : ((SATPMode.Bare == SATPMode.Bare) : Bool) = true := by
    decide
  simp [
    transform_effective_address,
    effectivePrivilege,
    mstatusBinding,
    privilegeBinding,
    mprvClear,
    get_pmlen,
    is_pmm_applicable,
    translationMode,
    pm_transform_PA,
    Functions.xlen,
    PreSail.readReg,
    bind,
    EStateM.bind,
    EStateM.map,
    pure,
    EStateM.pure,
    MonadState.get,
    getThe,
    MonadStateOf.get,
    EStateM.get,
    bne,
    Functions.not,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    zero_extend,
    Sail.BitVec.zeroExtend,
    BitVec.zeroExtend,
    machineEq,
    bareEq,
  ]

/-- Bare Machine translation maps the 32-bit virtual address injectively into
the generated 34-bit physical-address type. -/
theorem translateAddr_machine_bare_succeeds
    (state : GeneratedState)
    (address : BitVec 32)
    (access : MemoryAccessType mem_payload)
    (mstatus : BitVec 64)
    (mstatusBinding :
      state.regs.get? Register.mstatus = some mstatus)
    (mprvClear : _get_Mstatus_MPRV mstatus = 0#1)
    (privilegeBinding :
      state.regs.get? Register.cur_privilege = some .Machine)
    (notShadow : is_shadow_stack_access access = pure false) :
    translateAddr (.Virtaddr address) access state =
      .ok (.Ok
        (.Physaddr (zero_extend (m := 34) address), .PBMT_PMA, ())) state := by
  have machineEq :
      ((Privilege.Machine == Privilege.Machine) : Bool) = true := by
    decide
  have bareEq : ((SATPMode.Bare == SATPMode.Bare) : Bool) = true := by
    decide
  rw [translateAddr]
  rw [notShadow]
  simp [
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
    effectivePrivilege,
    mstatusBinding,
    privilegeBinding,
    mprvClear,
    translationMode,
    notShadow,
    PreSail.readReg,
    bind,
    EStateM.bind,
    EStateM.map,
    pure,
    EStateM.pure,
    MonadState.get,
    getThe,
    MonadStateOf.get,
    EStateM.get,
    bne,
    Functions.not,
    bits_of_virtaddr,
    zero_extend,
    Sail.BitVec.zeroExtend,
    BitVec.zeroExtend,
    machineEq,
    bareEq,
  ]

/-- A matching readable main-memory PMA region admits an aligned data load. -/
theorem pmaCheck_load_data_succeeds
    (state : GeneratedState)
    (paddr : physaddr)
    (width : Nat)
    (regions : List PMA_Region)
    (region : PMA_Region)
    (regionsBinding :
      state.regs.get? Register.pma_regions = some regions)
    (matching : matching_pma_region regions paddr width = some region)
    (mainMemory : region.attributes.mem_type = .MainMemory)
    (readable : region.attributes.readable = true)
    (aligned : is_aligned_paddr paddr width = true) :
    pmaCheck paddr width (.Load .Data) .PBMT_PMA false state =
      .ok (.Ok { splittable := .CannotSplit, granule_size_exp := 0 }) state := by
  simp [
    pmaCheck,
    Sail.SailME.run,
    PreSail.PreSailME.run,
    matching,
    regionsBinding,
    override_PMA,
    readable,
    mag_pma_check,
    aligned,
    is_mag_applicable_access,
    Functions.xlen_bytes,
    PreSail.assert,
    PreSail.readReg,
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
    Functions.not,
  ]

/-- A matching writable main-memory PMA region admits an aligned data store. -/
theorem pmaCheck_store_data_succeeds
    (state : GeneratedState)
    (paddr : physaddr)
    (width : Nat)
    (regions : List PMA_Region)
    (region : PMA_Region)
    (regionsBinding :
      state.regs.get? Register.pma_regions = some regions)
    (matching : matching_pma_region regions paddr width = some region)
    (mainMemory : region.attributes.mem_type = .MainMemory)
    (writable : region.attributes.writable = true)
    (aligned : is_aligned_paddr paddr width = true) :
    pmaCheck paddr width (.Store .Data) .PBMT_PMA false state =
      .ok (.Ok { splittable := .CannotSplit, granule_size_exp := 0 }) state := by
  simp [
    pmaCheck,
    Sail.SailME.run,
    PreSail.PreSailME.run,
    matching,
    regionsBinding,
    override_PMA,
    writable,
    mag_pma_check,
    aligned,
    is_mag_applicable_access,
    Functions.xlen_bytes,
    PreSail.assert,
    PreSail.readReg,
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
    Functions.not,
  ]

theorem check_pma_with_pmp_priority_load_succeeds
    (state : GeneratedState)
    (paddr : physaddr)
    (width : Nat)
    (regions : List PMA_Region)
    (region : PMA_Region)
    (regionsBinding :
      state.regs.get? Register.pma_regions = some regions)
    (matching : matching_pma_region regions paddr width = some region)
    (mainMemory : region.attributes.mem_type = .MainMemory)
    (readable : region.attributes.readable = true)
    (aligned : is_aligned_paddr paddr width = true) :
    check_pma_with_pmp_priority
        (.Load .Data) .PBMT_PMA .Machine paddr width false state =
      .ok (.Ok { splittable := .CannotSplit, granule_size_exp := 0 }) state := by
  have pmaOutcome := pmaCheck_load_data_succeeds state paddr width
    regions region regionsBinding matching mainMemory readable aligned
  simp [check_pma_with_pmp_priority, pmaOutcome, bind, EStateM.bind,
    pure, EStateM.pure]

theorem check_pma_with_pmp_priority_store_succeeds
    (state : GeneratedState)
    (paddr : physaddr)
    (width : Nat)
    (regions : List PMA_Region)
    (region : PMA_Region)
    (regionsBinding :
      state.regs.get? Register.pma_regions = some regions)
    (matching : matching_pma_region regions paddr width = some region)
    (mainMemory : region.attributes.mem_type = .MainMemory)
    (writable : region.attributes.writable = true)
    (aligned : is_aligned_paddr paddr width = true) :
    check_pma_with_pmp_priority
        (.Store .Data) .PBMT_PMA .Machine paddr width false state =
      .ok (.Ok { splittable := .CannotSplit, granule_size_exp := 0 }) state := by
  have pmaOutcome := pmaCheck_store_data_succeeds state paddr width
    regions region regionsBinding matching mainMemory writable aligned
  simp [check_pma_with_pmp_priority, pmaOutcome, bind, EStateM.bind,
    pure, EStateM.pure]

theorem pmpCheck_disabled
    (state : GeneratedState)
    (paddr : physaddr)
    (width : Nat)
    (access : MemoryAccessType mem_payload)
    (privilege : Privilege) :
    pmpCheck paddr width access privilege state = .ok none state := by
  simp [
    pmpCheck,
    sys_pmp_count,
    Sail.SailME.run,
    PreSail.PreSailME.run,
    ExceptT.pure,
    ExceptT.run,
    ExceptT.mk,
    bind,
    EStateM.bind,
    pure,
    EStateM.pure,
  ]

theorem split_misaligned_aligned_succeeds
    (state : GeneratedState)
    (paddr : physaddr)
    (width : Nat) :
    split_misaligned paddr width 0 .CannotSplit state =
      .ok (1, width) state := by
  have cannotSplit :
      ((Splittability.CannotSplit == Splittability.CannotSplit) : Bool) =
        true := by
    decide
  simp [
    split_misaligned,
    cannotSplit,
    bind,
    EStateM.bind,
    pure,
    EStateM.pure,
  ]

/-- Concrete, non-monadic statement that the access remains in one 4-KiB
page.  Publication state bindings retain the corresponding natural-number
bound as an independently reviewable fact. -/
def SamePage
    (address : BitVec 32)
    (width : Nat) : Prop :=
  (address &&& (0xFFFFF000#32 : BitVec 32)) =
    (BitVec.subInt (BitVec.addInt address width) 1 &&&
      (0xFFFFF000#32 : BitVec 32))

theorem split_on_page_boundary_succeeds
    (state : GeneratedState)
    (address : BitVec 32)
    (width : Nat)
    (samePage : SamePage address width) :
    split_on_page_boundary address width state =
      .ok (width, 0) state := by
  have pageMask :
      Sail.BitVec.updateSubrange
          ((ones (n := 32)) : BitVec 32)
          11 0 (zeros (n := 12)) =
        (0xFFFFF000#32 : BitVec 32) := by
    simp only [
      Sail.BitVec.updateSubrange,
      Sail.BitVec.updateSubrange',
      ones,
      zeros,
      sail_ones,
      BitVec.zero,
    ]
    decide
  change
    (address &&& (0xFFFFF000#32 : BitVec 32)) =
      (BitVec.subInt (BitVec.addInt address width) 1 &&&
        (0xFFFFF000#32 : BitVec 32)) at samePage
  simp [
    split_on_page_boundary,
    SamePage,
    samePage,
    Functions.pagesize_bits,
    pageMask,
    bind,
    EStateM.bind,
    pure,
    EStateM.pure,
  ]

/-- The ordinary-RAM boundary excludes every platform MMIO window.  CLINT and
signature support are compile-time disabled in the pinned model; HTIF is the
only state-dependent branch. -/
theorem within_mmio_readable_false
    (state : GeneratedState)
    (paddr : physaddr)
    (width : Nat)
    (htifDisabled :
      state.regs.get? Register.htif_tohost_base = some none) :
    within_mmio_readable paddr width state = .ok false state := by
  simp [
    within_mmio_readable,
    within_clint,
    within_sig,
    within_htif_readable,
    within_htif_writable,
    get_config_rvfi,
    plat_have_clint,
    plat_have_sig,
    htifDisabled,
    Functions.not,
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

theorem within_mmio_writable_false
    (state : GeneratedState)
    (paddr : physaddr)
    (width : Nat)
    (htifDisabled :
      state.regs.get? Register.htif_tohost_base = some none) :
    within_mmio_writable paddr width state = .ok false state := by
  simp [
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
    bind,
    EStateM.bind,
    pure,
    EStateM.pure,
    MonadState.get,
    getThe,
    MonadStateOf.get,
    EStateM.get,
  ]

/-- Exact raw-byte boundary used by the generated concurrency interface. -/
structure RawByteBindings
    (state : GeneratedState)
    (address : Nat)
    (width : Nat)
    (value : BitVec (8 * width)) : Prop where
  byte : ∀ offset : Fin width,
    state.mem.get? (address + offset.val) =
      some (BitVec.extractLsb' (8 * offset.val) 8 value)

/-- Little-endian subword presented to the generated load at an effective
address inside its aligned architectural word. -/
def accessValue
    (effectiveAddress memoryWord : BitVec 32)
    (width : Nat) : BitVec (8 * width) :=
  BitVec.extractLsb'
    (8 * (effectiveAddress.toNat % 4)) (8 * width) memoryWord

theorem accessValue_byte
    (effectiveAddress memoryWord : BitVec 32)
    (width : Nat)
    (offset : Fin width) :
    BitVec.extractLsb' (8 * offset.val) 8
        (accessValue effectiveAddress memoryWord width) =
      BitVec.extractLsb'
        (8 * (effectiveAddress.toNat % 4 + offset.val)) 8 memoryWord := by
  have offsetBound : offset.val < width := offset.isLt
  have bitBound : 8 * offset.val + 8 ≤ 8 * width := by
    exact Nat.mul_le_mul_left 8 (Nat.succ_le_iff.mpr offsetBound)
  ext index bound
  have indexBound : index < 8 := bound
  have inside : 8 * offset.val + index < 8 * width := by
    omega
  simp [accessValue, inside]
  congr 1
  omega

theorem rawByteBindings_of_access_bytes
    (state : GeneratedState)
    (effectiveAddress memoryWord : BitVec 32)
    (width : Nat)
    (bytes : ∀ offset : Fin width,
      state.mem.get? (effectiveAddress.toNat + offset.val) =
        some (BitVec.extractLsb'
          (8 * (effectiveAddress.toNat % 4 + offset.val)) 8 memoryWord)) :
    RawByteBindings state effectiveAddress.toNat width
      (accessValue effectiveAddress memoryWord width) := by
  constructor
  intro offset
  rw [accessValue_byte]
  exact bytes offset

theorem readBytes_one_succeeds
    (state : GeneratedState)
    (address : Nat)
    (value : BitVec 8)
    (binding : RawByteBindings state address 1 value) :
    (PreSail.readBytes 1 address :
      SailM ((BitVec (8 * 1)) × Option Bool)) state =
      .ok (value, none) state := by
  have byte0 :
      state.mem.get? address =
        some (BitVec.extractLsb' 0 8 value) := by
    simpa using binding.byte ⟨0, by decide⟩
  have byte0Exact : state.mem.get? address = some value := by
    simpa using byte0
  change state.mem[address]? = some value at byte0Exact
  simp [
    RawByteBindings,
    PreSail.readBytes,
    PreSail.readByte,
    byte0Exact,
    bind,
    EStateM.bind,
    pure,
    EStateM.pure,
    MonadState.get,
    getThe,
    MonadStateOf.get,
    EStateM.get,
  ]

theorem readBytes_two_succeeds
    (state : GeneratedState)
    (address : Nat)
    (value : BitVec 16)
    (binding : RawByteBindings state address 2 value) :
    (PreSail.readBytes 2 address :
      SailM ((BitVec (8 * 2)) × Option Bool)) state =
      .ok (value, none) state := by
  have byte0 :
      state.mem.get? address =
        some (BitVec.extractLsb' 0 8 value) := by
    simpa using binding.byte ⟨0, by decide⟩
  have byte1 :
      state.mem.get? (address + 1) =
        some (BitVec.extractLsb' 8 8 value) := by
    simpa using binding.byte ⟨1, by decide⟩
  change state.mem[address]? =
    some (BitVec.extractLsb' 0 8 value) at byte0
  change state.mem[address + 1]? =
    some (BitVec.extractLsb' 8 8 value) at byte1
  have reconstructed :
      BitVec.extractLsb' 8 8 value +++
          BitVec.extractLsb' 0 8 value = value := by
    exact BitVec.extractLsb'_append_extractLsb'
  simp [
    RawByteBindings,
    PreSail.readBytes,
    PreSail.readByte,
    byte0,
    byte1,
    bind,
    EStateM.bind,
    pure,
    EStateM.pure,
    MonadState.get,
    getThe,
    MonadStateOf.get,
    EStateM.get,
    reconstructed,
  ]

theorem readBytes_four_succeeds
    (state : GeneratedState)
    (address : Nat)
    (value : BitVec 32)
    (binding : RawByteBindings state address 4 value) :
    (PreSail.readBytes 4 address :
      SailM ((BitVec (8 * 4)) × Option Bool)) state =
      .ok (value, none) state := by
  have byte0 :
      state.mem.get? address =
        some (BitVec.extractLsb' 0 8 value) := by
    simpa using binding.byte ⟨0, by decide⟩
  have byte1 :
      state.mem.get? (address + 1) =
        some (BitVec.extractLsb' 8 8 value) := by
    simpa using binding.byte ⟨1, by decide⟩
  have byte2 :
      state.mem.get? (address + 2) =
        some (BitVec.extractLsb' 16 8 value) := by
    simpa using binding.byte ⟨2, by decide⟩
  have byte3 :
      state.mem.get? (address + 3) =
        some (BitVec.extractLsb' 24 8 value) := by
    simpa using binding.byte ⟨3, by decide⟩
  change state.mem[address]? =
    some (BitVec.extractLsb' 0 8 value) at byte0
  change state.mem[address + 1]? =
    some (BitVec.extractLsb' 8 8 value) at byte1
  change state.mem[address + 2]? =
    some (BitVec.extractLsb' 16 8 value) at byte2
  change state.mem[address + 3]? =
    some (BitVec.extractLsb' 24 8 value) at byte3
  have reconstructed :
      BitVec.extractLsb' 24 8 value +++
          BitVec.extractLsb' 16 8 value +++
        BitVec.extractLsb' 8 8 value +++
          BitVec.extractLsb' 0 8 value = value := by
    rw [BitVec.extractLsb'_append_extractLsb'_eq_extractLsb'
      (by decide)]
    rw [BitVec.extractLsb'_append_extractLsb'_eq_extractLsb'
      (by decide)]
    exact BitVec.extractLsb'_append_extractLsb'
  simp [
    RawByteBindings,
    PreSail.readBytes,
    PreSail.readByte,
    byte0,
    byte1,
    byte2,
    byte3,
    bind,
    EStateM.bind,
    pure,
    EStateM.pure,
    MonadState.get,
    getThe,
    MonadStateOf.get,
    EStateM.get,
    reconstructed,
  ]

theorem read_ram_plain_one_succeeds
    (state : GeneratedState)
    (address : BitVec 34)
    (value : BitVec 8)
    (binding : RawByteBindings state address.toNat 1 value) :
    read_ram .Read_plain (.Physaddr address) 1 false state =
      .ok (value, ()) state := by
  have rawOutcome := readBytes_one_succeeds state address.toNat value binding
  simp [
    read_ram,
    Sail.ConcurrencyInterfaceV1.sail_mem_read,
    PreSail.ConcurrencyInterfaceV1.sail_mem_read,
    rawOutcome,
    bind,
    EStateM.bind,
    pure,
    EStateM.pure,
  ]

theorem read_ram_plain_two_succeeds
    (state : GeneratedState)
    (address : BitVec 34)
    (value : BitVec 16)
    (binding : RawByteBindings state address.toNat 2 value) :
    read_ram .Read_plain (.Physaddr address) 2 false state =
      .ok (value, ()) state := by
  have rawOutcome := readBytes_two_succeeds state address.toNat value binding
  simp [
    read_ram,
    Sail.ConcurrencyInterfaceV1.sail_mem_read,
    PreSail.ConcurrencyInterfaceV1.sail_mem_read,
    rawOutcome,
    bind,
    EStateM.bind,
    pure,
    EStateM.pure,
  ]

theorem read_ram_plain_four_succeeds
    (state : GeneratedState)
    (address : BitVec 34)
    (value : BitVec 32)
    (binding : RawByteBindings state address.toNat 4 value) :
    read_ram .Read_plain (.Physaddr address) 4 false state =
      .ok (value, ()) state := by
  have rawOutcome := readBytes_four_succeeds state address.toNat value binding
  simp [
    read_ram,
    Sail.ConcurrencyInterfaceV1.sail_mem_read,
    PreSail.ConcurrencyInterfaceV1.sail_mem_read,
    rawOutcome,
    bind,
    EStateM.bind,
    pure,
    EStateM.pure,
  ]

theorem read_ram_plain_succeeds
    (state : GeneratedState)
    (address : BitVec 34)
    (width : Nat)
    (value : BitVec (8 * width))
    (widthCases : width = 1 ∨ width = 2 ∨ width = 4)
    (binding : RawByteBindings state address.toNat width value) :
    read_ram .Read_plain (.Physaddr address) width false state =
      .ok (value, ()) state := by
  rcases widthCases with rfl | rfl | rfl
  · exact read_ram_plain_one_succeeds state address value binding
  · exact read_ram_plain_two_succeeds state address value binding
  · exact read_ram_plain_four_succeeds state address value binding

theorem checked_mem_read_load_data_succeeds
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
    (readable : region.attributes.readable = true)
    (aligned : is_aligned_paddr (.Physaddr address) width = true)
    (htifDisabled :
      state.regs.get? Register.htif_tohost_base = some none)
    (bytes : RawByteBindings state address.toNat width value) :
    checked_mem_read (.Load .Data) .PBMT_PMA .Machine
        (.Physaddr address) width false false false false state =
      .ok (.Ok (value, ())) state := by
  have pmaOutcome := check_pma_with_pmp_priority_load_succeeds
    state (.Physaddr address) width regions region regionsBinding matching
    mainMemory readable aligned
  have splitOutcome := split_misaligned_aligned_succeeds
    state (.Physaddr address) width
  have pmpOutcome := pmpCheck_disabled state (.Physaddr address) width
    (.Load .Data) .Machine
  have mmioOutcome := within_mmio_readable_false
    state (.Physaddr address) width htifDisabled
  have ramOutcome := read_ram_plain_succeeds
    state address width value widthCases bytes
  have addIntZero : Sail.BitVec.addInt address 0 = address := by
    exact BitVec.add_zero address
  simp [
      checked_mem_read,
      Sail.SailME.run,
      PreSail.PreSailME.run,
      pmaOutcome,
      splitOutcome,
      pmpCheck,
      sys_pmp_count,
      within_mmio_readable,
      within_clint,
      within_sig,
      within_htif_readable,
      within_htif_writable,
      get_config_rvfi,
      plat_have_clint,
      plat_have_sig,
      htifDisabled,
      Functions.not,
      PreSail.readReg,
      mmioOutcome,
      addIntZero,
      ramOutcome,
      read_kind_of_flags,
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
      BitVec.add_zero,
      Sail.BitVec.updateSubrange,
    ]
  rcases widthCases with rfl | rfl | rfl <;>
    simp [Sail.BitVec.updateSubrange']
/-- The four component byte bindings used by the public state boundary really
make the generated four-byte observer total. -/
theorem generatedMemoryWord?_succeeds
    (state : GeneratedState)
    (address value : BitVec 32)
    (binding :
      LeanRV32IM.Publication.GeneratedMemoryWordBinding state address value) :
    generatedMemoryWord? address state = some value := by
  have raw : RawByteBindings state address.toNat 4 value := by
    constructor
    intro offset
    have cases :
        offset.val = 0 ∨ offset.val = 1 ∨
          offset.val = 2 ∨ offset.val = 3 := by
      omega
    rcases cases with h | h | h | h
    · have offsetEq : offset = (0 : Fin 4) := by
        apply Fin.ext
        exact h
      subst offset
      simpa using binding.byte0
    · have offsetEq : offset = (1 : Fin 4) := by
        apply Fin.ext
        exact h
      subst offset
      simpa using binding.byte1
    · have offsetEq : offset = (2 : Fin 4) := by
        apply Fin.ext
        exact h
      subst offset
      simpa using binding.byte2
    · have offsetEq : offset = (3 : Fin 4) := by
        apply Fin.ext
        exact h
      subst offset
      simpa using binding.byte3
  have outcome := readBytes_four_succeeds state address.toNat value raw
  simp [generatedMemoryWord?, outcome]

end LeanRV32IM.Publication.ExecutionMemory
