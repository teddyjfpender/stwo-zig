import RiscvRefinement.Air.Generated.Programs

/-!
# Universal publication inventory

This module turns the generated 46-entry `Programs.all` registry into
kernel-checked publication evidence.  The expected identities below are
deliberately independent literals: changing an opcode selector, family, or
production digest in a generated program makes the theorem fail until the
change is reviewed here.

The family-specific FV-2 implications consume this inventory.  It does not
claim that those implications, or the generated-Sail FV-1 projections, follow
merely from being listed.
-/

namespace RiscvRefinement.Publication

open RiscvRefinement.Air
open RiscvRefinement.Air.Generated

structure ProgramIdentity where
  manifestId : Nat
  mnemonic : String
  family : Family
  contentDigest : String
deriving DecidableEq, Repr

private def identity
    (manifestId : Nat)
    (mnemonic : String)
    (family : Family)
    (contentDigest : String) :
    ProgramIdentity where
  manifestId
  mnemonic
  family
  contentDigest

def expectedProgramIdentities : List ProgramIdentity := [
  identity 0 "add" .baseAluReg
    "93b8d4077863c2bbdf940e204c6411ab8d38f29c86b0fd47788441b429ac05b1",
  identity 1 "sub" .baseAluReg
    "d94ac84bb85aa14c8b914552a08ce7169d148688d45a019e3007a6388c1801b6",
  identity 2 "sll" .shiftsReg
    "d3fd3809b191a3c42695d89e367914846344edb3ae979dda79b81fb784b3d06e",
  identity 3 "slt" .ltReg
    "d78a80b687219818e82dcd0438b5daf3e42eaa10192b293cfee6c09afd7ef1c1",
  identity 4 "sltu" .ltReg
    "f00e0c2b42a71d6f212003f2543d61213ed1512d928e853e698d62e9f7a53926",
  identity 5 "xor" .baseAluReg
    "be8a0596b48fb0a8fe7273656c31f83ec15969249709e162410a662db30c57ad",
  identity 6 "srl" .shiftsReg
    "96a6ca4b440898c8712b0f7f54326f852f9a5529da98d114541c718983aaa53d",
  identity 7 "sra" .shiftsReg
    "4a7dbee1e94a857fef3825c26a5151205a2babe6385808279c804468620b6a9a",
  identity 8 "or" .baseAluReg
    "a9b2759660ffab9939727159d34f439534358224f931a2afc956165f5e469ac4",
  identity 9 "and" .baseAluReg
    "c152e786fa94ce3fe78bb8654a6bcc798f53c615bd1125125f864d777d472617",
  identity 10 "addi" .baseAluImm
    "6557d048ddabdc2610b8d5d124c16b20863417297b2188513f4796597e1ce037",
  identity 11 "slti" .ltImm
    "7733d881f13d427c5bb0978fc6e3c50e883742cb87e9ad986431a3c61bbb88be",
  identity 12 "sltiu" .ltImm
    "251fdf2d0e21e0c7119cab0be1c9dab0992f506a70e6813382cc1816ddfdff49",
  identity 13 "xori" .baseAluImm
    "771936a692427fa829b39fd759bae7f5b1f3390d4fd46c3a567004f133b6ee4f",
  identity 14 "ori" .baseAluImm
    "c431583c28c00d30955280a7c7a6e57d24b2609c8a1d996b528160fbc636c161",
  identity 15 "andi" .baseAluImm
    "8fe5640716fd139e896778ae10c80fdaef6d68123a83e53172ae335216afdb7b",
  identity 16 "slli" .shiftsImm
    "839a8c4508d5256b6ff5eed62f32bdd10fb22f135a127eaced4d278d74200007",
  identity 17 "srli" .shiftsImm
    "30510ce4474a4234c141ccbc937572ef6462a86af9088dcbb751f767ce8d3fcf",
  identity 18 "srai" .shiftsImm
    "b633c94e13cf0d6649882e55cc3f9cd87f3e5fe599d460b57a3f87f94e916bf8",
  identity 19 "lb" .loadStore
    "7d1ebab51de5b682e75f16db43f76b26281ef5136ab49ffa394a3bf65a4e9b8e",
  identity 20 "lh" .loadStore
    "c46b5bb1c5e4c03063f876b96355a0eafff562b43ce350f130711628467298d4",
  identity 21 "lw" .loadStore
    "3945d7dcfb1b6c20194efa0bfc921813588c594a606dca29925117b152060067",
  identity 22 "lbu" .loadStore
    "2c12ac0312f758c2543cc34d11eaf8eada2a24f9f72ae3c21149b6d38e78fa15",
  identity 23 "lhu" .loadStore
    "808538ff8e6dd1b6eb7d87e0ac9d994b1fd6e29daa4384956dcd6797212fd3e1",
  identity 24 "sb" .loadStore
    "095ed8ceb44da881b6a6f90733e717df76d12d1a60bd808a1caf68e50d7109b2",
  identity 25 "sh" .loadStore
    "3bf01c5b10378b0b322aafa43caa1e18c8c0a2f0003e9af81c799bd00e4b6457",
  identity 26 "sw" .loadStore
    "308979f09ebd7804b8b694f6c5651f0d2bb9f4ac86226d54f83f352e35a55767",
  identity 27 "beq" .branchEq
    "f94078384cb280f7dae5248b9bee2c9acc4706a156b7742c1ef7ae654de3ce42",
  identity 28 "bne" .branchEq
    "6150babc0e63e9bc49cd9d369e2bccdb85e70a808727aa294c02632430d01a5f",
  identity 29 "blt" .branchLt
    "5f2733a65def62d36f93b1b478f930f8873372abdbd95b28c852fe51972b6bdf",
  identity 30 "bge" .branchLt
    "27993749273b58da9481a157b855d8215f85ce9a16ef93d341eafbfda24c2596",
  identity 31 "bltu" .branchLt
    "e502a3bc7c118d5d86f7f3f4af99428033c62174d7e86d08a4ca86e09d09839e",
  identity 32 "bgeu" .branchLt
    "dc025f9d0b5b7b71e7729a04d51d9ee1a4f22558e2d1f532cdeeec82d20715ee",
  identity 33 "jal" .jal
    "fb6e0e2351f9b29732bc41ac72dde94252376cb5bc96584a49aa858f3ff014e7",
  identity 34 "jalr" .jalr
    "5f0a89f398693ff978e93711f7f724321aeb1722fad5ee371a69eddf85fa200f",
  identity 35 "lui" .lui
    "07c2d45b5082aaeb1d9c77f63a1cc21eb2aae3c5a635b7e77b8535e7288ed85c",
  identity 36 "auipc" .auipc
    "5c9df43006c52ac7d3e36f04ec7225fd6ba1b43f1dd60f5968b678bb30021c07",
  identity 37 "mul" .mul
    "c64c6c5a218fc6f966673dacc190de16aaeb030d5c3495118108cc9fe665ca55",
  identity 38 "mulh" .mulh
    "1815098fc2aa76037c0419370b1679daee694fd3863356618aa0031297ce0949",
  identity 39 "mulhsu" .mulh
    "c9af7ee41c4437fe606afb96c7d29a4244e38a63059509574a23ed1a0f93b9b4",
  identity 40 "mulhu" .mulh
    "85e037a7c8d52d5b65a6ee6e4f6fd99bbec5f2020540c5976eca1058103f95cc",
  identity 41 "div" .div
    "ded4ef0a25a4f0f7dc28a5b157ad224f9a481b0ab6fc7af84f625abceee7e04d",
  identity 42 "divu" .div
    "99bf3bc5ea983a9171abcfb0fee5836462feae417410520a4ac26b33b535f386",
  identity 43 "rem" .div
    "7158824451e9f30909e1e0f8d45fd3bfddc09679185eaacc6cef9b595aea490a",
  identity 44 "remu" .div
    "78d79d00716a232c6024bd8e16ae9c60ca759df8650b6f60bab7ea45061b0a94",
  identity 45 "fence" .fence
    "2eee10f293bacfcbe514b21ab4d79220693734651785294bbfebcd067d1f80b6"
]

def actualProgramIdentities : List ProgramIdentity :=
  Programs.all.map fun entry => {
    manifestId := entry.program.source.opcodeSelector.manifestId
    mnemonic := entry.program.source.opcodeSelector.mnemonic
    family := entry.program.source.family
    contentDigest := entry.program.source.contentDigest
  }

/-
All 46 exact generated local programs have the reviewed manifest selector,
family, and production content digest, in manifest order.
-/
set_option maxRecDepth 20000 in
theorem exactProductionProgramIdentities :
    actualProgramIdentities = expectedProgramIdentities := by
  rfl

theorem exactProductionProgramCount :
    actualProgramIdentities.length = 46 := by
  rfl

theorem exactProductionManifestOrder :
    actualProgramIdentities.map (·.manifestId) = List.range 46 := by
  decide

theorem exactProductionManifestIdsNodup :
    (actualProgramIdentities.map (·.manifestId)).Nodup := by
  rw [exactProductionManifestOrder]
  exact List.nodup_range

theorem exactProductionMnemonicUnique :
    (actualProgramIdentities.map (·.mnemonic)).Nodup := by
  decide

def admissionValid (entry : Programs.Entry) : Bool :=
  entry.program.source.family.validOpcode
    entry.program.source.opcodeSelector.manifestId
    entry.program.source.opcodeSelector.mnemonic

/-
The family decoder admits exactly the selector carried by every generated
production program in the universal registry.
-/
set_option maxRecDepth 20000 in
theorem universalAdmissionDecode :
    Programs.all.all admissionValid = true := by
  rfl

def expectedFixedTables : Array FixedTableIdentity :=
  FixedTableId.all.map FixedTableIdentity.expected

def fixedTableSchemasValid (entry : Programs.Entry) : Bool :=
  entry.program.source.fixedTables == expectedFixedTables

/-
Every one of the 46 generated production programs carries the exact six
reviewed fixed-table schemas.  Thus a family theorem interpreting
`fixedLookupsHold` is about the production tables, not an unconstrained
external predicate.
-/
set_option maxRecDepth 20000 in
theorem universalFixedTableSchemas :
    Programs.all.all fixedTableSchemasValid = true := by
  simp [
    Programs.all,
    fixedTableSchemasValid,
    expectedFixedTables,
    FixedTableId.all,
    FixedTableId.arity,
    FixedTableId.logSize,
    FixedTableIdentity.expected,
    FixedTableIdentity.expectedSchemaSha256,
    Domain.ofFixedTable,
    Programs.add, Programs.addSource,
    Programs.sub, Programs.subSource,
    Programs.sll, Programs.sllSource,
    Programs.slt, Programs.sltSource,
    Programs.sltu, Programs.sltuSource,
    Programs.xor, Programs.xorSource,
    Programs.srl, Programs.srlSource,
    Programs.sra, Programs.sraSource,
    Programs.or, Programs.orSource,
    Programs.and, Programs.andSource,
    Programs.addi, Programs.addiSource,
    Programs.slti, Programs.sltiSource,
    Programs.sltiu, Programs.sltiuSource,
    Programs.xori, Programs.xoriSource,
    Programs.ori, Programs.oriSource,
    Programs.andi, Programs.andiSource,
    Programs.slli, Programs.slliSource,
    Programs.srli, Programs.srliSource,
    Programs.srai, Programs.sraiSource,
    Programs.lb, Programs.lbSource,
    Programs.lh, Programs.lhSource,
    Programs.lw, Programs.lwSource,
    Programs.lbu, Programs.lbuSource,
    Programs.lhu, Programs.lhuSource,
    Programs.sb, Programs.sbSource,
    Programs.sh, Programs.shSource,
    Programs.sw, Programs.swSource,
    Programs.beq, Programs.beqSource,
    Programs.bne, Programs.bneSource,
    Programs.blt, Programs.bltSource,
    Programs.bge, Programs.bgeSource,
    Programs.bltu, Programs.bltuSource,
    Programs.bgeu, Programs.bgeuSource,
    Programs.jal, Programs.jalSource,
    Programs.jalr, Programs.jalrSource,
    Programs.lui, Programs.luiSource,
    Programs.auipc, Programs.auipcSource,
    Programs.mul, Programs.mulSource,
    Programs.mulh, Programs.mulhSource,
    Programs.mulhsu, Programs.mulhsuSource,
    Programs.mulhu, Programs.mulhuSource,
    Programs.div, Programs.divSource,
    Programs.divu, Programs.divuSource,
    Programs.rem, Programs.remSource,
    Programs.remu, Programs.remuSource,
    Programs.fence, Programs.fenceSource,
  ]

structure FixedTableInterpretation : Prop where
  bitwise :
    ∀ lhs rhs result operation : M31,
      FixedTableId.bitwise.contains
          [lhs, rhs, result, operation] = true ↔
        lhs.toNat < 2 ^ 8 ∧
          rhs.toNat < 2 ^ 8 ∧
          operation.toNat < 4 ∧
          FixedTableId.bitwiseResult
              lhs.toNat rhs.toNat operation.toNat =
            some result.toNat
  rangeCheck20 :
    ∀ value : M31,
      FixedTableId.rangeCheck20.contains [value] = true ↔
        value.toNat < 2 ^ 20
  rangeCheck811 :
    ∀ low high : M31,
      FixedTableId.rangeCheck811.contains [low, high] = true ↔
        low.toNat < 2 ^ 8 ∧ high.toNat < 2 ^ 11
  rangeCheck884 :
    ∀ low middle high : M31,
      FixedTableId.rangeCheck884.contains [low, middle, high] = true ↔
        low.toNat < 2 ^ 8 ∧
          middle.toNat < 2 ^ 8 ∧
          high.toNat < 2 ^ 4
  rangeCheck88 :
    ∀ low high : M31,
      FixedTableId.rangeCheck88.contains [low, high] = true ↔
        low.toNat < 2 ^ 8 ∧ high.toNat < 2 ^ 8
  rangeCheckM31 :
    ∀ low high : M31,
      FixedTableId.rangeCheckM31.contains [low, high] = true ↔
        low.toNat < 2 ^ 8 ∧
          high.toNat < 2 ^ 7 ∧
          low.toNat + 2 ^ 8 * high.toNat < 2 ^ 15 - 1

/--
One theorem gives the complete mathematical interpretation of all six exact
production fixed tables.  In particular, the M31 table's missing terminal row
is preserved by the final strict inequality.
-/
theorem universalFixedTableInterpretation :
    FixedTableInterpretation where
  bitwise := by
    intro lhs rhs result operation
    simp [
      FixedTableId.contains,
      Bool.and_eq_true,
      decide_eq_true_eq,
      and_assoc,
    ]
  rangeCheck20 := FixedTableId.rangeCheck20_contains_iff
  rangeCheck811 := FixedTableId.rangeCheck811_contains_iff
  rangeCheck884 := FixedTableId.rangeCheck884_contains_iff
  rangeCheck88 := FixedTableId.rangeCheck88_contains_iff
  rangeCheckM31 := FixedTableId.rangeCheckM31_contains_iff

end RiscvRefinement.Publication
