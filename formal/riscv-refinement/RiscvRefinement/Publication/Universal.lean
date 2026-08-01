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
    "61ba91ac87afda7e41906d1a7167664a4a80525ea497fe117dd06e608a00e186",
  identity 1 "sub" .baseAluReg
    "43b6f252f66cdcf82438c83fb738e22cca41ee8c23ae1d16c84cdceeb1c17373",
  identity 2 "sll" .shiftsReg
    "69e9eb8a4a78d0ffe16bebe020b32af43ecb7520fab92d84e2811844a96a93ac",
  identity 3 "slt" .ltReg
    "d638904f452145bfaada9b6005cb396a306607bd6097379873490900e5a2d490",
  identity 4 "sltu" .ltReg
    "48813e3a89590c2683450fc97c2fb5b0aca85b5a0019de9302ee7b1e4b328749",
  identity 5 "xor" .baseAluReg
    "f70c7b3737e74fd5c8bd0f35bb75e0a5b5e88467669a438896aca3776fddf5a3",
  identity 6 "srl" .shiftsReg
    "3ff07a7b37ddf01c3155a28ba70981bca6fa1159b24db4d83cb82bfa458391a0",
  identity 7 "sra" .shiftsReg
    "4437a8c8e51bf0c891d3e9547baf9cf51669e13c01a3c904bd94c7c2c0961cdb",
  identity 8 "or" .baseAluReg
    "854de747d1454431a43fedeb74b3513cba543d516d3b28e7e8f0a10c26d4f3ac",
  identity 9 "and" .baseAluReg
    "4a2a4dfe809a958f208bd5b1ec3582962dcdabc38fbfa63a63783750aa780d02",
  identity 10 "addi" .baseAluImm
    "c81449734da29c1e76450ace58542a3f9421ae4d8e540d766da674a2a9acbb2a",
  identity 11 "slti" .ltImm
    "f749061d1b4f84ae1990707debed715c7386d5dc4116ad4a53e6cb52036b0794",
  identity 12 "sltiu" .ltImm
    "bbed2f63b6d08c8b25bdadf11c4be6b1441e61c6901e6f833cfbd2468552b5b8",
  identity 13 "xori" .baseAluImm
    "708f83e7f83af6fbae6f74237a08eb1577d0fc6f4fa9b4aec217d0496daf2b27",
  identity 14 "ori" .baseAluImm
    "4a305fbe805eb7f44e23efb1e47ed74498aa56006f2416d1a733fd5d8a248e83",
  identity 15 "andi" .baseAluImm
    "b2d7bf2971f26c7d39fb65ee4211829f1b3f4bbf83cdf84ebb64bc7d8bd93aad",
  identity 16 "slli" .shiftsImm
    "983569f5facb419f3041b276ab70b346aad13b2a02d2058745062f34a82b3478",
  identity 17 "srli" .shiftsImm
    "03133d68fbd1bf6aba404665e68457606875cf717825acc8132b813fe6c2be51",
  identity 18 "srai" .shiftsImm
    "e66f5bac7a6f2d8a7fb82767e15bc7d4d5d29e03df72cb3456321b2a868fe271",
  identity 19 "lb" .loadStore
    "2ef5d5edbb8bdf8ef3cc1996bea98fa80bde20b25e6e2d2a53df0e843bc8ef0b",
  identity 20 "lh" .loadStore
    "c6ef1b0528e1f8d7b319d06b3edc6987749f733c441d6334c45b3bcc6e6a741e",
  identity 21 "lw" .loadStore
    "44fbf8eaa8a58ae3916e0f51396fb9f8f3a6d612aa62e9d7a2782afcc0dfcfe2",
  identity 22 "lbu" .loadStore
    "8504b6262e3ed0d01bdf399ef84403db010671cb864c8c46791684c19dbbe83d",
  identity 23 "lhu" .loadStore
    "a54b597e3cfe5077b40a88e0285e083f0dca5e45f3b240ba478b187167588e1f",
  identity 24 "sb" .loadStore
    "ad2aea46014e0301700c38e25821d16e5eafe3433e77d63fca3ba6d3f0fa8fbd",
  identity 25 "sh" .loadStore
    "7ec0001e7403388c25424b3259162996356ca8b1bde549f261ead019d647e195",
  identity 26 "sw" .loadStore
    "5b89a62bbb5fdbea09583e89270d9c440097e6832b1f6291234bf1813df6b198",
  identity 27 "beq" .branchEq
    "518d3a436310e9c88eca0c3e77accb07cbec721ce10605d1e6fbacbe8e7cafc2",
  identity 28 "bne" .branchEq
    "96d67d449f6d3991e09d73aa014b462725dd0dc869f229578dc8e46140d9b4ea",
  identity 29 "blt" .branchLt
    "24d3e737afd7b38cc80ccd69d60786622c63c127d977fa8910ea588aef0c0c88",
  identity 30 "bge" .branchLt
    "98a0b591f6fd3aee208ed24a1bf9571217109a15c30db4d3071a10ebf37669a3",
  identity 31 "bltu" .branchLt
    "499f688b4f82e7db549ebca2bd6333f73393b6a0b96ba30e9510a0b20278e171",
  identity 32 "bgeu" .branchLt
    "46c2548d4768c4aaac4a6af592f3198b77f8835d12eff48e9987b33bd32b604d",
  identity 33 "jal" .jal
    "aaf0ef1ed52224c5acbfcfd6f9bccb17fd0592ed1bf1075ea388dd5ed7403dc4",
  identity 34 "jalr" .jalr
    "2f8e61070de1a6797802b8de7222f226d67cc0758c7621cff09f1cacadd5e777",
  identity 35 "lui" .lui
    "a10ec4d79f67a21dd5097b21339f7b4bd4a5e98db1698eca7fa8c98c0a39d253",
  identity 36 "auipc" .auipc
    "b6b387fff5fe062a97c68c99d4780ec978d5b949570b4c1fd7a0d565088cb669",
  identity 37 "mul" .mul
    "3eac1802dd221b7f52558c30faceed3aa1c93929f9ff290c224178b3cdb01780",
  identity 38 "mulh" .mulh
    "3b14ad48cc6a791aec8963128a38c6397ff52a4cdf99839a40d0cd326782d489",
  identity 39 "mulhsu" .mulh
    "890244c6d80ee3ab146fec5d8d32f15d152c64658ed03ee49c9cdf807d421eaa",
  identity 40 "mulhu" .mulh
    "e4a0c26eac2c45390d08a38ac632f2c10a8719041ebd54293e11449dc75859f3",
  identity 41 "div" .div
    "6b2ddef2bd76db51496e7d99f22198a2aa4f7b2cc4428ac9f73c61dd974f4f1a",
  identity 42 "divu" .div
    "1ee989b2c36df4ed63e6e197bccbea2f3fabd564435c74830eefd8effd6ec9f0",
  identity 43 "rem" .div
    "45a6b30b5da7470f7a5bfff9298d7ea3ba536576a5ed3ed6e2217e4462f4dcce",
  identity 44 "remu" .div
    "920d2a87865baa6a4f9649896de5ebb9b69fc355b3be96ec7a9f81bb9c641dff",
  identity 45 "fence" .fence
    "e2f97664b63bba84a1a5e5a846f72d18d35842d5bdd72202a03c123e00ce4065"
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
