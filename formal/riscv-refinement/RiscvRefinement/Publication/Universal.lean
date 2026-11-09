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
    "9b1752b1cdb7ff9a8758fe7c5396a4a621ac245dcf7911990f5a2e9df944c080",
  identity 1 "sub" .baseAluReg
    "e785f779ade7380a45393efd8e9bf99bf61fe828e3868b04758c5a8c23e49ff9",
  identity 2 "sll" .shiftsReg
    "52022ad041db36a5dd07b3da5dfca6ff4203f60d6199562deef32347af17aae5",
  identity 3 "slt" .ltReg
    "766c4ce605d755858a43dee135d40b8d8f3544a89fb0af60d81e629199aa46bb",
  identity 4 "sltu" .ltReg
    "3d719f08be85bcdb88582d6e121a888aed49e7a35255f6c3cdb1b1b38c12cefe",
  identity 5 "xor" .baseAluReg
    "1a87fd20eebcd2480189353ceb7d3c130a6769d00f717d6807989e318166b9c6",
  identity 6 "srl" .shiftsReg
    "5c8ac19403807ea6c4b657d7b4a47473184c6423d8a8c7acb133c8e431791dd2",
  identity 7 "sra" .shiftsReg
    "04f196d6512eb3bcaa8a97a7f54becfc195a3dcead9f29940f713b9c76762450",
  identity 8 "or" .baseAluReg
    "175616456da991f296ebce3370dbe33c8a04aa75bb2ea4b1f0f2fc7716c7e8f0",
  identity 9 "and" .baseAluReg
    "fabe154a8ed7f8b69f646af3cddf5b2493d6cb55284f95afc8b631a5050fc780",
  identity 10 "addi" .baseAluImm
    "c5362d89c2f48d70f3788f93a4b5890e23ca926d892f02dcf909b8df611d2262",
  identity 11 "slti" .ltImm
    "3f13a56fdda720dec95e0d1021478e37f4829fb85c2de838ed832f7f7f5d2401",
  identity 12 "sltiu" .ltImm
    "c1b3083b57ac57da0f4c4e5a5b55a4cc89b53d578e0bf6523bd273f106b22aac",
  identity 13 "xori" .baseAluImm
    "0948c3f406cea783469bcc99564c0b6258fc12ce57eb13ac195c12599c21138d",
  identity 14 "ori" .baseAluImm
    "7ed57a62d53042be87aaae76b8fdcdfa0c37b7f543f08c834dff56735fc093ba",
  identity 15 "andi" .baseAluImm
    "1dd0c3365a1c32a26f96e3d31bdde6aa7ae6dc8f99105db187199c076f6b4305",
  identity 16 "slli" .shiftsImm
    "4c495eb6176d76116b74c946f9dae386bfb9928f2f3e191aa4d581f35d079db4",
  identity 17 "srli" .shiftsImm
    "eab44f64ec4d7ebe1f1f9ef1ec170e34bd2054760e4a1b19fb091d6b0ab33d38",
  identity 18 "srai" .shiftsImm
    "b77fc84e0d48c224f819f15a0616f299c31df40d697d2486fe61e5c188f41e12",
  identity 19 "lb" .loadStore
    "492a2db13150924c9cdf8593cf9902c88e7f9334215020e9ad970c603041af7e",
  identity 20 "lh" .loadStore
    "0a0c6470c844a35b7a38c8e6571ecef7274a3338fc1e9cebaaf95ab748a14a94",
  identity 21 "lw" .loadStore
    "a89be3eb641bd481f1b6e0a31b43ef1140bd48b610adea1501870fbb6e16b159",
  identity 22 "lbu" .loadStore
    "2e8c648dfd7f4c04892e84dcc46fa1d7fa8a59bf4b182b1f1016efbe5ac2886f",
  identity 23 "lhu" .loadStore
    "aa9ee277b9ea3fe7ba1becbd8a94a2b1be0e8caa4290312dbc9892163b0d1a76",
  identity 24 "sb" .loadStore
    "1b8cc030b71c69c17c75b9f00a73a14cf184c545d77a75f11343eddcd5dd6282",
  identity 25 "sh" .loadStore
    "da3c7e6302256f55233af8d7dfc246447f1922c362f6d20c7ca280445c8f8ec6",
  identity 26 "sw" .loadStore
    "d124acad69a53fd7525441bb73efaba34555fc4b84b0a8080b10590bb5cb8ef8",
  identity 27 "beq" .branchEq
    "ddf4c4a0002601c6a1b5f824d5926494e983f3b1a52cf95cd495b3971795e9fc",
  identity 28 "bne" .branchEq
    "59f964af02d827005c7507ac6a8d2ace33f19cd8d49ab89d391bb2bf39d8f58a",
  identity 29 "blt" .branchLt
    "8e95a46f53998f887b6e5ace225c2ebdca91f13a61a64eb3d8e20ca8aa046aef",
  identity 30 "bge" .branchLt
    "0023ecf42505c4a76e3f51a1bb84735c6ac4cdb5284f64f8c66e6399177224c5",
  identity 31 "bltu" .branchLt
    "b2d29fc948adc820f5b67562e748c5501f64082019a49735a76d96197b5a732a",
  identity 32 "bgeu" .branchLt
    "dcec35bdf0074d4bf0f649c0ec0b46b1ba89f62518bda4df6da6a8fbbb0c6dae",
  identity 33 "jal" .jal
    "d11075abd9988a417490fb4288b4aa0fc4a77516055ae0a1b2928e3465b111e6",
  identity 34 "jalr" .jalr
    "0c3a2bf5a23142b6c43128bceb3ea53c95a63f05adfef666e57d879a126b383f",
  identity 35 "lui" .lui
    "81f5de5e8e36076ceaed181fe5fe590a662c8391d2d6ea518549486917ba00ed",
  identity 36 "auipc" .auipc
    "5bbed20c3f7fff8327b403d98cd4ef179fbb42f4d008ff534b6a32a88d53f632",
  identity 37 "mul" .mul
    "209cbb505b4d93b8b3650644f1aa9dd373696dda09a52d2ac969a24adee1dce3",
  identity 38 "mulh" .mulh
    "47bfea2f6a1f8dc3a74c07c35b2cb2a37b43b5ae940c2e1f1aa0c1d20f574799",
  identity 39 "mulhsu" .mulh
    "a9b6f4b196463541ef7703d1a978391f9de23233d7b607edb8a6b6dce15bcb2d",
  identity 40 "mulhu" .mulh
    "c42c7fd6548a68e6775f9b7078246d4505338e3839b78d42daa7e2cb7619a4b6",
  identity 41 "div" .div
    "2fffce12c6ed3a8132fc509872e220d562ed8e8a5ac1e5cd7fb6fc4529748bf3",
  identity 42 "divu" .div
    "87431aac75e9ea7f587d99c2bdf273566e4eca4710db376843c543bc9cea85b5",
  identity 43 "rem" .div
    "4f6f5924b2249ca1bfc89876376825fa6c3f4e834327dc39a57ddb4cb02f99be",
  identity 44 "remu" .div
    "8fdf18112fc2ef406ed3441312d2c4aa260aef09b5b5ad4a9f7d6cff5253cb37",
  identity 45 "fence" .fence
    "04d344daf5ae260f35a49bfd58ed455c60bd5bc39229fa8fb527132eaf5c56bb"
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
