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
    "96098540ca6f58e5b0bde94cbf5727acbd3db3d9868898766c7474d988bfdb23",
  identity 1 "sub" .baseAluReg
    "1f146a64681264a724d3568c7abfd73889c5765cf03352087d0d22fedc99e8cc",
  identity 2 "sll" .shiftsReg
    "b4793de9f34ce707ecaa5d7bb49993fd5d347778f64a39e01a6dcbb34052711a",
  identity 3 "slt" .ltReg
    "277e6f4c17e2f2857992069c411fffdb02e922a737ed5340c80c40756f05119b",
  identity 4 "sltu" .ltReg
    "1c57fe3bdcaa606aeb3db1a5a22ea0d4b09ae3cb1e52f32053678dccba9527a6",
  identity 5 "xor" .baseAluReg
    "c453d30d36e2fa637cc9a0c65e47aab5bb38e882848bd540ca08ea1a153f45b4",
  identity 6 "srl" .shiftsReg
    "d259d153008f4ab6c7a50f1fe1a9db394369c368c09716092367def234018822",
  identity 7 "sra" .shiftsReg
    "84e225009501f1514a034949f3e30b8cddc78dd443d8540b2b3110b3c8cc92e6",
  identity 8 "or" .baseAluReg
    "40ea0b0b3e5d419f83115a57d6e506c52f27857a160fd9caa6dfd171905812b9",
  identity 9 "and" .baseAluReg
    "462b1cef92a836b1feef53e3429a2b33da2308edaf297ce26ae05ecc9e4bacf2",
  identity 10 "addi" .baseAluImm
    "b03c7e28c5155bae5c14686048582edb4e6b00da445203c776f49e8dd6b52560",
  identity 11 "slti" .ltImm
    "f33446efd7b209edef5c0b15898b555f557abf7ee3ae42d1a8d2f2b83d14479e",
  identity 12 "sltiu" .ltImm
    "22fb3f5a75eda3f1e9f2727179219264089e0289b6702f0bdc2e22fee6c00e4e",
  identity 13 "xori" .baseAluImm
    "e76fe6e0b939993cbc374cacbad91b25747b616091d292561a1aea0cc5197235",
  identity 14 "ori" .baseAluImm
    "ad51e77669d8c40d4f2e50e98f74fe58e5aa5d828498bc7c97d51f5bfba6fff2",
  identity 15 "andi" .baseAluImm
    "16cc2bf9ed9b958f1b866151f76f0adefb66e8e1c3b51ee923c5fe577bab39c5",
  identity 16 "slli" .shiftsImm
    "94ced944900552f84bf9397cd29b0ce95b63693954e0d536b98f5c68228eee3d",
  identity 17 "srli" .shiftsImm
    "4fb3e788193bb912abc29ef87d0ef59170225b73c05dd5ac9df2999190580545",
  identity 18 "srai" .shiftsImm
    "abb8d4c192a7437357ec3244841237aef090653d68a1e1410ccbbfea778f47cb",
  identity 19 "lb" .loadStore
    "2b62f6e98622ab98614fab7a40cd744e688f9e9fbe8f11997fbdb6ceacd31d1b",
  identity 20 "lh" .loadStore
    "bf5a6a84a5cc4eb91681a908d851203254de6a7dae2342761fdc5a6468923dfc",
  identity 21 "lw" .loadStore
    "a6b4e0e59b374e3bd74f4298745526dad77d3789b8888612246f6a8e4177c9c7",
  identity 22 "lbu" .loadStore
    "721de692ab100a2332c7a8ef2b2bbaaf838ff88fcb8619d3fadddc133f09e954",
  identity 23 "lhu" .loadStore
    "b67b5feaaef8a489e006502289f8c1ecc661befca6fc42f009177744cac65b65",
  identity 24 "sb" .loadStore
    "04b10279e3b05f6207de920e71dc65a5e5c527c8a2508281a27cffe6b0c39070",
  identity 25 "sh" .loadStore
    "d3df3e27ff3da0a78a5f8c91231ed1e744a646d0c8cee40c533c454c3570be10",
  identity 26 "sw" .loadStore
    "8d218f16f31f272b35df8fea3da5226749e6f0a3e7a38c524fb051ffd0c781ee",
  identity 27 "beq" .branchEq
    "eb46a0a28f25cb319af4de39cd1dc6e63626d62f548c173340db1fa217aeb77a",
  identity 28 "bne" .branchEq
    "53fc4699d9a90e1df6f416ee3fc322865b482cf8235d5d2f4902a60c25f4ba44",
  identity 29 "blt" .branchLt
    "2aa14f15b7189dcdf41dfb26b27dd15f127cae960cc10f1b37f3612d9749831d",
  identity 30 "bge" .branchLt
    "ee9e04ac6064b48ae9578733c94d87d655f1d63aff262fa0db0a17b96b6ccd66",
  identity 31 "bltu" .branchLt
    "0dbf140113049925b26e75f4e9c4eca9a29843398c74107f34e6647f818caa3e",
  identity 32 "bgeu" .branchLt
    "f5e3d4d380570e7d2f20ba4518424b3a62d9530defa6b7cb1338a1da7f5af0f1",
  identity 33 "jal" .jal
    "06f242801de268e482ca96da01a46aa046c7d6367d6161ec202c4aa1b6b62d79",
  identity 34 "jalr" .jalr
    "48e9021497bf34b8c42d49b34f341bec2bf0ab89ef6e1a63f0a4329b0bfb1138",
  identity 35 "lui" .lui
    "811217d457f0481ea9fc1bdf46c0c84f1751c30ca80cecdbe6fc2493a95e8ac8",
  identity 36 "auipc" .auipc
    "3efe5711b33f35136ff318744bbb43ec90667c7b6371b7a176752a6f5aa75b33",
  identity 37 "mul" .mul
    "c367dddeb57f94f1204d5c579460c496c3b46bb76a3288ff0ebb76f05e2e36b7",
  identity 38 "mulh" .mulh
    "3a55f1536af7086cbedef8ed8a0e783404b1b39132325e82f1343a4dede2706b",
  identity 39 "mulhsu" .mulh
    "112dd22f3a76343d75088f6cdec08aa6c23a1bd2f8174c2e98cdb13747afb267",
  identity 40 "mulhu" .mulh
    "f44f9b0393e8d931a92d3606da8be06c93bda14a465c56ca280e9560ff438d3a",
  identity 41 "div" .div
    "51ccf0bcb0a0ecd704fa24a78a27fc899a9082e2fedc70f14b659ec9f9fcc5e0",
  identity 42 "divu" .div
    "b4474df84c1169ca57aa0308c75322c9a3928a38a292fb3948e0b0171805f408",
  identity 43 "rem" .div
    "343633e4ea71a4f1f7805cba9ae79852e3a9a3a39bb2e4e47f9f30a1f4ac1e0f",
  identity 44 "remu" .div
    "b8bc11479443f9679682386ebbca323ccbc28883f0fa75667fefae09f89d256a",
  identity 45 "fence" .fence
    "86f9fa3730c41a418c9283b92b4ff82800cbdd4aefdee51c108ce9e9aa561031"
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
