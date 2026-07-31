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
    "f218f6b67c30ac0b9b8bf821850c74913300c6710a33dc213a7dcd1c58832328",
  identity 1 "sub" .baseAluReg
    "4adc9896f7779002c02678743cd0166e96247236008de0d94fc3be284a988c41",
  identity 2 "sll" .shiftsReg
    "5513a65cf4559ab46f66c31c7d24db7513b835be8ac41e556473ab816b036d60",
  identity 3 "slt" .ltReg
    "e9496d127ea88fdabd3dc47de1f821e46a688d972f04532ee919d4341a399436",
  identity 4 "sltu" .ltReg
    "7644ce466104ac8d551c7a43025c22410a5a22728e9db4df4bce7b9777bc7388",
  identity 5 "xor" .baseAluReg
    "ce5966b26eb06acaf9c549dea9f3416ef6a67060d76fdd1b13c61d6687427b87",
  identity 6 "srl" .shiftsReg
    "80870cd76a79b5d2b76703000662dcf2ce7d58b4dd89383ca89ecee5726bf3a2",
  identity 7 "sra" .shiftsReg
    "13e5be41b2c8989656eb070c70d8af825865aff741aef59244fd4ecccb3531ec",
  identity 8 "or" .baseAluReg
    "4c61a18c36cc10f7f2db39293b0fa5015d6a87ce6fe9c0ef4a8b221070504178",
  identity 9 "and" .baseAluReg
    "1c214fd57af1b05680ee164a7119e77ad3fe8f1efbbb735277d9b0b4d56ea405",
  identity 10 "addi" .baseAluImm
    "03e6006a68391ad90474d815dd03bce08feee4145e8ef0b37eaa757bc48d2bea",
  identity 11 "slti" .ltImm
    "5cf8afd75d757cf8ba46cd75cbc9db0ea0ad29dc37962e5e0cff7e877c40fc71",
  identity 12 "sltiu" .ltImm
    "1a6cd579d976d5c29e353e2ac6d0329ea176269a1f33f793faf4548e9341fdc4",
  identity 13 "xori" .baseAluImm
    "2a440e3181b18ee1def73c386ed80e35cbb779dc5951c7634f59adbf5f29855f",
  identity 14 "ori" .baseAluImm
    "6dd21dfee0ba53ea25e1947898a0fd594ae3f77c3ea1b256a538be9256f569a5",
  identity 15 "andi" .baseAluImm
    "2585ea4f0e98cc394ae6141dab45754c17893fe6e68a53a3a911baa94135cdc8",
  identity 16 "slli" .shiftsImm
    "d058ca878982cc51135ad32e494e80780b5425d69875d75b7f23c327cd435e0a",
  identity 17 "srli" .shiftsImm
    "1141a52df72f28a7b0998bcd42ea854c5157ce0868bf41d072c84046e9a447fa",
  identity 18 "srai" .shiftsImm
    "bbd0a049473e0332217ec7384623110ad666424a5199ef69195698871773847b",
  identity 19 "lb" .loadStore
    "3a9002c26918c94efd3a55df21df21153dbc1f941c2d0a3c4bbfecd1c9f7b02a",
  identity 20 "lh" .loadStore
    "00f4b464e7fa1e1efe36851b21b743f45a034c1cbdf8def419d2d0ca13376b7b",
  identity 21 "lw" .loadStore
    "9bb574de7204793e9aaf4aa82898d3111239c79771afb4a0e75102473efb7818",
  identity 22 "lbu" .loadStore
    "92d3266f83bc7a53f0ba3ecfe6b5c455991ee5f6afb275fd70f2d8ff9bc2176b",
  identity 23 "lhu" .loadStore
    "142df330e349fb0f4e0cc584e183ff6ee11908017cb15fc4756285118f932403",
  identity 24 "sb" .loadStore
    "61ec9371092a3dc047f907780998df737e9fe47f804822a11c03bcafc74af61a",
  identity 25 "sh" .loadStore
    "9a098803731cb8a4c17d0d3cbc4bc9cb1e9321dd2c62f09717a12a6ec708aa7b",
  identity 26 "sw" .loadStore
    "761bfb6d46fb0c1bec8e33134c0f49d063f8f2c6d3534a96ab53603508fd67fe",
  identity 27 "beq" .branchEq
    "c9cfcff8fb9d137d38495aeacd59fe58a63545e24179a598b72cf2daf250c07f",
  identity 28 "bne" .branchEq
    "e951ba027b4ea0ea191d8c03a04b9429ca5878e4b83073ecbaf340bcd5199037",
  identity 29 "blt" .branchLt
    "3eb8ce821bd051f857a578a798aa663d68c9c1ab848dd76ba5b0d0f9d3fc3c9e",
  identity 30 "bge" .branchLt
    "24eab70f3fb54eb8d66e13dc4d5c46485f10303936e6da1cdd43307f4bc9aaef",
  identity 31 "bltu" .branchLt
    "905b708274f4dafb70c35c02df67838fc11bda8984a93ce7ade2d82798286e3b",
  identity 32 "bgeu" .branchLt
    "df6755ebe46f0e1f787790920263853a5bfc187aeccb18e3dc1ded6f06ec07ed",
  identity 33 "jal" .jal
    "f4265ec20317fc012179ec95005b98c6417882b1a99bf3a2ae8b95758db8ce8f",
  identity 34 "jalr" .jalr
    "1964dff536a67c94e372a72eaf2eaccef250dbca51240e27423073e3e7555e04",
  identity 35 "lui" .lui
    "d5eb5ca5127828f57d7fb52c292ea3a74e39b1a26334c935fc66535dfca9f3ef",
  identity 36 "auipc" .auipc
    "0c85f7dd831b425813170ca776bf6acdcc397478991ed7e1ec71ecd77c706582",
  identity 37 "mul" .mul
    "e6ebc8ea809ed36e6e161ea0e4db802c659559076051841d97b95f2bbb5320c6",
  identity 38 "mulh" .mulh
    "2874db65e8b666a49a929e8f123cf10d43153e9ac4476e089cac57f50cc5b9c5",
  identity 39 "mulhsu" .mulh
    "336969932d87fa57b8c1119d9a6417de90fbbb5d273767fd9d3ebf9f5f3f0b41",
  identity 40 "mulhu" .mulh
    "d045f97955a2e27478f22ce67ec51e15d62f8fe055886c66415da9b053b63fb5",
  identity 41 "div" .div
    "4355b265b09fdf7a737b66b6a7bb54b52eba0d3dad450fe67dd5e7eda0763b74",
  identity 42 "divu" .div
    "243f9632581ae182ca454dca0cdd71956cfdcacd91877b601547acf1188bb99f",
  identity 43 "rem" .div
    "88d1f5d7c3d50d5471a537b5fc19e43bd44a688b59a275d7a656ed6fcdfc6108",
  identity 44 "remu" .div
    "02c4fe4d503963e01dc955428525ce9f2050613f2b0cad3538aea04feef7a072",
  identity 45 "fence" .fence
    "a675d8a769e8f29d444caa571c2f7f1d562db5a6001041e0e9a1e52418d22af3"
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
