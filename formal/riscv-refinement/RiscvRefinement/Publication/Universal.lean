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
    "a6303e0fa12517cc0d6fb2ae12890b15ae2799a696f540d13000d957c3f0a7d2",
  identity 1 "sub" .baseAluReg
    "6a7950bcee273474dfa3a366685ee3b1caeec5091fc4852fc3181a9ae513402c",
  identity 2 "sll" .shiftsReg
    "7b62fb42ff92827bf55533d67d584724c700ea179d1efcfd2f9b5ae3e20fbb32",
  identity 3 "slt" .ltReg
    "a5514838afdfa286601efb9856274169e31c6b6d0720bb21d681baa1e70ab892",
  identity 4 "sltu" .ltReg
    "4ce9b929880ca4bd00e4f10e95655ddab7f03b73da01a183af698bf036463a56",
  identity 5 "xor" .baseAluReg
    "f1c95c8f98200eb54a71176ba770850c40233fc93780ab57102cb635e28dfca6",
  identity 6 "srl" .shiftsReg
    "869c9706b00fd61143a8f6ed5b08507aa171c82b784c7d236555f6d2eb679f93",
  identity 7 "sra" .shiftsReg
    "4abb1006eb351fc2d570346833d1f3fa4c3175a30d02d0d4f05b5d8098b78b45",
  identity 8 "or" .baseAluReg
    "33c55dc1fdc6abb292c6d5f11994b83460bf60fb252057d930c37ead810cc9a1",
  identity 9 "and" .baseAluReg
    "1531795e236217168a70a78bb8ca24e13b0f684d94376a6d7afdbcdb77da3734",
  identity 10 "addi" .baseAluImm
    "437cc32977f4c9bb767e69e055266ede208c362b348ea35cb3891a38250305c2",
  identity 11 "slti" .ltImm
    "013cf0cc544c169eca8a236a0f3df0cdfacce41a7418265a238670aa9fda0960",
  identity 12 "sltiu" .ltImm
    "eb49bf0eecea44cb1f34d5cd2b0c2c0487de55e704931feffede15f6307cff3c",
  identity 13 "xori" .baseAluImm
    "59f4a2b943c1d0da84c61a3f0ab7962dd81feb17be09b9fcb807b0b83a6db359",
  identity 14 "ori" .baseAluImm
    "7390dd29e46e7128a2760e2cefb3051a04a728c9ae838f806a6a7321267c1dbf",
  identity 15 "andi" .baseAluImm
    "b70bfc3590d192c85dbc7d744da2e8203192a9f66fc13ba7c904384d6782b49d",
  identity 16 "slli" .shiftsImm
    "4c055fd72015887caae84bca79261a77464b5c5357adfa57a9959938f53f1dc5",
  identity 17 "srli" .shiftsImm
    "dc75bfeb776b77851cf313d9228b476d03d806df30af3de0ec40ca2ee94d03ee",
  identity 18 "srai" .shiftsImm
    "f0ebdc717fd1cb70b182fba5dc42dd4294ac8597fa23e04b702e9601292ad637",
  identity 19 "lb" .loadStore
    "129cebd7398199ce1422ebc94585919ee162b86280d16993ad4b0b0e1e2c1e80",
  identity 20 "lh" .loadStore
    "0691332a3cd4fb3b4e8d6f58b4f7ea4d76c860d657138b8d997049f57045532e",
  identity 21 "lw" .loadStore
    "5f71a5a3cdd16bf69b4b7c8db5371a7d1ba6e60c7dd5942537e6f6f08c3d2f60",
  identity 22 "lbu" .loadStore
    "6ce43657650ebd382bd55113bd5253a73b492811fbcfe0a93937e9f0d95e2a6b",
  identity 23 "lhu" .loadStore
    "6497611117cfb2e2662f36d777c5ff10f45cfb8c4fba1e880e6e5d7570862e79",
  identity 24 "sb" .loadStore
    "a888ec576c933b71e3c60a96b5ef040d942c688519f07c14fa0fcc6adcfa1213",
  identity 25 "sh" .loadStore
    "2b4c68e3d924b8fac221840d913ea14353df3d1e81f7cea231691ab68cacc456",
  identity 26 "sw" .loadStore
    "c9fd8e5aab6f0c079cbbcf896c28a0aa49ee33045fdcd727ec4c7c1d2a3cd4f7",
  identity 27 "beq" .branchEq
    "5a6adb0f4d3b792225dc5be68fa31b4cec925a871ff118083cbc715ce520113c",
  identity 28 "bne" .branchEq
    "787402ce2b3363746953984049946c6bf035d2dd762a338cfaee78fdca337a27",
  identity 29 "blt" .branchLt
    "94e53684f8c1e8ee123f92ab8e2fb0f33e6cdd7fe69b21b0418ea75375648f02",
  identity 30 "bge" .branchLt
    "b23a244a355b70ee2f5651eaeb78549a4168431c0c2399b673232407062de85f",
  identity 31 "bltu" .branchLt
    "216bf30a6ed658f1f171d73cb025f1978c569b66bd33cc7e568142baf72c3fd8",
  identity 32 "bgeu" .branchLt
    "9b67d41cb45015b6691826b09c7eaa00fcc0d77e6237d3dc1ef7415b15514c9b",
  identity 33 "jal" .jal
    "43e0f4c3a10272746ae84e195ee7290b5e13e78cb70ac370e21dd5e8679b891d",
  identity 34 "jalr" .jalr
    "410b6f2ec4f0e7db637dc4ecad3fbbe7e08e9cdb8ca83644c107a2a23dcb8a65",
  identity 35 "lui" .lui
    "90b48bf81c506fc024785727ebe33de6e98b96e8e0973bd82299de2a278e287e",
  identity 36 "auipc" .auipc
    "accba4813f2c0c3381de8b0cecc2cb44a815b496cf32e11d8688331dfad8b45d",
  identity 37 "mul" .mul
    "806a22150acdc82df7208d96ff2fb9ec5ff3ad8fd75f8f6b087f1c8f993e09d6",
  identity 38 "mulh" .mulh
    "57eac49375238359ba89eaa1854b36bef14b5211c93976739ab7e1dd71185e56",
  identity 39 "mulhsu" .mulh
    "b623312b168e8f8b6a193e524183fa1e9671def8266150a6be1176d12d0440ee",
  identity 40 "mulhu" .mulh
    "223e5dcdb0fb47153da9aad8985c200ae9a38e2f08f83ace848d11475c6ddf88",
  identity 41 "div" .div
    "681d13aee072a72e68cdb3903c76fe58a3e1b4f2e8df6722fc746024dd3314ab",
  identity 42 "divu" .div
    "882f8fe3a09b3ba780dfea6e7453bc039bff836804ff4dff774ac1edfbddeff8",
  identity 43 "rem" .div
    "5ec35248a3836ffa6265131c5e40dc0f69bd2268fb7458f25d57dcb6460b8cde",
  identity 44 "remu" .div
    "31a62c685e287fa010e6ae4bf4cd501d8ef587618a23b5901b116344a8d9de07",
  identity 45 "fence" .fence
    "3d7901704479363a7fc48613fe6953559346fc69a80b45fa252636317010aeb2"
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
