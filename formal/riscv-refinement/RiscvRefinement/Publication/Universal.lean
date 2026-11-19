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
    "39f8e38209c5e6a623cb4ebd837bedf5ae7d6c34ff673d61f152583fff073a76",
  identity 1 "sub" .baseAluReg
    "2ea97bdf33d16bb8bd11517fee848a2cdd3e3918ae3432ef6f8b3bf7e3774aed",
  identity 2 "sll" .shiftsReg
    "bc13e15f4c2d50df2cab0350619b79df62fc6d7f06093cc240fb20c8eb5f1239",
  identity 3 "slt" .ltReg
    "efbe516d1aef15388d754a6518ff5fda4240290caa909c7a939468e0a5889a39",
  identity 4 "sltu" .ltReg
    "c5ca04974648ad162561e361d0f7ec4c200c0b51c1fc64b4456f016288af7b6e",
  identity 5 "xor" .baseAluReg
    "895453e539f1d71e2a8eab319fdc6975135f5d44d4a30f5725d0e3b3db37e78c",
  identity 6 "srl" .shiftsReg
    "08db69a47163188066c3096cc7dc112c359dc04efe775ee1aa4a256d7a17658e",
  identity 7 "sra" .shiftsReg
    "baa418efbac0b671d149b9ad2e0003454c0d0c793817265b3d19aca52859b532",
  identity 8 "or" .baseAluReg
    "0aefc21cfac743adacc18b754365ec717c9ae02cfe8e07cce1be8e37c2c31a26",
  identity 9 "and" .baseAluReg
    "5e009788cb1bcc725a177851b84c184d4ca4fbd665684757de7e2169f734b74d",
  identity 10 "addi" .baseAluImm
    "728340538f1c45ce53ba11428fe3064670126e60b8cd399864fff174dcb3a502",
  identity 11 "slti" .ltImm
    "8367a8d0fb6671d9a58d2c8eb1c15079ba1d2b13d96ad6abe190476e5f05b298",
  identity 12 "sltiu" .ltImm
    "bb54e707f4c3a809c0404ddd80c03487c06b1b191e90cbb27a433b10d8ab83ba",
  identity 13 "xori" .baseAluImm
    "f99178abd4283db2c04c1c3f8d20150491b390731341380390c4f808a433f66d",
  identity 14 "ori" .baseAluImm
    "ff8d0f7556e8ac3065f458db684321b75b9bc0bc5491f36b609119410d792ccb",
  identity 15 "andi" .baseAluImm
    "d624f052edb6809c4fdebfe77e9f105d3efc7dd33e78c1f05167ca07bb6cee89",
  identity 16 "slli" .shiftsImm
    "14709d74f3f2a572766437fc413223a5e505a556de341b884b5bc5b8aeb785e7",
  identity 17 "srli" .shiftsImm
    "f42bc078fd9a031a6ad89373e19b2b7a0241c4b14c17b2296ddfe4f02841d0d1",
  identity 18 "srai" .shiftsImm
    "e4f9311c68dbfb04dd018b8618ed41da514b05b71e9b66178d0e0c52cbdf8026",
  identity 19 "lb" .loadStore
    "97dcbbd08f25e4202fc51cb87da67997c445ec3db500faa71d7d30ff506b712f",
  identity 20 "lh" .loadStore
    "729903ddd58141e4d0375bf7490be0ee39c40462631dbf7c760ed056a1a9a58f",
  identity 21 "lw" .loadStore
    "40a21fe3676e68217cb56663a379179ee55d62911d8f7992cf414852e9ecd972",
  identity 22 "lbu" .loadStore
    "443b2cb0d5fe6bd737766814f124aa33dbc868a6ae08578306e3825267927752",
  identity 23 "lhu" .loadStore
    "973a35f826e4e91e7b3303b1f8a93abd4598357f011a8f80fb2b3684115433cf",
  identity 24 "sb" .loadStore
    "0299ec168df9bfe14215f7e30f9a4e304ddfaad1d29c7b6d6fb02182450a389b",
  identity 25 "sh" .loadStore
    "301da21b74688124f75af0cdcc135ce1cff8fcf372a99fa7b406abc913e1dbeb",
  identity 26 "sw" .loadStore
    "1f5091a4a65928ec1bf0e0a4a67cecc6227c24a726080a8a0fca249831e122e8",
  identity 27 "beq" .branchEq
    "7f2065e5bd8371860fa08a162c9eaf91bd2f7ad89b84f688eb76e4f125e077cf",
  identity 28 "bne" .branchEq
    "77ba917b660032e13147da3d016abd0d1fc684e62403fffb170ed70b337d37de",
  identity 29 "blt" .branchLt
    "78c5d188694f41001699aa94e552a3d8f381d2ef67f1fa0ed70a8c2a6167b55a",
  identity 30 "bge" .branchLt
    "0998dd92767f5251d44890712c57c1d20187216457a5c43140d474e00808d6dd",
  identity 31 "bltu" .branchLt
    "5f75426baf42ef08498e61653d49cb4571a0bb616f8654572ef684ec40d07afc",
  identity 32 "bgeu" .branchLt
    "c8f779b90e2d917f739beda8c41c0f86e33875e854a870891cbb75c1af3fecd9",
  identity 33 "jal" .jal
    "e2c19a64b02cd45917a2aef16d9910b3ebffeaca403c6df6e8b9cc6d35ffb715",
  identity 34 "jalr" .jalr
    "5a9f0623bc350e0af5fe2263bf195f7c0bf7d73ac30cca1ca492893b7f6ccfcd",
  identity 35 "lui" .lui
    "9a9afa848946f2844276a306b804e551372d14815ead9664f0b4dbbc1cf4afd6",
  identity 36 "auipc" .auipc
    "7345bcf6bb93718c8bb10fd92c1aeaa290595ade84f3cfae2ac5ad8df7f28b9f",
  identity 37 "mul" .mul
    "bd98d85178387128bf92d13256dbc9b9d566603a9f01d98afe5595f9b6128af1",
  identity 38 "mulh" .mulh
    "e9bd557b3fca9404a06e82bc03372ab5e70e6194f6fb25956e30f41d473ac407",
  identity 39 "mulhsu" .mulh
    "ea4965cff6c6b6cc771428e6d94c35f98e7057cc9e2cb6c11061123e41c87053",
  identity 40 "mulhu" .mulh
    "1548ad0de15a7c33b62cca7376ab33a50eefd2fed93f8ba76ca95cb59e3fb6ba",
  identity 41 "div" .div
    "463a45a851035ee147e3f7008ca20d052b94e4df9585a8c5d6cfd500edebfdcb",
  identity 42 "divu" .div
    "2632279202c24d9cb864b232e84eadc96ddf3ffe3c61ffdeb699dcafa0b2cb2f",
  identity 43 "rem" .div
    "2917825ce5b62418b0a2bd3fd63771909078c7bf4b91bace1f9dd442f7ec5cd0",
  identity 44 "remu" .div
    "80e4869e78992541e565403a082bf59eb664d00edeb99b0de0c2bf2d15280347",
  identity 45 "fence" .fence
    "46bc2be34283e0fb31eb4f8fde524e2c32ef5aec7ab60ac5c33076bcc0331541"
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
