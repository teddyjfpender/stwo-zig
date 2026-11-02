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
    "6920c0ac60a7eb092f45914d6d10b1540a0f8ea16768611ba9abfe0197278783",
  identity 1 "sub" .baseAluReg
    "6458243a9fc790322613f4acee931e4392fd41d03e2dcf3ce3e29aae1eedaf76",
  identity 2 "sll" .shiftsReg
    "66b01f244d222234aca69c7b938727a3b181ec1f36b4926e5f793f6a81b003fd",
  identity 3 "slt" .ltReg
    "234461efb48727cdb845ac3c002ba55f944764b5e1bb419f101b59e3b857e280",
  identity 4 "sltu" .ltReg
    "54aab4f496221b93588858d2eee08b8b15dc8752b6c689ac32daf1f5bf58b83a",
  identity 5 "xor" .baseAluReg
    "45f0c76912cb4f1620ba8a88ddbcde4e5aa6aaeaa1f1a6f0b6fa3b325f6c399a",
  identity 6 "srl" .shiftsReg
    "365fdf45268d332fb4991bea37ea8864ac757a10fb5654860435488bd0fab00d",
  identity 7 "sra" .shiftsReg
    "cc82988f1fa30d0eff8cf87c49464609cc9f66a8401c25c6cfdf8dc747ac8ea6",
  identity 8 "or" .baseAluReg
    "30489ece7f695e176edaf960b7e8ebcccab2260b875e71553886cbb8850b8250",
  identity 9 "and" .baseAluReg
    "53aa2dbc9a6818bf2d1de0130738bc3cc5edd533949a136e9819c1788b1554de",
  identity 10 "addi" .baseAluImm
    "acdfbf8f3047845af893c1d6793e208e4f88c4a0e034103d5afdcfe0104918dd",
  identity 11 "slti" .ltImm
    "4304fc6eaa7c86346f5d2e566336f50c766fef6715b961ecdddf61924a53f095",
  identity 12 "sltiu" .ltImm
    "fc03412250c88ff5bf41d784fbf41addb1a938e129f568e70bfa919ed05f172a",
  identity 13 "xori" .baseAluImm
    "6b48507f547b5f6afc1d1003fef77371378d140c776f6f321d9f6034ded35854",
  identity 14 "ori" .baseAluImm
    "73d006d7d2a3a3e5c111dd50027c29150435852dc8c70d06e47a31f6c87ea837",
  identity 15 "andi" .baseAluImm
    "772140d730f1a7b50f60d77e46f3fe0310c92ba2af8f6093c8045f71f6040507",
  identity 16 "slli" .shiftsImm
    "2c103e9229af83aca5ed190d6045853c55656dbd6885986237dd8d6017622277",
  identity 17 "srli" .shiftsImm
    "ec49d68651d8116830850dbb402a54ca77f8cbb6a525c10b89fbb6577c6758c5",
  identity 18 "srai" .shiftsImm
    "756b233d3955a42662dfa7c787ef826ec3d8b311e2f433189c1455e674d08985",
  identity 19 "lb" .loadStore
    "bea45e36b04fbef09cb567851a344ef5ec11bd4917bcf71c2333b094141a4e2e",
  identity 20 "lh" .loadStore
    "9e649e0db99fe363fc3467d83e3659a5fc48191e3bd93f3e73a192f10b0a91e3",
  identity 21 "lw" .loadStore
    "a04ab7fd6f03d442196042867f24a30335ff053ac3c348e8389fc92f5014920c",
  identity 22 "lbu" .loadStore
    "523e4b39419653c6f6b13d5aad3a19e1e326e6587c4a058876eb7ce75a9abda9",
  identity 23 "lhu" .loadStore
    "1834352fcb767d23d36c8260e1a56227bc67fb01c3a0659599464eedf40a02bf",
  identity 24 "sb" .loadStore
    "b76e80f2bd0b37569b238af0ebaa10689e2df55588451734f6176734148973b5",
  identity 25 "sh" .loadStore
    "43a488275236dc95cd15b803a8bd654f5cac361b5b767a1f7a63e904f0090cb9",
  identity 26 "sw" .loadStore
    "cf68563a7847757e789f0b801c3b7976aba70a5c74638b5d6384ae071780017f",
  identity 27 "beq" .branchEq
    "5b9e82a390c085b12da6f74358b52d23207f2cbb748d59a570c2ad59d203feb0",
  identity 28 "bne" .branchEq
    "c2c479c664d8469a51c6349fbdbd26114c487929ad319c494bee5bd566a4f4e3",
  identity 29 "blt" .branchLt
    "b6479529fcc68e894e2515f1c87cc98b68d673ab9754610d1e0b91fec14f2757",
  identity 30 "bge" .branchLt
    "7e26fc55b2a269042f36dd53df00a0b2832e954e1721fcfe34b0e93ce7831310",
  identity 31 "bltu" .branchLt
    "85e5b0c3004190b70251c11968c6652acfebc12bf8f18814444f875982e0a755",
  identity 32 "bgeu" .branchLt
    "d146d618010d31c4c541660089ff7fdc22d5f01f333f81ff2f427ee0c5c361fc",
  identity 33 "jal" .jal
    "1d7f69d06568fcc36e7fae805df2e771db067a72742dc97617e091c1b9c5bd61",
  identity 34 "jalr" .jalr
    "4d8086c91ef60133e1a6ea93de8d4eaf139fdf73ed3362702241c3df2d11628d",
  identity 35 "lui" .lui
    "70149a07e7e053183afdf4d9765eec09986ed5bee3ecc5ebbef534c40c4216c6",
  identity 36 "auipc" .auipc
    "98d2c381093a145eef860298a47c6405c43d897dd9f80ab67cbea08143a40dc2",
  identity 37 "mul" .mul
    "b4b5c89065934e24f8b030e142190f3ac1436fa1a985d860dbfc874a1d103ce6",
  identity 38 "mulh" .mulh
    "5a9f419166d61df41c244e88ebfc1223167538c58ad329fcc788b54274b5d9ba",
  identity 39 "mulhsu" .mulh
    "c8a8f59f2a0004601c71488e896ec59ee78f0666d06debccbc452a9564187b43",
  identity 40 "mulhu" .mulh
    "ce7325bf79aa0fa335f8358a7ba08ea872a0611e1c25cf67095388be41c44f79",
  identity 41 "div" .div
    "31deb3f5858ad785b5cc163ada6d774bd9fd7f0bd9b57d2212bac520681a925d",
  identity 42 "divu" .div
    "337f1fe2793e0bb64fbeb0a0782aba62633f0af8dd18a26b62f0dd5f76036fd5",
  identity 43 "rem" .div
    "6d8177d230518937f1da0c3edd75b35ad6278f14d71ebf5fd62921d4527ea2de",
  identity 44 "remu" .div
    "a03cf4949924f71438b788300db215c31afb6abd7fb8b8e407b034d72771cc62",
  identity 45 "fence" .fence
    "c6dfc26b4a7408f5e470e796e6821f96f26bfaa6d0f58532d431aaa31ec84870"
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
