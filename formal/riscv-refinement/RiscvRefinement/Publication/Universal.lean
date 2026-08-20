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
    "ea14d4b4780fc05fa5cb70cd01e1241a7e113b0b23514160a0be0501ae54907a",
  identity 1 "sub" .baseAluReg
    "ce4f42b6988f71ee38d429dccbd0ead76b5c7138cec6f3967b997bdc69a1b1c7",
  identity 2 "sll" .shiftsReg
    "f5786421f55f1955257621a6ac0941496f20e9ad3a13c8c7a822f33b30bf6f77",
  identity 3 "slt" .ltReg
    "801ad0322cbabc01b301ba9a85000ee3eea6c8cf4c4ba178d9c917a0fe50a1d8",
  identity 4 "sltu" .ltReg
    "63f345598eb53045513ddf150afa0e3635dd423ac2600cfdb3d8214a3731a881",
  identity 5 "xor" .baseAluReg
    "3767b55b71f6ad2d047a5b418f45eab9a321d2dfc01957baacf00378acd6727d",
  identity 6 "srl" .shiftsReg
    "e9c5b81fa599d9deb21ffd6eab569d539ef9e01cc77cb06b23b6f5a07cb094d3",
  identity 7 "sra" .shiftsReg
    "78be33bc15d8232c7ad003236b4cc8dfbf77e277cf9590d9aa4a8f430ae02cc9",
  identity 8 "or" .baseAluReg
    "4e167495d33c5d70f796cfceb64c450bd7fcf812bf38a22e633aae42010c4409",
  identity 9 "and" .baseAluReg
    "04836589eb3d5a4777294fe5acc5c9151a0da987d647286dd5f795fcf94158d5",
  identity 10 "addi" .baseAluImm
    "d7051000f7bb17bd29e92ee742d861901e3329d7954939a3077b5fa708ab431e",
  identity 11 "slti" .ltImm
    "26a94ffe1ccc4b4f352580d8b012d725478e563852861a056290a4043ee894bf",
  identity 12 "sltiu" .ltImm
    "a12098569401aa6c1a3697f57d49874b9bac36284e49cc0ec1253ec6dc069ad6",
  identity 13 "xori" .baseAluImm
    "3d03015aea96693e90e43896efd8ea0a16f8224726eec390b283d078f1dd6464",
  identity 14 "ori" .baseAluImm
    "1920db3dff2e8d971f9e7870a2274b30565def4ef1f15bd1a0446cace804f335",
  identity 15 "andi" .baseAluImm
    "8784d98dc96d39ca2244dda1c1363f4b47a187302dfe873d1f378cba83c56125",
  identity 16 "slli" .shiftsImm
    "5931abd42cebfc014314ac6e8644e119aabef012e1a0e47a447fcb5fd1fc09fc",
  identity 17 "srli" .shiftsImm
    "ada35113fecf52cd9b09882722abdaeba6e25c5fd2f3aa6938bf2c065b7f36c7",
  identity 18 "srai" .shiftsImm
    "b4d6c1ca8f1d177dc7f3e9a5b0f8923a60ee95255f582cf50a1cee670afb7784",
  identity 19 "lb" .loadStore
    "8c63862acc341a4dca936e7fc5ae98a46bd38ed87a616b8e070d38bff91d5fab",
  identity 20 "lh" .loadStore
    "21f11b9f8b0a1146a0f221354106a6322f2ccb0a233975cedfc944715e902a73",
  identity 21 "lw" .loadStore
    "3cb600a3970cb736e5f5e85afd21d4a1b902f0b52d0204114f6b24620a00f6ee",
  identity 22 "lbu" .loadStore
    "0b859fab41ce88f1732b73352065bdc6eba0fac801952922a021c35dd2c8bdba",
  identity 23 "lhu" .loadStore
    "169f16b00cf6ec7bd61c6f38d810b6c19f9b5c35a6205253402eb02349a68605",
  identity 24 "sb" .loadStore
    "f309fb7651fd9dea9f888472d89d275edb5809aa4c64994fe3dd35a98f75618d",
  identity 25 "sh" .loadStore
    "89ba7d9e219f73ab732b68e2e7f96cfe324499dd76157631c41ee110633a6d95",
  identity 26 "sw" .loadStore
    "41732b22881b3cde4811eaaa9c36aebc3749bed250a5d9bb799cc0ee4ca3e0d2",
  identity 27 "beq" .branchEq
    "a9bc0a8b418c545433748c90bdccf808fe1b3e9f737246f01e64589995a21448",
  identity 28 "bne" .branchEq
    "903171124e207468a9e786821a78a0767cb5e1152a4acf10ec7f4466f30a619f",
  identity 29 "blt" .branchLt
    "2a87896db896f0cbc72938a33927684a7d4f0accf88734325c91cbc49092afb2",
  identity 30 "bge" .branchLt
    "a5a3fc32933c7a30063f648723fc2d24c2ad1457906017a9a398bfb251592237",
  identity 31 "bltu" .branchLt
    "480b643fa15b939ffaa251b0a86d600ceccb3e6fdd4669344926627105b1ff02",
  identity 32 "bgeu" .branchLt
    "cd5b083188ed23d2361b86417ed89d46495c216a385d429a16527a066e35b270",
  identity 33 "jal" .jal
    "7f83bbf2b8f98780308b83d19c586cb38d79c4fa7296110bce5c4e283938357e",
  identity 34 "jalr" .jalr
    "328e56d97ca4b3aed03327c696359d2067be66bfc3e42dea9fdbfcf81031824e",
  identity 35 "lui" .lui
    "cad1626eb4d007bdcabd11478305e2d00de93acaa321e1d0f0e7ffedd319b11b",
  identity 36 "auipc" .auipc
    "fac776de5445a716502c679cf96970c983e0ced2a79d399ec58a537de34be4e4",
  identity 37 "mul" .mul
    "7ff4f69a150823fa346fc5bb725a7b25387c8a9ba06aa08b52fe8b69a87f740c",
  identity 38 "mulh" .mulh
    "4539a77168233c6fffbbc45431384d088ad8315e3ac28919f218efce10a40778",
  identity 39 "mulhsu" .mulh
    "45a50ef65067b7a25d56349a808292825a115c1f2efdbf0c10dc0a267299d204",
  identity 40 "mulhu" .mulh
    "de5771dac745369dc50abd016e65aa0af9fd3c76eeec152672d68ebbf40af6fe",
  identity 41 "div" .div
    "3578197a291d77a20c0cf83b2a9ce56fc0b1b215202f1e1a4f0aaed459a745db",
  identity 42 "divu" .div
    "001ccdea48c186c876a8dce9e6b1360981d6fc385c76e3f5f0c86e918f014f87",
  identity 43 "rem" .div
    "1861fc303d92601104effcd0380f26c53d82053a4275a1bdb345b152369e20d8",
  identity 44 "remu" .div
    "9a4b272cf1dce095ebdd30d2658c3cacb58f01b01f0aa002361ab5b1c351c419",
  identity 45 "fence" .fence
    "55b887ab4abf5d7e6a3b159a1ffdb5a1641622e4e24dfd5e3cda6d5c4b50a7a3"
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
