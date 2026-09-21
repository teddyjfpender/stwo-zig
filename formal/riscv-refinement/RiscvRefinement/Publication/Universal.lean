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
    "9e021d9da2d7b531a9eedbc9934cdba56d6656702bab00b2f017a29429b98f0b",
  identity 1 "sub" .baseAluReg
    "4fc8932ebbd49bb7c71498ee1e3bad197f22c902e94e08449ef2a0ce52d39aa8",
  identity 2 "sll" .shiftsReg
    "4cae60937fe8e09fe441017f90e5cf3390bf520ef7d2a757446f1fee035d667e",
  identity 3 "slt" .ltReg
    "6995fbd04b6ea51057bd16e454bf9a5485e6a92751957428d7e2dfa2c679e589",
  identity 4 "sltu" .ltReg
    "3554b1d4d1347d0995b9a6074fe93607a65d4e15aa5f27b13ff81f504cba3d77",
  identity 5 "xor" .baseAluReg
    "e18969aae35cb84f143c3233636ba021e2048ddaa40fc0768db1f6f61898797b",
  identity 6 "srl" .shiftsReg
    "1cfdc5a139758c701a1f75ef9990cef5a95aa6fede99bfe8764ae129bbf8916a",
  identity 7 "sra" .shiftsReg
    "2e67c07b6f5023a0cb590f92ae81777861fe573ce90352acae5a1df431a3fc4d",
  identity 8 "or" .baseAluReg
    "c51c256f5dcb0ba4da1440042526434a8ce8bbb4bbaab96945e0647d2a94f0f1",
  identity 9 "and" .baseAluReg
    "8e8f34c84abf62674d30f645f1d485c7543780d4a56dce6168d0a376681e7329",
  identity 10 "addi" .baseAluImm
    "d682e62f49588e6a583b2b0ab5a204d2f36fa028552bd1e49f14c8a6f15482f9",
  identity 11 "slti" .ltImm
    "1c380b057b971b9ca8a105818d9086fb95abd5fa6f7cd0ce68d841e094707a7f",
  identity 12 "sltiu" .ltImm
    "cbd04096cf5be3f3ca21a4ecf0c54d773235c54303a9dfa4e3e5b79ec7e77e9e",
  identity 13 "xori" .baseAluImm
    "f3bb8b05f3ddc73195b610e4739ef7e365f604306dc3c54122c320ede69d4085",
  identity 14 "ori" .baseAluImm
    "8b4ed2967914d8f9b89e63a6b46e6bdd2037693d80ea616af330260e643dc1a5",
  identity 15 "andi" .baseAluImm
    "96f3cf0b089e53cd206d3f0df3d017659b1b6cdee8ff5df9723e196cd4344482",
  identity 16 "slli" .shiftsImm
    "dbf794487508cd5f7514322ffdb884de6d72fd164ec6d53aa6efdd257e1556f3",
  identity 17 "srli" .shiftsImm
    "adf72a5995f59bf02d83ccf486fd1f1cc802eeb44c21283b12a4519bf2a89b5a",
  identity 18 "srai" .shiftsImm
    "7fce8d81802280ba9f6eeda4c7752d2f787e6692b71a244174527b95809fa930",
  identity 19 "lb" .loadStore
    "dc7a7abc306d0bd0473b115f4cf674efb660caf9dc90c3e900f64e5542b14876",
  identity 20 "lh" .loadStore
    "7bb6c5d2c1b8e9caf0f9adf3aa97c040cb769e80447ba80e6dbe9ef7dae9b2bc",
  identity 21 "lw" .loadStore
    "5f6a7b3e4f5aea8a79aa5b8693e8b2516412f39cee1b64b1a90c26d1a80a5b08",
  identity 22 "lbu" .loadStore
    "9ec5aa1688ea41bb12419d84dc420da34ed5c9083c063cc26291b3725958ff31",
  identity 23 "lhu" .loadStore
    "ce6fc0e203cce0a691d6d99cda40c98424f69a76a9448771f82ff12a24aa2a2e",
  identity 24 "sb" .loadStore
    "7ae3b2a6309aee6b356644d35b9c8171e0fa22ade38eb892c3f702a0cb549cda",
  identity 25 "sh" .loadStore
    "2f6f2551983cd14f16aa827a30296b08bc9a2280f66f47906c28468b9c6da976",
  identity 26 "sw" .loadStore
    "56ad34410d630f12fb7c77bc41a92f696e26b567bc90af14200c7682ee2c363f",
  identity 27 "beq" .branchEq
    "2b5a8ba55eea070af2830d3b82e156cff670659c8a9eed934508f497c0f6f03b",
  identity 28 "bne" .branchEq
    "91d42cd84064c0c5c563cb82da12f42de8f3cc66b4f510150e558955ba1aaeef",
  identity 29 "blt" .branchLt
    "650b729c9564bdd70d16b81ae08faf2720bf05d959febc0c4790085f1303bb4d",
  identity 30 "bge" .branchLt
    "ec81aa317e7627683ce4eb63c57eab230b6e01a00793b0f50d2ac7cd1396ed31",
  identity 31 "bltu" .branchLt
    "649fd37447a2775b761708ed4336d506cf98cb2873812f4e409d9b00830ea54d",
  identity 32 "bgeu" .branchLt
    "3c4703ce6468a4b7f16e29b2c93b19777595d90fccd430876f565a8f8723bef7",
  identity 33 "jal" .jal
    "b820dbd42e7e21d1d8a2d17ce7617735996e8b4ef74b8c80e7280d2f143c40ee",
  identity 34 "jalr" .jalr
    "2a025498db6e47ab9626d2e5a2e7de85d95ee1c9128e2cc47b6a3e3f77b1a190",
  identity 35 "lui" .lui
    "0ef6b1d13ec86a69b7c9b91a85ff053dcb1b7b40712ad2cbc245af783e46b898",
  identity 36 "auipc" .auipc
    "29f14971c85ac2834d11baa3514b662fac07a1ed3b7d92e545e5622a872c5c86",
  identity 37 "mul" .mul
    "f8e3bfb496d2f1b9dd686824d4204fdcdd50c03aec6a772b4d6ca797028b4aa7",
  identity 38 "mulh" .mulh
    "1936ba6ea129ccfb9cae3b90072266eaa79cdbc74ce9a30f5fb2aa12c586d897",
  identity 39 "mulhsu" .mulh
    "da6aff5839dec3f68a55fc7124a4e7275be40937fffd683965f39f6091aff4d7",
  identity 40 "mulhu" .mulh
    "658d49c78c6f04653e7f723e2376ba4a4107f291c9d777669aeaa0baf366043c",
  identity 41 "div" .div
    "718a5698045c36b83716c60cf0bd44e010ee5d17a34a3c5191957b6baed47136",
  identity 42 "divu" .div
    "149dc2d7c5d5b1715016e4c84bcf1b49f75f2202e28379d8c1a6b15af74da0c3",
  identity 43 "rem" .div
    "072ef5320bb79d1f038e288f639e84fc2ce7f0b26a09913ef7cce3d6a7004bb0",
  identity 44 "remu" .div
    "c4611e681bea26a8d14530d39e30dfce1dd7d763aa43f2d70a402328a8cd7933",
  identity 45 "fence" .fence
    "ad5aabd626f78a58cdb3d6bf26e376fe53e7ae859e0093e6406394e4dcfb5a36"
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
