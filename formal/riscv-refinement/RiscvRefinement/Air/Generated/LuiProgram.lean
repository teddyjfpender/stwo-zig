-- GENERATED FILE. DO NOT EDIT.
-- Generator: scripts/riscv/riscv_refinement.py
-- Regenerate: python3 scripts/riscv/riscv_refinement.py generate
-- Binding: exact canonical production AIR IR v2 for LUI.

import RiscvRefinement.Air

namespace RiscvRefinement.Air.Generated

open RiscvRefinement

def luiProgramJson : String :=
  "{\"active_row\":0,\"columns\":[{\"index\":0,\"name\":\"enabler\",\"role\":\"witness\",\"type\":\"m31\",\"width\":1},{\"index\":1,\"name\":\"clock\",\"role\":\"input\",\"type\":\"m31\",\"width\":1},{\"index\":2,\"name\":\"pc\",\"role\":\"input\",\"type\":\"m31\",\"width\":1},{\"index\":3,\"name\":\"rd_addr\",\"role\":\"input\",\"type\":\"m31\",\"width\":1},{\"index\":4,\"name\":\"rd_previous_0\",\"role\":\"input\",\"type\":\"m31\",\"width\":1},{\"index\":5,\"name\":\"rd_previous_1\",\"role\":\"input\",\"type\":\"m31\",\"width\":1},{\"index\":6,\"name\":\"rd_previous_2\",\"role\":\"input\",\"type\":\"m31\",\"width\":1},{\"index\":7,\"name\":\"rd_previous_3\",\"role\":\"input\",\"type\":\"m31\",\"width\":1},{\"index\":8,\"name\":\"rd_previous_clock\",\"role\":\"input\",\"type\":\"m31\",\"width\":1},{\"index\":9,\"name\":\"rd_next_0\",\"role\":\"output\",\"type\":\"m31\",\"width\":1},{\"index\":10,\"name\":\"rd_next_1\",\"role\":\"output\",\"type\":\"m31\",\"width\":1},{\"index\":11,\"name\":\"rd_next_2\",\"role\":\"output\",\"type\":\"m31\",\"width\":1},{\"index\":12,\"name\":\"rd_next_3\",\"role\":\"output\",\"type\":\"m31\",\"width\":1},{\"index\":13,\"name\":\"imm_0\",\"role\":\"input\",\"type\":\"m31\",\"width\":1},{\"index\":14,\"name\":\"imm_1\",\"role\":\"input\",\"type\":\"m31\",\"width\":1},{\"index\":15,\"name\":\"imm_2\",\"role\":\"input\",\"type\":\"m31\",\"width\":1},{\"index\":16,\"name\":\"destination_nonzero\",\"role\":\"witness\",\"type\":\"m31\",\"width\":1},{\"index\":17,\"name\":\"destination_inverse\",\"role\":\"witness\",\"type\":\"m31\",\"width\":1}],\"content_digest\":\"9a9afa848946f2844276a306b804e551372d14815ead9664f0b4dbbc1cf4afd6\",\"events\":[{\"kind\":\"constraint\",\"ordinal\":0,\"root\":20},{\"kind\":\"constraint\",\"ordinal\":1,\"root\":22},{\"kind\":\"constraint\",\"ordinal\":2,\"root\":24},{\"kind\":\"constraint\",\"ordinal\":3,\"root\":26},{\"kind\":\"constraint\",\"ordinal\":4,\"root\":31},{\"kind\":\"constraint\",\"ordinal\":5,\"root\":33},{\"kind\":\"constraint\",\"ordinal\":6,\"root\":35},{\"kind\":\"constraint\",\"ordinal\":7,\"root\":37},{\"kind\":\"constraint\",\"ordinal\":8,\"root\":19},{\"access_ordinal\":null,\"domain\":\"program_access\",\"kind\":\"lookup\",\"liveness\":\"nonzero_numerator\",\"numerator\":50,\"ordinal\":9,\"role\":\"request\",\"table_id\":null,\"tuple\":[2,44,3,49,27]},{\"access_ordinal\":null,\"domain\":\"registers_state\",\"kind\":\"lookup\",\"liveness\":\"nonzero_numerator\",\"numerator\":50,\"ordinal\":10,\"role\":\"consume\",\"table_id\":null,\"tuple\":[2,1]},{\"access_ordinal\":null,\"domain\":\"registers_state\",\"kind\":\"lookup\",\"liveness\":\"nonzero_numerator\",\"numerator\":0,\"ordinal\":11,\"role\":\"emit\",\"table_id\":null,\"tuple\":[51,52]},{\"access_ordinal\":null,\"domain\":\"range_check_8_8_4\",\"kind\":\"lookup\",\"liveness\":\"nonzero_numerator\",\"numerator\":50,\"ordinal\":12,\"role\":\"request\",\"table_id\":\"range_check_8_8_4\",\"tuple\":[14,15,13]},{\"access_ordinal\":1,\"domain\":\"memory_access\",\"kind\":\"lookup\",\"liveness\":\"nonzero_numerator\",\"numerator\":50,\"ordinal\":13,\"role\":\"consume\",\"table_id\":null,\"tuple\":[27,3,8,4,5,6,7]},{\"access_ordinal\":1,\"domain\":\"memory_access\",\"kind\":\"lookup\",\"liveness\":\"nonzero_numerator\",\"numerator\":0,\"ordinal\":14,\"role\":\"emit\",\"table_id\":null,\"tuple\":[27,3,41,9,10,11,12]},{\"access_ordinal\":1,\"domain\":\"range_check_20\",\"kind\":\"lookup\",\"liveness\":\"nonzero_numerator\",\"numerator\":50,\"ordinal\":15,\"role\":\"request\",\"table_id\":\"range_check_20\",\"tuple\":[43]}],\"family\":\"lui\",\"field\":{\"modulus\":2147483647,\"name\":\"M31\"},\"fixed_tables\":[{\"arity\":4,\"domain\":\"bitwise\",\"id\":\"bitwise\",\"log_size\":18,\"schema_sha256\":\"7de3a5c8de009b1f2d9da74ce88f02b3705c26da488d0005d0c67b07b9a6daab\"},{\"arity\":1,\"domain\":\"range_check_20\",\"id\":\"range_check_20\",\"log_size\":20,\"schema_sha256\":\"618f993093152e26cd08fc37b4ddc942a7a7e998444ee2e34d433d42667613e0\"},{\"arity\":2,\"domain\":\"range_check_8_11\",\"id\":\"range_check_8_11\",\"log_size\":19,\"schema_sha256\":\"1fa99606e17949d62271f75ad3ecfdb68bc016dadaa1995579d8831417ab8976\"},{\"arity\":3,\"domain\":\"range_check_8_8_4\",\"id\":\"range_check_8_8_4\",\"log_size\":20,\"schema_sha256\":\"c5894ccdf667ad77987691500806fbdb7f93b91fa40672785465e41fb393e1df\"},{\"arity\":2,\"domain\":\"range_check_8_8\",\"id\":\"range_check_8_8\",\"log_size\":16,\"schema_sha256\":\"74691adaef966cf81ce717e97fc298c8272958c614327b87aee9dafea79c5102\"},{\"arity\":2,\"domain\":\"range_check_m31\",\"id\":\"range_check_m31\",\"log_size\":15,\"schema_sha256\":\"bf4f031af4d434f3d9ad028c3b8976822499b3f3cdfe81be0933e45baafd674d\"}],\"kind\":\"stwo-riscv-air-constraint-program\",\"nodes\":[{\"column\":0,\"op\":\"col\"},{\"column\":1,\"op\":\"col\"},{\"column\":2,\"op\":\"col\"},{\"column\":3,\"op\":\"col\"},{\"column\":4,\"op\":\"col\"},{\"column\":5,\"op\":\"col\"},{\"column\":6,\"op\":\"col\"},{\"column\":7,\"op\":\"col\"},{\"column\":8,\"op\":\"col\"},{\"column\":9,\"op\":\"col\"},{\"column\":10,\"op\":\"col\"},{\"column\":11,\"op\":\"col\"},{\"column\":12,\"op\":\"col\"},{\"column\":13,\"op\":\"col\"},{\"column\":14,\"op\":\"col\"},{\"column\":15,\"op\":\"col\"},{\"column\":16,\"op\":\"col\"},{\"column\":17,\"op\":\"col\"},{\"op\":\"const\",\"value\":1},{\"args\":[0,18],\"op\":\"sub\"},{\"args\":[0,19],\"op\":\"mul\"},{\"args\":[16,18],\"op\":\"sub\"},{\"args\":[16,21],\"op\":\"mul\"},{\"args\":[18,16],\"op\":\"sub\"},{\"args\":[3,23],\"op\":\"mul\"},{\"args\":[3,17],\"op\":\"mul\"},{\"args\":[25,16],\"op\":\"sub\"},{\"op\":\"const\",\"value\":0},{\"op\":\"const\",\"value\":16},{\"args\":[13,28],\"op\":\"mul\"},{\"args\":[16,27],\"op\":\"mul\"},{\"args\":[9,30],\"op\":\"sub\"},{\"args\":[16,29],\"op\":\"mul\"},{\"args\":[10,32],\"op\":\"sub\"},{\"args\":[16,14],\"op\":\"mul\"},{\"args\":[11,34],\"op\":\"sub\"},{\"args\":[16,15],\"op\":\"mul\"},{\"args\":[12,36],\"op\":\"sub\"},{\"args\":[1,18],\"op\":\"sub\"},{\"op\":\"const\",\"value\":4},{\"args\":[38,39],\"op\":\"mul\"},{\"args\":[40,18],\"op\":\"add\"},{\"args\":[41,8],\"op\":\"sub\"},{\"args\":[42,18],\"op\":\"sub\"},{\"op\":\"const\",\"value\":35},{\"args\":[14,28],\"op\":\"mul\"},{\"args\":[13,45],\"op\":\"add\"},{\"op\":\"const\",\"value\":4096},{\"args\":[15,47],\"op\":\"mul\"},{\"args\":[46,48],\"op\":\"add\"},{\"args\":[0],\"op\":\"neg\"},{\"args\":[2,39],\"op\":\"add\"},{\"args\":[1,18],\"op\":\"add\"}],\"opcode_selector\":{\"expression\":44,\"manifest_id\":35,\"mnemonic\":\"lui\"},\"projection\":{\"destination_events\":[13,14],\"next_pc\":51,\"program_event\":9,\"source_events\":[],\"state_events\":[10,11]},\"schema_version\":2,\"source_identity\":{\"builder\":\"src/frontends/riscv/rv32/air/constraint_program.zig\",\"files\":[{\"path\":\"src/frontends/riscv/air_lang/opcodes/arithmetic/typed_lui.zig\",\"sha256\":\"2a7b295eff66aa43a3bdb6319599b880f82e0806fcd4a34c43cb2812e8ab7e0d\"},{\"path\":\"src/frontends/riscv/air_lang/shared/air/extract/symbolic.zig\",\"sha256\":\"c8f54255347ad49034d88f5299ab5e51c5cc3dfab89b3f84e2326e223e43ccce\"},{\"path\":\"src/frontends/riscv/air_lang/shared/air/lookups/entry.zig\",\"sha256\":\"925623683f3b962b429aebcc172ba9b11e1f6b0528135652afc2ee80ec7265a8\"},{\"path\":\"src/frontends/riscv/air_lang/shared/air/lookups/tables/schema.zig\",\"sha256\":\"788273e0c240763e24423fa141c6218ef40aa6495bab8c5dc1182e747e1f197a\"},{\"path\":\"src/frontends/riscv/air_lang/shared/air/semantics/common.zig\",\"sha256\":\"4b43fa79a356e4f0284b0da5a838f68662c2d019ecddc3b7bdaf7090dedd9770\"},{\"path\":\"src/frontends/riscv/isa/access_clock.zig\",\"sha256\":\"6cc01e0c2fdbe92c295ce57289a1707ce9e27ca99b14c2a19732559156ad578b\"},{\"path\":\"src/frontends/riscv/isa/opcode_manifest.zig\",\"sha256\":\"bc4adb2263c2970eb82e04a564d4880eaaff4a7fd06eece16aeb46f7e97706f3\"},{\"path\":\"src/frontends/riscv/rv32/air/constraint_program.zig\",\"sha256\":\"d8b38e791d959692ca4b8345312ea04134718ad50c8f8f6d0ccc92af11f421ba\"},{\"path\":\"src/frontends/riscv/rv32/air/extract/model.zig\",\"sha256\":\"3c558a6b13093b4934952131f6846be836c8c767d479bcde80a9b53b1b459c27\"},{\"path\":\"src/frontends/riscv/rv32/air/extract/program.zig\",\"sha256\":\"dd426b0d0cc785f0d57e2828433295b500f745730144de709af797bde6c6d7de\"},{\"path\":\"src/frontends/riscv/rv32/air/extract/program_json.zig\",\"sha256\":\"e4f49232a86655d9111a50b57297f7bd8878c5186bc6d3fcc753da8980e14edf\"},{\"path\":\"src/frontends/riscv/rv32/air/lang/typed_lui_authority.zig\",\"sha256\":\"8b9d2099639cdc15fb57b149262d4a74ce54e2126f0460aab90236f90733ef68\"},{\"path\":\"src/frontends/riscv/rv32/air/lookups/opcode_entries.zig\",\"sha256\":\"b261e496a32000a6b8124829a87f30dade36abc41d9c365c37516fb53249a5f8\"},{\"path\":\"src/frontends/riscv/rv32/air/program/opcode.zig\",\"sha256\":\"de1dfd5425f8c5249441d850aed63cb5a67a304e90c8d8d7add8ed6e77fc1bb8\"},{\"path\":\"src/frontends/riscv/rv32/air/semantic_eval.zig\",\"sha256\":\"ce53bf0859fd8ca39a88525f21af8c67e1fec4135258b3fdaddcb8bec8910525\"},{\"path\":\"src/frontends/riscv/rv32/air/semantics/mod.zig\",\"sha256\":\"a6ca020ca961146815711f2705442d44e168ba03cf5995578a86327b9d76fe93\"},{\"path\":\"src/frontends/riscv/rv32/runner/trace.zig\",\"sha256\":\"42909ed46bf1e85fbe4a099365a4bc95ad8caf86a57924b553aab072f5c7d8d2\"},{\"path\":\"src/waist/core/fields/cm31.zig\",\"sha256\":\"a69ebf43415c9682d81a6f873217c1b006a28152f5a35fa6e917a6d50d9a70cf\"},{\"path\":\"src/waist/core/fields/m31.zig\",\"sha256\":\"a5d47cc1a8c57a858b943c25e63eb1561b9f994fdff36ea38517bc166ea66d73\"},{\"path\":\"src/waist/core/fields/qm31.zig\",\"sha256\":\"8568bcf8dea1d8e5477d22da74c58f6cbf6f72905a1dbca6b104f522c442c0cf\"}],\"source_closure_sha256\":\"c90b7efe7d5b2dd6c2bae2b76128ecc1fe988bdc8ab345ec2f15ced81af731fe\"}}"

def luiProgramDecodes : Bool :=
  match ConstraintProgram.decodeCanonical luiProgramJson with
  | .ok _ => true
  | .error _ => false

#guard luiProgramDecodes

private def m31 (value : Nat) : M31 :=
  M31.reduce value

def luiInactiveRow : Array M31 :=
  Array.replicate 18 0

def luiActiveRow : Array M31 :=
  #[
    m31 1, m31 8, m31 4096,
    m31 7, m31 0, m31 0, m31 0, m31 0, m31 0,
    m31 0, m31 192, m31 171, m31 222,
    m31 12, m31 171, m31 222,
    m31 1, m31 1840700269
  ]

def luiInactiveRowIsRejected : Bool :=
  match ConstraintProgram.decodeCanonical luiProgramJson with
  | .error _ => false
  | .ok program =>
    match program.eval luiInactiveRow with
    | .error _ => false
    | .ok evaluation =>
          !evaluation.rowActive &&
          !evaluation.constraintsHold &&
          evaluation.fixedLookupsHold &&
          evaluation.liveLookups.isEmpty

#guard luiInactiveRowIsRejected

def luiActiveRowEvaluates : Bool :=
  match ConstraintProgram.decodeCanonical luiProgramJson with
  | .error _ => false
  | .ok program =>
    match program.eval luiActiveRow with
    | .error _ => false
    | .ok evaluation =>
          evaluation.activeSelectorsAccepted &&
          evaluation.constraintsHold &&
          evaluation.fixedLookupsHold &&
          evaluation.liveLookups.size == 7 &&
          evaluation.projection.nextPc.toNat == 4100 &&
          evaluation.projection.programEvent.tuple.map M31.toNat ==
            #[4096, 35, 7, 912060, 0]

#guard luiActiveRowEvaluates

end RiscvRefinement.Air.Generated
