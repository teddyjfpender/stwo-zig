-- GENERATED FILE. DO NOT EDIT.
-- Generator: scripts/riscv_refinement.py
-- Regenerate: python3 scripts/riscv_refinement.py generate
-- Binding: exact canonical production AIR IR v2 for LUI.

import RiscvRefinement.Air

namespace RiscvRefinement.Air.Generated

open RiscvRefinement

def luiProgramJson : String :=
  "{\"active_row\":0,\"columns\":[{\"index\":0,\"name\":\"enabler\",\"role\":\"witness\",\"type\":\"m31\",\"width\":1},{\"index\":1,\"name\":\"clock\",\"role\":\"input\",\"type\":\"m31\",\"width\":1},{\"index\":2,\"name\":\"pc\",\"role\":\"input\",\"type\":\"m31\",\"width\":1},{\"index\":3,\"name\":\"rd_addr\",\"role\":\"input\",\"type\":\"m31\",\"width\":1},{\"index\":4,\"name\":\"rd_previous_0\",\"role\":\"input\",\"type\":\"m31\",\"width\":1},{\"index\":5,\"name\":\"rd_previous_1\",\"role\":\"input\",\"type\":\"m31\",\"width\":1},{\"index\":6,\"name\":\"rd_previous_2\",\"role\":\"input\",\"type\":\"m31\",\"width\":1},{\"index\":7,\"name\":\"rd_previous_3\",\"role\":\"input\",\"type\":\"m31\",\"width\":1},{\"index\":8,\"name\":\"rd_previous_clock\",\"role\":\"input\",\"type\":\"m31\",\"width\":1},{\"index\":9,\"name\":\"rd_next_0\",\"role\":\"output\",\"type\":\"m31\",\"width\":1},{\"index\":10,\"name\":\"rd_next_1\",\"role\":\"output\",\"type\":\"m31\",\"width\":1},{\"index\":11,\"name\":\"rd_next_2\",\"role\":\"output\",\"type\":\"m31\",\"width\":1},{\"index\":12,\"name\":\"rd_next_3\",\"role\":\"output\",\"type\":\"m31\",\"width\":1},{\"index\":13,\"name\":\"imm_0\",\"role\":\"input\",\"type\":\"m31\",\"width\":1},{\"index\":14,\"name\":\"imm_1\",\"role\":\"input\",\"type\":\"m31\",\"width\":1},{\"index\":15,\"name\":\"imm_2\",\"role\":\"input\",\"type\":\"m31\",\"width\":1},{\"index\":16,\"name\":\"destination_nonzero\",\"role\":\"witness\",\"type\":\"m31\",\"width\":1},{\"index\":17,\"name\":\"destination_inverse\",\"role\":\"witness\",\"type\":\"m31\",\"width\":1}],\"content_digest\":\"85dd47cf5bb62a2d1c88f69d17154e104ac445ac2a401dba611f3483ef6d8ec3\",\"events\":[{\"kind\":\"constraint\",\"ordinal\":0,\"root\":20},{\"kind\":\"constraint\",\"ordinal\":1,\"root\":22},{\"kind\":\"constraint\",\"ordinal\":2,\"root\":24},{\"kind\":\"constraint\",\"ordinal\":3,\"root\":26},{\"kind\":\"constraint\",\"ordinal\":4,\"root\":31},{\"kind\":\"constraint\",\"ordinal\":5,\"root\":33},{\"kind\":\"constraint\",\"ordinal\":6,\"root\":35},{\"kind\":\"constraint\",\"ordinal\":7,\"root\":37},{\"kind\":\"constraint\",\"ordinal\":8,\"root\":19},{\"access_ordinal\":null,\"domain\":\"program_access\",\"kind\":\"lookup\",\"liveness\":\"nonzero_numerator\",\"numerator\":50,\"ordinal\":9,\"role\":\"request\",\"table_id\":null,\"tuple\":[2,44,3,49,27]},{\"access_ordinal\":null,\"domain\":\"registers_state\",\"kind\":\"lookup\",\"liveness\":\"nonzero_numerator\",\"numerator\":50,\"ordinal\":10,\"role\":\"consume\",\"table_id\":null,\"tuple\":[2,1]},{\"access_ordinal\":null,\"domain\":\"registers_state\",\"kind\":\"lookup\",\"liveness\":\"nonzero_numerator\",\"numerator\":0,\"ordinal\":11,\"role\":\"emit\",\"table_id\":null,\"tuple\":[51,52]},{\"access_ordinal\":null,\"domain\":\"range_check_8_8_4\",\"kind\":\"lookup\",\"liveness\":\"nonzero_numerator\",\"numerator\":50,\"ordinal\":12,\"role\":\"request\",\"table_id\":\"range_check_8_8_4\",\"tuple\":[14,15,13]},{\"access_ordinal\":1,\"domain\":\"memory_access\",\"kind\":\"lookup\",\"liveness\":\"nonzero_numerator\",\"numerator\":50,\"ordinal\":13,\"role\":\"consume\",\"table_id\":null,\"tuple\":[27,3,8,4,5,6,7]},{\"access_ordinal\":1,\"domain\":\"memory_access\",\"kind\":\"lookup\",\"liveness\":\"nonzero_numerator\",\"numerator\":0,\"ordinal\":14,\"role\":\"emit\",\"table_id\":null,\"tuple\":[27,3,41,9,10,11,12]},{\"access_ordinal\":1,\"domain\":\"range_check_20\",\"kind\":\"lookup\",\"liveness\":\"nonzero_numerator\",\"numerator\":50,\"ordinal\":15,\"role\":\"request\",\"table_id\":\"range_check_20\",\"tuple\":[43]}],\"family\":\"lui\",\"field\":{\"modulus\":2147483647,\"name\":\"M31\"},\"fixed_tables\":[{\"arity\":4,\"domain\":\"bitwise\",\"id\":\"bitwise\",\"log_size\":18,\"schema_sha256\":\"7de3a5c8de009b1f2d9da74ce88f02b3705c26da488d0005d0c67b07b9a6daab\"},{\"arity\":1,\"domain\":\"range_check_20\",\"id\":\"range_check_20\",\"log_size\":20,\"schema_sha256\":\"618f993093152e26cd08fc37b4ddc942a7a7e998444ee2e34d433d42667613e0\"},{\"arity\":2,\"domain\":\"range_check_8_11\",\"id\":\"range_check_8_11\",\"log_size\":19,\"schema_sha256\":\"1fa99606e17949d62271f75ad3ecfdb68bc016dadaa1995579d8831417ab8976\"},{\"arity\":3,\"domain\":\"range_check_8_8_4\",\"id\":\"range_check_8_8_4\",\"log_size\":20,\"schema_sha256\":\"c5894ccdf667ad77987691500806fbdb7f93b91fa40672785465e41fb393e1df\"},{\"arity\":2,\"domain\":\"range_check_8_8\",\"id\":\"range_check_8_8\",\"log_size\":16,\"schema_sha256\":\"74691adaef966cf81ce717e97fc298c8272958c614327b87aee9dafea79c5102\"},{\"arity\":2,\"domain\":\"range_check_m31\",\"id\":\"range_check_m31\",\"log_size\":15,\"schema_sha256\":\"bf4f031af4d434f3d9ad028c3b8976822499b3f3cdfe81be0933e45baafd674d\"}],\"kind\":\"stwo-riscv-air-constraint-program\",\"nodes\":[{\"column\":0,\"op\":\"col\"},{\"column\":1,\"op\":\"col\"},{\"column\":2,\"op\":\"col\"},{\"column\":3,\"op\":\"col\"},{\"column\":4,\"op\":\"col\"},{\"column\":5,\"op\":\"col\"},{\"column\":6,\"op\":\"col\"},{\"column\":7,\"op\":\"col\"},{\"column\":8,\"op\":\"col\"},{\"column\":9,\"op\":\"col\"},{\"column\":10,\"op\":\"col\"},{\"column\":11,\"op\":\"col\"},{\"column\":12,\"op\":\"col\"},{\"column\":13,\"op\":\"col\"},{\"column\":14,\"op\":\"col\"},{\"column\":15,\"op\":\"col\"},{\"column\":16,\"op\":\"col\"},{\"column\":17,\"op\":\"col\"},{\"op\":\"const\",\"value\":1},{\"args\":[0,18],\"op\":\"sub\"},{\"args\":[0,19],\"op\":\"mul\"},{\"args\":[16,18],\"op\":\"sub\"},{\"args\":[16,21],\"op\":\"mul\"},{\"args\":[18,16],\"op\":\"sub\"},{\"args\":[3,23],\"op\":\"mul\"},{\"args\":[3,17],\"op\":\"mul\"},{\"args\":[25,16],\"op\":\"sub\"},{\"op\":\"const\",\"value\":0},{\"op\":\"const\",\"value\":16},{\"args\":[13,28],\"op\":\"mul\"},{\"args\":[16,27],\"op\":\"mul\"},{\"args\":[9,30],\"op\":\"sub\"},{\"args\":[16,29],\"op\":\"mul\"},{\"args\":[10,32],\"op\":\"sub\"},{\"args\":[16,14],\"op\":\"mul\"},{\"args\":[11,34],\"op\":\"sub\"},{\"args\":[16,15],\"op\":\"mul\"},{\"args\":[12,36],\"op\":\"sub\"},{\"args\":[1,18],\"op\":\"sub\"},{\"op\":\"const\",\"value\":4},{\"args\":[38,39],\"op\":\"mul\"},{\"args\":[40,18],\"op\":\"add\"},{\"args\":[41,8],\"op\":\"sub\"},{\"args\":[42,18],\"op\":\"sub\"},{\"op\":\"const\",\"value\":35},{\"args\":[14,28],\"op\":\"mul\"},{\"args\":[13,45],\"op\":\"add\"},{\"op\":\"const\",\"value\":4096},{\"args\":[15,47],\"op\":\"mul\"},{\"args\":[46,48],\"op\":\"add\"},{\"args\":[0],\"op\":\"neg\"},{\"args\":[2,39],\"op\":\"add\"},{\"args\":[1,18],\"op\":\"add\"}],\"opcode_selector\":{\"expression\":44,\"manifest_id\":35,\"mnemonic\":\"lui\"},\"projection\":{\"destination_events\":[13,14],\"next_pc\":51,\"program_event\":9,\"source_events\":[],\"state_events\":[10,11]},\"schema_version\":2,\"source_identity\":{\"builder\":\"src/frontends/riscv/air/constraint_program.zig\",\"files\":[{\"path\":\"src/core/fields/cm31.zig\",\"sha256\":\"4b7a14c91fba7c467f92e924ce90c7230a22d08329591e3d5b8874d862b31288\"},{\"path\":\"src/core/fields/m31.zig\",\"sha256\":\"b4cd73532f8535bf59840bcf34b9392f4868b06ab231aa1955fb5de2e1400b38\"},{\"path\":\"src/core/fields/qm31.zig\",\"sha256\":\"a60c2a5a6f10bf91b1bfab41a526e41b589d0d1d83275e0516cf68b7228be931\"},{\"path\":\"src/frontends/riscv/access_clock.zig\",\"sha256\":\"6cc01e0c2fdbe92c295ce57289a1707ce9e27ca99b14c2a19732559156ad578b\"},{\"path\":\"src/frontends/riscv/air/constraint_program.zig\",\"sha256\":\"7fba715f5f185c414c0af0ebf6eb2a555535c2d546ee1bf1824cdcfc2877594b\"},{\"path\":\"src/frontends/riscv/air/extract/model.zig\",\"sha256\":\"cd2174e0d94e4175ef65f2394762189ca15c7ad90c03eb24c304eabb07329ffe\"},{\"path\":\"src/frontends/riscv/air/extract/program.zig\",\"sha256\":\"05bd88460a92057bf1cd52b1e88436c4b5b8d3ac03f8221c6cf31a7da6b11a63\"},{\"path\":\"src/frontends/riscv/air/extract/program_json.zig\",\"sha256\":\"ef3be813dd1cd80a6ddc446b0c7b6d3814b3fd24a14326bdf47d71ea79918ee1\"},{\"path\":\"src/frontends/riscv/air/extract/symbolic.zig\",\"sha256\":\"c8f54255347ad49034d88f5299ab5e51c5cc3dfab89b3f84e2326e223e43ccce\"},{\"path\":\"src/frontends/riscv/air/lang/typed_lui.zig\",\"sha256\":\"406f8dbc4db25ea54dc3c4607c323194fa7b9d7393893cedf042ab4ae9cd4f62\"},{\"path\":\"src/frontends/riscv/air/lang/typed_lui_authority.zig\",\"sha256\":\"90c8788b1f047019356c08a853a5a705443dd4220a60e196e096dfad751456fd\"},{\"path\":\"src/frontends/riscv/air/lookups/entry.zig\",\"sha256\":\"550d5ca13ce830fe968f6bb250b165019c06b46dae074c4b22fb1456a8c72564\"},{\"path\":\"src/frontends/riscv/air/lookups/opcode_entries.zig\",\"sha256\":\"4f424e6ac7bc93f96b06d7ecd1d9073974db9dc15a766ed7956a09bcdf370df4\"},{\"path\":\"src/frontends/riscv/air/lookups/tables/schema.zig\",\"sha256\":\"788273e0c240763e24423fa141c6218ef40aa6495bab8c5dc1182e747e1f197a\"},{\"path\":\"src/frontends/riscv/air/program/opcode.zig\",\"sha256\":\"22687658ba7301e0b0eb0bd654510f6641f56aae0587b5cb92394fa7ecac9c7c\"},{\"path\":\"src/frontends/riscv/air/semantic_eval.zig\",\"sha256\":\"a919b3b3f2b2e1a91d09e74821815b5c2551e069fbb6e41c18afbbd0c28ada78\"},{\"path\":\"src/frontends/riscv/air/semantics/common.zig\",\"sha256\":\"5950815ac9d453228437003881c7b87b49f4bb9599e59e6875bd3f678a439dae\"},{\"path\":\"src/frontends/riscv/air/semantics/mod.zig\",\"sha256\":\"d027827483bc0cb80fb43b04232ac33f2868b3556e799a0892afdfd80eb4d4e8\"},{\"path\":\"src/frontends/riscv/opcode_manifest.zig\",\"sha256\":\"bc4adb2263c2970eb82e04a564d4880eaaff4a7fd06eece16aeb46f7e97706f3\"},{\"path\":\"src/frontends/riscv/runner/trace.zig\",\"sha256\":\"535c3ea41cdad1197e9143af938785066f1c96a10b11c163885e16750769c043\"}],\"source_closure_sha256\":\"4dd444edbf8a3611e517b12df88e630dcdf0998d14e025aed859dc741f2a3399\"}}"

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
