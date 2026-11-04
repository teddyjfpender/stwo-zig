## canon-native (branch codex/rv64-m5-canon-native) — native class keys, native VK table, native protocol version m5-chi-chain/v1

Published 2026-11-04 by stream canon-native. Status: **v1 FROZEN for canon-vk / rootverify to build against**; changes only by a
new `/v2` tag in this section. Executable spec: `scripts/rv64_m5_canon_native_ref.py` (Python, hashlib only). Golden vectors:
`vectors/rv64-m5/canon-native-v1-vectors.json`. Zig: `src/integrations/riscv_cpu/word16_global_execution/ethereum/canon_native.zig`
(its tests pin the same vectors byte for byte). Binding argument: `design/riscv-proving-stack/rv64-m5-binding.md` sec. 3.3, 5.1, 9.3(4).

### 0. Word/hash rule (all of this section)
- `H(tag, words) = Blake2s-256( Blake2s-256(ASCII tag) || LE32(words) )`. The 32-byte tag digest is 8 constant words in-circuit.
- Every message is a fixed-length list of u32 words **for a fixed class**: u64 = `(lo, hi)`; digest = 8 words = LE u32 of its 32
  bytes; optional log = `0` when absent (admitted logs are >= 5); OM31 value = 8 coordinates, each checked `< p` before hashing.
- Tags (all distinct): `rv64-m5-class-key/v1`, `rv64-m5-native-structure/v1`, `rv64-m5-native-vk/v1`, `rv64-m5-tnat-leaf/v1`,
  `rv64-m5-tnat-empty/v1`, `rv64-m5-merkle-node/v1`, `rv64-m5-tnat-header/v1`, `rv64-m5-native-version/v1`, `rv64-m5-state/v1`,
  `rv64-m5-stmt/v1`, `rv64-m5-rho/v1`, `rv64-m5-chain-iv/v1`, `rv64-m5-seg`, `rv64-m5-chi`. Leaf, empty and node tags differ
  (checklist 12).

### 1. Families (u32 id) and rungs
| id | family | notes |
|---:|---|---|
| 0 | `cpu_first` | first CPU segment of a block (carries INIT until `mb` lands) |
| 1 | `cpu_middle` | |
| 2 | `cpu_last` | last CPU segment (carries TEARDOWN until `mb` lands) |
| 3 | `cpu_single` | a block with exactly one CPU segment |
| 16+f | `truth_<f>` | f = `services/types.zig Family` (keccak 0, add 1, double 2, sha256 3, arith256_mod 4, bn254_g1_add 5, bn254_g1_double 6, bn254_fp2_mul 7, bls12_381_fp2_mul 8, arith384_mont 9, bls12_381_g1_add 10, bls12_381_g1_double 11) |
| 32 | `mb` | memory-boundary family (binding note 5.1); id and stmt encoding frozen here, native AIR split pending |

- `rung` = u32 index `0..R-1`, ascending in size. `R = 3` (kill rule: `R = 4` if the cells-weighted tax > 40 %; see section 6).
- A class's **rung vector** is the component -> log map of that (family, rung): CPU components = every `Geometry` log
  (`cpu_log ... terminal_log`, tails as optional logs) plus every bridge log (`bridge.<name>`); a truth = `(logs[0], logs[1])`.
  Component ids: index in `CPU_COMPONENTS` / `TRUTH_COMPONENTS` of the reference script (= `canon_native.zig`), frozen with v1: CPU `cpu_log, alu_log, alu_tail_log, binary_log, binary_tail_log, shift_log, shift_tail_log, jalr_log, division_log, multiplication_log, ls_log, ls_tail_log, boundary_log, initial_log, terminal_log` (0-14), then `bridge.` + keccak, add, double, sha256, arith256_mod, bn254_g1_add, bn254_g1_double, bn254_fp2_mul, bls12_381_fp2_mul, arith384_mont, bls12_381_g1_add, bls12_381_g1_double, bulk.{desc,copy,set,ucopy,cdesc,cmp,jdesc,jscan,jtab}, sponge.{call,perm}, ls_dword, ls_dword_tail, zbb (15-40); truth `main, aux` (0-1).
- `structure(f, r) = H(structure, [f, r, n, (comp_id, log)*n])`, components sorted by id. This is the S^nat summary digest.
- `rung_table_id = H(structure, [0xFFFFFFFF, n_fam, (f, n_rungs, structure(f, r)*)* ])`, families ascending.

### 2. Class key (ArtifactStore key of one native class)
```
ClassKey  = { family: u32, rung: u32, profile_identity: [32]u8, image: [32]u8, rung_table_id: [32]u8 }
class_key = H(class-key, [family, rung, profile(8), image(8), rung_table_id(8)])
```
- `profile_identity` = the native profile identity mixed into the native channel (`W.Candidate.profileIdentity`, today
  `conjectured128_b2_q108_p20_fold4`); `image` = program identity (ELF + ROM authority, `materials.program.identity`).
- ArtifactStore layout (M4 store, one file per class): `<store>/m5-native/<hex(image)[0:16]>/<hex(class_key)>.fixed` holding
  the M4 `setup_cache.zig` artifact (header + VK section + bulk). Install builds every class of the rung table once
  (`setup_install_s`, reported separately); a request only looks classes up. Receivers never read the store.

### 3. Native VK and the native VK table T_nat
```
V^nat(f,r) = { suite[32], fixed_identity[32], fixed_root[32], profile_identity[32], structure(f,r)[32] }
vkhash     = H(native-vk, [f, r, suite(8), fixed_identity(8), fixed_root(8), profile_identity(8), structure(8)])
leaf_i     = H(tnat-leaf, [i, f, r, vkhash(8)])          i = position of (f, r) in canonical order
empty_i    = H(tnat-empty, [i])                          i in [n, 2^D)
node       = H(merkle-node, [left(8), right(8)])
D          = max(1, ceil(log2 n))   (constant per table; path length is exactly D)
T_nat      = root;  header = H(tnat-header, [1, D, n, image(8), profile(8), rung_table_id(8), T_nat(8)])
```
- Canonical order: families ascending by id, rungs ascending. The index of (f, r) is a **circuit constant** of `R_leaf[f, r]`.
- `fixed_identity`/`fixed_root`: the candidate FIXED key of that class (`fixed_authority.zig Binding.fixed_identity/fixed_root`);
  `suite` = `Suite.identity()`.
- Path: siblings bottom-up; bit `j` of `i` = 0 means the running hash is the left child at level `j`.
- **VK table file** (`native-vk-table.json`, written by `derive-vk-tables` and by install; byte-reproducible):
  `{"schema":"rv64-m5-native-vk-table/v1","version":"rv64-m5-native-chi-chain/v1","image":hex,"profile_identity":hex,
  "rung_table_id":hex,"rungs":R,"depth":D,"count":n,"root":hex,"header":hex,
  "entries":[{"index","family","family_name","rung","rung_vector":{comp_name:log|null},"class_key","suite","fixed_identity",
  "fixed_root","profile_identity","structure","vkhash","leaf"}]}` (hex = lowercase, no prefix; entries in index order).

### 4. Native protocol version `rv64-m5-native-chi-chain/v1`
`version = H(native-version, [1, LOCAL_RELATIONS=10, GLOBAL_RELATIONS=3, R, 32])` — carries the `LOCAL_RELATIONS 9 -> 10`
identity bump of `rv64-m7-profiles.md` 2.1 (the native candidate identity bump itself is profiles' file; see integration notes).

**Machine state** (`s_in`, `s_out`, 8 words in `NS`): `state = H(state, [pc(2), regs[0..32](2 each), halted])` = 67 words.
Non-CPU families assert `s_out = s_in` (binding F3).

**stmt_k** (the per-segment request; every field is checked in-circuit by binding 3.2(7)):
```
cpu  : H(stmt, [1, k, cpu_ordinal, steps_in(2), steps, ls_count, ls_dword, calls[12], first_ids[12],
                sponge.calls, sponge.perms, sponge.first_id, bulk[8], mass.ram(2), mass.kio(2), mass.wire(2), relations, legacy(8)])
truth: H(stmt, [2, k, family, first_id, calls, logs[0], logs[1], mass.ram(2), mass.kio(2), mass.wire(2), relations, legacy(8)])
mb   : H(stmt, [3, k, chunk, cells, first_addr(2), last_addr(2), prev_last_addr(2), image_commit(8), init_digest(8),
                term_digest(8), mass.ram(2)])
```
`bulk[8]` = (calls, copy_words, set_words, ucopy_rows, cmp_calls, cmp_words, jump_calls, jump_rows); `relations` = ram | kio<<1 |
wire<<2; `cpu_ordinal` = epoch (CPU-segment counter, 1-based); `legacy` = today's worker statement digest
(`cpuStatementWithAuthority` / truth statement), which binds geometry, bridges, config and FIXED identity exactly as the
native verifier does today.

**rho_k** (every stage-one commitment of segment k = today's manifest entry):
`H(rho, [main(8), local_present, local_digest(8) or 0^8, n_inst, (n_vals, om31(8)*)* ])` — the instance roster is a class
constant, so the length is constant per class.

**Chain and chi** (binding 3.3; replaces today's flat `gkr_local/manifest.zig emitCanonical` digest):
```
m_0     = IV = H(chain-iv, version(8))
m_{k+1} = H(seg, [m_k(8), k, f, r, vkhash(8), stmt_k(8), s_in(8), s_out(8), rho_k(8)])     k = 0..kappa-1, index order
chi     = H(chi, [stmt(8), m_kappa(8)])                 stmt = block statement digest
shared  = manifest.drawShared(chi)                      (unchanged Om31 draw of RAM/KIO/Wire challenges from a 32-byte digest)
```
The global claims `c_k` are computed after chi and are NOT in the chain (binding 3.3).

### 5. What canon-vk / rootverify consume
- `R_leaf[f, r]` constants: `(f, r)`, `index(f, r)`, `D`, `structure(f, r)` and the rung vector -> log sizes (never guessed).
- Guessed + checked: `V^nat` words (membership against `T_nat` at constant index), `stmt_k` fields, `s_in/s_out`, `rho_k` parts.
- Root receiver: `m_in = IV`, `chi = H(chi, stmt || m_out)`, `T_nat = derived`.
- Agreement test: reproduce every digest of `vectors/rv64-m5/canon-native-v1-vectors.json` (tags, version, structure,
  class key, T_nat leaves/root/path/header, state, stmt (cpu/truth/mb), rho, chain, chi).

### 6. Rung table and tax (filled in by the cells-weighted run, see receipts under vectors/reports/rv64-m5-20261104/canon-native/)
Cells-weighted tax [D] (`scripts/rv64_m5_canon_rungs.py`, 15 M3 bundles, 579 proofs, widths exported by the
`canon_native_widths.zig` test = `widths-gkr-v3.json`; weight = main + interaction columns; CPU families dominate the weight,
truth proofs are rows-weighted inside their family, so the aggregate is CPU-conservative):

| model | R=2 | R=3 | R=4 | classes R3/R4 |
|---|---:|---:|---:|---:|
| strict roster (every rung component committed; needs the presence relaxation) | +57.1 % | **+41.6 %** | **+35.9 %** | 37 / 46 |
| presence-preserving (v1 admissible today: absent bridges/tails stay absent) | +41.1 % | +30.0 % | +25.5 % | 37 / 46 |

**Kill rule (plan M5): fired at R=3 (41.6 % > 40 %) -> v1 uses R = 4** (35.9 % strict, 25.5 % presence-preserving).
Per family at R=4 (presence-preserving): cpu_first +2.6 %, cpu_middle +27.3 %, cpu_last +27.2 %, keccak +1.4 %, add +8.2 %,
double +9.2 %, arith256_mod +10.6 %, the rest <= 1.7 %. Dev blocks (presence-preserving R=4, CPU cells): 26235156 +17.8 %,
24628607 +17.4 %. Receipt: `vectors/reports/rv64-m5-20261104/canon-native/rung-tax-cells.json`. The generated table is
`ethereum/canon_native_rungs.zig` (R=4; `rung_table_id` is computed from it).

**Amendment 2026-11-04 (same v1 tag):** R = 4 (kill rule). `version_identity`, `chain[0..3]` and `chi` of the vectors file
changed accordingly; every other vector is unchanged.

### 7. Producer mode available now: `STWO_RV64_CANON_RUNGS=1` (presence-preserving, today's native protocol)
`Plan.canonicalCpus/canonicalTruths` pad every declaration to the smallest admissible rung of its family (head/tail ladders are
refitted so a present tail always has rows; jtab, boundary and omitted division stay constants). The padded declarations are
ordinary admitted geometries, so today's receiver verifies them unchanged and statement authority does not move. Each class
logs `RV64_CANON_CLASS ordinal family rung`. The chi-chain wiring into the native prover/verifier (sections 4-5) is the next
step; until then proofs carry today's native protocol and `m5-chi-chain/v1` exists as encodings + agreement tests only.

### canon-native reconciliation with CV2 (2026-11-04, same v1 tag)
- **T_nat tree = CV2** (`rv64_recursion/vk_table.zig`, DEPTH 6, CV2 leaf/node hashing). canon-native section 3 tree
  (`tnat-leaf`/`tnat-empty`/`merkle-node`, depth ceil(log2 n)) is **withdrawn as the T_nat tree** to keep one definition; its
  vectors stay only as hash-agreement tests of the encodings.
- canon-native supplies the CV2 `T_nat` leaf words `[TAG_NAT, 1, family, rung, native_profile, vk_hash[8]]`:
  - `family` = canon-native ids (section 1: cpu_first 0, cpu_middle 1, cpu_last 2, cpu_single 3, truth 16+f, mb 32);
  - `rung` = 0..R-1, R = 4 (ascending; the rung vectors are `ethereum/canon_native_rungs.zig`); truth rungs are keyed by
    (family, profile word logs[1]) -> a family with two Keccak policies uses `rung = policy_slot*4 + r` (only r27 = 1770517
    occurs in the basket, slot 0);
  - `native_profile` = 1 for `conjectured128_b2_q108_p20_fold4` (production), 2 reserved for `d2_native_b4_q54_p20_fold4`;
  - `vk_hash` = section 3 `vkhash = H(native-vk, [f, r, suite(8), fixed_identity(8), fixed_root(8), profile_identity(8), structure(8)])`
    (LE u32 words of the digest). 4 CPU families x 4 + truth classes (<= 31 in the basket at R=4) fit DEPTH 6 (64 slots).
