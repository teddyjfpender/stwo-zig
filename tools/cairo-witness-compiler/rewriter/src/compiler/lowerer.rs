// ======================================================================================
// Lowerer — the finite rewrite table (SSA flattening + type inference + effects)
// ======================================================================================

enum Target {
    Temp,
    Named(Ident),
}
struct Lowerer {
    consts: BTreeMap<String, ConstVal>,
    /// Hoisted felt broadcast constants (G3), pre-decomposed into 28 canonical 9-bit
    /// limbs at transform time.
    felt_consts: BTreeMap<String, [u32; FELT252_LIMBS]>,
    /// Preamble `let <name> = Seq::new(..)` idents; `<name>.packed_at(row_index)` is the
    /// packed row index (census-only until the lane feeds it as an input word, G4).
    seq_idents: BTreeSet<String>,
    addr_state: Option<String>,
    big_state: Option<String>,
    input_name: String,
    /// Type of the 4th closure binder (`<comp>_input`), parsed from `PackedInputType`.
    /// Seeds input-projection typing (`.N` / `[i]` / `.get_m31(i)`).
    input_ty: Ty,
    /// The closure's outer row-index binder name (`row_index`).
    row_index_name: String,
    row_name: String,
    lookup_name: String,
    sub_name: String,
    lookup_fields: Vec<LookupField>,
    /// Declaration-order sub-input slots ((field, k) → flat base).
    sub_slots: Vec<SubSlot>,
    sub_base: BTreeMap<(String, usize), usize>,

    env: BTreeMap<String, Ty>,
    out: Vec<TokenStream>,
    referenced_m31: BTreeSet<u32>,
    used_slots: BTreeSet<&'static str>,
    skips: Vec<Skip>,
    u32_sites: usize,
    /// Census-only builtin-input access sites (`<comp>_input.N` / `[i]` / `.get_m31(i)`).
    /// Typed correctly but NOT emittable: `SimdWitnessEval`/recording model only the
    /// opcode `PackedCasmState` input (`input(SLOT_PC/AP/FP)`), so a builtin felt-tuple
    /// input has no read op yet. Any site > 0 blocks emission (like `u32_sites`).
    input_sites: usize,
    /// Census-only OPAQUE `Felt252Width27` sites: `get_m31(i)` on a W27 whose limbs the
    /// transformer does not hold (input/deduce-sourced), and the W27→Felt252 width
    /// conversion (needs `U32Shr`/`U32And` — 27-bit limbs exceed the u16 trait ops).
    /// The recording layer models only 28x9 felts (`FELT_N_LIMBS`), so these are typed
    /// correctly but never emitted. Any site > 0 blocks emission.
    w27_sites: usize,
    /// Whether the body reads the row-index iota (`seq.packed_at(row_index)`) — a REAL
    /// `eval.iota()` op (G4); the builtin record/driver assign it an input slot.
    uses_iota: bool,
    /// Multiplicity-column reads (`*mults[k].get(row_index).unwrap_or(&zero)`): REAL
    /// `eval.input(K + 2 + k)` reads — the builtin lane feeds `mults[k]` as an input
    /// column after the flat input words, the enabler and the iota. The set records
    /// which `k` the body reads (the driver emits exactly those columns).
    mults_reads: BTreeSet<usize>,
    /// Census-only KNOWN-SIGNATURE deduce sites (G5): `PackedX::deduce_output(..)` calls
    /// whose RESULT type is in [`known_deduce_output_ty`]'s table. Typing the result lets
    /// every downstream projection (`.N` / `[i]` / `.get_m31(i)`) resolve — collapsing the
    /// cascade of Unknown skips to the honest per-call deduce count — while the call
    /// itself stays census-only: it needs either a computed-deduce instruction or direct
    /// component-to-component feeding. Blocks emission.
    deduce_sites: usize,
    counter: usize,

    max_col: Option<usize>,
}
