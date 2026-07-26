// ======================================================================================
// Block emission (mirrors the retired hand-written add_opcode shape-spec)
// ======================================================================================

fn build_marked_block(
    component: &str,
    fa: &FileAnalysis,
    lw: &Lowerer,
    writer: &ItemFn,
    file: &syn::File,
) -> String {
    // Imports use bare names inside the block, mirroring the shape specification.
    let mut seg = vec![
        BEGIN_MARKER.to_string(),
        header_comment(component, fa, lw),
        "use crate::witness::witness_eval::recording::{RecordingOutput, RecordingWitnessEval};"
            .to_string(),
        "use crate::witness::witness_eval::simd::SimdWitnessEval;".to_string(),
    ];
    let slots: Vec<&str> = lw.used_slots.iter().copied().collect();
    seg.push(format!(
        "use crate::witness::witness_eval::{{WitnessEval{}}};",
        slots.iter().map(|s| format!(", {s}")).collect::<String>()
    ));
    seg.push(String::new());
    seg.push(format!(
        "pub(crate) const N_LOOKUP_WORDS: usize = {};",
        fa.n_lookup_words
    ));
    seg.push(format!(
        "pub(crate) const N_SUB_INPUT_WORDS: usize = {};",
        fa.n_sub_words
    ));
    seg.push(String::new());

    // 1. The generic per-row body.
    seg.push(format!(
        "/// The per-row `{component}` base-trace body, routed through `WitnessEval`.\n\
         /// Mechanical transcription of `write_trace_simd`'s per-row closure (baseline above)."
    ));
    seg.push(render(&row_body_tokens(component, lw)));
    seg.push(String::new());

    // 2. write_trace_generic_simd — same signature, generic driver, module-private.
    seg.push(format!(
        "/// Generic SIMD driver: same allocation as `write_trace_simd`, but each row runs\n\
         /// `{component}_row_body` on a per-row `SimdWitnessEval`, then reconstructs the concrete\n\
         /// `LookupData` / `SubComponentInputs` from the eval's flat scratch. Module-private (it\n\
         /// returns the module-private `LookupData` / `SubComponentInputs`; wider visibility would\n\
         /// be E0446 and force a change OUTSIDE this block). External callers use the `pub(crate)`\n\
         /// `write_trace_generic` method or the `#[cfg(test)]` `generic_simd_diff` harness."
    ));
    seg.push(render(&generic_simd_tokens(component, lw, writer)));
    seg.push(String::new());

    // 3. impl ClaimGenerator { write_trace_generic } — mirrors write_trace.
    if let Some(method_toks) = write_trace_generic_tokens(file) {
        seg.push("impl ClaimGenerator {".to_string());
        seg.push(
            "/// Generic-path counterpart of [`ClaimGenerator::write_trace`]: identical shape, but\n\
             /// the base trace is produced by `write_trace_generic_simd`."
                .to_string(),
        );
        seg.push(render(&method_toks));
        seg.push("}".to_string());
        seg.push(String::new());
    }

    // 4. record_<component>().
    let record_fn = Ident::new(&format!("record_{component}"), Span::call_site());
    let row_body_fn = Ident::new(&format!("{component}_row_body"), Span::call_site());
    seg.push(format!(
        "/// Record the `{component}` per-row body into witness-JIT bytecode\n\
         /// (statement-independent — recorded once). EXTENDED ops (if any) surface in\n\
         /// `RecordingOutput::poison_ops` — the honest ISA-V2 census, not a failure."
    ));
    let record_ctor: TokenStream = if matches!(lw.input_ty, Ty::Unknown) {
        quote! { RecordingWitnessEval::new(#component) }
    } else {
        // Builtin slot layout: flat input words 0..K, enabler = K, iota = K+1 (when
        // the body reads it). The device lane MUST feed its input columns in this
        // exact order.
        // Slot layout (uniform for every builtin): flat inputs 0..K, enabler K,
        // iota K+1 (reserved even when unused — no Input op records for it then),
        // multiplicity columns K+2+k. The device lane MUST feed its input columns in
        // this exact order.
        let k = u32_lit(lw.input_ty.flat_width() as u32);
        let ki = u32_lit(lw.input_ty.flat_width() as u32 + 1);
        quote! { RecordingWitnessEval::with_slots(#component, #k, Some(#ki)) }
    };
    seg.push(render(&quote! {
        #[allow(dead_code)]
        pub(crate) fn #record_fn() -> RecordingOutput {
            let mut eval = #record_ctor;
            #row_body_fn(&mut eval);
            eval.finish()
        }
    }));
    seg.push(String::new());

    // 5. Lookup-flat accessors (the witness-JIT prove / device-interaction
    // seam): JIT_LOOKUP_FIELDS + interaction_gen_from_flat_lookup_words, field
    // list in LookupData declaration order; ctor variant per the module's
    // InteractionClaimGenerator shape.
    {
        let mut inv = String::new();
        inv.push_str("crate::jit_lookup_accessor! {\n");
        if igen_has_n_rows(file) {
            inv.push_str(&format!("    with_n_rows {};\n", fa.n_lookup_words));
        } else {
            inv.push_str(&format!("    {};\n", fa.n_lookup_words));
        }
        for f in &lw.lookup_fields {
            if f.scalar {
                inv.push_str(&format!("    {}: scalar,\n", f.name));
            } else {
                inv.push_str(&format!("    {}: {},\n", f.name, f.width));
            }
        }
        inv.push('}');
        seg.push(inv);
        seg.push(String::new());
    }

    // 5b. Device-DAG feed layout: one entry per SubComponentInputs instance —
    // facts only (the feed driver classifies count-style vs input-list).
    {
        let feed_map = parse_feed_map(file);
        let mut lay = String::new();
        lay.push_str(
            "/// Device-DAG feed layout (facts, DECLARATION order): one entry per\n             /// `SubComponentInputs` instance — (field, instance, downstream state\n             /// param, relation_index, flat word base, words per instance).\n             #[allow(dead_code)]\n             pub(crate) const SUB_FEED_LAYOUT: &[(&str, usize, &str, u32, usize, usize)] = &[\n",
        );
        for slot in &lw.sub_slots {
            let (state, rel) = feed_map
                .get(&slot.field)
                .cloned()
                .unwrap_or_else(|| ("UNMAPPED".to_string(), u32::MAX));
            lay.push_str(&format!(
                "    (\"{}\", {}, \"{}\", {}, {}, {}),\n",
                slot.field,
                slot.index,
                state,
                rel,
                slot.base,
                slot.shape.scalar_count(),
            ));
        }
        lay.push_str("];");
        seg.push(lay);
        seg.push(String::new());
    }

    // 5c. §6a device-interaction descriptors: one entry per logup column, parsed
    // from this module's write_interaction_trace. Facts only — pairing order is
    // arbitrary and sign/mult patterns vary per component; an unrecognized
    // numerator form aborts the emit inside parse_logup_descs.
    {
        let descs = parse_logup_descs(file).unwrap_or_else(|| {
            eprintln!("JIT_LOGUP_DESCS: write_interaction_trace not found/empty");
            std::process::exit(1);
        });
        let mut d = String::new();
        d.push_str(
            "/// §6a device-interaction descriptors (facts, COLUMN order): one entry\n             /// per logup column — (a_field, a_mult, a_neg, b_field, b_mult, b_neg);\n             /// b_field == \"\" for a trailing solo column. mult encoding: \"1\" = one,\n             /// \"enabler\" = the real-row enabler, else a scalar lookup-data field.\n             #[allow(dead_code)]\n             pub(crate) const JIT_LOGUP_DESCS: &[(&str, &str, bool, &str, &str, bool)] = &[\n",
        );
        for (af, am, an, bf, bm, bn) in &descs {
            d.push_str(&format!(
                "    (\"{af}\", \"{am}\", {an}, \"{bf}\", \"{bm}\", {bn}),\n"
            ));
        }
        d.push_str("];");
        seg.push(d);
        seg.push(String::new());
    }

    // 6. Test-only surface: flats + GenericSimdDiff + generic_simd_diff.
    seg.push(
        "// ---- Test-only surface for the byte-equality gate ---------------------------------"
            .to_string(),
    );
    seg.push(String::new());
    seg.push(render(&lookup_flat_tokens(lw)));
    seg.push(String::new());
    seg.push(
        "#[cfg(test)]\npub(crate) fn test_lookup_data_flat(ig: &InteractionClaimGenerator)          -> Vec<Vec<PackedM31>> {\n    lookup_data_flat(&ig.lookup_data)\n}"
            .to_string(),
    );
    seg.push(String::new());
    seg.push(render(&sub_flat_tokens(lw)));
    seg.push(String::new());
    seg.push(
        "/// Byte-comparison bundle (only public types cross the module boundary).".to_string(),
    );
    seg.push(render(&generic_simd_diff_struct_tokens()));
    seg.push(String::new());
    seg.push(
        "/// Run BOTH SIMD writers on the same (pure-read) states and return public compare data."
            .to_string(),
    );
    seg.push(render(&generic_simd_diff_fn_tokens(writer, file)));
    seg.push(END_MARKER.to_string());

    seg.join("\n")
}

/// Deterministic generated header: provenance + the derived flat layouts.
fn header_comment(component: &str, fa: &FileAnalysis, lw: &Lowerer) -> String {
    let mut lines = Vec::new();
    lines.push("//".to_string());
    lines.push(format!(
        "// GENERATED by tools/witness_genericize for `{component}` — mechanical rewrite of"
    ));
    lines.push(
        "// `write_trace_simd`'s per-row closure into a generic body over `WitnessEval`. Do not"
            .to_string(),
    );
    lines.push(
        "// edit by hand: re-run the tool after upstream regeneration (this block is stripped and"
            .to_string(),
    );
    lines.push(
        "// re-emitted idempotently). The original `write_trace_simd` above is the untouched"
            .to_string(),
    );
    lines.push("// byte-equality baseline (see `witness_eval::differential_test`).".to_string());
    lines.push("//".to_string());
    lines.push("// Flat layouts (derived, DECLARATION order):".to_string());
    lines.push("//   LOOKUP words:".to_string());
    for f in &lw.lookup_fields {
        if f.width == 1 {
            lines.push(format!("//     {} {}", f.name, f.base));
        } else {
            lines.push(format!(
                "//     {}[{}] {}..{}",
                f.name,
                f.width,
                f.base,
                f.base + f.width - 1
            ));
        }
    }
    lines.push(format!("//     ({} words)", fa.n_lookup_words));
    lines.push("//   SUB-INPUT words:".to_string());
    for s in &lw.sub_slots {
        let count = s.shape.scalar_count();
        if count == 1 {
            lines.push(format!("//     {}[{}] {}", s.field, s.index, s.base));
        } else {
            lines.push(format!(
                "//     {}[{}] {}..{}",
                s.field,
                s.index,
                s.base,
                s.base + count - 1
            ));
        }
    }
    lines.push(format!("//     ({} words)", fa.n_sub_words));
    lines.join("\n")
}

fn row_body_tokens(component: &str, lw: &Lowerer) -> TokenStream {
    let row_body_fn = Ident::new(&format!("{component}_row_body"), Span::call_site());
    let mut const_lets: Vec<TokenStream> = Vec::new();
    for v in &lw.referenced_m31 {
        let id = Ident::new(&format!("m31_{v}"), Span::call_site());
        let vl = u32_lit(*v);
        const_lets.push(quote! { let #id = eval.m31_const(#vl); });
    }
    let body_stmts = &lw.out;
    quote! {
        #[allow(clippy::identity_op)]
        #[allow(clippy::erasing_op)]
        #[allow(unused_variables)]
        #[allow(dead_code)]
        fn #row_body_fn<E: WitnessEval>(eval: &mut E) {
            #(#const_lets)*
            #(#body_stmts)*
        }
    }
}

fn generic_simd_tokens(component: &str, lw: &Lowerer, writer: &ItemFn) -> TokenStream {
    let row_body_fn = Ident::new(&format!("{component}_row_body"), Span::call_site());

    // Transcribe signature inputs + output verbatim from write_trace_simd.
    let inputs = &writer.sig.inputs;
    let output = &writer.sig.output;

    // Preamble: keep the leading locals that are NOT broadcast constants.
    let mut preamble: Vec<TokenStream> = Vec::new();
    for st in &writer.block.stmts {
        match st {
            Stmt::Local(local) => {
                if local_const(local).is_some() {
                    continue; // materialized inside the row body via m31_const
                }
                preamble.push(quote! { #st });
            }
            _ => break, // stop at the rayon expression
        }
    }

    // Writers without a mem-state param pass `None` (`impl Into<Option<..>>` on the
    // eval constructor keeps the opcode emitted text unchanged for present states).
    let addr_id: TokenStream = match &lw.addr_state {
        Some(name) => {
            let id = Ident::new(name, Span::call_site());
            quote! { #id }
        }
        None => quote! { None },
    };
    let big_id: TokenStream = match &lw.big_state {
        Some(name) => {
            let id = Ident::new(name, Span::call_site());
            quote! { #id }
        }
        None => quote! { None },
    };
    let input_id = Ident::new(&lw.input_name, Span::call_site());
    // Opcode writers pass their `PackedCasmState` binder straight through
    // (`impl Into<SimdInputs>` — the emitted text is unchanged from the pre-builtin
    // lane). Builtin writers flatten their typed input tuple into the flat input
    // words IN SLOT ORDER — the exact depth-first order the transformer's
    // `Ty::InputAt` slot map assigned, so `eval.input(k)` reads word k.
    let eval_input: TokenStream = if matches!(lw.input_ty, Ty::Unknown) {
        quote! { #input_id }
    } else {
        // Builtin flat input words, IN SLOT ORDER: [flattened inputs (0..K), a zero
        // placeholder at the enabler slot (K) and the iota slot (K+1) — `enabler()` /
        // `iota()` never route through `input()` on the SIMD side, but keeping the
        // positions makes the slot arithmetic identical to the recording/device
        // layout — then the multiplicity columns (K+2+k).]
        let mut words = input_flatten_tokens(&lw.input_ty, quote! { #input_id });
        if !lw.mults_reads.is_empty() {
            words.push(quote! { Simd::splat(0) });
            words.push(quote! { Simd::splat(0) });
            let max_k = *lw.mults_reads.iter().max().unwrap();
            for k in 0..=max_k {
                if lw.mults_reads.contains(&k) {
                    let kl = usize_lit(k);
                    words.push(quote! {
                        mults[#kl]
                            .get(row_index)
                            .copied()
                            .unwrap_or(PackedM31::zero())
                            .into_simd()
                    });
                } else {
                    words.push(quote! { Simd::splat(0) });
                }
            }
        }
        quote! { vec![ #(#words),* ] }
    };
    let row_id = Ident::new(&lw.row_name, Span::call_site());
    let lookup_id = Ident::new(&lw.lookup_name, Span::call_site());
    let sub_id = Ident::new(&lw.sub_name, Span::call_site());

    let reconstruct_lookup = reconstruct_lookup(lw, &lookup_id);
    let reconstruct_sub = reconstruct_sub(lw, &sub_id);

    // Writers that never multiply by the enabler (padding handled via their mults
    // column, e.g. pedersen_aggregator) have no `enabler_col` in the preamble; the
    // eval constructor still takes one. `Enabler::new` is pure, so materializing an
    // unused one is semantics-free.
    let has_enabler = preamble
        .iter()
        .any(|t| t.to_string().contains("let enabler_col"));
    let enabler_fallback: TokenStream = if has_enabler {
        quote! {}
    } else {
        // A body can only reach `eval.enabler()` through the `enabler_col.packed_at`
        // idiom, which requires the preamble binding — so when it is absent the value
        // is genuinely unused and the arity-0 construction is semantics-free.
        quote! { let enabler_col = Enabler::new(0); }
    };

    quote! {
        #[allow(clippy::type_complexity)]
        #[allow(unused_variables)]
        #[allow(dead_code)]
        fn write_trace_generic_simd(#inputs) #output {
            #(#preamble)*
            #enabler_fallback

            (
                trace.par_iter_mut(),
                #lookup_id.par_iter_mut(),
                #sub_id.par_iter_mut(),
                inputs.into_par_iter(),
            )
                .into_par_iter()
                .enumerate()
                .for_each(|(row_index, (#row_id, #lookup_id, #sub_id, #input_id))| {
                    let mut eval = SimdWitnessEval::new(
                        #row_id,
                        #addr_id,
                        #big_id,
                        #eval_input,
                        row_index,
                        &enabler_col,
                        N_LOOKUP_WORDS,
                        N_SUB_INPUT_WORDS,
                    );
                    #row_body_fn(&mut eval);

                    let lw = eval.lookup_scratch();
                    #(#reconstruct_lookup)*

                    let sw = eval.sub_scratch();
                    #(#reconstruct_sub)*
                });

            (trace, #lookup_id, #sub_id)
        }
    }
}

fn reconstruct_lookup(lw: &Lowerer, lookup_id: &Ident) -> Vec<TokenStream> {
    let mut out = Vec::new();
    for lf in &lw.lookup_fields {
        let field = Ident::new(&lf.name, Span::call_site());
        if lf.scalar {
            let b = usize_lit(lf.base);
            out.push(quote! { *#lookup_id.#field = lw[#b]; });
        } else {
            let idxs: Vec<TokenStream> = (0..lf.width)
                .map(|j| {
                    let b = usize_lit(lf.base + j);
                    quote! { lw[#b] }
                })
                .collect();
            out.push(quote! { *#lookup_id.#field = [ #(#idxs),* ]; });
        }
    }
    out
}

fn reconstruct_sub(lw: &Lowerer, sub_id: &Ident) -> Vec<TokenStream> {
    let mut out = Vec::new();
    for sa in &lw.sub_slots {
        let field = Ident::new(&sa.field, Span::call_site());
        let k = usize_lit(sa.index);
        let mut idx = sa.base;
        let value = rebuild_shape(&sa.shape, &mut idx);
        out.push(quote! { *#sub_id.#field[#k] = #value; });
    }
    out
}

/// Flatten a typed builtin input value into its flat input words, IN SLOT ORDER
/// (depth-first over the `PackedInputType` tree — the same order [`Ty::InputAt`]
/// assigns slot bases, so `eval.input(k)` reads exactly word k). Only M31 leaves are
/// emitted; a file with felt/u16/u32 input leaves has `input_sites > 0` and is never
/// emitted, so this is unreachable for those (the unreachable!() is the guard).
fn input_flatten_tokens(ty: &Ty, base: TokenStream) -> Vec<TokenStream> {
    match ty {
        Ty::M31 => vec![quote! { #base.into_simd() }],
        Ty::U32 => vec![quote! { #base.simd }],
        Ty::Felt252 => (0..FELT252_LIMBS)
            .map(|j| {
                let lit = usize_lit(j);
                quote! { #base.get_m31(#lit).into_simd() }
            })
            .collect(),
        // W27 input leaf: 10 word columns (27-bit values, M31-safe raw words).
        Ty::FeltW27 => (0..FELTW27_LIMBS)
            .map(|j| {
                let lit = usize_lit(j);
                quote! { #base.get_m31(#lit).into_simd() }
            })
            .collect(),
        Ty::Tuple(v) => {
            let mut out = Vec::new();
            for (i, e) in v.iter().enumerate() {
                let lit = Literal::usize_unsuffixed(i);
                out.extend(input_flatten_tokens(e, quote! { #base.#lit }));
            }
            out
        }
        Ty::Array(e, n) => {
            let mut out = Vec::new();
            for j in 0..*n {
                let lit = usize_lit(j);
                out.extend(input_flatten_tokens(e, quote! { #base[#lit] }));
            }
            out
        }
        other => unreachable!(
            "input_flatten_tokens on non-emittable input leaf {other:?} (input_sites gate)"
        ),
    }
}

fn rebuild_shape(shape: &Shape, idx: &mut usize) -> TokenStream {
    match shape {
        Shape::Scalar => {
            let i = usize_lit(*idx);
            *idx += 1;
            // Raw lane -> canonical M31 (the store side wrote a canonical value).
            quote! { unsafe { PackedM31::from_simd_unchecked(sw[#i]) } }
        }
        Shape::U32 => {
            let i = usize_lit(*idx);
            *idx += 1;
            quote! { PackedUInt32::from_simd(sw[#i]) }
        }
        Shape::Felt => {
            // 28 consecutive limb words -> the felt value (exact inverse of the
            // canonical `felt_get_m31` decomposition the flatten side emitted).
            let limbs: Vec<TokenStream> = (0..FELT252_LIMBS)
                .map(|_| {
                    let i = usize_lit(*idx);
                    *idx += 1;
                    quote! { unsafe { PackedM31::from_simd_unchecked(sw[#i]) } }
                })
                .collect();
            quote! { PackedFelt252::from_limbs([ #(#limbs),* ]) }
        }
        Shape::Tuple(v) => {
            let parts: Vec<TokenStream> = v.iter().map(|s| rebuild_shape(s, idx)).collect();
            quote! { ( #(#parts),* ) }
        }
        Shape::Array(v) => {
            let parts: Vec<TokenStream> = v.iter().map(|s| rebuild_shape(s, idx)).collect();
            quote! { [ #(#parts),* ] }
        }
    }
}

/// Clone the component's `write_trace` method as `pub(crate) fn write_trace_generic`
/// (same receiver + params + body), retargeting the `write_trace_simd` call.
fn write_trace_generic_tokens(file: &syn::File) -> Option<TokenStream> {
    let method = file.items.iter().find_map(|it| match it {
        Item::Impl(im) => im.items.iter().find_map(|ii| match ii {
            syn::ImplItem::Fn(f) if f.sig.ident == "write_trace" => Some(f.clone()),
            _ => None,
        }),
        _ => None,
    })?;

    let mut method = method;
    method.sig.ident = Ident::new("write_trace_generic", Span::call_site());
    method.vis = syn::parse_quote!(pub(crate));
    method.attrs.push(syn::parse_quote!(#[allow(dead_code)]));
    struct CallRewriter;
    impl syn::visit_mut::VisitMut for CallRewriter {
        fn visit_ident_mut(&mut self, id: &mut Ident) {
            if *id == "write_trace_simd" {
                *id = Ident::new("write_trace_generic_simd", id.span());
            }
        }
    }
    syn::visit_mut::visit_impl_item_fn_mut(&mut CallRewriter, &mut method);
    Some(quote! { #method })
}

fn lookup_flat_tokens(lw: &Lowerer) -> TokenStream {
    let mut parts: Vec<TokenStream> = Vec::new();
    for lf in &lw.lookup_fields {
        let field = Ident::new(&lf.name, Span::call_site());
        if lf.scalar {
            parts.push(quote! { ld.#field.clone() });
        } else {
            parts.push(quote! { ld.#field.iter().flatten().copied().collect() });
        }
    }
    quote! {
        fn lookup_data_flat(ld: &LookupData) -> Vec<Vec<PackedM31>> {
            vec![ #(#parts),* ]
        }
    }
}

fn sub_flat_tokens(lw: &Lowerer) -> TokenStream {
    let mut parts: Vec<TokenStream> = Vec::new();
    for sa in &lw.sub_slots {
        let field = Ident::new(&sa.field, Span::call_site());
        let k = usize_lit(sa.index);
        match &sa.shape {
            Shape::Scalar => parts.push(quote! {
                sci.#field[#k].iter().map(|v| v.into_simd()).collect::<Vec<_>>()
            }),
            _ => {
                let t: Ident = Ident::new("t", Span::call_site());
                let scalars = shape_projection(&sa.shape, quote! { #t });
                parts.push(quote! {
                    sci.#field[#k]
                        .iter()
                        .flat_map(|#t| vec![ #(#scalars),* ])
                        .collect::<Vec<_>>()
                });
            }
        }
    }
    quote! {
        fn sub_inputs_flat(sci: &SubComponentInputs) -> Vec<Vec<Simd<u32, N_LANES>>> {
            vec![ #(#parts),* ]
        }
    }
}

/// Scalar projections of a shaped `PackedInputType` value. `base` navigates from an
/// `&PackedInputType` via `.N` / `[j]`; each leaf is a Copy `PackedM31` via auto-deref.
fn shape_projection(shape: &Shape, base: TokenStream) -> Vec<TokenStream> {
    match shape {
        Shape::Scalar => vec![quote! { #base.into_simd() }],
        Shape::U32 => vec![quote! { #base.simd }],
        Shape::Felt => (0..FELT252_LIMBS)
            .map(|j| {
                let lit = usize_lit(j);
                quote! { #base.get_m31(#lit).into_simd() }
            })
            .collect(),
        Shape::Tuple(v) => {
            let mut out = Vec::new();
            for (i, s) in v.iter().enumerate() {
                let lit = Literal::usize_unsuffixed(i);
                out.extend(shape_projection(s, quote! { #base.#lit }));
            }
            out
        }
        Shape::Array(v) => {
            let mut out = Vec::new();
            for (j, s) in v.iter().enumerate() {
                let lit = usize_lit(j);
                out.extend(shape_projection(s, quote! { #base[#lit] }));
            }
            out
        }
    }
}

/// The component-independent compare bundle (verbatim from the shape-spec).
fn generic_simd_diff_struct_tokens() -> TokenStream {
    quote! {
        #[cfg(test)]
        pub(crate) struct GenericSimdDiff {
            pub log_size: u32,
            pub orig_rows: Vec<[M31; N_TRACE_COLUMNS]>,
            pub gen_rows: Vec<[M31; N_TRACE_COLUMNS]>,
            pub orig_lookup: Vec<Vec<PackedM31>>,
            pub gen_lookup: Vec<Vec<PackedM31>>,
            pub orig_sub: Vec<Vec<Simd<u32, N_LANES>>>,
            pub gen_sub: Vec<Vec<Simd<u32, N_LANES>>>,
            pub orig_interaction_cols: Vec<Vec<M31>>,
            pub gen_interaction_cols: Vec<Vec<M31>>,
            pub orig_claimed_sum: SecureField,
            pub gen_claimed_sum: SecureField,
        }
    }
}

/// `generic_simd_diff(...)`: same params as `write_trace_simd`; runs both writers and
/// packages the compare bundle (verbatim body from the shape-spec).
fn generic_simd_diff_fn_tokens(writer: &ItemFn, file: &syn::File) -> TokenStream {
    // Some components' `InteractionClaimGenerator` carries an extra `n_rows` field
    // (e.g. blake_round); include it in the literal when declared (`n_rows` is a
    // writer param, in scope in the harness).
    let ig_has_n_rows = file.items.iter().any(|it| match it {
        Item::Struct(st) if st.ident == "InteractionClaimGenerator" => match &st.fields {
            Fields::Named(n) => n
                .named
                .iter()
                .any(|f| f.ident.as_ref().is_some_and(|i| i == "n_rows")),
            _ => false,
        },
        _ => false,
    });
    let ig_extra: TokenStream = if ig_has_n_rows {
        quote! { n_rows, }
    } else {
        quote! {}
    };
    let inputs = &writer.sig.inputs;
    // Argument names in order; the first must be `inputs`. BY-VALUE params (no `&` in
    // the type — e.g. the aggregator's `mults: Vec<Vec<PackedM31>>`) are cloned into
    // the FIRST call so the second still owns them; references pass through twice.
    let mut names: Vec<Ident> = Vec::new();
    let mut by_value: Vec<bool> = Vec::new();
    for arg in inputs {
        if let FnArg::Typed(pt) = arg
            && let Pat::Ident(pi) = &*pt.pat {
                names.push(pi.ident.clone());
                by_value.push(!matches!(&*pt.ty, Type::Reference(_)));
            }
    }
    let rest = &names[1..];
    let rest_first: Vec<TokenStream> = names[1..]
        .iter()
        .zip(&by_value[1..])
        .map(|(n, bv)| {
            if *bv {
                quote! { #n.clone() }
            } else {
                quote! { #n }
            }
        })
        .collect();
    quote! {
        #[cfg(test)]
        pub(crate) fn generic_simd_diff(#inputs) -> GenericSimdDiff {
            let (trace_o, ld_o, sci_o) = write_trace_simd(inputs.clone(), #(#rest_first),*);
            let (trace_g, ld_g, sci_g) = write_trace_generic_simd(inputs, #(#rest),*);

            let log_size = trace_o.log_size();
            let orig_rows = (0..(1usize << log_size))
                .map(|r| trace_o.row_at(r))
                .collect();
            let gen_rows = (0..(1usize << log_size))
                .map(|r| trace_g.row_at(r))
                .collect();

            let orig_lookup = lookup_data_flat(&ld_o);
            let gen_lookup = lookup_data_flat(&ld_g);
            let orig_sub = sub_inputs_flat(&sci_o);
            let gen_sub = sub_inputs_flat(&sci_g);

            let common = relations::CommonLookupElements::dummy();
            let (raw_o, _) = InteractionClaimGenerator {
                log_size,
                #ig_extra
                lookup_data: ld_o,
            }
            .write_interaction_trace(&common);
            let (raw_g, _) = InteractionClaimGenerator {
                log_size,
                #ig_extra
                lookup_data: ld_g,
            }
            .write_interaction_trace(&common);
            let (cols_o, orig_claimed_sum) = raw_o.finalize_on_simd();
            let (cols_g, gen_claimed_sum) = raw_g.finalize_on_simd();
            let orig_interaction_cols = cols_o.iter().map(|c| c.values.to_cpu()).collect();
            let gen_interaction_cols = cols_g.iter().map(|c| c.values.to_cpu()).collect();

            GenericSimdDiff {
                log_size,
                orig_rows,
                gen_rows,
                orig_lookup,
                gen_lookup,
                orig_sub,
                gen_sub,
                orig_interaction_cols,
                gen_interaction_cols,
                orig_claimed_sum,
                gen_claimed_sum,
            }
        }
    }
}
