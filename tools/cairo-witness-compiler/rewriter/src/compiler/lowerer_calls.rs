impl Lowerer {
    fn lower_call(&mut self, call: &ExprCall, target: Target) -> (Ty, TokenStream) {
        let path = match &*call.func {
            Expr::Path(p) => tok_str(&p.path),
            other => {
                self.skip("call", format!("call of non-path `{}`", tok_str(other)));
                return (Ty::Unknown, quote! { WG_SKIP });
            }
        };
        match path.as_str() {
            "PackedUInt16 :: from_m31" => {
                let (_t, a) = self.lower_arg(call.args.first());
                self.emit_op(target, Ty::U16, quote! { eval.u16_from_m31(#a) })
            }
            "PackedBool :: from_m31" => {
                let (_t, a) = self.lower_arg(call.args.first());
                self.emit_op(target, Ty::Mask, quote! { eval.mask_from_m31(#a) })
            }
            "PackedFelt252 :: from_limbs" => {
                // Single array argument of EXACTLY 28 M31 exprs (the trait's
                // `felt_from_limbs` takes `[M31; FELT_N_LIMBS]`; a shorter source array
                // would zero-fill on the host — not expressible, loud skip).
                let arr = match call.args.first().map(strip_parens) {
                    Some(Expr::Array(ExprArray { elems, .. })) => elems,
                    _ => {
                        self.skip("call", "from_limbs without array arg".to_string());
                        return (Ty::Unknown, quote! { WG_SKIP });
                    }
                };
                if arr.len() != FELT252_LIMBS {
                    self.skip(
                        "call",
                        format!("PackedFelt252::from_limbs with {} != 28 limbs", arr.len()),
                    );
                    return (Ty::Unknown, quote! { WG_SKIP });
                }
                let mut toks = Vec::new();
                for e in arr {
                    let (_t, k) = self.lower_node(strip_parens(e), Target::Temp);
                    toks.push(k);
                }
                self.emit_op(
                    target,
                    Ty::Felt252,
                    quote! { eval.felt_from_limbs([ #(#toks),* ]) },
                )
            }
            "PackedFelt252Width27 :: from_limbs" => {
                // 10 M31 limb exprs — the transformer itself holds the limbs, so the
                // W27 value is modeled as a `[E::M31; 10]` array binding (no trait op
                // needed). Same canonical-limb contract as `felt_from_limbs` (limbs
                // assumed < 2^27); the byte-equality gate is the arbiter.
                let arr = match call.args.first().map(strip_parens) {
                    Some(Expr::Array(ExprArray { elems, .. })) => elems,
                    _ => {
                        self.skip("call", "Width27 from_limbs without array arg".to_string());
                        return (Ty::Unknown, quote! { WG_SKIP });
                    }
                };
                if arr.len() != FELTW27_LIMBS {
                    self.skip(
                        "call",
                        format!(
                            "PackedFelt252Width27::from_limbs with {} != 10 limbs",
                            arr.len()
                        ),
                    );
                    return (Ty::Unknown, quote! { WG_SKIP });
                }
                let mut toks = Vec::new();
                for e in arr {
                    let (t, k) = self.lower_node(strip_parens(e), Target::Temp);
                    if !t.is_m31() && t != Ty::Unknown {
                        self.skip("call", format!("Width27 from_limbs limb is {t:?}, not M31"));
                    }
                    toks.push(k);
                }
                let tok = self.bind(target, quote! { [ #(#toks),* ] });
                (Ty::FeltW27Limbs, tok)
            }
            "PackedFelt252Width27 :: from_packed_felt252" => {
                // f252 → w27 width conversion (G2): w27[j] = f9[3j] + f9[3j+1]*2^9 +
                // f9[3j+2]*2^18 — exact (27 = 3*9; each w27 limb < 2^27 < P, so plain
                // M31 mul-by-const + add). For j = 9 only f9[27] exists (252 = 9*27+9).
                // Bit-matches `Felt252Width27::from(Felt252)` (limb reinterpretation,
                // cpu.rs) for canonical 9-bit source limbs — the same canonicity
                // contract every `felt_get_m31` use already carries.
                let (at, atok) = self.lower_arg(call.args.first());
                match at {
                    Ty::Felt252 | Ty::ConstFelt252(_) => {
                        let mut limb_toks: Vec<TokenStream> = Vec::new();
                        for j in 0..FELTW27_LIMBS {
                            let mut acc: Option<TokenStream> = None;
                            for k in 0..3usize {
                                let idx = 3 * j + k;
                                if idx >= FELT252_LIMBS {
                                    break;
                                }
                                let il = usize_lit(idx);
                                let limb = self
                                    .bind(Target::Temp, quote! { eval.felt_get_m31(&#atok, #il) });
                                let term = if k == 0 {
                                    limb
                                } else {
                                    let c = 1u32 << (FELT252_LIMB_BITS * k);
                                    self.referenced_m31.insert(c);
                                    let cid = Ident::new(&format!("m31_{c}"), Span::call_site());
                                    self.bind(Target::Temp, quote! { eval.m31_mul(#limb, #cid) })
                                };
                                acc = Some(match acc {
                                    None => term,
                                    Some(a) => {
                                        self.bind(Target::Temp, quote! { eval.m31_add(#a, #term) })
                                    }
                                });
                            }
                            limb_toks.push(acc.expect("j*3 < 28 for all j < 10"));
                        }
                        let tok = self.bind(target, quote! { [ #(#limb_toks),* ] });
                        (Ty::FeltW27Limbs, tok)
                    }
                    other => {
                        self.skip(
                            "call",
                            format!(
                                "from_packed_felt252 on {:?} `{}`",
                                other,
                                call.args.first().map(tok_str).unwrap_or_default()
                            ),
                        );
                        (Ty::Unknown, quote! { WG_SKIP })
                    }
                }
            }
            "PackedFelt252 :: from_packed_felt252width27" => {
                // w27 → f252 width conversion: the REAL `felt_from_w27_words` trait op
                // (SIMD = the production conversion pair; recording = the exact 27->9
                // regroup on raw u32 ops). Opaque W27 (no known limb tokens) stays
                // census-only.
                let (at, atok) = self.lower_arg(call.args.first());
                match at {
                    Ty::FeltW27Limbs => {
                        self.emit_op(target, Ty::Felt252, quote! { eval.felt_from_w27_words(#atok) })
                    }
                    Ty::FeltW27 => self.w27_site(Ty::Felt252),
                    other => {
                        self.skip(
                            "call",
                            format!(
                                "from_packed_felt252width27 on {:?} `{}`",
                                other,
                                call.args.first().map(tok_str).unwrap_or_default()
                            ),
                        );
                        (Ty::Unknown, quote! { WG_SKIP })
                    }
                }
            }
            "PackedFelt252 :: from_m31" => {
                // Felt252 whose VALUE is the (31-bit) M31: limbs 0..3 are 9-bit windows
                // of the value (limbs 4..28 zero) — needs `U32Shr`/`U32And`; census-only
                // under the u32 trait extension, typed Felt252.
                let (at, _a) = self.lower_arg(call.args.first());
                if at.is_m31() || at == Ty::Unknown {
                    self.u32_site(Ty::Felt252)
                } else {
                    self.skip("call", format!("PackedFelt252::from_m31 on {at:?}"));
                    (Ty::Unknown, quote! { WG_SKIP })
                }
            }
            "PackedUInt32 :: from_m31" => {
                let (at, a) = self.lower_arg(call.args.first());
                if at.is_m31() {
                    self.emit_op(target, Ty::U32, quote! { eval.u32_from_m31(#a) })
                } else {
                    self.skip("call", format!("PackedUInt32::from_m31 on {at:?}"));
                    (Ty::Unknown, quote! { WG_SKIP })
                }
            }
            "PackedUInt32 :: from_limbs" => {
                // `low + (high << 16)` (simd.rs:204) — a REAL trait op when the
                // literal `[low, high]` shape is present (the generated idiom).
                if let Some(Expr::Array(ExprArray { elems, .. })) =
                    call.args.first().map(strip_parens)
                {
                    if elems.len() == 2 {
                        let (lt, ltok) = self.lower_node(strip_parens(&elems[0]), Target::Temp);
                        let (ht, htok) = self.lower_node(strip_parens(&elems[1]), Target::Temp);
                        self.require_m31(&lt, "u32_from_limbs low", &elems[0]);
                        self.require_m31(&ht, "u32_from_limbs high", &elems[1]);
                        return self.emit_op(
                            target,
                            Ty::U32,
                            quote! { eval.u32_from_limbs(#ltok, #htok) },
                        );
                    }
                    for e in elems {
                        let _ = self.lower_node(strip_parens(e), Target::Temp);
                    }
                }
                self.u32_site(Ty::U32)
            }
            p if p.ends_with(":: deduce_output") => {
                // HOOKED deduces: a REAL `WitnessEval` trait call (SIMD = the exact
                // fast_deduction function the original writer calls — byte-identical;
                // recording = an all-poison result + poison_ops census = the pinned
                // manifest). Result is the KNOWN tuple type, so projections compile
                // natively on both evaluators. Falls back to the census-only site if
                // the call's argument does not match the generated literal shape.
                if p == "PackedPartialEcMulWindowBits18 :: deduce_output" {
                    if let Some(tok) = self.lower_w18_deduce(call, target) {
                        return (known_deduce_output_ty(p).expect("W18 is in the table"), tok);
                    }
                    for a in &call.args {
                        let _ = self.lower_aggregate(a);
                    }
                    return self.deduce_site(known_deduce_output_ty(p).expect("in table"));
                }
                if p == "PackedPedersenPointsTableWindowBits18 :: deduce_output" {
                    if let Some(tok) = self.lower_points_table_deduce(call, target) {
                        return (
                            known_deduce_output_ty(p).expect("PT18 is in the table"),
                            tok,
                        );
                    }
                    for a in &call.args {
                        let _ = self.lower_aggregate(a);
                    }
                    return self.deduce_site(known_deduce_output_ty(p).expect("in table"));
                }
                if p == "PackedBlakeG :: deduce_output" {
                    if let Some(tok) = self.lower_blake_g_deduce(call, target) {
                        return (known_deduce_output_ty(p).expect("BlakeG in table"), tok);
                    }
                    for a in &call.args {
                        let _ = self.lower_aggregate(a);
                    }
                    return self.deduce_site(known_deduce_output_ty(p).expect("in table"));
                }
                if p == "PackedBlakeRoundSigma :: deduce_output" {
                    let (rt, rtok) = match call.args.first() {
                        Some(e) => self.lower_node(strip_parens(e), Target::Temp),
                        None => (Ty::Unknown, quote! { WG_SKIP }),
                    };
                    self.require_m31(&rt, "sigma deduce round", &call.args[0]);
                    let tok = self.bind(target, quote! { eval.deduce_blake_round_sigma(#rtok) });
                    return (known_deduce_output_ty(p).expect("Sigma in table"), tok);
                }
                // Census-only / unknown deduces: lower the args for REAL first
                // (tuple/array shapes route through lower_aggregate, so their
                // M31/felt leaves record cleanly).
                for a in &call.args {
                    let _ = self.lower_aggregate(a);
                }
                // Known-signature deduce (G5): type the RESULT so downstream
                // projections resolve; the call stays census-only (deduce_sites).
                // The result type is transcribed from the host fast_deduction
                // signature — a WRONG shape here would silently mis-type everything
                // downstream, so entries are added only with the signature in view.
                if let Some(ty) = known_deduce_output_ty(p) {
                    return self.deduce_site(ty);
                }
                // Unknown-signature deduce: the honest skip — the quantified
                // EC/poseidon/blake deduce backlog.
                self.skip("deduce_output", p.to_string());
                (Ty::Unknown, quote! { WG_SKIP })
            }
            other => {
                for a in &call.args {
                    let _ = self.lower_aggregate(a);
                }
                self.skip("call", format!("call `{other}(..)`"));
                (Ty::Unknown, quote! { WG_SKIP })
            }
        }
    }

}
