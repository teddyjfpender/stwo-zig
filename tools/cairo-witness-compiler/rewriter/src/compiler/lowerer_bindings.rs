impl Lowerer {
    #[allow(clippy::too_many_arguments)]
    fn new(
        consts: BTreeMap<String, ConstVal>,
        felt_consts: BTreeMap<String, [u32; FELT252_LIMBS]>,
        seq_idents: BTreeSet<String>,
        preprocessed_slots: BTreeMap<String, usize>,
        addr_state: Option<String>,
        big_state: Option<String>,
        input_name: String,
        input_ty: Ty,
        row_index_name: String,
        row_name: String,
        lookup_name: String,
        sub_name: String,
        writer_shape: WriterShape,
        lookup_fields: Vec<LookupField>,
        sub_slots: Vec<SubSlot>,
    ) -> Self {
        let sub_base = sub_slots
            .iter()
            .map(|s| ((s.field.clone(), s.index), s.base))
            .collect();
        Self {
            consts,
            felt_consts,
            seq_idents,
            preprocessed_slots,
            addr_state,
            big_state,
            input_name,
            input_ty,
            row_index_name,
            row_name,
            lookup_name,
            sub_name,
            writer_shape,
            lookup_fields,
            sub_slots,
            sub_base,
            env: BTreeMap::new(),
            out: Vec::new(),
            referenced_m31: BTreeSet::new(),
            used_slots: BTreeSet::new(),
            skips: Vec::new(),
            u32_sites: 0,
            input_sites: 0,
            w27_sites: 0,
            uses_iota: false,
            mults_reads: BTreeSet::new(),
            deduce_sites: 0,
            counter: 0,
            max_col: None,
        }
    }

    fn skip(&mut self, category: &'static str, detail: String) {
        self.skips.push(Skip { category, detail });
    }

    /// Census-only u32-family site: type-checks (so inference proceeds) but the file is
    /// classified "matched (needs u32 trait extension)" and never emitted.
    fn u32_site(&mut self, ty: Ty) -> (Ty, TokenStream) {
        self.u32_sites += 1;
        (ty, quote! { WG_U32_CENSUS_ONLY })
    }

    /// Census-only OPAQUE-Width27 site (see `w27_sites`): typing proceeds, emission is
    /// blocked. NEVER lowered to `felt_get_m31` — that op is 28x9 semantics and using it
    /// on a 10x27 value would be a silent miscompile if it ever reached emission.
    fn w27_site(&mut self, ty: Ty) -> (Ty, TokenStream) {
        self.w27_sites += 1;
        (ty, quote! { WG_W27_CENSUS_ONLY })
    }

    /// Census-only KNOWN-SIGNATURE deduce site (G5): the call's RESULT is typed from
    /// [`known_deduce_output_ty`] so downstream projections resolve, but the deduce
    /// itself has no backend op yet (device EC/blake function or device-to-device feed).
    fn deduce_site(&mut self, ty: Ty) -> (Ty, TokenStream) {
        self.deduce_sites += 1;
        (ty, quote! { WG_DEDUCE_CENSUS_ONLY })
    }

    /// Lower one expression expected to produce an `E::Felt` value: a felt-typed
    /// expression as-is, or a hoisted felt constant materialized via
    /// `felt_from_limbs` over its 28 const limbs. `None` = not a felt here.
    /// Materialize a u32-shaped (ty, tok) pair as an `E::U32` value token —
    /// hoisted broadcast constants become `eval.u32_const(v)`.
    fn u32ish_value(&mut self, ty: Ty, tok: TokenStream) -> TokenStream {
        match ty {
            Ty::ConstU32(v) => {
                let vl = u32_lit(v);
                self.bind(Target::Temp, quote! { eval.u32_const(#vl) })
            }
            _ => tok,
        }
    }

    /// Materialize a felt-shaped (ty, tok) pair as an `E::Felt` value token —
    /// constants become `felt_from_limbs` of hoisted limb constants.
    fn feltish_value(&mut self, ty: Ty, tok: TokenStream) -> TokenStream {
        match ty {
            Ty::ConstFelt252(limbs) => self.felt_const_value(Target::Temp, limbs).1,
            _ => tok,
        }
    }

    fn lower_felt_value(&mut self, e: &Expr) -> Option<TokenStream> {
        if let Some(limbs) = self.peek_felt_const(e) {
            let (_t, tok) = self.felt_const_value(Target::Temp, limbs);
            return Some(tok);
        }
        let (ty, tok) = self.lower_node(strip_parens(e), Target::Temp);
        match ty {
            Ty::Felt252 => Some(tok),
            Ty::ConstFelt252(limbs) => {
                let (_t, tok) = self.felt_const_value(Target::Temp, limbs);
                Some(tok)
            }
            _ => None,
        }
    }

    /// A `PackedPartialEcMulWindowBits{18,9}::deduce_output((chain, round,
    /// ([window; N], [acc; 2])))` generated literal as the corresponding real
    /// `WitnessEval` call.
    /// `None` when the argument is not the literal tuple shape (caller falls back to
    /// the census-only site; nothing is emitted before the shape checks pass).
    fn lower_windowed_ec_deduce(
        &mut self,
        call: &syn::ExprCall,
        target: Target,
        window_bits: u32,
        window_count: usize,
    ) -> Option<TokenStream> {
        let arg = strip_parens(call.args.first()?);
        let Expr::Tuple(ExprTuple { elems, .. }) = arg else {
            return None;
        };
        let [chain_e, round_e, state_e] = elems.iter().collect::<Vec<_>>()[..] else {
            return None;
        };
        let Expr::Tuple(ExprTuple { elems: st, .. }) = strip_parens(state_e) else {
            return None;
        };
        let [wins_e, acc_e] = st.iter().collect::<Vec<_>>()[..] else {
            return None;
        };
        let Expr::Array(ExprArray { elems: wins, .. }) = strip_parens(wins_e) else {
            return None;
        };
        let Expr::Array(ExprArray { elems: accs, .. }) = strip_parens(acc_e) else {
            return None;
        };
        if wins.len() != window_count || accs.len() != 2 {
            return None;
        }
        // Shape checks passed — lower the pieces (any inner mismatch is a loud skip
        // from the piece's own lowering; the call still emits so the census stays 1:1
        // with the source, and the skip blocks emission).
        let chain = {
            let (ty, tok) = self.lower_node(strip_parens(chain_e), Target::Temp);
            self.require_m31(&ty, "windowed EC deduce chain", chain_e);
            tok
        };
        let round = {
            let (ty, tok) = self.lower_node(strip_parens(round_e), Target::Temp);
            self.require_m31(&ty, "windowed EC deduce round", round_e);
            tok
        };
        let win_toks: Vec<TokenStream> = wins
            .iter()
            .map(|w| {
                let (ty, tok) = self.lower_node(strip_parens(w), Target::Temp);
                self.require_m31(&ty, "windowed EC deduce window", w);
                tok
            })
            .collect();
        let acc_toks: Vec<TokenStream> = accs
            .iter()
            .map(|a| match self.lower_felt_value(a) {
                Some(tok) => tok,
                None => {
                    self.skip(
                        "deduce_output",
                        format!(
                            "window-bits-{window_bits} deduce accumulator is not a felt: `{}`",
                            tok_str(a)
                        ),
                    );
                    quote! { WG_SKIP }
                }
            })
            .collect();
        let method = Ident::new(
            &format!("deduce_partial_ec_mul_w{window_bits}"),
            Span::call_site(),
        );
        Some(self.bind(target, quote! {
            eval.#method(#chain, #round, [ #(#win_toks),* ], [ #(#acc_toks),* ])
        }))
    }

    /// `PackedBlakeG::deduce_output([a, b, c, d, m0, m1])` (6 full-32-bit words) as a
    /// REAL `eval.deduce_blake_g([...])` call. `None` when the literal array shape is
    /// absent (fallback: census-only).
    fn lower_blake_g_deduce(
        &mut self,
        call: &syn::ExprCall,
        target: Target,
    ) -> Option<TokenStream> {
        let arg = strip_parens(call.args.first()?);
        let Expr::Array(ExprArray { elems, .. }) = arg else {
            return None;
        };
        if elems.len() != 6 {
            return None;
        }
        let toks: Vec<TokenStream> = elems
            .iter()
            .map(|e| {
                let (ty, tok) = self.lower_node(strip_parens(e), Target::Temp);
                if !ty.is_u32() {
                    self.skip(
                        "deduce_output",
                        format!("blake_g input is not u32: `{}` ({ty:?})", tok_str(e)),
                    );
                }
                tok
            })
            .collect();
        Some(self.bind(target, quote! { eval.deduce_blake_g([ #(#toks),* ]) }))
    }

    /// A `PackedPedersenPointsTableWindowBits{18,9}::deduce_output([index])` call.
    fn lower_points_table_deduce(
        &mut self,
        call: &syn::ExprCall,
        target: Target,
        window_bits: u32,
    ) -> Option<TokenStream> {
        let arg = strip_parens(call.args.first()?);
        let Expr::Array(ExprArray { elems, .. }) = arg else {
            return None;
        };
        if elems.len() != 1 {
            return None;
        }
        let (ty, idx) = self.lower_node(strip_parens(&elems[0]), Target::Temp);
        self.require_m31(&ty, "points-table deduce index", &elems[0]);
        let method = Ident::new(
            &format!("deduce_pedersen_points_table_w{window_bits}"),
            Span::call_site(),
        );
        Some(self.bind(target, quote! { eval.#method(#idx) }))
    }

    /// A hoisted felt broadcast constant used as a bare VALUE (not via `.get_m31(i)`,
    /// which short-circuits to the const limb): materialize it through the REAL
    /// `felt_from_limbs` op over 28 M31 constants (RecFelt::Limbs of consts — no ISA
    /// change, G3). Byte-correct: the limbs are the canonical 9-bit windows, so the SIMD
    /// impl's `from_limbs` repacks exactly the broadcast value.
    fn felt_const_value(
        &mut self,
        target: Target,
        limbs: [u32; FELT252_LIMBS],
    ) -> (Ty, TokenStream) {
        let ids: Vec<Ident> = limbs
            .iter()
            .map(|v| {
                self.referenced_m31.insert(*v);
                Ident::new(&format!("m31_{v}"), Span::call_site())
            })
            .collect();
        self.emit_op(
            target,
            Ty::ConstFelt252(limbs),
            quote! { eval.felt_from_limbs([ #(#ids),* ]) },
        )
    }

    /// Peek: is `expr` a bare path naming a hoisted felt constant? (Used by `get_m31` to
    /// avoid materializing the whole felt when only one const limb is read.)
    fn peek_felt_const(&self, expr: &Expr) -> Option<[u32; FELT252_LIMBS]> {
        match strip_parens(expr) {
            Expr::Path(p) => self.felt_consts.get(&tok_str(&p.path)).copied(),
            _ => None,
        }
    }

    /// A single known-const M31 limb value as a leaf.
    fn const_m31_leaf(&mut self, target: Target, v: u32) -> (Ty, TokenStream) {
        self.referenced_m31.insert(v);
        let id = Ident::new(&format!("m31_{v}"), Span::call_site());
        self.leaf(target, Ty::ConstM31(v), quote! { #id })
    }

    /// Builtin-input leaf: the parsed `PackedInputType`, wrapped in [`Ty::InputAt`]
    /// with flat slot base 0. Projections descend the wrapper with the correct base;
    /// an M31 leaf lowers to the REAL `eval.input(<slot>)` read ([`Self::input_slot_leaf`]).
    /// Felt-typed leaves stay census-only (`input_sites`) — the lane does not feed felt
    /// limbs yet. A bare (unprojected) use of a tuple-typed input, or an unparseable
    /// alias (opcode `PackedCasmState`), is an honest skip exactly as before.
    fn input_leaf(&mut self, target: Target) -> (Ty, TokenStream) {
        if matches!(self.input_ty, Ty::Unknown) {
            self.skip(
                "expr",
                format!("bare use of input struct `{}`", self.input_name),
            );
            return (Ty::Unknown, quote! { WG_SKIP });
        }
        let ty = Ty::InputAt(Box::new(self.input_ty.clone()), 0);
        self.input_projection(target, ty, "bare input binder")
    }

    /// Resolve an [`Ty::InputAt`]-typed value: M31 leaf → the REAL `eval.input(<slot>)`
    /// read; aggregate → pass the wrapper through for further projection (placeholder
    /// token — a bare aggregate use that reaches an op is a skip downstream); felt/other
    /// leaf → census-only `input_sites` (typed, not yet fed by the lane).
    fn input_projection(&mut self, target: Target, ty: Ty, what: &str) -> (Ty, TokenStream) {
        let Ty::InputAt(inner, base) = &ty else {
            unreachable!("input_projection on non-InputAt");
        };
        match &**inner {
            Ty::M31 => {
                let slot = u32_lit(*base as u32);
                self.emit_op(target, Ty::M31, quote! { eval.input(#slot) })
            }
            Ty::U32 => {
                // Full-32-bit input word (blake message words) — its own read op; the
                // device lane's u32 input columns carry it raw.
                let slot = u32_lit(*base as u32);
                self.emit_op(target, Ty::U32, quote! { eval.input_u32(#slot) })
            }
            Ty::Tuple(_) | Ty::Array(..) => self.leaf(target, ty.clone(), quote! { WG_INPUT_AGG }),
            Ty::Felt252 => {
                // Felt input leaf: 28 consecutive limb slots -> a REAL felt value via
                // `felt_from_limbs` over 28 input reads (existing ops; the lane feeds
                // the felt's canonical limbs as 28 input columns).
                let limb_ids: Vec<TokenStream> = (0..FELT252_LIMBS)
                    .map(|j| {
                        let slot = u32_lit((*base + j) as u32);
                        self.bind(Target::Temp, quote! { eval.input(#slot) })
                    })
                    .collect();
                self.emit_op(
                    target,
                    Ty::Felt252,
                    quote! { eval.felt_from_limbs([ #(#limb_ids),* ]) },
                )
            }
            Ty::FeltW27 => {
                // W27 input leaf: 10 consecutive word slots (27-bit values are
                // M31-safe) -> the limb-array value FeltW27Limbs carries.
                let word_ids: Vec<TokenStream> = (0..FELTW27_LIMBS)
                    .map(|j| {
                        let slot = u32_lit((*base + j) as u32);
                        self.bind(Target::Temp, quote! { eval.input(#slot) })
                    })
                    .collect();
                let tok = self.bind(target, quote! { [ #(#word_ids),* ] });
                (Ty::FeltW27Limbs, tok)
            }
            _ => {
                // U16 / other input leaves: typed but not yet fed by the lane.
                let _ = what;
                self.input_sites += 1;
                self.leaf(target, (**inner).clone(), quote! { WG_INPUT_CENSUS_ONLY })
            }
        }
    }

    fn fresh(&mut self) -> Ident {
        let id = Ident::new(&format!("wg_v{}", self.counter), Span::call_site());
        self.counter += 1;
        id
    }

    /// Bind `rhs` to `target` (Named or a fresh temp); push the `let`, return the value tok.
    fn bind(&mut self, target: Target, rhs: TokenStream) -> TokenStream {
        let name = match target {
            Target::Named(n) => n,
            Target::Temp => self.fresh(),
        };
        self.out.push(quote! { let #name = #rhs; });
        quote! { #name }
    }

    // ---- statement-level -----------------------------------------------------------

    fn lower_body(&mut self, stmts: &[Stmt]) {
        for st in stmts {
            self.lower_stmt(st);
        }
    }

    fn lower_stmt(&mut self, st: &Stmt) {
        match st {
            Stmt::Local(local) => self.lower_local(local),
            Stmt::Expr(Expr::Assign(a), _) => self.lower_assign(a),
            Stmt::Expr(e, _) => {
                self.skip(
                    "stmt",
                    format!("unexpected expression statement: `{}`", tok_str(e)),
                );
            }
            Stmt::Macro(m) => {
                self.skip(
                    "macro",
                    format!("macro in body: `{}`", tok_str(&m.mac.path)),
                );
            }
            Stmt::Item(_) => self.skip("stmt", "nested item in body".to_string()),
        }
    }

    fn lower_local(&mut self, local: &Local) {
        let Some(name) = local_ident(local) else {
            self.skip(
                "stmt",
                format!("unsupported `let` pattern: `{}`", tok_str(&local.pat)),
            );
            return;
        };
        let Some(init) = &local.init else {
            self.skip("stmt", format!("`let {name}` without initializer"));
            return;
        };
        let name_ident = Ident::new(&name, Span::call_site());
        let expr = strip_parens(&init.expr);
        let ty = match expr {
            Expr::Tuple(_) | Expr::Array(_) => {
                let (ty, toks) = self.lower_aggregate(expr);
                self.out.push(quote! { let #name_ident = #toks; });
                ty
            }
            _ => {
                let (ty, _tok) = self.lower_node(expr, Target::Named(name_ident));
                ty
            }
        };
        self.env.insert(name, ty);
    }

    fn lower_assign(&mut self, a: &ExprAssign) {
        // LHS must be `*<place>`.
        let deref = match strip_parens(&a.left) {
            Expr::Unary(ExprUnary {
                op: UnOp::Deref(_),
                expr,
                ..
            }) => strip_parens(expr),
            other => {
                self.skip(
                    "effect",
                    format!("assignment to non-deref place: `{}`", tok_str(other)),
                );
                return;
            }
        };
        match deref {
            // *row[i] = v;
            Expr::Index(ExprIndex {
                expr: base, index, ..
            }) if is_path_named(base, &self.row_name) => {
                let Some(col) = expr_usize(index) else {
                    self.skip(
                        "effect",
                        format!("row index not a literal: `{}`", tok_str(index)),
                    );
                    return;
                };
                let (ty, v) = self.lower_node(strip_parens(&a.right), Target::Temp);
                self.require_m31(&ty, "set_col value", &a.right);
                let cl = usize_lit(col);
                self.out.push(quote! { eval.set_col(#cl, #v); });
                self.max_col = Some(self.max_col.map_or(col, |m| m.max(col)));
            }
            // *sub_component_inputs.field[k] = <tuple/array/scalar>;
            Expr::Index(ExprIndex {
                expr: base, index, ..
            }) => {
                let field = match strip_parens(base) {
                    Expr::Field(ExprField {
                        base: fb,
                        member: Member::Named(m),
                        ..
                    }) if is_path_named(fb, &self.sub_name) => m.to_string(),
                    _ => {
                        self.skip(
                            "effect",
                            format!("unrecognized sub-input place: `{}`", tok_str(deref)),
                        );
                        return;
                    }
                };
                let Some(k) = expr_usize(index) else {
                    self.skip(
                        "effect",
                        format!("sub-input index not a literal: `{}`", tok_str(index)),
                    );
                    return;
                };
                let Some(base_idx) = self.sub_base.get(&(field.clone(), k)).copied() else {
                    self.skip(
                        "effect",
                        format!("sub-input `{field}[{k}]` missing from layout"),
                    );
                    return;
                };
                let leaves = self.flatten_sub(strip_parens(&a.right));
                // Fail-closed width guard: the scan-time shape fixed this slot's flat
                // word count (and every later slot's base). A lowered width that
                // disagrees (e.g. a felt the scan recognizer missed) would silently
                // corrupt the whole layout — skip loudly instead.
                let expected = self
                    .sub_slots
                    .iter()
                    .find(|s| s.field == field && s.index == k)
                    .map(|s| s.shape.scalar_count());
                if expected != Some(leaves.len()) {
                    self.skip(
                        "effect",
                        format!(
                            "sub-input `{field}[{k}]` flat width {} != scan layout {:?}",
                            leaves.len(),
                            expected
                        ),
                    );
                    return;
                }
                for (j, leaf) in leaves.iter().enumerate() {
                    let w = usize_lit(base_idx + j);
                    let tok = &leaf.tok;
                    if leaf.u32 {
                        self.out
                            .push(quote! { eval.set_sub_input_word_u32(#w, #tok); });
                    } else {
                        self.out.push(quote! { eval.set_sub_input_word(#w, #tok); });
                    }
                }
            }
            // *lookup_data.field = <array or scalar>;
            Expr::Field(ExprField {
                base,
                member: Member::Named(m),
                ..
            }) if is_path_named(base, &self.lookup_name) => {
                let field = m.to_string();
                let Some(lf) = self.lookup_fields.iter().find(|f| f.name == field).cloned() else {
                    self.skip(
                        "effect",
                        format!("lookup field not in LookupData: `{field}`"),
                    );
                    return;
                };
                let rhs = strip_parens(&a.right);
                if lf.scalar {
                    let (ty, v) = self.lower_node(rhs, Target::Temp);
                    self.require_m31(&ty, "lookup word", rhs);
                    let w = usize_lit(lf.base);
                    self.out.push(quote! { eval.set_lookup_word(#w, #v); });
                } else {
                    let elems = match rhs {
                        Expr::Array(ExprArray { elems, .. }) => elems,
                        _ => {
                            self.skip(
                                "effect",
                                format!(
                                    "lookup field `{field}` RHS not an array: `{}`",
                                    tok_str(rhs)
                                ),
                            );
                            return;
                        }
                    };
                    if elems.len() != lf.width {
                        self.skip(
                            "effect",
                            format!(
                                "lookup field `{field}` width {} != RHS len {}",
                                lf.width,
                                elems.len()
                            ),
                        );
                        return;
                    }
                    for (j, e) in elems.iter().enumerate() {
                        let (ty, v) = self.lower_node(strip_parens(e), Target::Temp);
                        self.require_m31(&ty, "lookup word", e);
                        let w = usize_lit(lf.base + j);
                        self.out.push(quote! { eval.set_lookup_word(#w, #v); });
                    }
                }
            }
            other => {
                self.skip(
                    "effect",
                    format!("unrecognized effect place: `{}`", tok_str(other)),
                );
            }
        }
    }

    /// Effect values must be M31-typed (Unknown means an inner skip already fired).
    fn require_m31(&mut self, ty: &Ty, what: &str, expr: &Expr) {
        if !ty.is_m31() && *ty != Ty::Unknown {
            self.skip(
                "effect",
                format!("{what} is {ty:?}, not M31: `{}`", tok_str(expr)),
            );
        }
    }

    // ---- aggregate (kept-verbatim tuples/arrays) -----------------------------------

    fn lower_aggregate(&mut self, expr: &Expr) -> (Ty, TokenStream) {
        match strip_parens(expr) {
            Expr::Tuple(ExprTuple { elems, .. }) => {
                let mut tys = Vec::new();
                let mut toks = Vec::new();
                for e in elems {
                    let (t, k) = self.lower_agg_elem(e);
                    tys.push(t);
                    toks.push(k);
                }
                (Ty::Tuple(tys), quote! { ( #(#toks),* ) })
            }
            Expr::Array(ExprArray { elems, .. }) => {
                let mut tys = Vec::new();
                let mut toks = Vec::new();
                for e in elems {
                    let (t, k) = self.lower_agg_elem(e);
                    tys.push(t);
                    toks.push(k);
                }
                let et = tys.first().cloned().unwrap_or(Ty::Unknown);
                (
                    Ty::Array(Box::new(et), toks.len()),
                    quote! { [ #(#toks),* ] },
                )
            }
            other => self.lower_node(other, Target::Temp),
        }
    }

    fn lower_agg_elem(&mut self, e: &Expr) -> (Ty, TokenStream) {
        match strip_parens(e) {
            Expr::Tuple(_) | Expr::Array(_) => self.lower_aggregate(e),
            other => self.lower_node(other, Target::Temp),
        }
    }

}
