impl Lowerer {
    // ---- expression-level (the op routing table) -----------------------------------

    /// Lower `expr`, emitting SSA temps for every eval op. Returns the inferred type and a
    /// SIMPLE token (ident / literal / projection) naming the value.
    fn lower_node(&mut self, expr: &Expr, target: Target) -> (Ty, TokenStream) {
        let expr = strip_parens(expr);
        // Multiplicity-column read (`*mults[k].get(row_index).unwrap_or(&zero)`): a
        // REAL per-row input read — the builtin lane feeds `mults[k]` as the input
        // column after the flat inputs, enabler, iota, and named preprocessed
        // columns. The SIMD driver appends the same reads in the same order.
        if let Some(k) = match_mults_read(expr, &self.row_index_name) {
            if matches!(self.input_ty, Ty::Unknown) {
                self.skip(
                    "expr",
                    format!("mults read outside a typed builtin: `{}`", tok_str(expr)),
                );
                return (Ty::Unknown, quote! { WG_SKIP });
            }
            self.mults_reads.insert(k);
            let slot = u32_lit(self.multiplicity_slot(k) as u32);
            return self.emit_op(target, Ty::M31, quote! { eval.input(#slot) });
        }
        match expr {
            Expr::Path(p) => self.lower_path(p, target),
            Expr::Field(f) => self.lower_field(f, target),
            Expr::Index(ix) => self.lower_index(ix, target),
            Expr::MethodCall(mc) => self.lower_method(mc, target),
            Expr::Call(call) => self.lower_call(call, target),
            Expr::Binary(b) => self.lower_binary(b, target),
            Expr::Struct(st) => self.lower_struct(st, target),
            other => {
                self.skip(
                    "expr",
                    format!("unsupported expression: `{}`", tok_str(other)),
                );
                (Ty::Unknown, quote! { WG_SKIP })
            }
        }
    }

    /// Leaf value: return its token, aliasing into `target` only when Named.
    fn leaf(&mut self, target: Target, ty: Ty, tok: TokenStream) -> (Ty, TokenStream) {
        match target {
            Target::Named(_) => {
                let out = self.bind(target, tok);
                (ty, out)
            }
            Target::Temp => (ty, tok),
        }
    }

    fn lower_path(&mut self, p: &ExprPath, target: Target) -> (Ty, TokenStream) {
        let name = tok_str(&p.path);
        if let Some(cv) = self.classify_const(&name) {
            match cv.kind {
                ConstKind::M31 => {
                    self.referenced_m31.insert(cv.value);
                    let id = Ident::new(&format!("m31_{}", cv.value), Span::call_site());
                    return self.leaf(target, Ty::ConstM31(cv.value), quote! { #id });
                }
                ConstKind::U16 => {
                    // A u16 const as a bare value only occurs in shift/mask (peeked) or
                    // additive (specially lowered) position — never materialized here.
                    return (Ty::ConstU16(cv.value), quote! { WG_U16_CONST });
                }
                ConstKind::U32 => {
                    return (Ty::ConstU32(cv.value), quote! { WG_U32_CONST });
                }
            }
        }
        if let Some(limbs) = self.felt_consts.get(&name).copied() {
            return self.felt_const_value(target, limbs);
        }
        if name == self.input_name {
            return self.input_leaf(target);
        }
        if let Some(ty) = self.env.get(&name).cloned() {
            let id = Ident::new(&name, Span::call_site());
            // `E::Felt` is Clone-not-Copy: an alias binding (`let new = old;`)
            // must clone, or the original moves and later uses are E0382
            // (cube_252's unpack alias). Every other handle type is Copy.
            if ty == Ty::Felt252 {
                return self.leaf(target, ty, quote! { #id.clone() });
            }
            return self.leaf(target, ty, quote! { #id });
        }
        self.skip("expr", format!("unknown identifier `{name}`"));
        (Ty::Unknown, quote! { WG_SKIP })
    }

    fn lower_field(&mut self, f: &ExprField, target: Target) -> (Ty, TokenStream) {
        match &f.member {
            Member::Named(m) => {
                // <name>_input.pc / .ap / .fp
                if is_path_named(&f.base, &self.input_name) {
                    let slot: &'static str = match m.to_string().as_str() {
                        "pc" => "SLOT_PC",
                        "ap" => "SLOT_AP",
                        "fp" => "SLOT_FP",
                        other => {
                            self.skip(
                                "input_field",
                                format!("input.{other} (unsupported input field)"),
                            );
                            return (Ty::Unknown, quote! { WG_SKIP });
                        }
                    };
                    self.used_slots.insert(slot);
                    let slot_id = Ident::new(slot, Span::call_site());
                    return self.emit_op(target, Ty::M31, quote! { eval.input(#slot_id) });
                }
                let (bt, btok) = self.lower_node(&f.base, Target::Temp);
                if bt == Ty::CasmState {
                    let index = match m.to_string().as_str() {
                        "pc" => 0,
                        "ap" => 1,
                        "fp" => 2,
                        other => {
                            self.skip(
                                "expr",
                                format!("unknown PackedCasmState field `.{other}`"),
                            );
                            return (Ty::Unknown, quote! { WG_SKIP });
                        }
                    };
                    let index = Literal::usize_unsuffixed(index);
                    return self.leaf(target, Ty::M31, quote! { #btok.#index });
                }
                self.skip(
                    "expr",
                    format!(
                        "field access `.{m}` on non-input base `{}`",
                        tok_str(&f.base)
                    ),
                );
                (Ty::Unknown, quote! { WG_SKIP })
            }
            Member::Unnamed(idx) => {
                // Tuple projection x.0 / x.1 ...
                let (bt, btok) = self.lower_node(&f.base, Target::Temp);
                let i = idx.index as usize;
                // Input-rooted projection: descend the wrapper with the flat slot base
                // advanced past the preceding elements' widths.
                if let Ty::InputAt(inner, base) = &bt {
                    if let Ty::Tuple(v) = &**inner
                        && i < v.len() {
                            let child_base =
                                base + v[..i].iter().map(Ty::flat_width).sum::<usize>();
                            let child = Ty::InputAt(Box::new(v[i].clone()), child_base);
                            return self.input_projection(target, child, "input tuple elem");
                        }
                    self.skip(
                        "expr",
                        format!("tuple projection .{i} on input `{}`", tok_str(&f.base)),
                    );
                    return (Ty::Unknown, quote! { WG_SKIP });
                }
                let elem_ty = match &bt {
                    Ty::Tuple(v) if i < v.len() => v[i].clone(),
                    _ => {
                        self.skip(
                            "expr",
                            format!("tuple projection .{i} on non-tuple `{}`", tok_str(&f.base)),
                        );
                        Ty::Unknown
                    }
                };
                let lit = Literal::usize_unsuffixed(i);
                // `E::Felt` is Clone (not Copy): reading a felt element out of a
                // runtime tuple must clone, or the emitted code moves out of the value.
                if matches!(elem_ty, Ty::Felt252) {
                    return self.leaf(target, elem_ty, quote! { #btok.#lit.clone() });
                }
                self.leaf(target, elem_ty, quote! { #btok.#lit })
            }
        }
    }

    /// Lower the one named aggregate generated in witness bodies without coupling
    /// emitted code to its concrete Rust type. Field names, completeness, and value
    /// types are checked explicitly; source drift therefore fails closed.
    fn lower_struct(&mut self, st: &ExprStruct, target: Target) -> (Ty, TokenStream) {
        if tok_str(&st.path) != "PackedCasmState" {
            self.skip(
                "expr",
                format!("unsupported struct expression `{}`", tok_str(&st.path)),
            );
            return (Ty::Unknown, quote! { WG_SKIP });
        }
        if st.rest.is_some() {
            self.skip(
                "expr",
                "PackedCasmState update syntax is unsupported".to_string(),
            );
            return (Ty::Unknown, quote! { WG_SKIP });
        }

        let mut fields = BTreeMap::new();
        for field in &st.fields {
            let Member::Named(name) = &field.member else {
                self.skip(
                    "expr",
                    "PackedCasmState has an unnamed field".to_string(),
                );
                return (Ty::Unknown, quote! { WG_SKIP });
            };
            let name = name.to_string();
            if !matches!(name.as_str(), "pc" | "ap" | "fp") {
                self.skip(
                    "expr",
                    format!("unknown PackedCasmState field `{name}`"),
                );
                return (Ty::Unknown, quote! { WG_SKIP });
            }
            if fields.insert(name.clone(), &field.expr).is_some() {
                self.skip(
                    "expr",
                    format!("duplicate PackedCasmState field `{name}`"),
                );
                return (Ty::Unknown, quote! { WG_SKIP });
            }
        }

        let mut values = Vec::with_capacity(3);
        for name in ["pc", "ap", "fp"] {
            let Some(expr) = fields.get(name) else {
                self.skip(
                    "expr",
                    format!("missing PackedCasmState field `{name}`"),
                );
                return (Ty::Unknown, quote! { WG_SKIP });
            };
            let (ty, tok) = self.lower_node(strip_parens(expr), Target::Temp);
            self.require_m31(&ty, &format!("PackedCasmState.{name}"), expr);
            values.push(tok);
        }
        let tok = self.bind(target, quote! { ( #(#values),* ) });
        (Ty::CasmState, tok)
    }

    fn lower_index(&mut self, ix: &ExprIndex, target: Target) -> (Ty, TokenStream) {
        let (bt, btok) = self.lower_node(&ix.expr, Target::Temp);
        let Some(i) = expr_usize(&ix.index) else {
            self.skip(
                "expr",
                format!("non-literal index: `{}`", tok_str(&ix.index)),
            );
            return (Ty::Unknown, quote! { WG_SKIP });
        };
        // Input-rooted projection: descend the wrapper, base advanced by whole elements.
        if let Ty::InputAt(inner, base) = &bt {
            if let Ty::Array(e, n) = &**inner
                && i < *n {
                    let child_base = base + e.flat_width() * i;
                    let child = Ty::InputAt(Box::new((**e).clone()), child_base);
                    return self.input_projection(target, child, "input array elem");
                }
            self.skip(
                "expr",
                format!("index [{i}] on input `{}`", tok_str(&ix.expr)),
            );
            return (Ty::Unknown, quote! { WG_SKIP });
        }
        let elem_ty = match &bt {
            Ty::Array(e, _) => (**e).clone(),
            _ => {
                self.skip(
                    "expr",
                    format!("index [{i}] on non-array `{}`", tok_str(&ix.expr)),
                );
                Ty::Unknown
            }
        };
        let lit = usize_lit(i);
        // `E::Felt` is Clone (not Copy): see the tuple-projection note.
        if matches!(elem_ty, Ty::Felt252) {
            return self.leaf(target, elem_ty, quote! { #btok[#lit].clone() });
        }
        self.leaf(target, elem_ty, quote! { #btok[#lit] })
    }

    fn lower_method(&mut self, mc: &ExprMethodCall, target: Target) -> (Ty, TokenStream) {
        let method = mc.method.to_string();
        match method.as_str() {
            "get_m31" => {
                // Hoisted felt const receiver: the limb is a transform-time constant
                // (G3) — no need to materialize the felt.
                if let Some(limbs) = self.peek_felt_const(&mc.receiver) {
                    let Some(i) = mc.args.first().and_then(expr_usize) else {
                        self.skip("expr", "get_m31 without literal index".to_string());
                        return (Ty::Unknown, quote! { WG_SKIP });
                    };
                    if i >= FELT252_LIMBS {
                        self.skip(
                            "expr",
                            format!("get_m31({i}) out of range for Felt252 (28 limbs)"),
                        );
                        return (Ty::Unknown, quote! { WG_SKIP });
                    }
                    return self.const_m31_leaf(target, limbs[i]);
                }
                let (rt, rtok) = self.lower_node(&mc.receiver, Target::Temp);
                let Some(i) = mc.args.first().and_then(expr_usize) else {
                    self.skip("expr", "get_m31 without literal index".to_string());
                    return (Ty::Unknown, quote! { WG_SKIP });
                };
                let lit = usize_lit(i);
                // WIDTH-AWARE (G1): `felt_get_m31` is 28x9 semantics ONLY. A Width27
                // receiver must never route through it, and out-of-range indices are
                // SOURCE bugs that must skip loudly, not wrap.
                match rt {
                    Ty::Array(element, len) if element.is_m31() && i < len => {
                        self.leaf(target, Ty::M31, quote! { #rtok[#lit] })
                    }
                    Ty::Array(element, len) if element.is_m31() => {
                        self.skip(
                            "expr",
                            format!("get_m31({i}) out of range for M31 array ({len} words)"),
                        );
                        (Ty::Unknown, quote! { WG_SKIP })
                    }
                    Ty::Felt252 if i < FELT252_LIMBS => {
                        self.emit_op(target, Ty::M31, quote! { eval.felt_get_m31(&#rtok, #lit) })
                    }
                    Ty::Felt252 => {
                        self.skip(
                            "expr",
                            format!("get_m31({i}) out of range for Felt252 (28 limbs)"),
                        );
                        (Ty::Unknown, quote! { WG_SKIP })
                    }
                    Ty::ConstFelt252(limbs) if i < FELT252_LIMBS => {
                        self.const_m31_leaf(target, limbs[i])
                    }
                    Ty::ConstFelt252(_) => {
                        self.skip(
                            "expr",
                            format!("get_m31({i}) out of range for Felt252 (28 limbs)"),
                        );
                        (Ty::Unknown, quote! { WG_SKIP })
                    }
                    Ty::FeltW27 if i < FELTW27_LIMBS => self.w27_site(Ty::M31),
                    Ty::FeltW27Limbs if i < FELTW27_LIMBS => {
                        // The transformer holds the 10 limb tokens as an array value.
                        self.leaf(target, Ty::M31, quote! { #rtok[#lit] })
                    }
                    Ty::FeltW27 | Ty::FeltW27Limbs => {
                        self.skip(
                            "expr",
                            format!(
                                "get_m31({i}) out of range for Felt252Width27 (10 limbs) — \
                                 source bug"
                            ),
                        );
                        (Ty::Unknown, quote! { WG_SKIP })
                    }
                    _ => {
                        // Unknown/other receiver: record the skip; the RESULT of a
                        // source-level `get_m31` is always PackedM31, so type M31 to
                        // limit cascade noise (emission is blocked by the skip).
                        self.skip(
                            "expr",
                            format!("get_m31 on non-Felt `{}`", tok_str(&mc.receiver)),
                        );
                        self.emit_op(target, Ty::M31, quote! { eval.felt_get_m31(&#rtok, #lit) })
                    }
                }
            }
            "as_m31" => {
                let (rt, rtok) = self.lower_node(&mc.receiver, Target::Temp);
                if rt.is_u16() {
                    self.emit_op(target, Ty::M31, quote! { eval.u16_as_m31(#rtok) })
                } else if rt.is_mask() {
                    self.emit_op(target, Ty::M31, quote! { eval.mask_as_m31(#rtok) })
                } else {
                    self.skip(
                        "expr",
                        format!("as_m31 on {:?} `{}`", rt, tok_str(&mc.receiver)),
                    );
                    (Ty::Unknown, quote! { WG_SKIP })
                }
            }
            // u32 family (census-only): .low()/.high() split a u32 into u16 halves.
            // Cross-checked against `UInt32` (common `prover_types/cpu.rs`):
            //   .low()  = value & 0xFFFF  → ISA `Trunc16` (or `U32And` imm 0xFFFF)
            //   .high() = value >> 16     → ISA `U32Shr` imm 16
            //   from_limbs(low, high) = (low & 0xFFFF) | ((high & 0xFFFF) << 16)
            // Both halves are U16-typed; emission needs the u32 trait extension.
            "low" | "high" => {
                let (rt, rtok) = self.lower_node(&mc.receiver, Target::Temp);
                if rt.is_u32() {
                    // REAL trait ops now (u32 trait extension landed).
                    let op = Ident::new(
                        if method == "low" {
                            "u32_low"
                        } else {
                            "u32_high"
                        },
                        Span::call_site(),
                    );
                    self.emit_op(target, Ty::U16, quote! { eval.#op(#rtok) })
                } else {
                    self.skip(
                        "method",
                        format!(".{method}() on `{}`", tok_str(&mc.receiver)),
                    );
                    (Ty::Unknown, quote! { WG_SKIP })
                }
            }
            "eq" => {
                let (rt, rtok) = self.lower_node(&mc.receiver, Target::Temp);
                if rt == Ty::BigUInt384DiffZeroMask
                    && mc.args.len() == 1
                    && tok_str(strip_parens(mc.args.first().expect("length checked")))
                        == "BigUInt_384_6_32_0_0_0_0_0_0"
                {
                    return self.leaf(target, Ty::Mask, quote! { #rtok });
                }
                let (_at, atok) = self.lower_arg(mc.args.first());
                if !rt.is_m31() {
                    self.skip("expr", format!("eq on non-M31 `{}`", tok_str(&mc.receiver)));
                }
                self.emit_op(target, Ty::Mask, quote! { eval.m31_eq(#rtok, #atok) })
            }
            "inverse" => {
                let (rt, rtok) = self.lower_node(&mc.receiver, Target::Temp);
                if !rt.is_m31() {
                    self.skip(
                        "expr",
                        format!("inverse on non-M31 `{}`", tok_str(&mc.receiver)),
                    );
                }
                self.emit_op(target, Ty::M31, quote! { eval.m31_inverse(#rtok) })
            }
            "deduce_output" => {
                let recv = tok_str(strip_parens(&mc.receiver));
                if Some(&recv) == self.blake_round_state.as_ref() {
                    return match mc.args.first() {
                        Some(argument) => self
                            .lower_blake_round_deduce(argument, target)
                            .unwrap_or_else(|| (Ty::Unknown, quote! { WG_SKIP })),
                        None => {
                            self.skip("expr", "missing Blake-round argument".to_string());
                            (Ty::Unknown, quote! { WG_SKIP })
                        }
                    };
                }
                // Aggregate-aware: builtin deduce args are tuples; lower their leaves
                // for real (the deduce itself skips below for non-mem receivers).
                let (_at, atok) = match mc.args.first() {
                    Some(e) => self.lower_aggregate(strip_parens(e)),
                    None => {
                        self.skip("expr", "missing argument".to_string());
                        (Ty::Unknown, quote! { WG_SKIP })
                    }
                };
                if Some(&recv) == self.addr_state.as_ref() {
                    self.emit_op(target, Ty::M31, quote! { eval.mem_addr_to_id(#atok) })
                } else if Some(&recv) == self.big_state.as_ref() {
                    self.emit_op(target, Ty::Felt252, quote! { eval.mem_id_to_value(#atok) })
                } else {
                    self.skip("deduce_output", format!("{recv}.deduce_output"));
                    (Ty::Unknown, quote! { WG_SKIP })
                }
            }
            "packed_at" => {
                if is_path_named(&mc.receiver, "enabler_col") {
                    self.emit_op(target, Ty::M31, quote! { eval.enabler() })
                } else if self
                    .seq_idents
                    .iter()
                    .any(|s| is_path_named(&mc.receiver, s))
                    && mc
                        .args
                        .first()
                        .map(|a| is_path_named(a, &self.row_index_name))
                        .unwrap_or(false)
                {
                    // `seq.packed_at(row_index)` — the packed row index (Seq is the
                    // identity sequence). A REAL trait op now: the SIMD evaluator
                    // derives it from `row_index` bit-identically to `Seq::packed_at`;
                    // the recording lane reads the designated iota input slot (G4).
                    self.uses_iota = true;
                    self.emit_op(target, Ty::M31, quote! { eval.iota() })
                } else if let Expr::Path(path) = strip_parens(&mc.receiver)
                    && let Some(ordinal) = path
                        .path
                        .get_ident()
                        .and_then(|ident| self.preprocessed_slots.get(&ident.to_string()))
                    && mc
                        .args
                        .first()
                        .map(|arg| is_path_named(arg, &self.row_index_name))
                        .unwrap_or(false)
                {
                    let slot = u32_lit(self.preprocessed_slot(*ordinal) as u32);
                    self.emit_op(target, Ty::M31, quote! { eval.input(#slot) })
                } else {
                    // preprocessed column .packed_at(row_index) etc.
                    self.skip(
                        "method",
                        format!("{}.packed_at (non-enabler)", tok_str(&mc.receiver)),
                    );
                    (Ty::Unknown, quote! { WG_SKIP })
                }
            }
            other => {
                // Recurse into args for census completeness, then skip.
                for a in &mc.args {
                    let _ = self.lower_aggregate(a);
                }
                self.skip(
                    "method",
                    format!(".{other}() on `{}`", tok_str(&mc.receiver)),
                );
                (Ty::Unknown, quote! { WG_SKIP })
            }
        }
    }

}
