impl Lowerer {
    fn lower_binary(&mut self, b: &ExprBinary, target: Target) -> (Ty, TokenStream) {
        match b.op {
            BinOp::Shl(_) => {
                let (lt, ltok) = self.lower_node(&b.left, Target::Temp);
                if let Some(k) = self.peek_const_u16(&b.right) {
                    if lt.is_u16() {
                        let kl = u32_lit(k);
                        return self.emit_op(target, Ty::U16, quote! { eval.u16_shl(#ltok, #kl) });
                    }
                    self.skip("binop", format!("`<<` on non-U16 `{}`", tok_str(&b.left)));
                    return (Ty::Unknown, quote! { WG_SKIP });
                }
                if let Some(k) = self.peek_const_u32(&b.right) {
                    if lt.is_u32() {
                        let l = self.u32ish_value(lt, ltok);
                        let kl = u32_lit(k);
                        return self.emit_op(target, Ty::U32, quote! { eval.u32_shl_imm(#l, #kl) });
                    }
                    self.skip("binop", format!("`<<` (u32) on {:?}", lt));
                    return (Ty::Unknown, quote! { WG_SKIP });
                }
                let (rt, _rtok) = self.lower_node(&b.right, Target::Temp);
                if lt.is_u32() && rt.is_u32() {
                    return self.u32_site(Ty::U32);
                }
                self.skip(
                    "binop",
                    format!("`<<` by non-const `{}`", tok_str(&b.right)),
                );
                (Ty::Unknown, quote! { WG_SKIP })
            }
            BinOp::Shr(_) => {
                let (lt, ltok) = self.lower_node(&b.left, Target::Temp);
                if let Some(k) = self.peek_const_u16(&b.right) {
                    if lt.is_u16() {
                        let kl = u32_lit(k);
                        return self.emit_op(target, Ty::U16, quote! { eval.u16_shr(#ltok, #kl) });
                    }
                    self.skip("binop", format!("`>>` on non-U16 `{}`", tok_str(&b.left)));
                    return (Ty::Unknown, quote! { WG_SKIP });
                }
                if let Some(k) = self.peek_const_u32(&b.right) {
                    if lt.is_u32() {
                        let l = self.u32ish_value(lt, ltok);
                        let kl = u32_lit(k);
                        return self.emit_op(target, Ty::U32, quote! { eval.u32_shr_imm(#l, #kl) });
                    }
                    self.skip("binop", format!("`>>` (u32) on {:?}", lt));
                    return (Ty::Unknown, quote! { WG_SKIP });
                }
                let (rt, _rtok) = self.lower_node(&b.right, Target::Temp);
                if lt.is_u32() && rt.is_u32() {
                    return self.u32_site(Ty::U32);
                }
                self.skip(
                    "binop",
                    format!("`>>` by non-const `{}`", tok_str(&b.right)),
                );
                (Ty::Unknown, quote! { WG_SKIP })
            }
            BinOp::BitAnd(_) => {
                // `&` is either `u16 & CONST_MASK` (const on EITHER side — AND commutes),
                // `mask & mask`, or the census-only u32 form.
                if let Some(k) = self.peek_const_u16(&b.right) {
                    let (lt, ltok) = self.lower_node(&b.left, Target::Temp);
                    if lt.is_u16() {
                        let kl = u32_lit(k);
                        return self.emit_op(target, Ty::U16, quote! { eval.u16_and(#ltok, #kl) });
                    }
                    self.skip(
                        "binop",
                        format!("`&` (mask) on non-U16 `{}`", tok_str(&b.left)),
                    );
                    return (Ty::Unknown, quote! { WG_SKIP });
                }
                if let Some(k) = self.peek_const_u16(&b.left) {
                    let (rt, rtok) = self.lower_node(&b.right, Target::Temp);
                    if rt.is_u16() {
                        let kl = u32_lit(k);
                        return self.emit_op(target, Ty::U16, quote! { eval.u16_and(#rtok, #kl) });
                    }
                    self.skip(
                        "binop",
                        format!("`&` (mask) on non-U16 `{}`", tok_str(&b.right)),
                    );
                    return (Ty::Unknown, quote! { WG_SKIP });
                }
                if let Some(k) = self.peek_const_u32(&b.right) {
                    let (lt, ltok) = self.lower_node(&b.left, Target::Temp);
                    if lt.is_u32() {
                        let l = self.u32ish_value(lt, ltok);
                        let kl = u32_lit(k);
                        return self.emit_op(target, Ty::U32, quote! { eval.u32_and_imm(#l, #kl) });
                    }
                    self.skip("binop", format!("`&` (u32 mask) on {:?}", lt));
                    return (Ty::Unknown, quote! { WG_SKIP });
                }
                if let Some(k) = self.peek_const_u32(&b.left) {
                    let (rt, rtok) = self.lower_node(&b.right, Target::Temp);
                    if rt.is_u32() {
                        let r = self.u32ish_value(rt, rtok);
                        let kl = u32_lit(k);
                        return self.emit_op(target, Ty::U32, quote! { eval.u32_and_imm(#r, #kl) });
                    }
                    self.skip("binop", format!("`&` (u32 mask) on {:?}", rt));
                    return (Ty::Unknown, quote! { WG_SKIP });
                }
                let (lt, ltok) = self.lower_node(&b.left, Target::Temp);
                let (rt, rtok) = self.lower_node(&b.right, Target::Temp);
                if lt.is_mask() && rt.is_mask() {
                    return self.emit_op(target, Ty::Mask, quote! { eval.mask_and(#ltok, #rtok) });
                }
                if lt.is_u32() && rt.is_u32() {
                    return self.u32_site(Ty::U32);
                }
                self.skip("binop", format!("`&` on {:?}/{:?}", lt, rt));
                (Ty::Unknown, quote! { WG_SKIP })
            }
            BinOp::BitXor(_) => {
                if let Some(k) = self.peek_const_u16(&b.right) {
                    let (lt, ltok) = self.lower_node(&b.left, Target::Temp);
                    if lt.is_u16() {
                        let constant = self.materialize_u16_const(k);
                        return self.emit_op(
                            target,
                            Ty::U16,
                            quote! { eval.u16_xor(#ltok, #constant) },
                        );
                    }
                }
                if let Some(k) = self.peek_const_u16(&b.left) {
                    let (rt, rtok) = self.lower_node(&b.right, Target::Temp);
                    if rt.is_u16() {
                        let constant = self.materialize_u16_const(k);
                        return self.emit_op(
                            target,
                            Ty::U16,
                            quote! { eval.u16_xor(#constant, #rtok) },
                        );
                    }
                }
                let (lt, ltok) = self.lower_node(&b.left, Target::Temp);
                let (rt, rtok) = self.lower_node(&b.right, Target::Temp);
                if lt.is_u16() && rt.is_u16() {
                    return self.emit_op(target, Ty::U16, quote! { eval.u16_xor(#ltok, #rtok) });
                }
                if lt.is_u32() && rt.is_u32() {
                    return self.u32_site(Ty::U32);
                }
                self.skip("binop", format!("`^` on {:?}/{:?}", lt, rt));
                (Ty::Unknown, quote! { WG_SKIP })
            }
            BinOp::Add(_) => {
                let (lt, ltok) = self.lower_node(&b.left, Target::Temp);
                let (rt, rtok) = self.lower_node(&b.right, Target::Temp);
                if lt == Ty::BigUInt384 && rt == Ty::BigUInt384 {
                    let token = self.bind(target, quote! { (#ltok, #rtok) });
                    (Ty::BigUInt384Sum, token)
                } else if lt.is_m31() && rt.is_m31() {
                    self.emit_op(target, Ty::M31, quote! { eval.m31_add(#ltok, #rtok) })
                } else if lt.is_u16() && rt.is_u16() {
                    self.emit_op(target, Ty::U16, quote! { eval.u16_add(#ltok, #rtok) })
                } else if lt.is_u16() {
                    if let Ty::ConstU16(k) = rt {
                        let c = self.materialize_u16_const(k);
                        self.emit_op(target, Ty::U16, quote! { eval.u16_add(#ltok, #c) })
                    } else {
                        self.skip("binop", format!("`+` on U16/{:?}", rt));
                        (Ty::Unknown, quote! { WG_SKIP })
                    }
                } else if rt.is_u16() {
                    if let Ty::ConstU16(k) = lt {
                        let c = self.materialize_u16_const(k);
                        self.emit_op(target, Ty::U16, quote! { eval.u16_add(#c, #rtok) })
                    } else {
                        self.skip("binop", format!("`+` on {:?}/U16", lt));
                        (Ty::Unknown, quote! { WG_SKIP })
                    }
                } else if lt.is_u32() && rt.is_u32() {
                    let l = self.u32ish_value(lt, ltok);
                    let r = self.u32ish_value(rt, rtok);
                    self.emit_op(target, Ty::U32, quote! { eval.u32_add(#l, #r) })
                } else if lt.is_feltish() && rt.is_feltish() {
                    let l = self.feltish_value(lt, ltok);
                    let r = self.feltish_value(rt, rtok);
                    self.emit_op(
                        target,
                        Ty::Felt252,
                        quote! { eval.felt_add(#l.clone(), #r.clone()) },
                    )
                } else {
                    self.skip("binop", format!("`+` on {:?}/{:?}", lt, rt));
                    (Ty::Unknown, quote! { WG_SKIP })
                }
            }
            BinOp::Sub(_) => {
                let (lt, ltok) = self.lower_node(&b.left, Target::Temp);
                let (rt, rtok) = self.lower_node(&b.right, Target::Temp);
                if lt == Ty::BigUInt384Sum && rt == Ty::BigUInt384 {
                    let token = self.bind(
                        target,
                        quote! { eval.deduce_add_mod_is_zero(#ltok.0, #ltok.1, #rtok) },
                    );
                    (Ty::BigUInt384DiffZeroMask, token)
                } else if lt.is_m31() && rt.is_m31() {
                    self.emit_op(target, Ty::M31, quote! { eval.m31_sub(#ltok, #rtok) })
                } else if lt.is_u32() && rt.is_u32() {
                    let l = self.u32ish_value(lt, ltok);
                    let r = self.u32ish_value(rt, rtok);
                    self.emit_op(target, Ty::U32, quote! { eval.u32_sub(#l, #r) })
                } else if lt.is_feltish() && rt.is_feltish() {
                    let l = self.feltish_value(lt, ltok);
                    let r = self.feltish_value(rt, rtok);
                    self.emit_op(
                        target,
                        Ty::Felt252,
                        quote! { eval.felt_sub(#l.clone(), #r.clone()) },
                    )
                } else {
                    self.skip("binop", format!("`-` on {:?}/{:?}", lt, rt));
                    (Ty::Unknown, quote! { WG_SKIP })
                }
            }
            BinOp::Mul(_) => {
                let (lt, ltok) = self.lower_node(&b.left, Target::Temp);
                let (rt, rtok) = self.lower_node(&b.right, Target::Temp);
                if lt.is_m31() && rt.is_m31() {
                    self.emit_op(target, Ty::M31, quote! { eval.m31_mul(#ltok, #rtok) })
                } else if lt.is_feltish() && rt.is_feltish() {
                    let l = self.feltish_value(lt, ltok);
                    let r = self.feltish_value(rt, rtok);
                    self.emit_op(
                        target,
                        Ty::Felt252,
                        quote! { eval.felt_mul(#l.clone(), #r.clone()) },
                    )
                } else {
                    self.skip("binop", format!("`*` on {:?}/{:?}", lt, rt));
                    (Ty::Unknown, quote! { WG_SKIP })
                }
            }
            BinOp::Div(_) => {
                // ONLY felt division exists in the writers (EC slope denominators;
                // the host `Felt252::div` panics on zero — see DeduceKind::FeltDiv).
                let (lt, ltok) = self.lower_node(&b.left, Target::Temp);
                let (rt, rtok) = self.lower_node(&b.right, Target::Temp);
                if lt.is_feltish() && rt.is_feltish() {
                    let l = self.feltish_value(lt, ltok);
                    let r = self.feltish_value(rt, rtok);
                    self.emit_op(
                        target,
                        Ty::Felt252,
                        quote! { eval.felt_div(#l.clone(), #r.clone()) },
                    )
                } else {
                    self.skip("binop", format!("`/` on {:?}/{:?}", lt, rt));
                    (Ty::Unknown, quote! { WG_SKIP })
                }
            }
            other => {
                let _ = self.lower_node(&b.left, Target::Temp);
                let _ = self.lower_node(&b.right, Target::Temp);
                self.skip(
                    "binop",
                    format!("unsupported binary op `{}`", tok_str_op(&other)),
                );
                (Ty::Unknown, quote! { WG_SKIP })
            }
        }
    }

    /// Emit an eval-op RHS bound to `target`. Returns (ty, value-token).
    fn emit_op(&mut self, target: Target, ty: Ty, rhs: TokenStream) -> (Ty, TokenStream) {
        let tok = self.bind(target, rhs);
        (ty, tok)
    }

    fn lower_arg(&mut self, arg: Option<&Expr>) -> (Ty, TokenStream) {
        match arg {
            Some(e) => self.lower_node(strip_parens(e), Target::Temp),
            None => {
                self.skip("expr", "missing argument".to_string());
                (Ty::Unknown, quote! { WG_SKIP })
            }
        }
    }

    /// Lower a `sub_component_inputs` RHS into ordered scalar leaf tokens (source order,
    /// which is exactly the shape's scalar order).
    fn flatten_sub(&mut self, expr: &Expr) -> Vec<SubLeaf> {
        let m31 = |tok: TokenStream| SubLeaf { tok, u32: false };
        match strip_parens(expr) {
            Expr::Tuple(ExprTuple { elems, .. }) | Expr::Array(ExprArray { elems, .. }) => {
                let mut leaves = Vec::new();
                for e in elems {
                    leaves.extend(self.flatten_sub(e));
                }
                leaves
            }
            other => {
                let (ty, tok) = self.lower_node(other, Target::Temp);
                match ty {
                    // Full-32-bit sub element (blake words): one raw word, stored via
                    // the u32 effect (the flat transport is raw lanes).
                    Ty::U32 => vec![SubLeaf { tok, u32: true }],
                    constant @ Ty::ConstU32(_) => vec![SubLeaf {
                        tok: self.u32ish_value(constant, tok),
                        u32: true,
                    }],
                    // Felt-valued sub element: 28 flat limb words (the canonical
                    // decomposition; the driver's `from_limbs` reconstruction is the
                    // exact inverse, so the receiver sees the identical felt).
                    Ty::Felt252 => {
                        let felt = self.bind(Target::Temp, quote! { #tok });
                        (0..FELT252_LIMBS)
                            .map(|j| {
                                let jl = usize_lit(j);
                                m31(self
                                    .bind(Target::Temp, quote! { eval.felt_get_m31(&#felt, #jl) }))
                            })
                            .collect()
                    }
                    Ty::ConstFelt252(limbs) => (0..FELT252_LIMBS)
                        .map(|j| {
                            let (_t, tok) = self.const_m31_leaf(Target::Temp, limbs[j]);
                            m31(tok)
                        })
                        .collect(),
                    Ty::FeltW27Limbs => (0..FELTW27_LIMBS)
                        .map(|j| {
                            let index = usize_lit(j);
                            m31(quote! { #tok[#index] })
                        })
                        .collect(),
                    _ => {
                        self.require_m31(&ty, "sub-input word", other);
                        vec![m31(tok)]
                    }
                }
            }
        }
    }

    fn materialize_u16_const(&mut self, k: u32) -> TokenStream {
        self.referenced_m31.insert(k);
        let c = Ident::new(&format!("m31_{k}"), Span::call_site());
        let t = self.fresh();
        self.out.push(quote! { let #t = eval.u16_from_m31(#c); });
        quote! { #t }
    }

    fn classify_const(&self, name: &str) -> Option<ConstVal> {
        if let Some(cv) = self.consts.get(name) {
            return Some(*cv);
        }
        // Fallback: parse `M31_<k>` / `UInt16_<k>` / `UInt32_<k>` from the name.
        for (prefix, kind) in [
            ("M31_", ConstKind::M31),
            ("UInt16_", ConstKind::U16),
            ("UInt32_", ConstKind::U32),
        ] {
            if let Some(rest) = name.strip_prefix(prefix)
                && let Ok(v) = rest.parse::<u32>() {
                    return Some(ConstVal { kind, value: v });
                }
        }
        None
    }

    fn peek_const_u16(&self, expr: &Expr) -> Option<u32> {
        self.peek_const_kind(expr, |k| matches!(k, ConstKind::U16))
    }
    fn peek_const_u32(&self, expr: &Expr) -> Option<u32> {
        self.peek_const_kind(expr, |k| matches!(k, ConstKind::U32))
    }
    fn peek_const_kind(&self, expr: &Expr, want: impl Fn(&ConstKind) -> bool) -> Option<u32> {
        match strip_parens(expr) {
            Expr::Path(p) => {
                let name = tok_str(&p.path);
                match self.classify_const(&name) {
                    Some(ConstVal { kind, value }) if want(&kind) => Some(value),
                    _ => None,
                }
            }
            _ => None,
        }
    }
}
