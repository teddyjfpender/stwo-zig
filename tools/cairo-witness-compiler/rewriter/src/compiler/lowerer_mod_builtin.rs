impl Lowerer {
    /// Lowers the official mul-mod quotient boundary:
    /// `Big384::from_biguint((Big384(a)*Big384(b)-Big768(c))/Big768(p))`.
    fn lower_mul_mod_quotient(
        &mut self,
        call: &ExprCall,
        target: Target,
    ) -> Option<(Ty, TokenStream)> {
        if tok_str(&call.func)
            != "PackedBigUInt :: < 384 , 6 , 32 > :: from_packed_biguint :: < 768 , 12 , 64 >"
            || call.args.len() != 1
        {
            return None;
        }

        let Expr::Binary(div) = strip_parens(call.args.first()?) else {
            return None;
        };
        if !matches!(div.op, BinOp::Div(_)) {
            return None;
        }
        let Expr::Binary(sub) = strip_parens(&div.left) else {
            return None;
        };
        if !matches!(sub.op, BinOp::Sub(_)) {
            return None;
        }
        let Expr::MethodCall(mul) = strip_parens(&sub.left) else {
            return None;
        };
        if mul.method != "widening_mul" || mul.args.len() != 1 {
            return None;
        }

        let a = packed_biguint_felt4(&mul.receiver)?;
        let b = packed_biguint_felt4(mul.args.first()?)?;
        let c = packed_biguint_768_from_384_felt4(&sub.right)?;
        let p = packed_biguint_768_from_384_felt4(&div.right)?;

        let p = self.lower_mod_felts(p)?;
        let a = self.lower_mod_felts(a)?;
        let b = self.lower_mod_felts(b)?;
        let c = self.lower_mod_felts(c)?;
        Some(self.emit_op(
            target,
            Ty::Array(Box::new(Ty::M31), 32),
            quote! { eval.deduce_mul_mod_quotient([#(#p),*], [#(#a),*], [#(#b),*], [#(#c),*]) },
        ))
    }

    fn lower_mod_felts(&mut self, felts: Vec<&Expr>) -> Option<Vec<TokenStream>> {
        let mut tokens = Vec::with_capacity(4);
        for felt in felts {
            let (ty, token) = self.lower_node(strip_parens(felt), Target::Temp);
            if !ty.is_feltish() {
                self.skip(
                    "mod_biguint",
                    format!("expected Felt252 operand, got {ty:?} `{}`", tok_str(felt)),
                );
                return None;
            }
            tokens.push(self.feltish_value(ty, token));
        }
        Some(tokens)
    }

    fn lower_biguint384_felt4(
        &mut self,
        call: &ExprCall,
        target: Target,
    ) -> Option<(Ty, TokenStream)> {
        let felts = packed_biguint_felt4_call(call)?;
        let felts = self.lower_mod_felts(felts)?;
        let token = self.bind(target, quote! { [#(#felts),*] });
        Some((Ty::BigUInt384, token))
    }
}

fn packed_biguint_felt4(expr: &Expr) -> Option<Vec<&Expr>> {
    let Expr::Call(call) = strip_parens(expr) else {
        return None;
    };
    packed_biguint_felt4_call(call)
}

fn packed_biguint_felt4_call(call: &ExprCall) -> Option<Vec<&Expr>> {
    if tok_str(&call.func)
        != "PackedBigUInt :: < 384 , 6 , 32 > :: from_packed_felt252_array"
        || call.args.len() != 1
    {
        return None;
    }
    let mut array = strip_parens(call.args.first()?);
    if let Expr::Reference(reference) = array {
        array = strip_parens(&reference.expr);
    }
    let Expr::Array(array) = array else {
        return None;
    };
    (array.elems.len() == 4).then(|| array.elems.iter().collect())
}

fn packed_biguint_768_from_384_felt4(expr: &Expr) -> Option<Vec<&Expr>> {
    let Expr::Call(call) = strip_parens(expr) else {
        return None;
    };
    if tok_str(&call.func)
        != "PackedBigUInt :: < 768 , 12 , 64 > :: from_packed_biguint :: < 384 , 6 , 32 >"
        || call.args.len() != 1
    {
        return None;
    }
    packed_biguint_felt4(call.args.first()?)
}
