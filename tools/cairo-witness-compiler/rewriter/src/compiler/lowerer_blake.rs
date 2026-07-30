impl Lowerer {
    /// `PackedTripleXor32::deduce_output([a, b, c])`.
    fn lower_triple_xor_deduce(
        &mut self,
        call: &ExprCall,
        target: Target,
    ) -> Option<TokenStream> {
        let Expr::Array(ExprArray { elems, .. }) = strip_parens(call.args.first()?) else {
            return None;
        };
        if call.args.len() != 1 || elems.len() != 3 {
            return None;
        }
        let values: Vec<TokenStream> = elems
            .iter()
            .map(|expr| {
                let (ty, token) = self.lower_node(strip_parens(expr), Target::Temp);
                if !ty.is_u32() {
                    self.skip(
                        "deduce_output",
                        format!("triple-xor input is not u32: `{}` ({ty:?})", tok_str(expr)),
                    );
                }
                self.u32ish_value(ty, token)
            })
            .collect();
        Some(self.bind(
            target,
            quote! { eval.deduce_triple_xor_32([ #(#values),* ]) },
        ))
    }

    /// Stateful `blake_round_state.deduce_output((chain, round, ([state; 16], ptr)))`.
    ///
    /// The semantic operation owns the memory reads. The emitted row body therefore
    /// stays backend-neutral while SIMD delegates to the official claim generator and
    /// recorded bytecode exposes one table-aware deduction selector to accelerators.
    fn lower_blake_round_deduce(
        &mut self,
        argument: &Expr,
        target: Target,
    ) -> Option<(Ty, TokenStream)> {
        let (input_ty, input) = self.lower_aggregate(argument);
        let output_ty = blake_round_io_ty();
        if input_ty != output_ty {
            self.skip(
                "deduce_output",
                format!("blake-round input has shape {input_ty:?}, expected {output_ty:?}"),
            );
            return None;
        }
        let token = self.bind(
            target,
            quote! {
                eval.deduce_blake_round(#input.0, #input.1, #input.2.0, #input.2.1)
            },
        );
        Some((output_ty, token))
    }
}
