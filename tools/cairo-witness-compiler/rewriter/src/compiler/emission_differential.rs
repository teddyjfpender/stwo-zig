/// The component-independent compare bundle.
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

/// Emit the test-only original-versus-generic SIMD comparison harness.
fn generic_simd_diff_fn_tokens(
    writer: &ItemFn,
    file: &syn::File,
    lw: &Lowerer,
) -> TokenStream {
    // Some interaction generators carry an extra `n_rows` field. The writer
    // parameter is already in scope in the generated harness.
    let ig_has_n_rows = file.items.iter().any(|item| match item {
        Item::Struct(item) if item.ident == "InteractionClaimGenerator" => match &item.fields {
            Fields::Named(fields) => fields
                .named
                .iter()
                .any(|field| field.ident.as_ref().is_some_and(|ident| ident == "n_rows")),
            _ => false,
        },
        _ => false,
    });
    let ig_extra: TokenStream = if ig_has_n_rows {
        quote! { n_rows, }
    } else {
        quote! {}
    };
    let ig_log_size: TokenStream = if igen_has_log_size(file) {
        quote! { log_size, }
    } else {
        quote! {}
    };
    let inputs = &writer.sig.inputs;
    let mut names: Vec<Ident> = Vec::new();
    let mut by_value: Vec<bool> = Vec::new();
    for argument in inputs {
        if let FnArg::Typed(argument) = argument
            && let Pat::Ident(pattern) = &*argument.pat
        {
            names.push(pattern.ident.clone());
            by_value.push(!matches!(&*argument.ty, Type::Reference(_)));
        }
    }
    let first_args: Vec<TokenStream> = names
        .iter()
        .zip(&by_value)
        .map(|(name, by_value)| {
            if *by_value {
                quote! { #name.clone() }
            } else {
                quote! { #name }
            }
        })
        .collect();
    let second_args = &names;
    let calls = match lw.writer_shape {
        WriterShape::Lookup => quote! {
            let (trace_o, ld_o) = write_trace_simd(#(#first_args),*);
            let (trace_g, ld_g) = write_trace_generic_simd(#(#second_args),*);
            let orig_sub = sub_inputs_flat();
            let gen_sub = sub_inputs_flat();
        },
        WriterShape::LookupSub | WriterShape::LookupSubInput => quote! {
            let (trace_o, ld_o, sci_o) = write_trace_simd(#(#first_args),*);
            let (trace_g, ld_g, sci_g) = write_trace_generic_simd(#(#second_args),*);
            let orig_sub = sub_inputs_flat(&sci_o);
            let gen_sub = sub_inputs_flat(&sci_g);
        },
    };
    quote! {
        #[cfg(test)]
        pub(crate) fn generic_simd_diff(#inputs) -> GenericSimdDiff {
            #calls

            let log_size = trace_o.log_size();
            let orig_rows = (0..(1usize << log_size))
                .map(|r| trace_o.row_at(r))
                .collect();
            let gen_rows = (0..(1usize << log_size))
                .map(|r| trace_g.row_at(r))
                .collect();

            let orig_lookup = lookup_data_flat(&ld_o);
            let gen_lookup = lookup_data_flat(&ld_g);

            let common = relations::CommonLookupElements::dummy();
            let (raw_o, _) = InteractionClaimGenerator {
                #ig_log_size
                #ig_extra
                lookup_data: ld_o,
            }
            .write_interaction_trace(&common);
            let (raw_g, _) = InteractionClaimGenerator {
                #ig_log_size
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
