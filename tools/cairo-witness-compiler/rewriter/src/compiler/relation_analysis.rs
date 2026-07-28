fn parse_logup_descs(file: &syn::File) -> Option<Vec<LogupDescFact>> {
    use quote::ToTokens;

    // `&self.lookup_data.FIELD` → FIELD.
    fn lookup_field(e: &Expr) -> Option<String> {
        let e = strip_parens(e);
        let inner = if let Expr::Reference(r) = e {
            strip_parens(&r.expr)
        } else {
            e
        };
        let Expr::Field(f) = inner else { return None };
        let Expr::Field(base) = strip_parens(&f.base) else {
            return None;
        };
        let syn::Member::Named(m) = &base.member else {
            return None;
        };
        if m != "lookup_data" {
            return None;
        }
        match &f.member {
            syn::Member::Named(id) => Some(id.to_string()),
            syn::Member::Unnamed(_) => None,
        }
    }

    // Find `fn write_interaction_trace` (any impl block).
    let mut body: Option<&syn::Block> = None;
    for item in &file.items {
        if let syn::Item::Impl(im) = item {
            for ii in &im.items {
                if let syn::ImplItem::Fn(f) = ii
                    && f.sig.ident == "write_interaction_trace" {
                        body = Some(&f.block);
                    }
            }
        }
    }
    let body = body?;

    struct ColVisitor {
        descs: Vec<LogupDescFact>,
        failed: Option<String>,
    }
    impl<'a> syn::visit::Visit<'a> for ColVisitor {
        fn visit_expr_method_call(&mut self, node: &'a syn::ExprMethodCall) {
            syn::visit::visit_expr_method_call(self, node);
            if node.method != "for_each" || self.failed.is_some() {
                return;
            }
            // Receiver chain: TUPLE.into_par_iter()[.enumerate()]
            let mut recv = strip_parens(&node.receiver);
            if let Expr::MethodCall(mc) = recv
                && mc.method == "enumerate" {
                    recv = strip_parens(&mc.receiver);
                }
            let Expr::MethodCall(ipi) = recv else { return };
            if ipi.method != "into_par_iter" {
                return;
            }
            let Expr::Tuple(tup) = strip_parens(&ipi.receiver) else {
                return;
            };
            // First tuple element must be col_gen.par_iter_mut(); the rest are
            // lookup-data field refs.
            let mut elems = tup.elems.iter();
            let Some(Expr::MethodCall(first)) = elems.next().map(strip_parens) else {
                return;
            };
            if first.method != "par_iter_mut" {
                return;
            }
            let fields: Vec<String> = elems.map(lookup_field).collect::<Option<_>>()
                .unwrap_or_default();
            if fields.is_empty() {
                return;
            }
            // The closure body's write_frac numerator, whitespace-normalized.
            let Some(Expr::Closure(cl)) = node.args.first().map(strip_parens) else {
                return;
            };
            let mut numerator: Option<String> = None;
            struct FracVisitor<'b>(&'b mut Option<String>);
            impl<'a, 'b> syn::visit::Visit<'a> for FracVisitor<'b> {
                fn visit_expr_method_call(&mut self, n: &'a syn::ExprMethodCall) {
                    if n.method == "write_frac"
                        && let Some(arg) = n.args.first() {
                            *self.0 = Some(
                                arg.to_token_stream()
                                    .to_string()
                                    .chars()
                                    .filter(|c| !c.is_whitespace())
                                    .collect(),
                            );
                        }
                    syn::visit::visit_expr_method_call(self, n);
                }
            }
            FracVisitor(&mut numerator).visit_expr(&cl.body);
            let Some(num) = numerator else { return };

            let fact = match (num.as_str(), fields.len()) {
                ("denom0**mult1+denom1**mult0", 4) => (
                    fields[0].clone(), fields[2].clone(), false,
                    fields[1].clone(), fields[3].clone(), false,
                ),
                ("-(denom0**mult1+denom1**mult0)", 4) => (
                    fields[0].clone(), fields[2].clone(), true,
                    fields[1].clone(), fields[3].clone(), true,
                ),
                ("denom0+denom1", 2) => (
                    fields[0].clone(), "1".into(), false,
                    fields[1].clone(), "1".into(), false,
                ),
                ("denom1**mult0-denom0**mult1", 4) => (
                    fields[0].clone(), fields[2].clone(), false,
                    fields[1].clone(), fields[3].clone(), true,
                ),
                ("denom0**mult1-denom1**mult0", 4) => (
                    fields[0].clone(), fields[2].clone(), true,
                    fields[1].clone(), fields[3].clone(), false,
                ),
                ("denom0*enabler_col.packed_at(i)+denom1", 2) => (
                    fields[0].clone(), "1".into(), false,
                    fields[1].clone(), "enabler".into(), false,
                ),
                ("(-mult).into()", 2) => (
                    fields[0].clone(), fields[1].clone(), true,
                    String::new(), String::new(), false,
                ),
                ("(mult).into()", 2) => (
                    fields[0].clone(), fields[1].clone(), false,
                    String::new(), String::new(), false,
                ),
                ("-PackedQM31::one()*enabler_col.packed_at(i)", 1) => (
                    fields[0].clone(), "enabler".into(), true,
                    String::new(), String::new(), false,
                ),
                _ => {
                    self.failed = Some(format!(
                        "unrecognized logup numerator form ({} fields): {num}",
                        fields.len()
                    ));
                    return;
                }
            };
            self.descs.push(fact);
        }
    }
    let mut v = ColVisitor {
        descs: Vec::new(),
        failed: None,
    };
    syn::visit::Visit::visit_block(&mut v, body);
    if let Some(err) = v.failed {
        eprintln!("parse_logup_descs: {err}");
        std::process::exit(1);
    }
    if v.descs.is_empty() {
        return None;
    }
    Some(v.descs)
}
fn parse_feed_map(file: &syn::File) -> std::collections::BTreeMap<String, (String, u32)> {
    use syn::visit::Visit;
    #[derive(Default)]
    struct FeedVisitor {
        map: std::collections::BTreeMap<String, (String, u32)>,
    }
    fn int_lit(e: &Expr) -> Option<u32> {
        if let Expr::Lit(l) = strip_parens(e)
            && let syn::Lit::Int(i) = &l.lit {
                return i.base10_parse::<u32>().ok();
            }
        None
    }
    impl<'a> Visit<'a> for FeedVisitor {
        // `sub_component_inputs.FIELD.iter().for_each(|inputs| { STATE.add_packed_
        // inputs(inputs, REL); })` — the generated chain shape.
        fn visit_expr_method_call(&mut self, node: &'a syn::ExprMethodCall) {
            if node.method == "for_each" {
                // receiver: sub_component_inputs.FIELD.iter()
                let field = (|| {
                    let Expr::MethodCall(iter_mc) = strip_parens(&node.receiver) else {
                        return None;
                    };
                    if iter_mc.method != "iter" && iter_mc.method != "into_iter" {
                        return None;
                    }
                    let Expr::Field(f) = strip_parens(&iter_mc.receiver) else {
                        return None;
                    };
                    if !is_path_named(&f.base, "sub_component_inputs") {
                        return None;
                    }
                    match &f.member {
                        syn::Member::Named(id) => Some(id.to_string()),
                        syn::Member::Unnamed(_) => None,
                    }
                })();
                if let (Some(field), Some(Expr::Closure(cl))) =
                    (field, node.args.first().map(strip_parens))
                    && let Expr::Block(b) = strip_parens(&cl.body) {
                        for st in &b.block.stmts {
                            let Stmt::Expr(e, _) = st else { continue };
                            if let Expr::MethodCall(mc) = strip_parens(e)
                                && mc.method == "add_packed_inputs"
                                    && let Expr::Path(p) = strip_parens(&mc.receiver)
                                        && let Some(rel) = mc.args.last().and_then(int_lit) {
                                            self.map
                                                .insert(field.clone(), (tok_str(&p.path), rel));
                                        }
                        }
                    }
            }
            syn::visit::visit_expr_method_call(self, node);
        }

        fn visit_expr_for_loop(&mut self, node: &'a syn::ExprForLoop) {
            // The iterated expr: sub_component_inputs.FIELD (possibly behind refs).
            let mut it: &Expr = strip_parens(&node.expr);
            if let Expr::Reference(r) = it {
                it = strip_parens(&r.expr);
            }
            if let Expr::Field(f) = it
                && is_path_named(&f.base, "sub_component_inputs")
                    && let syn::Member::Named(field_id) = &f.member {
                        let field = field_id.to_string();
                        for st in &node.body.stmts {
                            let e = match st {
                                Stmt::Expr(e, _) => e,
                                _ => continue,
                            };
                            match strip_parens(e) {
                                // STATE.add_packed_inputs(inputs, REL)
                                Expr::MethodCall(mc) if mc.method == "add_packed_inputs" => {
                                    if let Expr::Path(p) = strip_parens(&mc.receiver)
                                        && let Some(rel) = mc.args.last().and_then(int_lit) {
                                            self.map.insert(
                                                field.clone(),
                                                (tok_str(&p.path), rel),
                                            );
                                        }
                                }
                                // add_inputs(STATE, &inputs, LEN, REL)
                                Expr::Call(c) => {
                                    let is_add = matches!(&*c.func, Expr::Path(p)
                                        if p.path.segments.last()
                                            .is_some_and(|s| s.ident == "add_inputs"));
                                    if is_add
                                        && let (Some(Expr::Path(sp)), Some(rel)) = (
                                            c.args.first().map(strip_parens),
                                            c.args.last().and_then(int_lit),
                                        ) {
                                            self.map.insert(
                                                field.clone(),
                                                (tok_str(&sp.path), rel),
                                            );
                                        }
                                }
                                _ => {}
                            }
                        }
                    }
            syn::visit::visit_expr_for_loop(self, node);
        }
    }
    let mut v = FeedVisitor::default();
    v.visit_file(file);
    v.map
}
