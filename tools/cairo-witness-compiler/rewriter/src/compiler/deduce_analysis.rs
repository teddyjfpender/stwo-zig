// ======================================================================================
// Deduce-output census visitor
// ======================================================================================

struct DeduceVisitor {
    hits: Vec<String>,
}
impl<'ast> syn::visit::Visit<'ast> for DeduceVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        if node.method == "deduce_output" {
            self.hits.push(receiver_label(&node.receiver));
        }
        syn::visit::visit_expr_method_call(self, node);
    }
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let Expr::Path(p) = &*node.func
            && let Some(last) = p.path.segments.last()
                && last.ident == "deduce_output" {
                    let segs: Vec<String> = p
                        .path
                        .segments
                        .iter()
                        .take(p.path.segments.len() - 1)
                        .map(|s| s.ident.to_string())
                        .collect();
                    self.hits
                        .push(format!("{}::deduce_output", segs.join("::")));
                }
        syn::visit::visit_expr_call(self, node);
    }
}

fn receiver_label(recv: &Expr) -> String {
    match strip_parens(recv) {
        Expr::Path(p) => format!("{}.deduce_output", tok_str(&p.path)),
        other => format!("{}.deduce_output", tok_str(other)),
    }
}
