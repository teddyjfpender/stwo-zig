// ======================================================================================
// File analysis
// ======================================================================================

struct FileAnalysis {
    component: String,
    has_writer: bool,
    skeleton_ok: bool,
    /// Non-empty when the whole file is skipped (skeleton-level reason).
    file_skip: Option<Skip>,
    /// Per-construct skips collected during a full walk (census backlog data).
    skips: Vec<Skip>,
    /// Fully rewritable by the emit table (skips empty AND no u32 sites).
    matched: bool,
    /// Rewrite table matches ONLY via the census-only u32 rules — needs the u32 trait
    /// extension before it can be emitted.
    matched_u32: bool,
    u32_sites: usize,
    /// Census-only builtin-input access sites (see `Lowerer::input_sites`).
    input_sites: usize,
    /// Census-only opaque-Width27 sites (see `Lowerer::w27_sites`).
    w27_sites: usize,
    /// Whether the body reads the row-index iota (`seq.packed_at(row_index)` — a REAL
    /// `eval.iota()` op; the record/driver assign it an input slot after the flat words).
    uses_iota: bool,
    /// Census-only KNOWN-SIGNATURE deduce sites (see `Lowerer::deduce_sites`).
    deduce_sites: usize,
    n_cols: usize,
    n_lookup_words: usize,
    n_sub_words: usize,
    /// Deduce-output receiver -> count within this file (all writer files).
    deduce_hits: BTreeMap<String, usize>,
    /// rustfmt'd generated block (only when requested + matched).
    block: Option<String>,
}

fn analyze_file(path: &Path, build_block: bool) -> FileAnalysis {
    let component = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let mut fa = FileAnalysis {
        component: component.clone(),
        has_writer: false,
        skeleton_ok: false,
        file_skip: None,
        skips: Vec::new(),
        matched: false,
        matched_u32: false,
        u32_sites: 0,
        input_sites: 0,
        w27_sites: 0,
        uses_iota: false,
        deduce_sites: 0,
        n_cols: 0,
        n_lookup_words: 0,
        n_sub_words: 0,
        deduce_hits: BTreeMap::new(),
        block: None,
    };

    let src = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            fa.file_skip = Some(Skip {
                category: "io",
                detail: format!("read: {e}"),
            });
            return fa;
        }
    };
    let file = match syn::parse_file(&src) {
        Ok(f) => f,
        Err(e) => {
            fa.file_skip = Some(Skip {
                category: "parse",
                detail: format!("syn: {e}"),
            });
            return fa;
        }
    };

    let writer = file.items.iter().find_map(|it| match it {
        Item::Fn(f) if f.sig.ident == "write_trace_simd" => Some(f),
        _ => None,
    });
    let Some(writer) = writer else {
        fa.file_skip = Some(Skip {
            category: "skeleton",
            detail: "no `fn write_trace_simd`".to_string(),
        });
        return fa;
    };
    fa.has_writer = true;

    // Global deduce-output census (independent of skeleton match).
    {
        let mut v = DeduceVisitor { hits: Vec::new() };
        syn::visit::Visit::visit_item_fn(&mut v, writer);
        for r in v.hits {
            *fa.deduce_hits.entry(r).or_insert(0) += 1;
        }
    }

    // The mem-state param idents (for deduce_output receiver matching).
    let (addr_state, big_state) = mem_state_param_names(writer);

    // Collect hoisted constants (scalar broadcast + felt broadcast + Seq) + locate the
    // `for_each` closure.
    let mut consts: BTreeMap<String, ConstVal> = BTreeMap::new();
    let mut felt_consts: BTreeMap<String, [u32; FELT252_LIMBS]> = BTreeMap::new();
    let mut seq_idents: BTreeSet<String> = BTreeSet::new();
    let mut preprocessed_slots: BTreeMap<String, usize> = BTreeMap::new();
    for st in &writer.block.stmts {
        if let Stmt::Local(local) = st {
            if let (Some(name), Some(cv)) = (local_ident(local), local_const(local)) {
                consts.insert(name, cv);
            } else if let (Some(name), Some(words)) = (local_ident(local), local_felt_const(local))
            {
                felt_consts.insert(name, felt252_const_limbs(words));
            } else if let Some(name) = local_seq_ident(local) {
                seq_idents.insert(name);
            } else if let Some(name) = local_preprocessed_column_ident(local) {
                let ordinal = preprocessed_slots.len();
                preprocessed_slots.insert(name, ordinal);
            }
        }
    }

    let Some(closure) = find_for_each_closure(writer) else {
        fa.file_skip = Some(Skip {
            category: "skeleton",
            detail: "no `.for_each(|(row_index, (...))| {..})` closure".to_string(),
        });
        return fa;
    };
    let (row_index_name, binders) = match closure_binders(&closure.inputs) {
        Some(b) => b,
        None => {
            fa.file_skip = Some(Skip {
                category: "skeleton",
                detail: format!(
                    "unrecognized closure binder: `{}`",
                    tok_str(&closure.inputs[0])
                ),
            });
            return fa;
        }
    };
    let writer_shape = match binders.len() {
        2 => WriterShape::Lookup,
        3 => WriterShape::LookupSub,
        4 => WriterShape::LookupSubInput,
        _ => {
            fa.file_skip = Some(Skip {
                category: "skeleton",
                detail: format!(
                    "unsupported skeleton: {}-tuple closure `({})`",
                    binders.len(),
                    binders.join(", ")
                ),
            });
            return fa;
        }
    };
    let row_name = binders[0].clone();
    let lookup_name = binders[1].clone();
    let sub_name = if writer_shape.has_sub_inputs() {
        binders[2].clone()
    } else {
        "__no_sub_component_inputs".to_string()
    };
    let input_name = if writer_shape.has_row_input() {
        binders[3].clone()
    } else {
        "__no_row_input".to_string()
    };
    if writer_shape.has_row_input() && !input_name.ends_with("_input") {
        fa.file_skip = Some(Skip {
            category: "skeleton",
            detail: format!("4th closure binder `{input_name}` is not `<name>_input`"),
        });
        return fa;
    }
    fa.skeleton_ok = true;

    // Parse the LookupData layout (declaration order).
    let lookup_fields = match parse_lookup_data(&file) {
        Ok(f) => f,
        Err(s) => {
            fa.file_skip = Some(s);
            return fa;
        }
    };
    fa.n_lookup_words = lookup_fields.iter().map(|f| f.width).sum();

    // Closure body statements.
    let body_stmts: &[Stmt] = match &*closure.body {
        Expr::Block(b) => &b.block.stmts,
        _ => {
            fa.file_skip = Some(Skip {
                category: "skeleton",
                detail: "closure body is not a block".to_string(),
            });
            return fa;
        }
    };

    // Scan-time felt recognizer for the sub-input layout: a sub element is
    // felt-valued when it is (a) a hoisted felt broadcast constant ident, or (b) a
    // projection chain rooted at a `let x = PackedX::deduce_output(..)` binding whose
    // KNOWN result type resolves to `Felt252` at that path. The flatten side re-checks
    // the LOWERED type per leaf and skips loudly on any disagreement (fail-closed) —
    // this recognizer only sets the flat WIDTH layout, never semantics.
    // Derive the SubComponentInputs DECLARATION-ORDER flat layout: struct fields ×
    // array lengths × the DECLARED element shapes (the host-typed ground truth).
    let sub_slots = if writer_shape.has_sub_inputs() {
        match build_sub_layout(&file, body_stmts, &sub_name, path.parent()) {
            Ok(l) => l,
            Err(s) => {
                fa.file_skip = Some(s);
                return fa;
            }
        }
    } else {
        Vec::new()
    };
    fa.n_sub_words = sub_slots.iter().map(|s| s.shape.scalar_count()).sum();

    // Parse the packed-input type alias so the input binder's projections can be typed.
    let input_ty = if writer_shape.has_row_input() {
        parse_input_type(&file)
    } else {
        Ty::Tuple(Vec::new())
    };

    // Run the lowering (collects skips + builds SSA).
    let mut lw = Lowerer::new(
        consts,
        felt_consts,
        seq_idents,
        preprocessed_slots,
        addr_state,
        big_state,
        input_name.clone(),
        input_ty,
        row_index_name,
        row_name,
        lookup_name,
        sub_name,
        writer_shape,
        lookup_fields.clone(),
        sub_slots,
    );
    lw.lower_body(body_stmts);

    fa.n_cols = lw.max_col.map(|m| m + 1).unwrap_or(0);
    fa.u32_sites = lw.u32_sites;
    fa.input_sites = lw.input_sites;
    fa.w27_sites = lw.w27_sites;
    fa.uses_iota = lw.uses_iota;
    fa.deduce_sites = lw.deduce_sites;
    fa.skips = lw.skips.clone();
    // Emittable only when there are no skips AND no census-only sites (u32 / builtin
    // input / opaque Width27 / row-index / known-signature deduce). A census-only site is
    // typed correctly but has no backend op yet, so it must NEVER be emitted — an honest
    // "needs trait extension" classification.
    fa.matched = fa.skeleton_ok
        && fa.skips.is_empty()
        && lw.u32_sites == 0
        && lw.input_sites == 0
        && lw.w27_sites == 0
        && lw.deduce_sites == 0;
    fa.matched_u32 = fa.skeleton_ok && fa.skips.is_empty() && !fa.matched;

    if fa.matched && build_block {
        let block = build_marked_block(&component, &fa, &lw, writer, &file);
        fa.block = Some(rustfmt_block(&block));
    }

    fa
}

/// Extract the `&memory_address_to_id::ClaimGenerator` / `&memory_id_to_big::ClaimGenerator`
/// parameter identifiers from the `write_trace_simd` signature.
fn mem_state_param_names(f: &ItemFn) -> (Option<String>, Option<String>) {
    let mut addr = None;
    let mut big = None;
    for arg in &f.sig.inputs {
        if let FnArg::Typed(pt) = arg {
            let tystr = tok_str(&pt.ty);
            let name = match &*pt.pat {
                Pat::Ident(pi) => pi.ident.to_string(),
                _ => continue,
            };
            if tystr.contains("memory_address_to_id :: ClaimGenerator") {
                addr = Some(name);
            } else if tystr.contains("memory_id_to_big :: ClaimGenerator") {
                big = Some(name);
            }
        }
    }
    (addr, big)
}

fn find_for_each_closure(f: &ItemFn) -> Option<syn::ExprClosure> {
    for st in &f.block.stmts {
        let expr = match st {
            Stmt::Expr(e, _) => e,
            Stmt::Local(l) => match &l.init {
                Some(init) => &init.expr,
                None => continue,
            },
            _ => continue,
        };
        if let Some(c) = search_for_each(expr) {
            return Some(c);
        }
    }
    None
}

fn search_for_each(expr: &Expr) -> Option<syn::ExprClosure> {
    if let Expr::MethodCall(mc) = expr {
        if mc.method == "for_each"
            && let Some(Expr::Closure(c)) = mc.args.first() {
                return Some(c.clone());
            }
        return search_for_each(&mc.receiver);
    }
    None
}

/// Match `|(row_index, (a, b, c, d))|` → returns (row-index binder name, inner binder
/// names [a, b, c, d]).
fn closure_binders(
    inputs: &syn::punctuated::Punctuated<Pat, syn::token::Comma>,
) -> Option<(String, Vec<String>)> {
    let first = inputs.first()?;
    let outer = match first {
        Pat::Tuple(t) => t,
        _ => return None,
    };
    if outer.elems.len() != 2 {
        return None;
    }
    // outer.elems[0] is row_index; outer.elems[1] is the inner tuple.
    let row_index = match &outer.elems[0] {
        Pat::Ident(pi) => pi.ident.to_string(),
        _ => return None,
    };
    let inner = match &outer.elems[1] {
        Pat::Tuple(t) => t,
        _ => return None,
    };
    let mut names = Vec::new();
    for e in &inner.elems {
        match e {
            Pat::Ident(pi) => names.push(pi.ident.to_string()),
            _ => return None,
        }
    }
    Some((row_index, names))
}

/// Whether the module's `InteractionClaimGenerator` carries a real-row count
/// (`n_rows`) alongside `log_size` + `lookup_data` — selects the accessor
/// macro's ctor variant.
fn igen_has_n_rows(file: &syn::File) -> bool {
    igen_has_field(file, "n_rows")
}

fn igen_has_log_size(file: &syn::File) -> bool {
    igen_has_field(file, "log_size")
}

fn igen_has_field(file: &syn::File, field: &str) -> bool {
    file.items.iter().any(|it| {
        matches!(it,
            Item::Struct(s) if s.ident == "InteractionClaimGenerator"
                && matches!(&s.fields, syn::Fields::Named(f)
                    if f.named.iter().any(|fld| fld.ident.as_ref().is_some_and(|i| i == field))))
    })
}

/// Parse the ORIGINAL `write_trace` feed loops into field -> (downstream state
/// param, relation_index): `for inputs in sub_component_inputs.FIELD {
/// STATE.add_packed_inputs(inputs, REL) }` or `{ add_inputs(STATE, &inputs, _,
/// REL) }`. The literal REL argument is the consumer's multiplicity slot — the
/// device-DAG feed layout's ground truth.
/// Parse the module's `write_interaction_trace` into per-logup-column descriptor
/// FACTS for the §6a device-interaction lane: `(a_field, a_mult, a_neg, b_field,
/// b_mult, b_neg)` per column, in column order; `b_field == ""` for a trailing
/// solo column; mult encoding `"1"` (one), `"enabler"` (real-row enabler), else a
/// scalar lookup-data field name. Pairing order is arbitrary (blake_round pairs
/// sigma with rc_7_2_5) and sign patterns vary (the aggregator negates yields
/// mid-stream), so these are parsed facts — never derivation rules. An
/// unrecognized numerator form ABORTS the emit: new AIR shapes must be examined,
/// not skipped.
type LogupDescFact = (String, String, bool, String, String, bool);
