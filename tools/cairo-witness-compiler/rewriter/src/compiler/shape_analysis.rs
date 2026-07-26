fn parse_lookup_data(file: &syn::File) -> Result<Vec<LookupField>, Skip> {
    let st = file.items.iter().find_map(|it| match it {
        Item::Struct(s) if s.ident == "LookupData" => Some(s),
        _ => None,
    });
    let Some(st) = st else {
        return Err(Skip {
            category: "skeleton",
            detail: "no `struct LookupData`".to_string(),
        });
    };
    let named = match &st.fields {
        Fields::Named(n) => n,
        _ => {
            return Err(Skip {
                category: "skeleton",
                detail: "LookupData is not a named struct".to_string(),
            })
        }
    };
    let mut fields = Vec::new();
    let mut base = 0usize;
    for f in &named.named {
        let name = f.ident.as_ref().unwrap().to_string();
        let (width, scalar) = lookup_field_width(&f.ty).ok_or_else(|| Skip {
            category: "skeleton",
            detail: format!(
                "LookupData.{name}: unrecognized field type `{}`",
                tok_str(&f.ty)
            ),
        })?;
        fields.push(LookupField {
            name,
            width,
            scalar,
            base,
        });
        base += width;
    }
    Ok(fields)
}
/// `Vec<[PackedM31; N]>` → (N, false); `Vec<PackedM31>` → (1, true).
fn lookup_field_width(ty: &Type) -> Option<(usize, bool)> {
    let s = tok_str(ty);
    if let Some(rest) = s.strip_prefix("Vec < [PackedM31 ;") {
        let n: usize = rest.trim().trim_end_matches("] >").trim().parse().ok()?;
        return Some((n, false));
    }
    if s == "Vec < PackedM31 >" {
        return Some((1, true));
    }
    None
}

/// Parse the component's `pub type PackedInputType = <ty>;` alias into a `Ty` tree, so the
/// 4th closure binder (`<comp>_input`) can be typed and its `.N` / `[i]` / `.get_m31(i)`
/// projections resolved. Unrecognized leaves (e.g. the opcode `PackedCasmState` struct,
/// whose fields are read via the named `input(SLOT_*)` path, not projections) map to
/// `Ty::Unknown` — an honest fallthrough, never a fabricated type.
fn parse_input_type(file: &syn::File) -> Ty {
    let alias = file.items.iter().find_map(|it| match it {
        Item::Type(t) if t.ident == "PackedInputType" => Some(&*t.ty),
        _ => None,
    });
    match alias {
        Some(ty) => syn_type_to_ty(ty),
        None => Ty::Unknown,
    }
}

/// Map a packed-input `syn::Type` to the inferred `Ty`. Only the shapes the generated
/// builtin inputs use are recognized; everything else is `Ty::Unknown` (honest skip).
fn syn_type_to_ty(ty: &Type) -> Ty {
    match ty {
        Type::Paren(p) => syn_type_to_ty(&p.elem),
        Type::Group(g) => syn_type_to_ty(&g.elem),
        Type::Tuple(t) => Ty::Tuple(t.elems.iter().map(syn_type_to_ty).collect()),
        Type::Array(a) => match expr_usize(&a.len) {
            Some(n) => Ty::Array(Box::new(syn_type_to_ty(&a.elem)), n),
            None => Ty::Unknown,
        },
        Type::Path(p) => match p.path.segments.last() {
            Some(seg) => {
                let name = seg.ident.to_string();
                if name == "PackedM31" {
                    Ty::M31
                } else if name == "PackedUInt16" {
                    Ty::U16
                } else if name == "PackedUInt32" {
                    Ty::U32
                } else if name == "PackedFelt252" {
                    // 28 x 9-bit limbs.
                    Ty::Felt252
                } else if name == "PackedFelt252Width27" {
                    // 10 x 27-bit limbs — a DIFFERENT layout; never conflate (G1).
                    Ty::FeltW27
                } else {
                    Ty::Unknown
                }
            }
            None => Ty::Unknown,
        },
        _ => Ty::Unknown,
    }
}

/// Shape of a declared sub-input element type `T` (from `[Vec<T>; N]`): the
/// DECLARATION is the ground truth for the flat layout + typed reconstruction (RHS
/// expressions cannot always be type-walked — e.g. u32 locals built via
/// `from_limbs`). Recognized leaves mirror `syn_type_to_ty`.
fn shape_from_syn_type(ty: &Type, dir: Option<&Path>) -> Option<Shape> {
    match ty {
        Type::Paren(p) => shape_from_syn_type(&p.elem, dir),
        Type::Group(g) => shape_from_syn_type(&g.elem, dir),
        Type::Tuple(t) => Some(Shape::Tuple(
            t.elems
                .iter()
                .map(|e| shape_from_syn_type(e, dir))
                .collect::<Option<Vec<_>>>()?,
        )),
        Type::Array(a) => {
            let n = expr_usize(&a.len)?;
            let e = shape_from_syn_type(&a.elem, dir)?;
            Some(Shape::Array(vec![e; n]))
        }
        Type::Path(p) => {
            let segs: Vec<String> = p
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            match segs.last()?.as_str() {
                "PackedM31" => Some(Shape::Scalar),
                "PackedUInt32" => Some(Shape::U32),
                "PackedFelt252" => Some(Shape::Felt),
                // `<component>::PackedInputType` — resolve by parsing the SIBLING
                // component file's alias (the transformer runs over the components
                // dir, so the sibling is on disk next to the current file).
                "PackedInputType" if segs.len() == 2 => {
                    let dir = dir?;
                    let sibling = dir.join(format!("{}.rs", segs[0]));
                    let ty = sibling_input_ty(&sibling)?;
                    ty_to_shape(&ty)
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// Parse (and cache) a sibling component file's `PackedInputType` alias as a `Ty`.
fn sibling_input_ty(path: &Path) -> Option<Ty> {
    use std::sync::Mutex;
    static CACHE: Mutex<Option<BTreeMap<PathBuf, Option<Ty>>>> = Mutex::new(None);
    let mut guard = CACHE.lock().unwrap();
    let cache = guard.get_or_insert_with(BTreeMap::new);
    if let Some(t) = cache.get(path) {
        return t.clone();
    }
    let ty = std::fs::read_to_string(path)
        .ok()
        .and_then(|src| syn::parse_file(&src).ok())
        .map(|file| parse_input_type(&file))
        .filter(|t| !matches!(t, Ty::Unknown));
    cache.insert(path.to_path_buf(), ty.clone());
    ty
}

/// Convert an input `Ty` tree to a flat sub-word `Shape` (leaves must be M31 / U32 /
/// Felt252; anything else — e.g. a FeltW27 — is unsupported and returns None loudly
/// upstream, never a silent width guess).
fn ty_to_shape(ty: &Ty) -> Option<Shape> {
    match ty {
        Ty::M31 => Some(Shape::Scalar),
        Ty::U32 => Some(Shape::U32),
        Ty::Felt252 => Some(Shape::Felt),
        Ty::Tuple(v) => Some(Shape::Tuple(
            v.iter().map(ty_to_shape).collect::<Option<Vec<_>>>()?,
        )),
        Ty::Array(e, n) => {
            let s = ty_to_shape(e)?;
            Some(Shape::Array(vec![s; *n]))
        }
        _ => None,
    }
}

/// Parse `struct SubComponentInputs` field declarations: (name, array_len, DECLARED
/// element shape) in order. Field types are `[Vec<T>; N]`.
fn parse_sub_struct(
    file: &syn::File,
    dir: Option<&Path>,
) -> Result<Vec<(String, usize, Shape)>, Skip> {
    let st = file.items.iter().find_map(|it| match it {
        Item::Struct(s) if s.ident == "SubComponentInputs" => Some(s),
        _ => None,
    });
    let Some(st) = st else {
        return Err(Skip {
            category: "skeleton",
            detail: "no `struct SubComponentInputs`".to_string(),
        });
    };
    let named = match &st.fields {
        Fields::Named(n) => n,
        _ => {
            return Err(Skip {
                category: "skeleton",
                detail: "SubComponentInputs is not a named struct".to_string(),
            })
        }
    };
    let mut out = Vec::new();
    for f in &named.named {
        let name = f.ident.as_ref().unwrap().to_string();
        let Type::Array(arr) = &f.ty else {
            return Err(Skip {
                category: "skeleton",
                detail: format!(
                    "SubComponentInputs.{name}: not an array type `{}`",
                    tok_str(&f.ty)
                ),
            });
        };
        let Some(len) = expr_usize(&arr.len) else {
            return Err(Skip {
                category: "skeleton",
                detail: format!("SubComponentInputs.{name}: non-literal array length"),
            });
        };
        // [Vec<T>; N] -> T's declared shape.
        let elem_shape = (|| {
            let Type::Path(p) = &*arr.elem else {
                return None;
            };
            let seg = p.path.segments.last()?;
            if seg.ident != "Vec" {
                return None;
            }
            let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
                return None;
            };
            let syn::GenericArgument::Type(t) = args.args.first()? else {
                return None;
            };
            shape_from_syn_type(t, dir)
        })();
        let Some(elem_shape) = elem_shape else {
            return Err(Skip {
                category: "skeleton",
                detail: format!(
                    "SubComponentInputs.{name}: unrecognized element type `{}`",
                    tok_str(&arr.elem)
                ),
            });
        };
        out.push((name, len, elem_shape));
    }
    Ok(out)
}

/// Match the generated multiplicity-column read idiom
/// `* mults [k] . get (row_index) . unwrap_or (& PackedM31 :: zero ())`,
/// returning `k`. Anything that deviates (a different base ident, a non-literal
/// index, a different default) does NOT match and falls through to the loud
/// unsupported-expression skip — never a silent approximation.
fn match_mults_read(expr: &Expr, row_index_name: &str) -> Option<usize> {
    let Expr::Unary(ExprUnary {
        op: UnOp::Deref(_),
        expr: inner,
        ..
    }) = strip_parens(expr)
    else {
        return None;
    };
    // .unwrap_or(&PackedM31::zero())
    let Expr::MethodCall(unwrap) = strip_parens(inner) else {
        return None;
    };
    if unwrap.method != "unwrap_or" || unwrap.args.len() != 1 {
        return None;
    }
    let default_ok = matches!(
        strip_parens(unwrap.args.first().unwrap()),
        Expr::Reference(r) if tok_str(&r.expr) == "PackedM31 :: zero ()"
    );
    if !default_ok {
        return None;
    }
    // .get(row_index)
    let Expr::MethodCall(get) = strip_parens(&unwrap.receiver) else {
        return None;
    };
    if get.method != "get"
        || get.args.len() != 1
        || !is_path_named(get.args.first().unwrap(), row_index_name)
    {
        return None;
    }
    // mults[k]
    let Expr::Index(ExprIndex {
        expr: base, index, ..
    }) = strip_parens(&get.receiver)
    else {
        return None;
    };
    if !is_path_named(base, "mults") {
        return None;
    }
    expr_usize(index)
}

/// Pre-scan the closure body's top-level statements for
/// `*<sub_name>.<field>[k] = rhs;` and derive the DECLARATION-ORDER flat layout.
fn build_sub_layout(
    file: &syn::File,
    body_stmts: &[Stmt],
    sub_name: &str,
    dir: Option<&Path>,
) -> Result<Vec<SubSlot>, Skip> {
    // Collect assigned (field, k) sites for coverage checking (file order). The slot
    // SHAPES come from the SubComponentInputs DECLARATION — the ground truth the host
    // type checker already enforces on every RHS.
    let mut seen: BTreeSet<(String, usize)> = BTreeSet::new();
    for st in body_stmts {
        let Stmt::Expr(Expr::Assign(a), _) = st else {
            continue;
        };
        let Expr::Unary(ExprUnary {
            op: UnOp::Deref(_),
            expr: place,
            ..
        }) = strip_parens(&a.left)
        else {
            continue;
        };
        let Expr::Index(ExprIndex {
            expr: base, index, ..
        }) = strip_parens(place)
        else {
            continue;
        };
        let Expr::Field(ExprField {
            base: fb,
            member: Member::Named(m),
            ..
        }) = strip_parens(base)
        else {
            continue;
        };
        if !is_path_named(fb, sub_name) {
            continue;
        }
        let field = m.to_string();
        let Some(k) = expr_usize(index) else {
            return Err(Skip {
                category: "effect",
                detail: format!("sub-input index not a literal: `{}`", tok_str(index)),
            });
        };
        if !seen.insert((field.clone(), k)) {
            return Err(Skip {
                category: "effect",
                detail: format!("sub-input `{field}[{k}]` assigned more than once"),
            });
        }
    }

    if seen.is_empty() {
        // No sub-input writes in this body (some components have an empty struct).
        return Ok(Vec::new());
    }

    let decl = parse_sub_struct(file, dir)?;
    // Every observed field must be declared; every declared (field,k) must be assigned.
    let declared: BTreeSet<&String> = decl.iter().map(|(n, ..)| n).collect();
    for (field, k) in seen.iter() {
        if !declared.contains(field) {
            return Err(Skip {
                category: "effect",
                detail: format!("sub-input `{field}[{k}]` not declared in SubComponentInputs"),
            });
        }
    }
    let mut slots = Vec::new();
    let mut base = 0usize;
    for (field, len, elem_shape) in &decl {
        for k in 0..*len {
            if !seen.contains(&(field.clone(), k)) {
                return Err(Skip {
                    category: "effect",
                    detail: format!("sub-input `{field}[{k}]` declared but never assigned"),
                });
            }
            let count = elem_shape.scalar_count();
            slots.push(SubSlot {
                field: field.clone(),
                index: k,
                shape: elem_shape.clone(),
                base,
            });
            base += count;
        }
    }
    Ok(slots)
}
