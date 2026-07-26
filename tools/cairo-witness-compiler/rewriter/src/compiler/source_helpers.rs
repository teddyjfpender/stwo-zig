fn render(t: &TokenStream) -> String {
    t.to_string()
}
// ======================================================================================
// Small syn helpers
// ======================================================================================

fn strip_parens(mut e: &Expr) -> &Expr {
    while let Expr::Paren(ExprParen { expr, .. }) = e {
        e = expr;
    }
    e
}

fn local_ident(local: &Local) -> Option<String> {
    match &local.pat {
        Pat::Ident(pi) => Some(pi.ident.to_string()),
        Pat::Type(pt) => match &*pt.pat {
            Pat::Ident(pi) => Some(pi.ident.to_string()),
            _ => None,
        },
        _ => None,
    }
}

/// If `local` is `let IDENT = PackedM31::broadcast(M31::from(K));` (or UInt16/UInt32),
/// return its ConstVal.
fn local_const(local: &Local) -> Option<ConstVal> {
    let init = local.init.as_ref()?;
    let call = match strip_parens(&init.expr) {
        Expr::Call(c) => c,
        _ => return None,
    };
    let path = match &*call.func {
        Expr::Path(p) => tok_str(&p.path),
        _ => return None,
    };
    let kind = match path.as_str() {
        "PackedM31 :: broadcast" => ConstKind::M31,
        "PackedUInt16 :: broadcast" => ConstKind::U16,
        "PackedUInt32 :: broadcast" => ConstKind::U32,
        _ => return None,
    };
    // arg: M31::from(K) / UInt16::from(K) / UInt32::from(K)
    let inner = match call.args.first().map(strip_parens) {
        Some(Expr::Call(c)) => c,
        _ => return None,
    };
    let v = match inner.args.first().map(strip_parens) {
        Some(Expr::Lit(el)) => match &el.lit {
            Lit::Int(i) => i.base10_parse::<u32>().ok()?,
            _ => return None,
        },
        _ => return None,
    };
    Some(ConstVal { kind, value: v })
}

/// If `local` is `let IDENT = PackedFelt252::broadcast(Felt252::from([A, B, C, D]));`
/// (the hoisted felt-constant idiom, G3 — 4 LITTLE-ENDIAN u64 words), return the words.
/// A `PackedFelt252Width27::broadcast` would decompose to 10 x 27-bit limbs instead, but
/// no such method exists on the packed type today, so only the Felt252 form is parsed.
fn local_felt_const(local: &Local) -> Option<[u64; 4]> {
    let init = local.init.as_ref()?;
    let call = match strip_parens(&init.expr) {
        Expr::Call(c) => c,
        _ => return None,
    };
    let path = match &*call.func {
        Expr::Path(p) => tok_str(&p.path),
        _ => return None,
    };
    if path != "PackedFelt252 :: broadcast" {
        return None;
    }
    // arg: Felt252::from([A, B, C, D])
    let inner = match call.args.first().map(strip_parens) {
        Some(Expr::Call(c)) => c,
        _ => return None,
    };
    let inner_path = match &*inner.func {
        Expr::Path(p) => tok_str(&p.path),
        _ => return None,
    };
    if inner_path != "Felt252 :: from" {
        return None;
    }
    let arr = match inner.args.first().map(strip_parens) {
        Some(Expr::Array(ExprArray { elems, .. })) if elems.len() == 4 => elems,
        _ => return None,
    };
    let mut words = [0u64; 4];
    for (i, e) in arr.iter().enumerate() {
        match strip_parens(e) {
            Expr::Lit(el) => match &el.lit {
                Lit::Int(l) => words[i] = l.base10_parse::<u64>().ok()?,
                _ => return None,
            },
            _ => return None,
        }
    }
    Some(words)
}

/// Decompose the 4 little-endian u64 words of a `Felt252::from([u64; 4])` into the 28
/// canonical 9-bit limbs — bit-identical to `Felt252::from([u64;4])` (which masks the
/// top word to 60 bits, keeping the low 252 bits) followed by `Felt252::get_m31(i)`
/// (9-bit window at bit `9*i`; common `prover_types/cpu.rs`).
fn felt252_const_limbs(words: [u64; 4]) -> [u32; FELT252_LIMBS] {
    let mut limbs = words;
    limbs[3] &= 0x0fff_ffff_ffff_ffff; // From<[u64;4]> masks to 252 bits.
    std::array::from_fn(|i| {
        let mask = (1u64 << FELT252_LIMB_BITS) - 1;
        let shift = FELT252_LIMB_BITS * i;
        let low = shift / 64;
        let shift_low = shift & 0x3F;
        let high = (shift + FELT252_LIMB_BITS - 1) / 64;
        let v = if low == high {
            (limbs[low] >> shift_low) & mask
        } else {
            ((limbs[low] >> shift_low) | (limbs[high] << (64 - shift_low))) & mask
        };
        v as u32
    })
}

/// RESULT types of the KNOWN `PackedX::deduce_output` signatures (G5), transcribed from
/// the host `witness/fast_deduction/{pedersen,ec_op,blake}.rs` with the signatures in
/// view — a WRONG shape here would silently mis-type everything downstream of a deduce,
/// so entries are never guessed:
///   * `PackedPartialEcMul<N>::deduce_output((M31, M31, ([M31; N], [Felt252; 2])))` returns the
///     same tuple shape (pedersen.rs; WindowBits18 => N=14, WindowBits9 => N=28).
///   * `PackedPartialEcMulGeneric::deduce_output` returns `Box<(M31, M31, State)>` with `State =
///     (Felt252Width27, [Felt252; 2], [Felt252; 2], M31)` (ec_op.rs) — typed as the inner tuple;
///     source projections auto-deref through the `Box`.
///   * points tables: `([M31; 1]) -> [Felt252; 2]` (pedersen.rs).
///   * `PackedBlakeG: ([U32; 6]) -> [U32; 4]`; `PackedTripleXor32: [U32; 3] -> U32`;
///     `PackedBlakeRoundSigma: (M31) -> [M31; 16]` (blake.rs).
fn blake_round_io_ty() -> Ty {
    Ty::Tuple(vec![
        Ty::M31,
        Ty::M31,
        Ty::Tuple(vec![
            Ty::Array(Box::new(Ty::U32), 16),
            Ty::M31,
        ]),
    ])
}

fn known_deduce_output_ty(path: &str) -> Option<Ty> {
    let felt2 = || Ty::Array(Box::new(Ty::Felt252), 2);
    let w27 = || Ty::FeltW27Limbs;
    let poseidon_chain = |width| {
        Ty::Tuple(vec![
            Ty::M31,
            Ty::M31,
            Ty::Array(Box::new(w27()), width),
        ])
    };
    match path {
        "PackedPartialEcMulWindowBits18 :: deduce_output" => Some(Ty::Tuple(vec![
            Ty::M31,
            Ty::M31,
            Ty::Tuple(vec![Ty::Array(Box::new(Ty::M31), 14), felt2()]),
        ])),
        "PackedPartialEcMulWindowBits9 :: deduce_output" => Some(Ty::Tuple(vec![
            Ty::M31,
            Ty::M31,
            Ty::Tuple(vec![Ty::Array(Box::new(Ty::M31), 28), felt2()]),
        ])),
        "PackedPartialEcMulGeneric :: deduce_output" => Some(Ty::Tuple(vec![
            Ty::M31,
            Ty::M31,
            Ty::Tuple(vec![w27(), felt2(), felt2(), Ty::M31]),
        ])),
        "PackedPedersenPointsTableWindowBits18 :: deduce_output"
        | "PackedPedersenPointsTableWindowBits9 :: deduce_output" => Some(felt2()),
        "PackedBlakeG :: deduce_output" => Some(Ty::Array(Box::new(Ty::U32), 4)),
        "PackedTripleXor32 :: deduce_output" => Some(Ty::U32),
        "PackedBlakeRoundSigma :: deduce_output" => Some(Ty::Array(Box::new(Ty::M31), 16)),
        "PackedPoseidonRoundKeys :: deduce_output" => {
            Some(Ty::Array(Box::new(w27()), 3))
        }
        "PackedCube252 :: deduce_output" => Some(w27()),
        "PackedPoseidonFullRoundChain :: deduce_output" => Some(poseidon_chain(3)),
        "PackedPoseidon3PartialRoundsChain :: deduce_output" => Some(poseidon_chain(4)),
        _ => None,
    }
}

/// If `local` is `let IDENT = Seq::new(...);` (the preamble row-index sequence), return
/// its name. Inside the closure, `IDENT.packed_at(row_index)` IS the packed row index
/// (an iota) — typed M31 and census-only until the builtin lane feeds it as an input
/// word (G4).
fn local_seq_ident(local: &Local) -> Option<String> {
    let name = local_ident(local)?;
    let init = local.init.as_ref()?;
    let call = match strip_parens(&init.expr) {
        Expr::Call(c) => c,
        _ => return None,
    };
    match &*call.func {
        Expr::Path(p) if tok_str(&p.path) == "Seq :: new" => Some(name),
        _ => None,
    }
}

/// If `local` binds a canonical preprocessed column, return its local name. Source
/// declaration order becomes the witness-program input-slot order.
fn local_preprocessed_column_ident(local: &Local) -> Option<String> {
    let name = local_ident(local)?;
    let init = local.init.as_ref()?;
    let call = match strip_parens(&init.expr) {
        Expr::MethodCall(call) => call,
        _ => return None,
    };
    if call.method == "get_column"
        && is_path_named(&call.receiver, "preprocessed_trace")
        && call.args.len() == 1
    {
        Some(name)
    } else {
        None
    }
}

/// Uniform per-statement M31 values accepted by the generated row program.
///
/// Official builtin writers expose these as scalar `u32` segment-start parameters,
/// then broadcast them with the exact expression recognized by
/// [`m31_broadcast_input_ident`]. Restricting admission to that generated naming and
/// type convention keeps unrelated scalar configuration out of the witness ABI.
fn writer_uniform_m31_inputs(writer: &ItemFn) -> BTreeMap<String, usize> {
    let mut inputs = BTreeMap::new();
    for argument in &writer.sig.inputs {
        let FnArg::Typed(argument) = argument else {
            continue;
        };
        let Pat::Ident(pattern) = &*argument.pat else {
            continue;
        };
        let name = pattern.ident.to_string();
        if !name.ends_with("_segment_start")
            || !matches!(&*argument.ty, Type::Path(path) if path.path.is_ident("u32"))
        {
            continue;
        }
        inputs.insert(name, inputs.len());
    }
    inputs
}

/// Match exactly `PackedM31::broadcast(M31::from(<uniform-ident>))`.
fn m31_broadcast_input_ident(call: &ExprCall) -> Option<String> {
    let outer_path = match &*call.func {
        Expr::Path(path) => tok_str(&path.path),
        _ => return None,
    };
    if outer_path != "PackedM31 :: broadcast" || call.args.len() != 1 {
        return None;
    }
    let Expr::Call(inner) = call.args.first().map(strip_parens)? else {
        return None;
    };
    let inner_path = match &*inner.func {
        Expr::Path(path) => tok_str(&path.path),
        _ => return None,
    };
    if inner_path != "M31 :: from" || inner.args.len() != 1 {
        return None;
    }
    let Expr::Path(input) = inner.args.first().map(strip_parens)? else {
        return None;
    };
    input.path.get_ident().map(ToString::to_string)
}

fn is_path_named(e: &Expr, name: &str) -> bool {
    matches!(strip_parens(e), Expr::Path(p) if p.path.is_ident(name))
}

fn expr_usize(e: &Expr) -> Option<usize> {
    match strip_parens(e) {
        Expr::Lit(el) => match &el.lit {
            Lit::Int(i) => i.base10_parse::<usize>().ok(),
            _ => None,
        },
        _ => None,
    }
}

fn usize_lit(v: usize) -> Literal {
    Literal::usize_unsuffixed(v)
}
fn u32_lit(v: u32) -> Literal {
    Literal::u32_unsuffixed(v)
}

fn tok_str<T: quote::ToTokens>(t: &T) -> String {
    quote! { #t }.to_string()
}

fn tok_str_op(op: &BinOp) -> String {
    quote! { #op }.to_string()
}

// ======================================================================================
// rustfmt
// ======================================================================================

fn rustfmt_block(block: &str) -> String {
    // The block is a set of top-level items; rustfmt formats it as a standalone file.
    // Some official writers expand into multi-megabyte straight-line programs. rustfmt
    // recursively visits their expression trees and can exhaust the process stack. The
    // proc-macro token stream is deterministic already, so formatting is presentation
    // only and must not make artifact generation dependent on host stack limits.
    const RUSTFMT_MAX_BLOCK_BYTES: usize = 1_000_000;
    if block.len() > RUSTFMT_MAX_BLOCK_BYTES {
        return block.to_string();
    }
    let dir = std::env::temp_dir();
    let tmp = dir.join(format!("wg_block_{}.rs", std::process::id()));
    if std::fs::write(&tmp, block).is_err() {
        return block.to_string();
    }
    let rustfmt = rustfmt_bin();
    let ok = std::process::Command::new(&rustfmt)
        .arg("--edition")
        .arg("2021")
        .arg(&tmp)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let out = if ok {
        std::fs::read_to_string(&tmp).unwrap_or_else(|_| block.to_string())
    } else {
        block.to_string()
    };
    let _ = std::fs::remove_file(&tmp);
    out
}

fn rustfmt_bin() -> String {
    if let Ok(out) = std::process::Command::new("rustup")
        .args(["which", "rustfmt"])
        .output()
        && out.status.success() {
            let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !p.is_empty() {
                return p;
            }
        }
    "rustfmt".to_string()
}

// ======================================================================================
// Block insert / strip (idempotent)
// ======================================================================================

/// Remove any existing marked block (BEGIN..END inclusive) from `src`.
fn strip_existing_block(src: &str) -> String {
    let Some(bstart) = src.find(BEGIN_MARKER) else {
        return src.to_string();
    };
    let Some(erel) = src[bstart..].find(END_MARKER) else {
        return src.to_string();
    };
    let eend = bstart + erel + END_MARKER.len();
    // Trim the line containing BEGIN back to the start of its line, and consume one
    // trailing newline after END.
    let line_start = src[..bstart].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let mut after = eend;
    if src[after..].starts_with('\n') {
        after += 1;
    }
    let mut s = String::new();
    s.push_str(&src[..line_start]);
    s.push_str(&src[after..]);
    s
}

/// Insert `block` immediately before the `LookupData` struct (and its attributes),
/// separated by exactly one blank line on each side. Trimming surrounding newlines makes
/// strip+reinsert round-trip to identical bytes regardless of blank-line drift.
fn insert_block(src: &str, block: &str) -> Option<String> {
    let anchor = src.find("struct LookupData")?;
    // Walk back over the attribute/comment lines directly preceding the struct.
    let mut line_start = src[..anchor].rfind('\n').map(|i| i + 1).unwrap_or(0);
    loop {
        if line_start == 0 {
            break;
        }
        let prev_line_start = src[..line_start - 1]
            .rfind('\n')
            .map(|i| i + 1)
            .unwrap_or(0);
        let prev = src[prev_line_start..line_start - 1].trim_start();
        if prev.starts_with("#[") || prev.starts_with("///") || prev.starts_with("//!") {
            line_start = prev_line_start;
        } else {
            break;
        }
    }
    let before = src[..line_start].trim_end_matches('\n');
    let after = &src[line_start..];
    let block = block.trim_matches('\n');
    Some(format!("{before}\n\n{block}\n\n{after}"))
}

/// Extract the current on-disk marked block (for --check), if present.
fn extract_block(src: &str) -> Option<String> {
    let bstart = src.find(BEGIN_MARKER)?;
    let erel = src[bstart..].find(END_MARKER)?;
    let eend = bstart + erel + END_MARKER.len();
    Some(src[bstart..eend].to_string())
}
