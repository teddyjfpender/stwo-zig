// ======================================================================================
// Modes
// ======================================================================================

fn run_census(files: &[PathBuf]) -> ExitCode {
    let mut analyses: Vec<(PathBuf, FileAnalysis)> = Vec::new();
    for f in files {
        analyses.push((f.clone(), analyze_file(f, false)));
    }

    let n = analyses.len();
    let writers = analyses.iter().filter(|(_, a)| a.has_writer).count();
    let matched: Vec<&(PathBuf, FileAnalysis)> =
        analyses.iter().filter(|(_, a)| a.matched).collect();
    let matched_u32: Vec<&(PathBuf, FileAnalysis)> =
        analyses.iter().filter(|(_, a)| a.matched_u32).collect();

    println!("======================================================================");
    println!("witness_genericize CENSUS");
    println!("======================================================================");
    println!("Files scanned:                          {n}");
    println!("  with write_trace_simd:                {writers}");
    println!("  MATCHED (rewritable):                 {}", matched.len());
    println!(
        "  MATCHED (needs trait ext: u32/input):  {}",
        matched_u32.len()
    );
    println!(
        "  skipped:                              {}",
        n - matched.len() - matched_u32.len()
    );
    println!();

    println!("--- MATCHED files (rewritable now) ---");
    for (_p, a) in &matched {
        println!(
            "  {:<34} cols={:<4} lookup_words={:<4} sub_words={}",
            a.component, a.n_cols, a.n_lookup_words, a.n_sub_words
        );
    }
    println!();

    println!(
        "--- MATCHED files (needs trait extension: u32/input/w27/deduce; census-only, NOT emitted) ---"
    );
    for (_p, a) in &matched_u32 {
        println!(
            "  {:<34} cols={:<4} lookup_words={:<4} sub_words={:<4} u32_sites={:<4} \
             input_sites={:<4} w27_sites={:<4} deduce_sites={}",
            a.component,
            a.n_cols,
            a.n_lookup_words,
            a.n_sub_words,
            a.u32_sites,
            a.input_sites,
            a.w27_sites,
            a.deduce_sites
        );
    }
    println!();

    println!("--- SKIPPED files (loud reasons) ---");
    for (_p, a) in analyses
        .iter()
        .filter(|(_, a)| !a.matched && !a.matched_u32)
    {
        if let Some(fs) = &a.file_skip {
            println!("  {:<34} [{}] {}", a.component, fs.category, fs.detail);
        } else {
            let mut by_cat: BTreeMap<&'static str, usize> = BTreeMap::new();
            for s in &a.skips {
                *by_cat.entry(s.category).or_insert(0) += 1;
            }
            let summ: Vec<String> = by_cat.iter().map(|(c, n)| format!("{c}×{n}")).collect();
            println!(
                "  {:<34} skeleton OK; {} unmatched constructs ({}){}",
                a.component,
                a.skips.len(),
                summ.join(", "),
                census_site_suffix(a)
            );
            let mut seen: BTreeSet<String> = BTreeSet::new();
            for s in &a.skips {
                let key = format!("[{}] {}", s.category, s.detail);
                if seen.insert(key.clone()) {
                    println!("        {key}");
                }
                if seen.len() >= 4 {
                    println!(
                        "        ... ({} more distinct)",
                        distinct_skips(&a.skips) - seen.len()
                    );
                    break;
                }
            }
        }
    }
    println!();

    // deduce_output backlog table (the device-kernel / ISA-V2 backlog).
    println!("--- deduce_output census (device-kernel backlog) ---");
    let mut recv_count: BTreeMap<String, usize> = BTreeMap::new();
    let mut recv_files: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (_p, a) in &analyses {
        for (recv, c) in &a.deduce_hits {
            *recv_count.entry(recv.clone()).or_insert(0) += c;
            recv_files
                .entry(recv.clone())
                .or_default()
                .insert(a.component.clone());
        }
    }
    let handled: BTreeSet<&str> = [
        "memory_address_to_id_state.deduce_output",
        "memory_id_to_big_state.deduce_output",
    ]
    .into_iter()
    .collect();
    let mut rows: Vec<(String, usize, usize)> = recv_count
        .iter()
        .map(|(r, c)| (r.clone(), *c, recv_files[r].len()))
        .collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    for (recv, count, nfiles) in &rows {
        let tag = if handled.contains(recv.as_str()) {
            "HANDLED "
        } else {
            "BACKLOG "
        };
        println!("  {tag}{recv:<48} {count:>5} sites  in {nfiles} files");
    }
    println!();

    // Construct-skip census grouped across files (non-deduce), normalized so specific
    // identifiers/values collapse into one backlog row per construct KIND.
    println!(
        "--- unmatched-construct census (grouped by kind across files, excl. deduce_output) ---"
    );
    let mut group: BTreeMap<(&'static str, String), (usize, BTreeSet<String>)> = BTreeMap::new();
    for (_p, a) in &analyses {
        if let Some(fs) = &a.file_skip {
            let key = normalize_detail(fs.category, &fs.detail);
            let ent = group.entry((fs.category, key)).or_default();
            ent.0 += 1;
            ent.1.insert(a.component.clone());
        }
        for s in &a.skips {
            if s.category == "deduce_output" {
                continue;
            }
            let key = normalize_detail(s.category, &s.detail);
            let ent = group.entry((s.category, key)).or_default();
            ent.0 += 1;
            ent.1.insert(a.component.clone());
        }
    }
    type ConstructGroup = ((&'static str, String), (usize, BTreeSet<String>));
    let mut gvec: Vec<ConstructGroup> = group.into_iter().collect();
    gvec.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then(a.0.cmp(&b.0)));
    let shown = gvec.len().min(70);
    for ((cat, detail), (count, fileset)) in gvec.iter().take(shown) {
        println!(
            "  [{cat}] {detail}  — {count} sites in {} files",
            fileset.len()
        );
    }
    if gvec.len() > shown {
        println!("  ... ({} more construct kinds)", gvec.len() - shown);
    }

    ExitCode::SUCCESS
}

/// Collapse a per-site skip detail into a construct-KIND key for the grouped census:
/// specific identifiers (after the first backtick) are dropped; numeric const payloads
/// are stripped, so e.g. `ConstU16(7)` and `ConstU16(1)` group together.
fn normalize_detail(category: &str, detail: &str) -> String {
    match category {
        // The backtick payload IS the key (callee path / macro path).
        "call" | "macro" => detail.to_string(),
        "binop" => strip_paren_nums(detail),
        // Everything else: keep the reason head, drop the quoted specific identifier.
        _ => detail
            .split('`')
            .next()
            .unwrap_or(detail)
            .trim()
            .to_string(),
    }
}

/// Remove `(<digits>)` groups (e.g. `ConstU16(7)` → `ConstU16`).
fn strip_paren_nums(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(open) = rest.find('(') {
        if let Some(close_rel) = rest[open + 1..].find(')') {
            let inner = &rest[open + 1..open + 1 + close_rel];
            if !inner.is_empty() && inner.chars().all(|c| c.is_ascii_digit()) {
                out.push_str(&rest[..open]);
                rest = &rest[open + 1 + close_rel + 1..];
                continue;
            }
        }
        out.push_str(&rest[..=open]);
        rest = &rest[open + 1..];
    }
    out.push_str(rest);
    out
}

/// " + N u32 sites + M input sites + ..." suffix for census rows (census-only sites that
/// are typed but not emittable).
fn census_site_suffix(a: &FileAnalysis) -> String {
    let mut parts = Vec::new();
    for (n, what) in [
        (a.u32_sites, "u32"),
        (a.input_sites, "input"),
        (a.w27_sites, "w27"),
        (a.deduce_sites, "deduce"),
    ] {
        if n > 0 {
            parts.push(format!(" + {n} {what} sites"));
        }
    }
    parts.concat()
}

fn distinct_skips(skips: &[Skip]) -> usize {
    skips
        .iter()
        .map(|s| format!("[{}] {}", s.category, s.detail))
        .collect::<BTreeSet<_>>()
        .len()
}

fn not_emittable_reason(a: &FileAnalysis) -> String {
    if a.matched_u32 {
        return format!(
            "matched via census-only rules ({} u32 / {} input / {} w27 / {} deduce sites) — \
             needs trait/lane extension; not emitted",
            a.u32_sites, a.input_sites, a.w27_sites, a.deduce_sites
        );
    }
    a.file_skip
        .as_ref()
        .map(|s| format!("[{}] {}", s.category, s.detail))
        .unwrap_or_else(|| {
            format!(
                "{} unmatched constructs (first: {})",
                a.skips.len(),
                a.skips
                    .first()
                    .map(|s| format!("[{}] {}", s.category, s.detail))
                    .unwrap_or_default()
            )
        })
}

fn run_emit_dir(files: &[PathBuf], dir: &Path) -> ExitCode {
    if std::fs::create_dir_all(dir).is_err() {
        eprintln!("cannot create emit dir {}", dir.display());
        return ExitCode::from(2);
    }
    let mut emitted = 0;
    let mut skipped = 0;
    for f in files {
        let a = analyze_file(f, true);
        if !a.matched {
            skipped += 1;
            eprintln!("SKIP {}: {}", a.component, not_emittable_reason(&a));
            continue;
        }
        let Some(block) = &a.block else {
            eprintln!("SKIP {}: matched but no block built", a.component);
            skipped += 1;
            continue;
        };
        let src = std::fs::read_to_string(f).unwrap();
        let cleaned = strip_existing_block(&src);
        let Some(full) = insert_block(&cleaned, block) else {
            eprintln!(
                "SKIP {}: no `struct LookupData` anchor for insert",
                a.component
            );
            skipped += 1;
            continue;
        };
        let out_path = dir.join(f.file_name().unwrap());
        if std::fs::write(&out_path, &full).is_ok() {
            emitted += 1;
            println!("EMIT {} -> {}", a.component, out_path.display());
        } else {
            eprintln!("SKIP {}: write failed", a.component);
            skipped += 1;
        }
    }
    println!("witness_genericize --emit-dir: {emitted} emitted, {skipped} skipped");
    ExitCode::SUCCESS
}

fn run_in_place(files: &[PathBuf]) -> ExitCode {
    let mut changed = 0;
    let mut skipped = 0;
    for f in files {
        let a = analyze_file(f, true);
        if !a.matched {
            skipped += 1;
            eprintln!("SKIP {}: {}", a.component, not_emittable_reason(&a));
            continue;
        }
        let Some(block) = &a.block else {
            skipped += 1;
            continue;
        };
        let src = std::fs::read_to_string(f).unwrap();
        let cleaned = strip_existing_block(&src);
        let Some(full) = insert_block(&cleaned, block) else {
            skipped += 1;
            continue;
        };
        if full != src {
            if std::fs::write(f, &full).is_ok() {
                changed += 1;
                println!("REWROTE {}", a.component);
            }
        } else {
            println!("UNCHANGED {} (already up to date)", a.component);
        }
    }
    println!("witness_genericize --in-place: {changed} rewritten, {skipped} skipped");
    ExitCode::SUCCESS
}

/// Comparison view of a block for `--check`: comment-only lines are dropped
/// (rustfmt's `wrap_comments` reflows generated prose at `comment_width`, and for
/// long component names the reflow differs from the emitted wrapping — pure
/// noise). Code lines compare EXACTLY; the fence's teeth are unchanged.
fn check_view(block: &str) -> String {
    block
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
        .trim_end()
        .to_string()
}

fn run_check(files: &[PathBuf]) -> ExitCode {
    let mut drift = 0;
    for f in files {
        let a = analyze_file(f, true);
        if !a.matched {
            continue;
        }
        let Some(block) = &a.block else { continue };
        let src = std::fs::read_to_string(f).unwrap();
        match extract_block(&src) {
            Some(on_disk) => {
                if check_view(&on_disk) != check_view(block) {
                    drift += 1;
                    eprintln!(
                        "DRIFT {}: on-disk block differs from generated",
                        a.component
                    );
                }
            }
            None => {
                drift += 1;
                eprintln!("MISSING {}: matched file has no on-disk block", a.component);
            }
        }
    }
    if drift == 0 {
        println!("witness_genericize --check: OK (no drift)");
        ExitCode::SUCCESS
    } else {
        eprintln!("witness_genericize --check: {drift} files drifted");
        ExitCode::from(1)
    }
}
