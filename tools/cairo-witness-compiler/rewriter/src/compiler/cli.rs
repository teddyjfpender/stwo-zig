// CLI
// ======================================================================================

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Census,
    EmitDir,
    InPlace,
    Check,
}
pub(super) fn run() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!(
            "usage: cairo-witness-rewriter <MODE> <file-or-dir> [more...]\n\
             MODES:\n\
             \x20 --census            parse + classify all files; print coverage + census.\n\
             \x20 --emit-dir <dir>    write transformed full-file copies into <dir>.\n\
             \x20 --in-place          strip + re-insert the marked block in the real file.\n\
             \x20 --check             verify on-disk block == freshly generated block.\n\
             A directory argument expands to its *.rs files (excluding mod.rs)."
        );
        return ExitCode::from(2);
    }

    let mut mode = Mode::Census;
    let mut emit_dir: Option<PathBuf> = None;
    let mut positionals: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--census" => mode = Mode::Census,
            "--in-place" => mode = Mode::InPlace,
            "--check" => mode = Mode::Check,
            "--emit-dir" => {
                mode = Mode::EmitDir;
                i += 1;
                if i >= args.len() {
                    eprintln!("--emit-dir requires a directory argument");
                    return ExitCode::from(2);
                }
                emit_dir = Some(PathBuf::from(&args[i]));
            }
            other if other.starts_with("--") => {
                eprintln!("unknown flag: {other}");
                return ExitCode::from(2);
            }
            other => positionals.push(other.to_string()),
        }
        i += 1;
    }

    let files = expand_files(&positionals);
    if files.is_empty() {
        eprintln!("no input .rs files found");
        return ExitCode::from(2);
    }

    match mode {
        Mode::Census => run_census(&files),
        Mode::EmitDir => run_emit_dir(&files, emit_dir.as_ref().unwrap()),
        Mode::InPlace => run_in_place(&files),
        Mode::Check => run_check(&files),
    }
}

fn expand_files(positionals: &[String]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for p in positionals {
        let path = PathBuf::from(p);
        if path.is_dir() {
            if let Ok(rd) = std::fs::read_dir(&path) {
                let mut entries: Vec<PathBuf> = rd
                    .filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| p.extension().map(|e| e == "rs").unwrap_or(false))
                    .filter(|p| p.file_name().map(|n| n != "mod.rs").unwrap_or(true))
                    .collect();
                entries.sort();
                out.extend(entries);
            }
        } else {
            out.push(path);
        }
    }
    out
}
