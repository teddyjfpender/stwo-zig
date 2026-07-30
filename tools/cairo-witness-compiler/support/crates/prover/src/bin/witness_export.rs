use std::path::Path;

fn main() -> std::io::Result<()> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or_else(|| std::io::Error::other("usage: witness_export OUTPUT"))?;
    stwo_cairo_prover::witness::recording_export::write_bundle(Path::new(&path))
}
