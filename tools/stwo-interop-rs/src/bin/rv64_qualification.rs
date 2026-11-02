//! Independent bounded RV64 proof qualification, not a production guest verifier.
#[path = "../rv64_qualification/mod.rs"]
mod qualification;
fn main() -> anyhow::Result<()> {
    qualification::run()
}
