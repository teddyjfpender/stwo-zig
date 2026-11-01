//! Independent partial numerical oracle; never a PCS/execution receiver.
#[path = "../om_gkr/mod.rs"]
mod om_gkr;
fn main() -> anyhow::Result<()> {
    om_gkr::run()
}
