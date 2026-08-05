//! Test-only bridge that keeps the reviewed design artifacts authoritative.

pub const m2_production_shadow_machine =
    @embedFile("m2-production-shadow-report-v1.tsv");
pub const m2_production_shadow_markdown =
    @embedFile("m2-production-shadow-report-v1.md");
