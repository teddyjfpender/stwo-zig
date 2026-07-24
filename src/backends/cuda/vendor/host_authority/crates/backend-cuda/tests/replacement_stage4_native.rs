//! One native-CUDA admission binary for Stage-4 quotient and commitment replacement bytes.
//!
//! The test writes a PASS receipt only after both production binders match their legacy and CPU
//! references under eager execution and captured mutation. A non-CUDA build keeps the test visible
//! but ignored, so hardware automation can distinguish an absent native link from a passing gate.

#[path = "support/quotient_numerator_oracle.rs"]
mod quotient_numerator_oracle;
#[cfg(stwo_cuda_link)]
#[path = "support/replacement_stage4_bench.rs"]
mod replacement_stage4_bench;
#[path = "support/replacement_stage4_common.rs"]
mod replacement_stage4_common;
#[path = "support/replacement_stage4_mode_a.rs"]
mod replacement_stage4_mode_a;
#[path = "support/replacement_stage4_quotient.rs"]
mod replacement_stage4_quotient;
#[path = "support/replacement_stage4_quotient_prepacked.rs"]
mod replacement_stage4_quotient_prepacked;
#[cfg(stwo_cuda_link)]
#[path = "support/replacement_stage4_quotient_resources.rs"]
mod replacement_stage4_quotient_resources;

#[test]
#[cfg_attr(not(stwo_cuda_link), ignore = "requires a native CUDA-linked backend")]
fn replacement_stage4_native_bytes_match() {
    let memory_before = std::cell::Cell::new((0usize, 0usize));
    let memory_after = std::cell::Cell::new((0usize, 0usize));
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert!(
            stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT,
            "replacement admission cannot run against CUDA stubs"
        );
        memory_before.set(stwo_backend_cuda::gpu_memory_info());
        let fixture_filter = fixture_filter();
        let fixtures = match fixture_filter {
            FixtureFilter::All => vec![
                replacement_stage4_quotient::run(),
                replacement_stage4_quotient_prepacked::run(),
                replacement_stage4_mode_a::run(),
            ],
            FixtureFilter::StagedPrepackedQuotient => {
                vec![replacement_stage4_quotient_prepacked::run()]
            }
        };
        let performance_requested = std::env::var_os("STWO_STAGE4_NATIVE_PERF").is_some();
        let (performance, performance_failure) = if performance_requested {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_performance(fixture_filter)
            })) {
                Ok(performance) => (performance, None),
                Err(payload) => {
                    let failure = replacement_stage4_common::panic_message(payload.as_ref());
                    eprintln!(
                        "STWO_STAGE4_NATIVE_PERFORMANCE_FAILURE_JSON={}",
                        serde_json::json!({"passed": false, "failure": failure})
                    );
                    (Vec::new(), Some(failure))
                }
            }
        } else {
            (Vec::new(), None)
        };
        memory_after.set(stwo_backend_cuda::gpu_memory_info());
        let receipt = replacement_stage4_common::receipt(
            fixture_filter.name(),
            fixtures,
            performance_requested,
            performance_failure,
            performance,
            memory_before.get(),
            memory_after.get(),
        )
        .unwrap_or_else(|failure| panic!("native admission identity is incomplete: {failure}"));
        replacement_stage4_common::publish_receipt(&receipt);
    }));
    if let Err(payload) = outcome {
        if memory_after.get() == (0, 0) {
            memory_after.set(
                std::panic::catch_unwind(stwo_backend_cuda::gpu_memory_info).unwrap_or((0, 0)),
            );
        }
        let failure = replacement_stage4_common::panic_message(payload.as_ref());
        print_failure(&failure, memory_before.get(), memory_after.get());
        std::panic::resume_unwind(payload);
    }
}

#[cfg(stwo_cuda_link)]
fn run_performance(
    fixture_filter: FixtureFilter,
) -> Vec<replacement_stage4_common::PerformanceReceipt> {
    let mut logs = std::env::var("STWO_STAGE4_NATIVE_PERF_LOGS")
        .unwrap_or_else(|_| "18,20".to_owned())
        .split(',')
        .map(|value| value.trim().parse::<u32>().unwrap())
        .collect::<Vec<_>>();
    logs.sort_unstable();
    logs.dedup();
    assert!(
        logs.len() >= 2,
        "performance mode requires at least two distinct logs"
    );
    assert!(logs.iter().all(|log| (4..=20).contains(log)));
    let warmups = env_usize("STWO_STAGE4_NATIVE_PERF_WARMUPS", 5, 1);
    let iterations = env_usize("STWO_STAGE4_NATIVE_PERF_ITERATIONS", 30, 2);
    let mut output = Vec::new();
    for log in logs {
        if fixture_filter == FixtureFilter::All {
            output.push(replacement_stage4_quotient::benchmark(
                log, warmups, iterations,
            ));
        }
        output.extend(replacement_stage4_quotient_prepacked::benchmark(
            log, warmups, iterations,
        ));
        if fixture_filter == FixtureFilter::All {
            output.push(replacement_stage4_bench::benchmark_mode_a(
                log, warmups, iterations,
            ));
        }
    }
    output
}

#[cfg(not(stwo_cuda_link))]
fn run_performance(_: FixtureFilter) -> Vec<replacement_stage4_common::PerformanceReceipt> {
    unreachable!("native performance mode requires CUDA")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FixtureFilter {
    All,
    StagedPrepackedQuotient,
}

impl FixtureFilter {
    const fn name(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::StagedPrepackedQuotient => "staged-prepacked-quotient",
        }
    }
}

fn fixture_filter() -> FixtureFilter {
    parse_fixture_filter(
        &std::env::var("STWO_STAGE4_NATIVE_FIXTURE").unwrap_or_else(|_| "all".to_owned()),
    )
}

fn parse_fixture_filter(value: &str) -> FixtureFilter {
    match value {
        "all" => FixtureFilter::All,
        "staged-prepacked-quotient" => FixtureFilter::StagedPrepackedQuotient,
        value => panic!("unsupported STWO_STAGE4_NATIVE_FIXTURE={value:?}"),
    }
}

#[test]
fn stage4_fixture_filter_is_exact() {
    assert_eq!(parse_fixture_filter("all"), FixtureFilter::All);
    assert_eq!(
        parse_fixture_filter("staged-prepacked-quotient"),
        FixtureFilter::StagedPrepackedQuotient
    );
    assert!(std::panic::catch_unwind(|| parse_fixture_filter("quotient")).is_err());
}

#[cfg(stwo_cuda_link)]
fn env_usize(name: &str, default: usize, minimum: usize) -> usize {
    let value = std::env::var(name)
        .map(|value| value.parse::<usize>().unwrap())
        .unwrap_or(default);
    assert!(value >= minimum, "{name} must be at least {minimum}");
    value
}

fn print_failure(failure: &str, before: (usize, usize), after: (usize, usize)) {
    eprintln!(
        "STWO_STAGE4_NATIVE_FAILURE_JSON={}",
        serde_json::json!({
            "schema": "stwo.replacement-stage4-native.failure.v1",
            "passed": false,
            "failure": failure,
            "free_memory_before_bytes": before.0,
            "free_memory_after_bytes": after.0,
            "total_memory_before_bytes": before.1,
            "total_memory_after_bytes": after.1,
        })
    );
}
