"""Paired-ratio statistics: Hodges-Lehmann estimate and bootstrap CI.

Deterministic: every resample uses a caller-supplied seed so a verdict is
reproducible from its inputs. Stdlib only.
"""

from __future__ import annotations

import math
import random
import statistics


PORTFOLIO_CI_METHOD = "independent_workload_round_bootstrap_percentile_v1"
PORTFOLIO_PROVE_MS_METHOD = "geometric_mean_candidate_workload_medians_ms_v1"
PORTFOLIO_PROOF_BYTES_METHOD = "rounded_geometric_mean_candidate_proof_bytes_v1"
PORTFOLIO_BOOTSTRAP_ITERATIONS = 4000


def hodges_lehmann(ratios: list[float]) -> float:
    """Median of pairwise means (Walsh averages) — robust location estimate."""
    if not ratios:
        raise ValueError("no ratios")
    walsh = [
        (ratios[i] + ratios[j]) / 2.0
        for i in range(len(ratios))
        for j in range(i, len(ratios))
    ]
    return statistics.median(walsh)


def bootstrap_ci(
    ratios: list[float],
    level: float = 0.95,
    iterations: int = PORTFOLIO_BOOTSTRAP_ITERATIONS,
    seed: int = 0,
) -> tuple[float, float]:
    """Percentile bootstrap CI of the Hodges-Lehmann estimate over paired ratios."""
    if len(ratios) < 3:
        raise ValueError("need at least 3 paired rounds for a CI")
    rng = random.Random(seed)
    n = len(ratios)
    estimates = []
    for _ in range(iterations):
        sample = [ratios[rng.randrange(n)] for _ in range(n)]
        estimates.append(hodges_lehmann(sample))
    estimates.sort()
    alpha = (1.0 - level) / 2.0
    lo = estimates[max(0, math.floor(alpha * iterations))]
    hi = estimates[min(iterations - 1, math.ceil((1.0 - alpha) * iterations) - 1)]
    return (lo, hi)


def portfolio_geomean_ci(
    workload_ratios: list[list[float]],
    level: float = 0.95,
    iterations: int = PORTFOLIO_BOOTSTRAP_ITERATIONS,
    seed: int = 0,
) -> tuple[float, tuple[float, float]]:
    """Geometric-mean portfolio estimate and deterministic bootstrap CI.

    Workloads may stop after different numbers of paired rounds. Each bootstrap
    draw therefore resamples every workload independently at its observed round
    count, applies the per-workload Hodges-Lehmann estimator, and then takes the
    geometric mean across workloads. This keeps a noisy or longer-running row
    from supplying synthetic pairings to another row.
    """
    if not workload_ratios:
        raise ValueError("no workload ratios")
    if iterations <= 0:
        raise ValueError("iterations must be positive")
    if not 0.0 < level < 1.0:
        raise ValueError("level must be in (0, 1)")
    if any(len(ratios) < 3 for ratios in workload_ratios):
        raise ValueError("need at least 3 paired rounds per workload for a portfolio CI")

    estimate = geometric_mean(
        [hodges_lehmann(ratios) for ratios in workload_ratios]
    )
    rng = random.Random(seed)
    estimates = []
    for _ in range(iterations):
        workload_estimates = []
        for ratios in workload_ratios:
            n = len(ratios)
            sample = [ratios[rng.randrange(n)] for _ in range(n)]
            workload_estimates.append(hodges_lehmann(sample))
        estimates.append(geometric_mean(workload_estimates))
    estimates.sort()
    alpha = (1.0 - level) / 2.0
    lo = estimates[max(0, math.floor(alpha * iterations))]
    hi = estimates[min(iterations - 1, math.ceil((1.0 - alpha) * iterations) - 1)]
    return estimate, (lo, hi)


def geometric_mean(values: list[float]) -> float:
    if not values:
        raise ValueError("no values")
    if any(v <= 0 for v in values):
        raise ValueError("geometric mean requires positive values")
    return math.exp(sum(math.log(v) for v in values) / len(values))


def mad(values: list[float]) -> float:
    med = statistics.median(values)
    return statistics.median([abs(v - med) for v in values])


def theta(dispersion: float | None, floor: float, multiplier: float) -> float:
    """Promotion threshold: max(floor, multiplier x measured A/A dispersion)."""
    if dispersion is None:
        return floor
    return max(floor, multiplier * dispersion)
