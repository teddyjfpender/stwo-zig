from __future__ import annotations

import unittest

from scripts.typed_air_r006_capture_lib.codec import content_digest
from scripts.typed_air_r006_capture_lib.model import CaptureError
from scripts.typed_air_r006_capture_lib.orchestration import host_preflight
from scripts.typed_air_r006_capture_lib.post_capture_quieting import (
    POST_CAPTURE_QUIETING_POLICY,
    await_admitted_post_capture_preflight,
)
from scripts.tests.test_typed_air_r006_capture import (
    preflight_host,
    quiet_evidence,
)


class FakeClock:
    def __init__(self) -> None:
        self.now_ns = 0
        self.sleeps: list[float] = []

    def monotonic(self) -> int:
        return self.now_ns

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now_ns += int(seconds * 1_000_000_000)


class PostCaptureQuietingTests(unittest.TestCase):
    @staticmethod
    def preflight(*, admitted: bool) -> dict[str, object]:
        host = preflight_host(logical_cpu_count=10)
        return host_preflight(
            host_provider=lambda: host,
            quiet_provider=lambda _: quiet_evidence(
                host,
                idle_percent=(97.0, 98.0, 99.0) if admitted else (80.0, 81.0, 82.0),
            ),
        )

    def test_retries_fresh_samples_until_one_is_admitted(self) -> None:
        rejected = self.preflight(admitted=False)
        admitted = self.preflight(admitted=True)
        samples = iter((rejected, rejected, admitted))
        clock = FakeClock()
        result = await_admitted_post_capture_preflight(
            provider=lambda: next(samples),
            expected_host=admitted["host"],
            sleeper=clock.sleep,
            monotonic=clock.monotonic,
        )
        self.assertEqual(result, admitted)
        self.assertEqual(clock.sleeps, [30.0, 30.0])
        self.assertEqual(
            POST_CAPTURE_QUIETING_POLICY["thresholds"],
            "host-preflight-v2-unchanged",
        )

    def test_timeout_is_bounded_and_never_admits_a_rejected_sample(self) -> None:
        rejected = self.preflight(admitted=False)
        clock = FakeClock()
        with self.assertRaisesRegex(CaptureError, "quieting timed out"):
            await_admitted_post_capture_preflight(
                provider=lambda: rejected,
                expected_host=rejected["host"],
                sleeper=clock.sleep,
                monotonic=clock.monotonic,
                retry_interval_ns=1_000_000_000,
                timeout_ns=2_000_000_000,
            )
        self.assertEqual(clock.sleeps, [1.0, 1.0])

    def test_sample_completed_after_timeout_is_not_admitted(self) -> None:
        admitted = self.preflight(admitted=True)
        ticks = iter((0, 3))
        with self.assertRaisesRegex(CaptureError, "quieting timed out"):
            await_admitted_post_capture_preflight(
                provider=lambda: admitted,
                expected_host=admitted["host"],
                sleeper=lambda _: self.fail("late admitted sample must not sleep"),
                monotonic=lambda: next(ticks),
                retry_interval_ns=1,
                timeout_ns=2,
            )

    def test_host_identity_drift_fails_without_retry(self) -> None:
        expected = self.preflight(admitted=True)
        changed = self.preflight(admitted=True)
        changed["host"] = dict(changed["host"])
        changed["host"]["cpu"] = "different-host"
        changed["content_sha256"] = content_digest(changed)
        with self.assertRaisesRegex(CaptureError, "identity changed while quieting"):
            await_admitted_post_capture_preflight(
                provider=lambda: changed,
                expected_host=expected["host"],
                sleeper=lambda _: self.fail("host drift must not sleep"),
                monotonic=lambda: 0,
            )

    def test_power_source_drift_fails_without_retry(self) -> None:
        expected = self.preflight(admitted=True)
        changed_host = preflight_host(
            logical_cpu_count=10,
            power_source="Battery Power",
        )
        changed = host_preflight(
            host_provider=lambda: changed_host,
            quiet_provider=lambda _: quiet_evidence(changed_host),
        )
        with self.assertRaisesRegex(CaptureError, "identity changed while quieting"):
            await_admitted_post_capture_preflight(
                provider=lambda: changed,
                expected_host=expected["host"],
                sleeper=lambda _: self.fail("power-source drift must not sleep"),
                monotonic=lambda: 0,
            )


if __name__ == "__main__":
    unittest.main()
