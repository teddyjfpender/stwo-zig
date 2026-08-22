from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
from unittest import mock

from scripts.typed_air_r006_capture_lib.codec import canonical_bytes, content_digest
from scripts.typed_air_r006_capture_lib.controller import ProcessResult
from scripts.typed_air_r006_capture_lib.model import CaptureError
from scripts.typed_air_r006_capture_lib.orchestration import host_preflight
from scripts.typed_air_r006_capture_lib import pair as pair_module
from scripts.typed_air_r006_capture_lib import pair_durability as durability
from scripts.typed_air_r006_capture_lib import pair_publication as publication
from scripts.typed_air_r006_capture_lib.pair import (
    PAIR_ATTEMPTS,
    PairCaptureSettings,
    PairPlanSettings,
    build_pair_plan,
    capture_pair,
    validate_pair_bundle,
    write_pair_plan_new,
)
from scripts.tests.test_typed_air_r006_capture import (
    R006Fixture,
    preflight_host,
    quiet_evidence,
)


class SimulatedCrash(RuntimeError):
    pass


class R006DurabilityTests(R006Fixture):
    def preflight(self) -> dict[str, object]:
        host = preflight_host(logical_cpu_count=10)
        result = host_preflight(
            host_provider=lambda: host,
            quiet_provider=lambda _: quiet_evidence(host),
        )
        result["captured_at_utc"] = "2026-08-21T00:00:00Z"
        result["content_sha256"] = content_digest(result)
        return result

    def pair_plan(self, session: str) -> dict[str, object]:
        return build_pair_plan(
            PairPlanSettings(
                repository=self.repository,
                session_id=session,
                power_state="AC power; fixture",
                cpu_executable=self.executable,
                metal_executable=self.executable,
                workloads=self.workloads,
                toolchain="zig:fixture",
                target="aarch64-macos",
                cpu_features="apple-m2",
            ),
            source_provider=self.source,
            host_provider=self.host,
            closure_provider=self.closure,
            preflight_provider=self.preflight,
            clock=lambda: dt.datetime(2026, 8, 21, tzinfo=dt.timezone.utc),
        )

    def runner_for(
        self,
        plan: dict[str, object],
        proof_attempts: list[tuple[str, int]],
        *,
        fail_proof: bool = False,
    ):
        def runner(command, cwd, timeout, environment):
            del timeout, environment
            lane = Path(cwd).name
            lane_plan = plan["lanes"][lane]
            if command[1] == "bench":
                relative = command[command.index("--proof-out") + 1]
                ordinal = int(Path(relative).name.split(".")[0])
                proof_attempts.append((lane, ordinal))
                if fail_proof:
                    return ProcessResult(9, b"failed", b"", 123)
                attempt = lane_plan["attempts"][ordinal]
                payload = f"proof:{attempt['workload_id']}".encode("ascii")
                artifact = self.base_artifact(
                    payload, backend=lane_plan["lane"]["cli_backend"]
                )
                (Path(cwd) / relative).write_bytes(artifact)
                return ProcessResult(
                    0, self.report(lane_plan, attempt, artifact), b"", 123
                )
            relative = command[command.index("--artifact") + 1]
            proof = self.base_artifact_payload((Path(cwd) / relative).read_bytes())
            return ProcessResult(
                0, self.verifier_receipt(lane_plan, proof_payload=proof), b"", 45
            )

        return runner

    def settings(
        self, plan_path: Path, bundle: Path, *, maximum: int | None
    ) -> PairCaptureSettings:
        return PairCaptureSettings(
            repository=self.repository,
            plan_path=plan_path,
            bundle_path=bundle,
            execute_frozen_2080_attempt_schedule=True,
            timeout_seconds=10,
            max_new_attempts=maximum,
        )

    def capture_arguments(self) -> dict[str, object]:
        return {
            "sleeper": lambda _: None,
            "preflight_provider": self.preflight,
            "source_provider": self.source,
            "closure_provider": self.closure,
        }

    def test_preflight_boundaries_recover_open_invocation_and_replay(self) -> None:
        plan = self.pair_plan("fixture-boundaries")
        root = self.scratch / "boundaries"
        root.mkdir()
        first = durability.PreflightBoundaryJournal(root, plan, 0)
        self.assertTrue(first.admit(self.preflight(), 0))
        first.abandon()

        resumed = durability.PreflightBoundaryJournal(root, plan, 1)
        self.assertTrue(resumed.admit(self.preflight(), 1))
        resumed.checkpoint(self.preflight(), PAIR_ATTEMPTS)
        summary = resumed.summary(
            completed_attempts=PAIR_ATTEMPTS, require_complete=True
        )
        identity = resumed.close()
        self.assertEqual(summary["invocations"], 2)
        self.assertEqual(summary["recoveries"], 1)
        self.assertEqual(summary["closed_prefix"], PAIR_ATTEMPTS)
        replay, replay_identity = durability.read_boundary_journal(
            root / durability.BOUNDARY_JOURNAL_NAME,
            plan=plan,
            completed_attempts=PAIR_ATTEMPTS,
            require_complete=True,
        )
        self.assertEqual(replay, summary)
        self.assertEqual(replay_identity, identity)
        phases = [
            json.loads(line)["boundary"]
            for line in (root / durability.BOUNDARY_JOURNAL_NAME)
            .read_bytes()
            .splitlines()[1:]
        ]
        self.assertEqual(phases, ["start", "recovery", "start", "checkpoint"])

        path = root / durability.BOUNDARY_JOURNAL_NAME
        original = path.read_bytes()
        records = [json.loads(line) for line in original.splitlines()]
        records[-1]["completed_attempts"] -= 1
        records[-1]["content_sha256"] = content_digest(records[-1])
        path.write_bytes(b"".join(canonical_bytes(record) for record in records))
        with self.assertRaisesRegex(CaptureError, "advanced outside"):
            durability.read_boundary_journal(
                path,
                plan=plan,
                completed_attempts=PAIR_ATTEMPTS,
                require_complete=True,
            )
        path.write_bytes(original)
        records = [json.loads(line) for line in original.splitlines()]
        records[1]["preflight"]["host"]["cpu"] = "mutated cpu"
        records[1]["preflight"]["content_sha256"] = content_digest(
            records[1]["preflight"]
        )
        records[1]["content_sha256"] = content_digest(records[1])
        path.write_bytes(b"".join(canonical_bytes(record) for record in records))
        with self.assertRaisesRegex(CaptureError, "host identity drifted"):
            durability.read_boundary_journal(
                path,
                plan=plan,
                completed_attempts=PAIR_ATTEMPTS,
                require_complete=True,
            )

    def test_attempt_publication_recovers_every_commit_window(self) -> None:
        for cut in ("prepared", "lane", "pair"):
            with self.subTest(cut=cut):
                plan = self.pair_plan(f"fixture-publication-{cut}")
                plan_path = self.scratch / f"{cut}-plan.json"
                bundle = self.scratch / f"{cut}-bundle"
                write_pair_plan_new(plan_path, plan)
                proof_attempts: list[tuple[str, int]] = []
                runner = self.runner_for(plan, proof_attempts)
                settings = self.settings(plan_path, bundle, maximum=1)

                if cut == "prepared":
                    original = publication.AttemptPublicationJournal.prepare

                    def crash_after_prepare(instance, schedule, record):
                        original(instance, schedule, record)
                        raise SimulatedCrash("after prepared publication")

                    patcher = mock.patch.object(
                        publication.AttemptPublicationJournal,
                        "prepare",
                        new=crash_after_prepare,
                    )
                elif cut == "lane":
                    original = durability.PairProgressJournal.append

                    def crash_before_pair(instance, value, *, sealed=False):
                        if sealed:
                            raise SimulatedCrash("after lane commit")
                        return original(instance, value, sealed=sealed)

                    patcher = mock.patch.object(
                        durability.PairProgressJournal,
                        "append",
                        new=crash_before_pair,
                    )
                else:
                    original = publication.AttemptPublicationJournal.commit

                    def crash_before_transaction_commit(instance, schedule):
                        raise SimulatedCrash("after pair commit")

                    patcher = mock.patch.object(
                        publication.AttemptPublicationJournal,
                        "commit",
                        new=crash_before_transaction_commit,
                    )
                with patcher, self.assertRaises(SimulatedCrash):
                    capture_pair(
                        settings,
                        child_runner=runner,
                        **self.capture_arguments(),
                    )

                resumed = capture_pair(
                    settings,
                    child_runner=runner,
                    **self.capture_arguments(),
                )
                self.assertEqual(resumed["completed_attempts"], 2)
                self.assertEqual(
                    proof_attempts,
                    [("cpu-native", 0), ("metal-hybrid", 0)],
                )
                records = durability.read_journal_regular(
                    bundle / publication.PUBLICATION_JOURNAL_NAME,
                    "test attempt-publication journal",
                )
                phases = [record["phase"] for record in records[1:]]
                self.assertEqual(
                    phases,
                    [
                        "intent",
                        "prepared",
                        "committed",
                        "intent",
                        "prepared",
                        "committed",
                    ],
                )

    def test_normal_child_failure_is_prepared_and_resumable(self) -> None:
        plan = self.pair_plan("fixture-failed-publication")
        plan_path = self.scratch / "failed-plan.json"
        bundle = self.scratch / "failed-bundle"
        write_pair_plan_new(plan_path, plan)
        proof_attempts: list[tuple[str, int]] = []
        runner = self.runner_for(plan, proof_attempts, fail_proof=True)
        settings = self.settings(plan_path, bundle, maximum=1)
        original = publication.AttemptPublicationJournal.prepare

        def crash_after_prepare(instance, schedule, record):
            original(instance, schedule, record)
            raise SimulatedCrash("sealed failed attempt")

        with (
            mock.patch.object(
                publication.AttemptPublicationJournal,
                "prepare",
                new=crash_after_prepare,
            ),
            self.assertRaises(SimulatedCrash),
        ):
            capture_pair(
                settings,
                child_runner=runner,
                **self.capture_arguments(),
            )
        capture_pair(
            settings,
            child_runner=runner,
            **self.capture_arguments(),
        )
        records = durability.read_journal_regular(
            bundle / "cpu-native/journal.ndjson", "failed lane journal"
        )
        self.assertEqual(records[1]["status"], "failed")
        self.assertEqual(proof_attempts.count(("cpu-native", 0)), 1)

    def test_publication_semantic_mutation_is_rejected(self) -> None:
        plan = self.pair_plan("fixture-publication-mutation")
        plan_path = self.scratch / "mutation-plan.json"
        bundle = self.scratch / "mutation-bundle"
        write_pair_plan_new(plan_path, plan)
        capture_pair(
            self.settings(plan_path, bundle, maximum=1),
            child_runner=self.runner_for(plan, []),
            **self.capture_arguments(),
        )
        lane_records = {
            lane: durability.read_journal_regular(
                bundle / lane / "journal.ndjson", "mutation lane journal"
            )[1:]
            for lane in pair_module.PAIR_LANE_ORDER
        }
        path = bundle / publication.PUBLICATION_JOURNAL_NAME
        records = [json.loads(line) for line in path.read_bytes().splitlines()]
        records[3]["attempt_record_sha256"] = "e" * 64
        records[3]["content_sha256"] = content_digest(records[3])
        path.write_bytes(b"".join(canonical_bytes(record) for record in records))
        with self.assertRaisesRegex(CaptureError, "commit changed"):
            publication.read_publication_journal(
                path,
                plan=plan,
                lane_records=lane_records,
                require_complete=False,
            )

    def test_intent_only_recovery_is_catastrophic_and_never_launches(self) -> None:
        plan = self.pair_plan("fixture-intent-only-publication")
        plan_path = self.scratch / "intent-only-plan.json"
        bundle = self.scratch / "intent-only-bundle"
        write_pair_plan_new(plan_path, plan)
        settings = self.settings(plan_path, bundle, maximum=1)
        proof_attempts: list[tuple[str, int]] = []
        original = publication.AttemptPublicationJournal.begin

        def crash_after_intent(instance, schedule, lane_root, attempt):
            original(instance, schedule, lane_root, attempt)
            raise SimulatedCrash("host death after durable intent")

        with (
            mock.patch.object(
                publication.AttemptPublicationJournal,
                "begin",
                new=crash_after_intent,
            ),
            self.assertRaises(SimulatedCrash),
        ):
            capture_pair(
                settings,
                child_runner=self.runner_for(plan, proof_attempts),
                **self.capture_arguments(),
            )
        self.assertEqual(proof_attempts, [])

        with self.assertRaisesRegex(CaptureError, "unresolved attempt intent"):
            capture_pair(
                settings,
                child_runner=lambda *_: (_ for _ in ()).throw(
                    AssertionError("pending intent reran its child")
                ),
                **self.capture_arguments(),
            )
        self.assertEqual(proof_attempts, [])

    def test_publication_authority_rejects_reopening_its_pending_intent(self) -> None:
        plan = self.pair_plan("fixture-direct-pending-intent")
        bundle = self.scratch / "direct-pending-intent"
        bundle.mkdir()
        schedule = plan["interleaving"][0]
        lane = schedule["lane"]
        lane_root = bundle / lane
        lane_root.mkdir()
        attempt = plan["lanes"][lane]["attempts"][schedule["lane_ordinal"]]
        journal = publication.AttemptPublicationJournal(bundle, plan)
        try:
            journal.begin(schedule, lane_root, attempt)
            with self.assertRaisesRegex(CaptureError, "unresolved attempt intent"):
                journal.begin(schedule, lane_root, attempt)
        finally:
            journal.abandon()

    def test_child_return_before_first_retain_is_never_retried(self) -> None:
        plan = self.pair_plan("fixture-child-return-publication")
        plan_path = self.scratch / "child-return-plan.json"
        bundle = self.scratch / "child-return-bundle"
        write_pair_plan_new(plan_path, plan)
        settings = self.settings(plan_path, bundle, maximum=1)
        proof_attempts: list[tuple[str, int]] = []

        def crash_before_first_retain(instance, relative, raw):
            del instance, relative, raw
            raise SimulatedCrash("host death after child return")

        with (
            mock.patch.object(
                durability.ResumableLaneJournal,
                "retain",
                new=crash_before_first_retain,
            ),
            self.assertRaises(SimulatedCrash),
        ):
            capture_pair(
                settings,
                child_runner=self.runner_for(
                    plan, proof_attempts, fail_proof=True
                ),
                **self.capture_arguments(),
            )
        self.assertEqual(proof_attempts, [("cpu-native", 0)])

        with self.assertRaisesRegex(CaptureError, "unresolved attempt intent"):
            capture_pair(
                settings,
                child_runner=lambda *_: (_ for _ in ()).throw(
                    AssertionError("returned child reran after host death")
                ),
                **self.capture_arguments(),
            )
        self.assertEqual(proof_attempts, [("cpu-native", 0)])

    def test_unprepared_partial_attempt_is_explicitly_fail_closed(self) -> None:
        plan = self.pair_plan("fixture-catastrophic-publication")
        plan_path = self.scratch / "catastrophic-plan.json"
        bundle = self.scratch / "catastrophic-bundle"
        write_pair_plan_new(plan_path, plan)
        proof_attempts: list[tuple[str, int]] = []
        runner = self.runner_for(plan, proof_attempts)
        settings = self.settings(plan_path, bundle, maximum=1)
        original = durability.ResumableLaneJournal.retain

        def crash_after_first_file(instance, relative, raw):
            identity = original(instance, relative, raw)
            if relative.endswith(".report.json"):
                raise SimulatedCrash("mid-publication host death")
            return identity

        with (
            mock.patch.object(
                durability.ResumableLaneJournal,
                "retain",
                new=crash_after_first_file,
            ),
            self.assertRaises(SimulatedCrash),
        ):
            capture_pair(
                settings,
                child_runner=runner,
                **self.capture_arguments(),
            )
        with self.assertRaisesRegex(CaptureError, "catastrophic interruption"):
            capture_pair(
                settings,
                child_runner=runner,
                **self.capture_arguments(),
            )

    def test_pair_and_lane_journals_reject_symlink_reopen(self) -> None:
        for relative in ("pair-journal.ndjson", "cpu-native/journal.ndjson"):
            with self.subTest(relative=relative):
                plan = self.pair_plan("fixture-symlink-" + relative.split("/")[0])
                plan_path = self.scratch / (relative.replace("/", "-") + ".plan")
                bundle = self.scratch / (relative.replace("/", "-") + ".bundle")
                write_pair_plan_new(plan_path, plan)
                capture_pair(
                    self.settings(plan_path, bundle, maximum=1),
                    child_runner=self.runner_for(plan, []),
                    **self.capture_arguments(),
                )
                journal = bundle / relative
                backing = self.scratch / (relative.replace("/", "-") + ".backing")
                journal.rename(backing)
                os.symlink(backing, journal)
                with self.assertRaisesRegex(CaptureError, "non-symlink regular file"):
                    capture_pair(
                        self.settings(plan_path, bundle, maximum=1),
                        child_runner=self.runner_for(plan, []),
                        **self.capture_arguments(),
                    )

    def test_identical_finalization_survives_every_publish_cut(self) -> None:
        payloads = {"cpu-native": b"cpu\n", "metal-hybrid": b"metal\n"}
        root_payload = b"root\n"
        for cut in ("cpu-native", "metal-hybrid", "root"):
            with self.subTest(cut=cut):
                root = self.scratch / f"publish-{cut}"
                (root / "cpu-native").mkdir(parents=True)
                (root / "metal-hybrid").mkdir()

                def stop(label):
                    if label == cut:
                        raise SimulatedCrash(label)

                with self.assertRaises(SimulatedCrash):
                    durability.publish_pair_manifests(
                        root, payloads, root_payload, after_publish=stop
                    )
                durability.publish_pair_manifests(root, payloads, root_payload)
                before = {
                    path.relative_to(root).as_posix(): path.read_bytes()
                    for path in root.rglob("*.json")
                }
                durability.publish_pair_manifests(root, payloads, root_payload)
                after = {
                    path.relative_to(root).as_posix(): path.read_bytes()
                    for path in root.rglob("*.json")
                }
                self.assertEqual(before, after)

        root = self.scratch / "publish-conflict"
        (root / "cpu-native").mkdir(parents=True)
        (root / "metal-hybrid").mkdir()
        durability.publish_pair_manifests(root, payloads, root_payload)
        (root / "cpu-native/bundle.json").write_bytes(b"changed\n")
        with self.assertRaisesRegex(CaptureError, "differs"):
            durability.publish_pair_manifests(root, payloads, root_payload)

    def test_link_before_temp_cleanup_leaves_no_bundle_inventory_debris(self) -> None:
        root = self.scratch / "external-staging"
        root.mkdir()
        target = root / "manifest.json"
        original_unlink = Path.unlink

        def crash_unlink(path, *args, **kwargs):
            if path.parent == root.parent and path.name.startswith(".r006-"):
                raise SimulatedCrash("host death after final link")
            return original_unlink(path, *args, **kwargs)

        with (
            mock.patch.object(Path, "unlink", new=crash_unlink),
            self.assertRaises(SimulatedCrash),
        ):
            durability.publish_new_or_identical(
                target, b"sealed\n", staging_directory=root.parent
            )
        self.assertEqual(target.read_bytes(), b"sealed\n")
        self.assertEqual([path.name for path in root.iterdir()], ["manifest.json"])
        durability.publish_new_or_identical(
            target, b"sealed\n", staging_directory=root.parent
        )

    def test_full_v2_replay_and_manifest_only_resume_need_no_live_preflight(self) -> None:
        plan = self.pair_plan("fixture-full-v2-replay")
        plan_path = self.scratch / "full-plan.json"
        bundle = self.scratch / "full-bundle"
        write_pair_plan_new(plan_path, plan)
        proof_attempts: list[tuple[str, int]] = []
        runner = self.runner_for(plan, proof_attempts)
        original_publish = durability.publish_pair_manifests

        def crash_after_cpu(root, lane_payloads, root_payload):
            durability.publish_new_or_identical(
                root / "cpu-native/bundle.json",
                lane_payloads["cpu-native"],
                staging_directory=root.parent,
            )
            raise SimulatedCrash("after first lane manifest")

        with (
            mock.patch.object(
                durability, "publish_pair_manifests", new=crash_after_cpu
            ),
            self.assertRaises(SimulatedCrash),
        ):
            capture_pair(
                self.settings(plan_path, bundle, maximum=None),
                child_runner=runner,
                **self.capture_arguments(),
            )
        self.assertEqual(len(proof_attempts), PAIR_ATTEMPTS)
        self.assertTrue((bundle / "cpu-native/bundle.json").is_file())
        self.assertFalse((bundle / "pair-bundle.json").exists())

        def forbidden_preflight():
            raise AssertionError("durably complete finalization sampled the live host")

        completed = capture_pair(
            self.settings(plan_path, bundle, maximum=None),
            child_runner=lambda *_: (_ for _ in ()).throw(
                AssertionError("durably complete finalization reran an attempt")
            ),
            sleeper=lambda _: None,
            preflight_provider=forbidden_preflight,
            source_provider=self.source,
            closure_provider=self.closure,
        )
        self.assertEqual(completed["schema_version"], 2)
        self.assertEqual(completed["recorded_attempts"], PAIR_ATTEMPTS)
        validation = validate_pair_bundle(self.repository, bundle)
        self.assertEqual(validation["schema_version"], 3)
        self.assertTrue(validation["attempt_publication_journal_valid"])
        self.assertTrue(validation["preflight_boundary_journal_valid"])

        manifest_before = (bundle / "pair-bundle.json").read_bytes()
        replayed = capture_pair(
            self.settings(plan_path, bundle, maximum=None),
            child_runner=lambda *_: (_ for _ in ()).throw(AssertionError("rerun")),
            sleeper=lambda _: None,
            preflight_provider=forbidden_preflight,
            source_provider=self.source,
            closure_provider=self.closure,
        )
        self.assertEqual(replayed, completed)
        self.assertEqual((bundle / "pair-bundle.json").read_bytes(), manifest_before)
