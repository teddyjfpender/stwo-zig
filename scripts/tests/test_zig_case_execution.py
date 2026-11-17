from __future__ import annotations

import contextlib
import io
import json
import os
import resource
import signal
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from scripts import dev_test
from scripts.repo import zig_case_execution as cases
from scripts.repo.ci_scope_plan import PlanError, write_json

ROOT = Path(__file__).resolve().parents[2]
SERVER = r'''
import json,struct,sys,os
from pathlib import Path
cfg=json.loads(Path(CONFIG).read_text()); count=Path(CONFIG+'.count')
k=int(count.read_text())+1 if count.exists() else 1; count.write_text(str(k))
def send(tag,body):
 sys.stdout.buffer.write(struct.pack('<II',tag,len(body))+body);sys.stdout.buffer.flush()
send(0,cfg.get('version','0.15.2').encode())
while True:
 header=sys.stdin.buffer.read(8)
 if not header:break
 tag,n=struct.unpack('<II',header);body=sys.stdin.buffer.read(n)
 if cfg.get('record_limits') and tag in (4,5):
  import resource
  with Path(CONFIG+'.limits').open('a') as f:f.write(json.dumps([tag,list(resource.getrlimit(resource.RLIMIT_CPU))])+'\n')
 if tag==0:break
 if tag==4:
  if cfg.get('query_crash'):os._exit(7)
  if cfg.get('query_signal'):os.kill(os.getpid(),15)
  if cfg.get('query_sleep'):__import__('time').sleep(20)
  names=cfg.get('names',['first','second']); names=names[::-1] if cfg.get('change') and k>1 else names
  text=b'\0';offsets=[]
  for name in names:offsets.append(len(text));text+=name.encode()+b'\0'
  send(3,struct.pack('<II',len(text),len(names))+struct.pack('<%dI'%len(names),*offsets)+struct.pack('<%dI'%len(names),*[cfg.get('panic',0)]*len(names))+text)
 if tag==5:
  i,=struct.unpack('<I',body)
  if cfg.get('sleep'):__import__('time').sleep(20)
  with Path(CONFIG+'.runs').open('a') as f:f.write(str(i)+'\n')
  if cfg.get('descendant'):
   import subprocess
   p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(20)'])
   Path(CONFIG+'.pid').write_text(str(p.pid))
  if cfg.get('crash')==i:os._exit(7)
  if cfg.get('signal')==i:os.kill(os.getpid(),15)
  send(99 if cfg.get('unknown') else 4,struct.pack('<II',i+1 if cfg.get('forged') else i,cfg.get('flags',[0,0])[i]))
  if cfg.get('duplicate'):send(4,struct.pack('<II',i,0))
'''


class ExactCaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name).resolve()
        self.binary, self.config = self.folder / "server", self.folder / "config.json"
        self.binary.write_text("#!" + sys.executable + "\nCONFIG=" + repr(str(self.config)) + "\n" + SERVER)
        self.binary.chmod(0o755)
        self.config.write_text("{}")
        self.out = self.folder / "output"
        self.addCleanup(mock.patch.stopall)
        mock.patch("sys.stdout", new=io.StringIO()).start()

    def run_cases(self, resume=None):
        return cases.execute(self.binary, cases.sha(self.binary), 17, self.out, ROOT, resume, max_cases=65536)

    def test_complete_original_coverage_and_verified_resume(self):
        result = self.run_cases()
        self.assertEqual(("PASS", 2, 0), (result["status"], result["passed"], result["skipped"]))
        self.run_cases(cases.sha(self.out / "receipt.json"))
        self.assertEqual("0\n1\n", Path(str(self.config) + ".runs").read_text())

    def test_skip_fail_leak_log_and_fuzz_flags_preserve_meaning(self):
        self.config.write_text(json.dumps({"names": list("abcde"), "flags": [2, 1, 4, 16, 8]}))
        result = self.run_cases()
        self.assertEqual(("FAIL", 1, 1, 3, 1),
                         (result["status"], result["passed"], result["skipped"], result["failed"], result["fuzz_initial_cases"]))
        self.run_cases(cases.sha(self.out / "receipt.json"))
        self.assertEqual("0\n1\n2\n3\n4\n", Path(str(self.config) + ".runs").read_text())

    def test_clean_prefix_resume_never_reexecutes_a_completed_case(self):
        def interrupt(path, value):
            write_json(path, value)
            if path == self.out / "receipt.json" and len(value["results"]) == 1:
                raise KeyboardInterrupt
        with mock.patch.object(cases, "write_json", side_effect=interrupt), self.assertRaises(KeyboardInterrupt):
            self.run_cases()
        self.assertEqual("INCOMPLETE", json.loads((self.out / "receipt.json").read_text())["status"])
        self.assertEqual("PASS", self.run_cases(cases.sha(self.out / "receipt.json"))["status"])
        self.assertEqual("0\n1\n", Path(str(self.config) + ".runs").read_text())

    def test_ambiguous_crashed_case_is_not_automatically_retried(self):
        self.config.write_text('{"crash":1}')
        with self.assertRaises(PlanError):
            self.run_cases()
        self.assertEqual(1, len(json.loads((self.out / "receipt.json").read_text())["results"]))
        with self.assertRaisesRegex(PlanError, "cannot automatically retry"):
            self.run_cases(cases.sha(self.out / "receipt.json"))
        self.assertEqual("0\n1\n", Path(str(self.config) + ".runs").read_text())

    def test_eof_retains_exit_and_signal_without_reclassifying_protocol_failure(self):
        for key, code in (("crash", 7), ("signal", -signal.SIGTERM)):
            with self.subTest(key=key):
                self.out = self.folder / key
                self.config.write_text(json.dumps({key: 0}))
                with self.assertRaisesRegex(PlanError, "expected one result"):
                    self.run_cases()
                record = json.loads((self.out / "000000.interrupted.json").read_text())
                self.assertEqual("INCOMPLETE", record["status"])
                self.assertEqual(code, record["termination"]["returncode"])
                self.assertTrue(record["termination"]["cleanup"]["already_exited"])
                self.assertGreater(record["termination"]["resources"]["peak_rss_bytes"], 0)
                self.assertGreater(record["duration_ns"], 0)
                self.assertEqual({}, record["evidence_errors"])
                for extension in (".stdout.bin", ".stderr"):
                    self.assertEqual(cases.sha(self.out / ("000000" + extension)), record["evidence"][extension])
                with self.assertRaisesRegex(PlanError, "cannot automatically retry"):
                    self.run_cases(cases.sha(self.out / "receipt.json"))

        self.out = self.folder / "hash-unavailable"
        self.config.write_text('{"crash":0}')
        original_sha = cases.sha
        def unavailable(path):
            if path.suffix == ".stderr":
                raise OSError("evidence unavailable")
            return original_sha(path)
        with mock.patch.object(cases, "sha", side_effect=unavailable), self.assertRaisesRegex(PlanError, "expected one result"):
            self.run_cases()
        record = json.loads((self.out / "000000.interrupted.json").read_text())
        self.assertIsNone(record["evidence"][".stderr"])
        self.assertIn("evidence unavailable", record["evidence_errors"][".stderr"])
        self.assertEqual(7, record["termination"]["returncode"])

    def test_cpu_allowance_applies_to_kernel_query_case_and_resume_identity(self):
        for cpu in (110, 3):
            with self.subTest(cpu=cpu):
                self.out = self.folder / str(cpu)
                self.config.write_text('{"record_limits":true}')
                limits_path = Path(str(self.config) + ".limits")
                limits_path.unlink(missing_ok=True)
                result = cases.execute(self.binary, cases.sha(self.binary), 17, self.out, ROOT, cpu_seconds=cpu)
                self.assertEqual({**cases.LIMITS, "cpu_seconds": cpu}, result["identity"]["limits"])
                self.assertEqual(110, cases.LIMITS["cpu_seconds"])
                self.assertIsNot(cases.LIMITS, result["identity"]["limits"])
                observed = [json.loads(line) for line in limits_path.read_text().splitlines()]
                self.assertEqual([[4, [cpu, cpu]], [4, [cpu, cpu]], [5, [cpu, cpu]]], observed)
                anchor = cases.sha(self.out / "receipt.json")
                with mock.patch.object(cases.subprocess, "Popen", side_effect=AssertionError("must not spawn metadata")):
                    with self.assertRaisesRegex(PlanError, "identity changed"):
                        cases.execute(self.binary, cases.sha(self.binary), 17, self.out, ROOT,
                                      anchor, cpu_seconds=3 if cpu == 110 else 110)
                self.assertEqual(anchor, cases.sha(self.out / "receipt.json"))
                result = cases.execute(self.binary, cases.sha(self.binary), 17, self.out, ROOT, anchor, cpu_seconds=cpu)
                self.assertEqual("PASS", result["status"])

    def test_cpu_admission_bounds_and_inherited_hard_refuse_before_output(self):
        for cpu in (0, 1921, True, 1.5, "3"):
            with self.subTest(cpu=cpu), mock.patch.object(cases.subprocess, "Popen", side_effect=AssertionError("must not spawn")):
                with self.assertRaises(PlanError):
                    cases.execute(self.binary, cases.sha(self.binary), 17, self.out, ROOT, cpu_seconds=cpu)
                self.assertFalse(self.out.exists())
        with mock.patch.object(resource, "getrlimit", return_value=(2, 2)):
            with self.assertRaisesRegex(PlanError, "inherited hard"):
                cases.execute(self.binary, cases.sha(self.binary), 17, self.out, ROOT, cpu_seconds=3)
            session = cases.Session(self.binary, 17, self.folder / "direct", None, None, cpu_seconds=3)
            with self.assertRaisesRegex(PlanError, "inherited hard"):
                session.run(ROOT)
        self.assertFalse(self.out.exists())
        self.assertFalse((self.folder / "direct.stderr").exists())
        with mock.patch.object(resource, "getrlimit", return_value=(resource.RLIM_INFINITY, resource.RLIM_INFINITY)):
            self.assertEqual(1, cases.admit_cpu_seconds(1))
            self.assertEqual(1920, cases.admit_cpu_seconds(1920))
            result = cases.execute(self.binary, cases.sha(self.binary), 17, self.out, ROOT, cpu_seconds=3)
        self.assertEqual(3, result["identity"]["limits"]["cpu_seconds"])

    def test_explicit_cpu_cli_is_exact_case_only_and_cannot_retry_interrupted_case(self):
        self.assertEqual(2, dev_test.main(["--case-cpu-seconds", "3"]))
        argv = ["--case-binary", str(self.binary), "--case-sha256", cases.sha(self.binary),
                "--case-seed", "17", "--case-output", str(self.out), "--case-cpu-seconds", "3"]
        self.assertEqual(2, dev_test.main([*argv, "--optimize", "ReleaseFast"]))
        self.assertEqual(3, dev_test.main(argv))
        self.assertEqual(0, dev_test.main([*argv, "--case-resume-digest", cases.sha(self.out / "receipt.json")]))
        self.out = self.folder / "interrupted-cpu"
        Path(str(self.config) + ".runs").unlink()
        self.config.write_text('{"crash":0}')
        with self.assertRaisesRegex(PlanError, "expected one result"):
            cases.execute(self.binary, cases.sha(self.binary), 17, self.out, ROOT, cpu_seconds=3)
        with self.assertRaisesRegex(PlanError, "cannot automatically retry"):
            cases.execute(self.binary, cases.sha(self.binary), 17, self.out, ROOT,
                          cases.sha(self.out / "receipt.json"), cpu_seconds=3)
        self.assertEqual("0\n", Path(str(self.config) + ".runs").read_text())

    def test_discovery_failure_retains_native_evidence_before_case_admission(self):
        for key, code in (("query_crash", 7), ("query_signal", -signal.SIGTERM)):
            with self.subTest(key=key):
                self.out = self.folder / key
                self.config.write_text(json.dumps({key: True}))
                with self.assertRaisesRegex(PlanError, "expected complete metadata"):
                    self.run_cases()
                records = list(self.out.glob("query-*.interrupted.json"))
                self.assertEqual(1, len(records))
                record = json.loads(records[0].read_text())
                self.assertEqual(code, record["termination"]["returncode"])
                base = records[0].name.removesuffix(".interrupted.json")
                for suffix in (".stdout.bin", ".stderr"):
                    self.assertEqual(cases.sha(self.out / (base + suffix)), record["evidence"][suffix])
                self.assertEqual([], list(self.out.glob("*.started.json")))
                self.assertEqual("INCOMPLETE", json.loads((self.out / "receipt.json").read_text())["status"])

        self.out = self.folder / "query-hash-unavailable"
        self.config.write_text('{"query_crash":true}')
        original_sha = cases.sha
        def unavailable(path):
            if path.suffix == ".stderr":
                raise OSError("query evidence unavailable")
            return original_sha(path)
        with mock.patch.object(cases, "sha", side_effect=unavailable), self.assertRaisesRegex(PlanError, "expected complete metadata"):
            self.run_cases()
        record = json.loads(next(self.out.glob("query-*.interrupted.json")).read_text())
        self.assertIsNone(record["evidence"][".stderr"])
        self.assertIn("query evidence unavailable", record["evidence_errors"][".stderr"])
        self.assertEqual(7, record["termination"]["returncode"])

    def test_discovery_spawn_failure_marks_unavailable_evidence(self):
        self.binary.chmod(0o644)
        with mock.patch.object(cases, "interrupted", wraps=cases.interrupted) as publication:
            with self.assertRaises(PermissionError) as raised:
                self.run_cases()
        self.assertIs(raised.exception, publication.call_args.args[1])
        record = json.loads(next(self.out.glob("query-*.interrupted.json")).read_text())
        self.assertIsNone(record["termination"])
        self.assertIsNone(record["evidence"][".stdout.bin"])
        self.assertIn(".stdout.bin", record["evidence_errors"])
        self.assertEqual(cases.sha(next(self.out.glob("query-*.stderr"))), record["evidence"][".stderr"])

    def test_discovery_watchdog_direct_signal_preserves_wait4(self):
        self.config.write_text('{"query_sleep":true}')
        with mock.patch.object(cases, "RSS_CAP", -1), mock.patch.object(
            cases.os, "killpg", side_effect=PermissionError("forced group refusal")
        ), mock.patch.object(subprocess.Popen, "kill", side_effect=AssertionError("must not poll/reap")):
            with self.assertRaises(PlanError):
                self.run_cases()
        record = json.loads(next(self.out.glob("query-*.interrupted.json")).read_text())
        self.assertEqual("RSS_CAP", record["guard_reason"])
        self.assertEqual(-signal.SIGKILL, record["termination"]["returncode"])
        self.assertGreater(record["termination"]["resources"]["peak_rss_bytes"], 0)

    def test_live_malformed_protocol_drains_owned_descendant_and_retains_cause(self):
        self.config.write_text('{"unknown":true,"descendant":true}')
        with self.assertRaisesRegex(PlanError, "expected one result"):
            self.run_cases()
        record = json.loads((self.out / "000000.interrupted.json").read_text())
        self.assertEqual(-signal.SIGKILL, record["termination"]["returncode"])
        self.assertFalse(record["termination"]["cleanup"]["already_exited"])
        pid = Path(str(self.config) + ".pid").read_text()
        remaining = subprocess.run(["ps", "-p", pid, "-o", "stat="], capture_output=True, text=True)
        self.assertTrue(remaining.returncode != 0 or remaining.stdout.strip().startswith("Z"))

    def test_guard_kill_retains_exact_native_status(self):
        self.config.write_text('{"sleep":true}')
        session = cases.Session(self.binary, 17, self.folder / "guard", 0, None)
        with mock.patch.object(cases, "RSS_CAP", -1), self.assertRaises(PlanError):
            session.run(ROOT)
        self.assertEqual("RSS_CAP", session.reason)
        self.assertEqual(-signal.SIGKILL, session.termination["returncode"])
        self.assertGreater(session.termination["resources"]["peak_rss_bytes"], 0)

    def test_bad_version_inventory_panic_and_frames_fail_closed(self):
        for key, value in (("version", "0.16.0"), ("change", True), ("panic", 1), ("names", ["same", "same"]),
                           ("forged", True), ("duplicate", True), ("unknown", True)):
            with self.subTest(key=key):
                self.out = self.folder / key
                Path(str(self.config) + ".count").unlink(missing_ok=True)
                self.config.write_text(json.dumps({key: value}))
                with self.assertRaises(PlanError):
                    self.run_cases()
                self.assertEqual("INCOMPLETE", json.loads((self.out / "receipt.json").read_text())["status"])

    def test_resume_rejects_changed_anchor_record_flags_and_evidence(self):
        self.run_cases()
        anchor = cases.sha(self.out / "receipt.json")
        with self.assertRaisesRegex(PlanError, "receipt digest"):
            self.run_cases("0" * 64)
        record = self.out / "000000.completed.json"
        before = record.read_bytes()
        modified = json.loads(before); modified["flags"] = 1; write_json(record, modified)
        with self.assertRaisesRegex(PlanError, "forged completed"):
            self.run_cases(anchor)
        record.write_bytes(before)
        (self.out / "000000.stdout.bin").write_bytes(b"bad")
        with self.assertRaises(PlanError):
            self.run_cases(anchor)

    def test_metadata_bounds_names_and_truncation_are_checked(self):
        for body in (b"", struct.pack("<II", 1, 0) + b"\0", struct.pack("<II", 1, 999999)):
            with self.assertRaises(PlanError):
                cases.inventory(body)
        with self.assertRaises(PlanError):
            cases.frame(io.BytesIO(struct.pack("<II", 0, cases.MAX_FRAME + 1)))
        with self.assertRaises(PlanError):
            cases.frame(io.BytesIO(b"\0"))

    def test_guard_failure_keeps_the_aggregate_incomplete(self):
        with mock.patch.object(cases, "RSS_CAP", -1), self.assertRaises(PlanError):
            self.run_cases()
        self.assertEqual("INCOMPLETE", json.loads((self.out / "receipt.json").read_text())["status"])
        interrupted = list(self.out.glob("*.interrupted.json"))
        # The watchdog may stop discovery before a selected case is admitted.
        if interrupted:
            record = json.loads(interrupted[0].read_text())
            self.assertEqual(-signal.SIGKILL, record["termination"]["returncode"])

    def test_binary_and_seed_admission_cannot_change_on_resume(self):
        with self.assertRaisesRegex(PlanError, "SHA256"):
            cases.execute(self.binary, "0" * 64, 17, self.out, ROOT)
        self.run_cases()
        with self.assertRaisesRegex(PlanError, "identity"):
            cases.execute(self.binary, cases.sha(self.binary), 18, self.out, ROOT,
                          cases.sha(self.out / "receipt.json"))

    def test_existing_entrypoint_excludes_recompile_and_planning_modes(self):
        self.assertEqual(2, dev_test.main(["--case-binary", str(self.binary)]))
        argv = ["--case-binary", str(self.binary), "--case-sha256", cases.sha(self.binary),
                "--case-seed", "17", "--case-output", str(self.out)]
        self.assertEqual(2, dev_test.main([*argv, "--optimize", "ReleaseFast"]))
        self.assertEqual(3, dev_test.main(argv))
        anchor = cases.sha(self.out / "receipt.json")
        self.assertEqual(0, dev_test.main([*argv, "--case-resume-digest", anchor]))
