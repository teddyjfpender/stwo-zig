"""Compile-time threshold identities cannot inherit hidden environment state."""

import contextlib
import io
import subprocess
import sys
import unittest

from opstack.build import bulk_environment, execution_requirements, LEAN_VARIANTS


class BuildEnvironment(unittest.TestCase):
    def test_execution_failure_preserves_exit_and_bounded_diagnostic(self):
        from opstack.benchmark import run
        diagnostic = io.StringIO()
        with contextlib.redirect_stderr(diagnostic):
            with self.assertRaises(subprocess.CalledProcessError) as error:
                run([sys.executable, '-c',
                     "import sys;sys.stderr.write('x'*9000+'missing preimage');sys.exit(7)"])
        self.assertEqual(error.exception.returncode, 7)
        self.assertEqual(len(diagnostic.getvalue()), 8192)
        self.assertTrue(diagnostic.getvalue().endswith('missing preimage'))

    def test_explicit_thresholds_and_ambient_cleanup(self):
        env, thresholds = bulk_environment(
            {
                "PATH": "test",
                "STWO_ADMITTED_COPY_MIN": "0",
                "STWO_ADMITTED_EXTRA": "bad",
            }
        )
        self.assertEqual(
            thresholds, {"COPY": "16", "UCOPY": "16", "SET": "16", "CMP": "8"}
        )
        self.assertEqual(env["PATH"], "test")
        self.assertNotIn("STWO_ADMITTED_EXTRA", env)
        for value in ["8", "1048576", "off"]:
            _, thresholds = bulk_environment({}, value)
            self.assertEqual(set(thresholds.values()), {value})
        for value in ["0", "7", "1048577", "-8", "", "1.5"]:
            with self.assertRaises(ValueError):
                bulk_environment({}, value)

    def test_service_requirements_follow_features_including_diagnostic_aliases(self):
        requirement = execution_requirements(["crypto-services"])
        self.assertEqual(requirement["required_execution_profile"], "ethereum_services_v3")
        self.assertEqual(requirement["extra_service_tags"], [0x30010, 0x30130])
        for name in ["canonical-glv-hinted-sparse", "canonical-glv-hinted-sparse-dense", "dense-probe-control", "dense-probe-candidate"]:
            requirement = execution_requirements(LEAN_VARIANTS[name][1])
            self.assertEqual(requirement["required_execution_profile"], "ethereum_services_op_v1", name)
            self.assertEqual(requirement["extra_service_tags"], [0x40001], name)
        self.assertIsNone(execution_requirements(["services-v3,montgomery-services"])["required_execution_profile"])
