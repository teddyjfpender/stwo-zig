"""Invalid explicit build references refuse before artifact/build work."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

class BuildReferences(unittest.TestCase):
    def test_missing_reference_fails_before_artifact_creation(self):
        script=Path(__file__).resolve().parents[1]/'build.py'
        with tempfile.TemporaryDirectory()as directory:
            base=Path(directory)
            for flag in('--native-reference','--runner-reference'):
                output=base/flag[2:]
                result=subprocess.run([sys.executable,str(script),'--artifacts',str(output),flag,str(base/'missing')],capture_output=True,timeout=5)
                self.assertEqual(result.returncode,2)
                self.assertIn(b'reference binary missing',result.stderr)
                self.assertFalse(output.exists())
