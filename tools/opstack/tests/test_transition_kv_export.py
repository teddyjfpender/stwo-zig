"""Exact oracle blob scaffold; KZG itself has separate native physical gates."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).parents[1]))
import transition_kv_export as E
import transition_capture as C


class BlobScaffoldTests(unittest.TestCase):
    def test_exact_roots_fields_proof_slot_and_canonical_boundaries(self):
        roots=E.roots();self.assertEqual(len(set(roots)),4096)
        self.assertEqual(roots[0],(1).to_bytes(32,'big'))
        commitment=b'\xc0'+bytes(47);helpers={C.keccak(commitment+r):commitment+r for r in roots}
        proof_input=commitment+roots[-1][:24]+(4096).to_bytes(8,'big');proof_key=C.keccak(proof_input);helpers[proof_key]=proof_input
        class Store:
            bad=None
            def read(self,tag,digest,width):
                if tag==2:
                    value=helpers[digest]
                    return b'bad'if self.bad=='helper'else value
                if width==48:return commitment
                return E.FR.to_bytes(32,'big')if self.bad=='scalar'else bytes(32)
        store=Store();row,keys,blob=E.reconstruct(store,commitment,roots)
        self.assertEqual(len(keys),4097);self.assertEqual(len(blob),4097)
        self.assertEqual(C.unhex(row['blob']),bytes(131072));self.assertEqual(row['kzg_proof'],commitment.hex())
        store.bad='helper'
        with self.assertRaisesRegex(ValueError,'helper'):E.reconstruct(store,commitment,roots)
        store.bad='scalar'
        with self.assertRaisesRegex(ValueError,'noncanonical'):E.reconstruct(store,commitment,roots)


if __name__=='__main__':unittest.main()
