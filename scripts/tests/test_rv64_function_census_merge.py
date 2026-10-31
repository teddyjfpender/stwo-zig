"""Small exact-merge integrity regressions; no retained-packet or prover dependency."""
import hashlib
import heapq
import importlib.util
from pathlib import Path
import tempfile
import unittest

path=Path(__file__).resolve().parents[1]/'rv64_function_census_merge.py'
spec=importlib.util.spec_from_file_location('function_census',path)
M=importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
class ExactMergeTests(unittest.TestCase):
    def input(self,directory,name,rows):
        path=Path(directory)/name
        raw=b''.join(M.ROW.pack(a,b,c,op,count) for op,a,b,c,count in rows)
        path.write_bytes(raw)
        return path,dict(unique=len(rows),run_sha256=hashlib.sha256(raw).hexdigest())
    def stream(self,path,meta):
        return M.run(path,meta,M.Stats(),{f:M.Stats() for f in ('alu','binary','shift')})
    def test_overlap_and_global_ids_preserve_exact_mass(self):
        with tempfile.TemporaryDirectory() as d:
            p0,m0=self.input(d,'a',[(0,0,0,0,3),(16,0,0,0,2)])
            p1,m1=self.input(d,'b',[(0,0,0,0,4),(32,0,0,0,5)])
            counter={}
            for key,n in heapq.merge(self.stream(p0,m0),self.stream(p1,m1)):
                counter[key]=counter.get(key,0)+n
            self.assertEqual(counter,{(0,0,0,0):7,(16,0,0,0):2,(32,0,0,0):5})
            stats=M.Stats()
            for key,n in counter.items():stats.add(key,n)
            self.assertEqual((stats.n,stats.mass),(3,14))
            self.assertEqual(stats.json()['duplicate_occurrences'],11)
    def test_unsorted_duplicate_truncated_and_digest_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            for rows in [[(16,0,0,0,1),(0,0,0,0,1)],[(0,0,0,0,1),(0,0,0,0,1)]]:
                p,m=self.input(d,'bad',rows)
                with self.assertRaises(ValueError):list(self.stream(p,m))
            p,m=self.input(d,'bad',[(0,0,0,0,1)])
            m['run_sha256']='0'*64
            with self.assertRaises(ValueError):list(self.stream(p,m))
            p.write_bytes(b'x');m['run_sha256']=hashlib.sha256(b'x').hexdigest()
            with self.assertRaises(ValueError):list(self.stream(p,m))
    def test_count_bound_and_invalid_family_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            for row in [(0,0,0,0,0),(15,0,0,0,1)]:
                p,m=self.input(d,'bad',[row])
                with self.assertRaises(ValueError):list(self.stream(p,m))
            p,m=self.input(d,'bad',[(0,0,0,0,1)]);m['unique']=2
            with self.assertRaises(ValueError):list(self.stream(p,m))
if __name__=='__main__':unittest.main()
