import sqlite3
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.rv64.rv64_m7_gpu_seconds_lib.census import request_census
from scripts.rv64.rv64_m7_gpu_seconds_lib.ranges import native_ranges


class ActivityTests(unittest.TestCase):
    def database(self):
        db = sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        db.executescript('''
            CREATE TABLE StringIds(id INTEGER, value TEXT);
            CREATE TABLE CUPTI_ACTIVITY_KIND_RUNTIME(start INTEGER,end INTEGER,correlationId INTEGER,nameId INTEGER);
            CREATE TABLE CUPTI_ACTIVITY_KIND_MEMCPY(start INTEGER,end INTEGER,correlationId INTEGER,bytes INTEGER,copyKind INTEGER);
            INSERT INTO StringIds VALUES (1,'cudaMemcpyPeerAsync_v4000'),(2,'cudaMemcpyAsync_v3020'),(3,'cudaEventSynchronize_v3020');
            INSERT INTO CUPTI_ACTIVITY_KIND_RUNTIME VALUES (110,120,1,1),(130,140,2,2),(90,95,3,2),(160,220,4,3);
            INSERT INTO CUPTI_ACTIVITY_KIND_MEMCPY VALUES (125,135,1,32,2),(145,155,2,64,2),(96,105,3,16,2),(145,155,2,1000,1);
        ''')
        return db

    def test_peer_transport_is_separate_from_ordinary_and_unattributed_readbacks(self):
        result = request_census(self.database(), 100, 200)
        self.assertEqual(result['status'], 'MEASURED')
        d2h = result['d2h_activities']
        self.assertEqual(d2h['peer_transport'], {'activities': 1, 'bytes': 32})
        self.assertEqual(d2h['ordinary_cuda_copy'], {'activities': 1, 'bytes': 64})
        self.assertEqual(d2h['unattributed'], {'activities': 1, 'bytes': 16})
        self.assertEqual(result['host_synchronization_calls'], 1)
        self.assertEqual(result['runtime_api_duration_sum_ns']['cudaEventSynchronize_v3020'], 40)

    def test_ambiguous_correlations_are_not_guessed(self):
        db = self.database()
        db.execute('INSERT INTO CUPTI_ACTIVITY_KIND_RUNTIME VALUES (115,120,1,2)')
        result = request_census(db, 100, 200)
        self.assertEqual(result['d2h_activities']['peer_transport']['activities'], 0)
        self.assertEqual(result['d2h_activities']['unattributed']['activities'], 2)

    def test_missing_tables_are_unavailable_instead_of_zero(self):
        db = sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        result = request_census(db, 100, 200)
        self.assertEqual(result['status'], 'UNAVAILABLE')
        self.assertIsNone(result['runtime_api_entered'])
        self.assertIsNone(result['d2h_activities'])

    def test_invalid_windows_fail(self):
        for bounds in ((200, 100), (100, 100), (True, 200)):
            with self.assertRaises(ValueError):
                request_census(self.database(), *bounds)

    def traced_database(self):
        db = self.database()
        db.executescript('''
            CREATE TABLE NVTX_EVENTS(start INTEGER,end INTEGER,globalTid INTEGER,text TEXT,textId INTEGER);
            ALTER TABLE CUPTI_ACTIVITY_KIND_RUNTIME ADD COLUMN globalTid INTEGER;
            UPDATE CUPTI_ACTIVITY_KIND_RUNTIME SET globalTid=10;
            INSERT INTO StringIds VALUES (4,'rv64/gpu/fold/7');
            INSERT INTO NVTX_EVENTS VALUES (105,150,10,NULL,4);
            INSERT INTO CUPTI_ACTIVITY_KIND_RUNTIME VALUES (115,118,5,2,11);
        ''')
        return db

    def test_native_ranges_count_only_contained_calls_on_owner_thread(self):
        result = native_ranges(self.traced_database(), 100, 200)
        self.assertEqual(result['status'], 'MEASURED')
        self.assertEqual(result['ranges'], [{
            'label': 'rv64/gpu/fold/7', 'thread': 10, 'host_enqueue_ns': 45,
            'runtime_api_contained': {'cudaMemcpyAsync_v3020': 1, 'cudaMemcpyPeerAsync_v4000': 1}}])
        self.assertIn('not device durations', result['scope'])

    def test_incomplete_ranges_are_explicitly_partial(self):
        db = self.traced_database()
        db.executescript('''
            INSERT INTO NVTX_EVENTS VALUES (99,120,10,'rv64/gpu/root/0',NULL);
            INSERT INTO NVTX_EVENTS VALUES (180,NULL,10,'rv64/gpu/leaf/3',NULL);
            INSERT INTO NVTX_EVENTS VALUES (180,190,10,'rv64/gpu/malformed',NULL);
        ''')
        result = native_ranges(db, 100, 200)
        self.assertEqual(result['status'], 'PARTIAL')
        self.assertEqual(len(result['ranges']), 1)
        self.assertEqual(len(result['excluded_incomplete_or_malformed_ranges']), 3)

    def test_range_coverage_is_not_zero_when_absent(self):
        db = self.database()
        self.assertEqual(native_ranges(db, 100, 200)['status'], 'UNAVAILABLE')
        db.executescript('CREATE TABLE NVTX_EVENTS(start INTEGER,end INTEGER,globalTid INTEGER,text TEXT,textId INTEGER);')
        result = native_ranges(db, 100, 200)
        self.assertEqual(result['status'], 'NOT_INSTRUMENTED')
        self.assertIsNone(result['ranges'])


if __name__ == '__main__':
    unittest.main()
